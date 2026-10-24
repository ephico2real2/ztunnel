// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;
use std::error::Error as StdErr;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tracing::Level;

use tokio::sync::mpsc;
#[cfg(any(test, feature = "testing"))]
use tracing::error;
use tracing::{debug, info, instrument, trace, warn};

pub use client::*;
pub use metrics::*;
pub use types::*;
use xds::istio::security::Authorization as XdsAuthorization;
use xds::istio::workload::Address as XdsAddress;
use xds::istio::workload::PortList;
use xds::istio::workload::Service as XdsService;
use xds::istio::workload::Workload as XdsWorkload;
use xds::istio::workload::address::Type as XdsType;

use crate::cert_fetcher::{CertFetcher, NoCertFetcher};
use crate::config::ConfigSource;
use crate::rbac::Authorization;
use crate::state::ProxyState;
use crate::state::service::{Endpoint, Service, ServiceStore};
use crate::state::workload::{NamespacedHostname, Workload, WorkloadStore};
use crate::strng::Strng;
use crate::{rbac, strng};
use crate::{tls, xds};

use self::service::discovery::v3::DeltaDiscoveryRequest;

mod client;
pub mod metrics;
mod session;
mod types;

pub(crate) use session::{DrainParticipant, XdsSessionGate};

struct DisplayStatus<'a>(&'a tonic::Status);

impl fmt::Display for DisplayStatus<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = &self.0;
        write!(f, "status: {:?}, message: {:?}", s.code(), s.message())?;

        if s.message().to_string().contains("authentication failure") {
            write!(
                f,
                " (hint: check the control plane logs for more information)"
            )?;
        }
        if !s.details().is_empty()
            && let Ok(st) = std::str::from_utf8(s.details())
        {
            write!(f, ", details: {st}")?;
        }
        if let Some(src) = s.source().and_then(|s| s.source()) {
            write!(f, ", source: {src}")?;
            // Error is not public to explicitly match on, so do a fuzzy match
            if format!("{src}").contains("Temporary failure in name resolution") {
                write!(f, " (hint: is the DNS server reachable?)")?;
            }
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("gRPC error {}", DisplayStatus(.0))]
    GrpcStatus(#[from] tonic::Status),
    #[error("gRPC connection error connecting to {}: {}", .0, DisplayStatus(.1))]
    Connection(String, #[source] tonic::Status),
    /// Attempted to send on a MPSC channel which has been canceled
    #[error(transparent)]
    RequestFailure(#[from] Box<mpsc::error::SendError<DeltaDiscoveryRequest>>),
    #[error("failed to send on demand resource")]
    OnDemandSend(),
    #[error("xDS rejected a resource response for {0}")]
    RejectedResponse(String),
    #[error("failed to clear stale xDS state: {0}")]
    Reset(String),
    #[error("TLS Error: {0}")]
    TLSError(#[from] tls::Error),
}

/// Updates the [ProxyState] from XDS.
/// All state updates code goes in ProxyStateUpdateMutator, that takes state as a parameter.
/// this guarantees that the state is always locked when it is updated.
#[derive(Clone)]
pub struct ProxyStateUpdateMutator {
    cert_fetcher: Arc<dyn CertFetcher>,
}

#[derive(Clone)]
pub struct ProxyStateUpdater {
    state: Arc<RwLock<ProxyState>>,
    updater: ProxyStateUpdateMutator,
}

impl ProxyStateUpdater {
    /// Creates a new updater for the given stores. Will prefetch certs when workloads are updated.
    pub fn new(state: Arc<RwLock<ProxyState>>, cert_fetcher: Arc<dyn CertFetcher>) -> Self {
        Self {
            state,
            updater: ProxyStateUpdateMutator { cert_fetcher },
        }
    }
    /// Creates a new updater that does not prefetch workload certs.
    pub fn new_no_fetch(state: Arc<RwLock<ProxyState>>) -> Self {
        Self {
            state,
            updater: ProxyStateUpdateMutator::new_no_fetch(),
        }
    }
}

impl ProxyStateUpdateMutator {
    /// Creates a new updater that does not prefetch workload certs.
    pub fn new_no_fetch() -> Self {
        ProxyStateUpdateMutator {
            cert_fetcher: Arc::new(NoCertFetcher()),
        }
    }

    #[instrument(
        level = Level::TRACE,
        name="insert_workload",
        skip_all,
        fields(uid=%w.uid),
    )]
    pub fn insert_workload(&self, state: &mut ProxyState, w: XdsWorkload) -> anyhow::Result<()> {
        debug!("handling insert");

        // Clone services, so we can pass full ownership of the rest of XdsWorkload to build our Workload
        // object, which doesn't include Services.
        // In theory, I think we could avoid this if Workload::try_from returning the services.
        // let services = w.services.clone();
        // Convert the workload.
        let (workload, services): (Workload, HashMap<String, PortList>) = w.try_into()?;
        let workload = Arc::new(workload);

        // First, remove the entry entirely to make sure things are cleaned up properly.
        self.replace_workload_for_update(state, &workload);

        // Prefetch the cert for the workload.
        self.cert_fetcher.prefetch_cert(&workload);

        // Lock and upstate the stores.
        state.workloads.insert(workload.clone());
        insert_service_endpoints(&workload, &services, &mut state.services)?;

        Ok(())
    }

    pub fn remove(&self, state: &mut ProxyState, xds_name: &Strng) {
        if self.remove_workload_by_uid(state, xds_name, false) {
            return;
        }
        let Ok(name) = NamespacedHostname::from_str(xds_name) else {
            warn!(
                "tried to remove service but it did not have the expected namespace/hostname format"
            );
            return;
        };
        if name.hostname.contains('/') {
            trace!("not a service, not attempting to delete as such");
            return;
        }
        if !state.services.remove(&name) {
            warn!("tried to remove service, but it was not found");
        }
    }

    fn replace_workload_for_update(&self, state: &mut ProxyState, workload: &Workload) {
        let preserve_certificate = state
            .workloads
            .find_uid(&workload.uid)
            .is_some_and(|previous| previous.identity() == workload.identity());
        self.remove_workload_by_uid(state, &workload.uid, preserve_certificate);
    }

    fn remove_workload_by_uid(
        &self,
        state: &mut ProxyState,
        workload_uid: &Strng,
        for_workload_insert: bool,
    ) -> bool {
        let Some(prev) = state.workloads.remove(workload_uid) else {
            return false;
        };
        state.workload_xds_names.retain(|_, uid| uid != &prev.uid);
        state.services.remove_endpoint(&prev);
        if !for_workload_insert
            && state
                .workloads
                .was_last_identity_on_node(&prev.node, &prev.identity())
        {
            self.cert_fetcher.clear_cert(&prev);
        }
        true
    }

    fn remove_address_resource(&self, state: &mut ProxyState, xds_name: &Strng) {
        if let Some(service_key) = state.service_xds_names.remove(xds_name) {
            state.service_xds_names.retain(|_, key| key != &service_key);
            state.services.remove(&service_key);
            return;
        }
        if let Some(workload_uid) = state.workload_xds_names.remove(xds_name) {
            self.remove_workload_by_uid(state, &workload_uid, false);
            return;
        }
        trace!(resource_name = %xds_name, "Address resource already absent");
    }

    pub fn insert_address(&self, state: &mut ProxyState, a: XdsAddress) -> anyhow::Result<()> {
        match a.r#type {
            Some(XdsType::Workload(w)) => self.insert_workload(state, w),
            Some(XdsType::Service(s)) => self.insert_service(state, s),
            _ => Err(anyhow::anyhow!("unknown address type")),
        }
    }

    #[instrument(
        level = Level::TRACE,
        name="insert_service",
        skip_all,
        fields(name=%service.name),
    )]
    pub fn insert_service(
        &self,
        state: &mut ProxyState,
        service: XdsService,
    ) -> anyhow::Result<()> {
        debug!("handling insert");
        let mut service = Service::try_from(&service)?;

        // If the service already exists, add existing endpoints into the new service.
        if let Some(prev) = state
            .services
            .get_by_namespaced_host(&service.namespaced_hostname())
        {
            for ep in prev.endpoints.iter() {
                if service.should_include_endpoint(ep.status) {
                    service
                        .endpoints
                        .insert(ep.workload_uid.clone(), ep.clone());
                }
            }
        }

        state.services.insert(service);
        Ok(())
    }

    pub fn insert_authorization(
        &self,
        state: &mut ProxyState,
        xds_name: Strng,
        r: XdsAuthorization,
    ) -> anyhow::Result<()> {
        info!("handling RBAC update {}", r.name);

        let rbac = rbac::Authorization::try_from(r)?;
        trace!(
            "insert policy {}, {}",
            xds_name,
            serde_json::to_string(&rbac)?
        );
        state.policies.insert(xds_name, rbac);
        Ok(())
    }

    pub fn remove_authorization(&self, state: &mut ProxyState, xds_name: Strng) {
        info!("handling RBAC delete {}", xds_name);
        state.policies.remove(xds_name);
    }
}

impl Handler<XdsWorkload> for ProxyStateUpdater {
    fn handle(
        &self,
        updates: Box<&mut dyn Iterator<Item = XdsUpdate<XdsWorkload>>>,
    ) -> Result<(), Vec<RejectedConfig>> {
        // use deepsize::DeepSizeOf;
        let mut state = self.state.write().unwrap();
        let handle = |res: XdsUpdate<XdsWorkload>| {
            match res {
                XdsUpdate::Update(w) => self.updater.insert_workload(&mut state, w.resource)?,
                XdsUpdate::Remove(name) => {
                    debug!("handling delete {}", name);
                    self.updater.remove(&mut state, &strng::new(name))
                }
            }
            Ok(())
        };
        handle_single_resource(updates, handle)
    }
}

impl Handler<XdsAddress> for ProxyStateUpdater {
    fn handle(
        &self,
        updates: Box<&mut dyn Iterator<Item = XdsUpdate<XdsAddress>>>,
    ) -> Result<(), Vec<RejectedConfig>> {
        let mut prepared = Vec::new();
        let mut rejects = Vec::new();
        for update in updates {
            let name = update.name();
            match self.updater.prepare_address_update(update) {
                Ok(update) => prepared.push(update),
                Err(err) => rejects.push(RejectedConfig::new(name, err)),
            }
        }
        if !rejects.is_empty() {
            return Err(rejects);
        }

        // Do not let a valid prefix of an Address response change the cache when
        // a later resource is invalid and the complete response will be NACKed.
        let mut state = self.state.write().unwrap();
        for update in prepared {
            self.updater.apply_address_update(&mut state, update);
        }
        Ok(())
    }
}

enum PreparedAddressUpdate {
    Workload {
        xds_name: Strng,
        workload: Arc<Workload>,
        endpoints: Vec<(NamespacedHostname, Endpoint)>,
    },
    Service {
        xds_name: Strng,
        service: Box<Service>,
    },
    Remove(Strng),
}

impl ProxyStateUpdateMutator {
    fn prepare_address_update(
        &self,
        update: XdsUpdate<XdsAddress>,
    ) -> anyhow::Result<PreparedAddressUpdate> {
        match update {
            XdsUpdate::Remove(name) => Ok(PreparedAddressUpdate::Remove(name)),
            XdsUpdate::Update(resource) => {
                let xds_name = resource.name;
                match resource.resource.r#type {
                    Some(XdsType::Workload(workload)) => {
                        let (workload, services): (Workload, HashMap<String, PortList>) =
                            workload.try_into()?;
                        let status = workload.status;
                        let workload = Arc::new(workload);
                        let endpoints = services
                            .into_iter()
                            .map(|(host, ports)| {
                                Ok((
                                    NamespacedHostname::from_str(&host)?,
                                    Endpoint {
                                        workload_uid: workload.uid.clone(),
                                        port: (&ports).into(),
                                        status,
                                    },
                                ))
                            })
                            .collect::<anyhow::Result<Vec<_>>>()?;
                        Ok(PreparedAddressUpdate::Workload {
                            xds_name,
                            workload,
                            endpoints,
                        })
                    }
                    Some(XdsType::Service(service)) => Ok(PreparedAddressUpdate::Service {
                        xds_name,
                        service: Box::new(Service::try_from(&service)?),
                    }),
                    None => Err(anyhow::anyhow!("address resource has no type")),
                }
            }
        }
    }

    fn apply_address_update(&self, state: &mut ProxyState, update: PreparedAddressUpdate) {
        match update {
            PreparedAddressUpdate::Workload {
                xds_name,
                workload,
                endpoints,
            } => {
                if let Some(previous_service) = state.service_xds_names.remove(&xds_name) {
                    state
                        .service_xds_names
                        .retain(|_, key| key != &previous_service);
                    state.services.remove(&previous_service);
                }
                if let Some(previous_uid) = state.workload_xds_names.remove(&xds_name) {
                    let preserve_certificate = previous_uid == workload.uid
                        && state
                            .workloads
                            .find_uid(&previous_uid)
                            .is_some_and(|previous| previous.identity() == workload.identity());
                    self.remove_workload_by_uid(state, &previous_uid, preserve_certificate);
                }
                self.replace_workload_for_update(state, &workload);
                state
                    .workload_xds_names
                    .insert(xds_name, workload.uid.clone());
                self.cert_fetcher.prefetch_cert(&workload);
                state.workloads.insert(workload);
                for (host, endpoint) in endpoints {
                    state.services.insert_endpoint(host, endpoint);
                }
            }
            PreparedAddressUpdate::Service { xds_name, service } => {
                let mut service = *service;
                let service_key = service.namespaced_hostname();
                if let Some(previous_uid) = state.workload_xds_names.remove(&xds_name) {
                    self.remove_workload_by_uid(state, &previous_uid, false);
                }
                if let Some(previous_key) = state.service_xds_names.remove(&xds_name)
                    && previous_key != service_key
                {
                    state
                        .service_xds_names
                        .retain(|_, key| key != &previous_key);
                    state.services.remove(&previous_key);
                }
                state.service_xds_names.retain(|_, key| key != &service_key);
                // Preserve endpoint updates that arrived before the Service.
                if let Some(previous) = state.services.get_by_namespaced_host(&service_key) {
                    for endpoint in previous.endpoints.iter() {
                        if service.should_include_endpoint(endpoint.status) {
                            service
                                .endpoints
                                .insert(endpoint.workload_uid.clone(), endpoint.clone());
                        }
                    }
                }
                state.service_xds_names.insert(xds_name, service_key);
                state.services.insert(service);
            }
            PreparedAddressUpdate::Remove(name) => self.remove_address_resource(state, &name),
        }
    }
}

fn insert_service_endpoints(
    workload: &Workload,
    services: &HashMap<String, PortList>,
    services_state: &mut ServiceStore,
) -> anyhow::Result<()> {
    for (namespaced_host, ports) in services {
        // Parse the namespaced hostname for the service.
        let namespaced_host = NamespacedHostname::from_str(namespaced_host)?;
        services_state.insert_endpoint(
            namespaced_host,
            Endpoint {
                workload_uid: workload.uid.clone(),
                port: ports.into(),
                status: workload.status,
            },
        )
    }
    Ok(())
}

impl Handler<XdsAuthorization> for ProxyStateUpdater {
    fn no_on_demand(&self) -> bool {
        true
    }

    fn handle(
        &self,
        updates: Box<&mut dyn Iterator<Item = XdsUpdate<XdsAuthorization>>>,
    ) -> Result<(), Vec<RejectedConfig>> {
        let mut validated = Vec::new();
        let mut rejects = Vec::new();
        for update in updates {
            match update {
                XdsUpdate::Update(workload) => {
                    let name = workload.name;
                    info!("handling RBAC update {}", workload.resource.name);
                    match rbac::Authorization::try_from(workload.resource) {
                        Ok(policy) => match serde_json::to_string(&policy) {
                            Ok(serialized) => {
                                trace!("insert policy {}, {}", name, serialized);
                                validated.push((name, Some(policy)));
                            }
                            Err(err) => rejects.push(RejectedConfig::new(name, err.into())),
                        },
                        Err(err) => rejects.push(RejectedConfig::new(name, err.into())),
                    }
                }
                XdsUpdate::Remove(name) => validated.push((name, None)),
            }
        }
        if !rejects.is_empty() {
            return Err(rejects);
        }

        // Validate every update before changing the shared policy store. A NACK
        // must not accompany a partial policy commit, especially for a batch
        // that removes a deny/quarantine policy and also contains an invalid item.
        let mut state = self.state.write().unwrap();
        for (name, policy) in validated {
            match policy {
                Some(policy) => state.policies.insert(name, policy),
                None => state.policies.remove(name),
            }
        }
        state.policies.send();
        Ok(())
    }
}

/// LocalClient serves as a local file reader alternative for XDS. This is intended for testing.
pub struct LocalClient {
    pub cfg: ConfigSource,
    pub state: Arc<RwLock<ProxyState>>,
    pub cert_fetcher: Arc<dyn CertFetcher>,
    pub local_node: Option<Strng>,
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalWorkload {
    #[serde(flatten)]
    pub workload: Workload,
    pub services: HashMap<String, HashMap<u16, u16>>,
}

#[derive(Default, Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalConfig {
    #[serde(default)]
    pub workloads: Vec<LocalWorkload>,
    #[serde(default)]
    pub policies: Vec<Authorization>,
    #[serde(default)]
    pub services: Vec<Service>,
}

impl LocalClient {
    #[instrument(skip_all, name = "local_client")]
    pub async fn run(self) -> Result<(), anyhow::Error> {
        // Load initial state
        match &self.cfg {
            #[cfg(any(test, feature = "testing"))]
            ConfigSource::Dynamic(rx) => {
                let mut rx = rx.lock().await;
                let r = rx
                    .recv()
                    .await
                    .ok_or(anyhow::anyhow!("did not get initial config"))?;
                self.load_config(r)?;
                rx.ack().await?;
            }
            f => {
                let r: LocalConfig = serde_yaml::from_str(&f.read_to_string().await?)?;
                self.load_config(r)?;
            }
        };
        #[cfg(any(test, feature = "testing"))]
        if let ConfigSource::Dynamic(ref rx) = self.cfg {
            let rx = rx.clone();
            tokio::spawn(async move {
                // Mutex is just for borrow checker; we know we are the only user and can hold the lock forever.
                let mut rx = rx.lock().await;
                while let Some(req) = rx.recv().await {
                    if let Err(e) = self.load_config(req) {
                        error!("failed to load dynamic config update: {e:?}");
                    }
                    if let Err(e) = rx.ack().await {
                        error!("failed to ack: {}", e);
                    }
                }
            });
        };
        Ok(())
    }

    fn load_config(&self, r: LocalConfig) -> anyhow::Result<()> {
        debug!(
            "load local config: {}",
            serde_yaml::to_string(&r).unwrap_or_default()
        );
        let mut state = self.state.write().unwrap();
        // Clear the state
        state.workloads = WorkloadStore::new(self.local_node.clone());
        state.workload_xds_names.clear();
        state.service_xds_names.clear();
        state.services = Default::default();
        // Policies have some channels, so we don't want to reset it entirely
        state.policies.clear_all_policies();
        let num_workloads = r.workloads.len();
        let num_policies = r.policies.len();
        for wl in r.workloads {
            trace!("inserting local workload {}", &wl.workload.uid);
            self.cert_fetcher.prefetch_cert(&wl.workload);
            let w = Arc::new(wl.workload);
            state.workloads.insert(w.clone());

            let services: HashMap<String, PortList> = wl
                .services
                .into_iter()
                .map(|(k, v)| (k, PortList::from(v)))
                .collect();

            insert_service_endpoints(&w, &services, &mut state.services)?;
        }
        for rbac in r.policies {
            let xds_name = rbac.to_key();
            state.policies.insert(xds_name, rbac);
        }
        for svc in r.services {
            state.services.insert(svc);
        }
        info!(%num_workloads, %num_policies, "local config initialized");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex, RwLock};

    use super::*;
    use crate::rbac::{RbacAction, RbacScope};

    #[derive(Default)]
    struct RecordingCertFetcher(Mutex<Vec<Strng>>);

    impl CertFetcher for RecordingCertFetcher {
        fn prefetch_cert(&self, _: &Workload) {}

        fn clear_cert(&self, workload: &Workload) {
            self.0.lock().unwrap().push(workload.uid.clone());
        }
    }

    fn xds_workload_address(name: &str, ip: Ipv4Addr) -> XdsAddress {
        XdsAddress {
            r#type: Some(XdsType::Workload(XdsWorkload {
                uid: "default/pod-1".to_string(),
                name: name.to_string(),
                namespace: "default".to_string(),
                addresses: vec![ip.octets().to_vec().into()],
                tunnel_protocol: 0,
                trust_domain: "local".to_string(),
                service_account: "default".to_string(),
                node: "default".to_string(),
                native_tunnel: true,
                ..Default::default()
            })),
        }
    }

    #[test]
    fn invalid_address_batch_does_not_replace_existing_workload() {
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        let updater = ProxyStateUpdater::new_no_fetch(state.clone());
        let old_address = xds_workload_address("old-name", Ipv4Addr::new(10, 0, 0, 1));
        let mut initial = vec![XdsUpdate::Update(XdsResource {
            name: "default/pod-1".into(),
            resource: old_address,
        })]
        .into_iter();

        <ProxyStateUpdater as Handler<XdsAddress>>::handle(&updater, Box::new(&mut initial))
            .unwrap();

        let mut updates = vec![
            XdsUpdate::Update(XdsResource {
                name: "default/pod-1".into(),
                resource: xds_workload_address("replacement-name", Ipv4Addr::new(10, 0, 0, 2)),
            }),
            XdsUpdate::Update(XdsResource {
                name: "invalid".into(),
                resource: XdsAddress { r#type: None },
            }),
        ]
        .into_iter();

        let result =
            <ProxyStateUpdater as Handler<XdsAddress>>::handle(&updater, Box::new(&mut updates));

        assert!(result.is_err());
        let state = state.read().unwrap();
        let workload = state
            .workloads
            .find_uid(&strng::new("default/pod-1"))
            .expect("the pre-existing workload should survive the rejected batch");
        assert_eq!(workload.name, "old-name");
        assert_eq!(
            workload.workload_ips,
            vec![std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
        );
    }

    #[test]
    fn opaque_address_names_update_and_remove_only_the_mapped_workload() {
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        let updater = ProxyStateUpdater::new_no_fetch(state.clone());
        let workload_update = |resource_name: &str, uid: &str, ip: Ipv4Addr| {
            XdsUpdate::Update(XdsResource {
                name: resource_name.into(),
                resource: XdsAddress {
                    r#type: Some(XdsType::Workload(XdsWorkload {
                        uid: uid.to_string(),
                        name: uid.rsplit('/').next().unwrap().to_string(),
                        namespace: "default".to_string(),
                        addresses: vec![ip.octets().to_vec().into()],
                        trust_domain: "local".to_string(),
                        service_account: "default".to_string(),
                        node: "default".to_string(),
                        services: HashMap::from([(
                            "/example.com".to_string(),
                            PortList {
                                ports: vec![xds::istio::workload::Port {
                                    service_port: 80,
                                    target_port: 8080,
                                }],
                            },
                        )]),
                        ..Default::default()
                    })),
                },
            })
        };
        let service_update = XdsUpdate::Update(XdsResource {
            name: "opaque-service-resource".into(),
            resource: XdsAddress {
                r#type: Some(XdsType::Service(XdsService {
                    hostname: "example.com".to_string(),
                    ports: vec![xds::istio::workload::Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                    ..Default::default()
                })),
            },
        });

        let mut initial = vec![
            workload_update(
                "opaque-workload-a",
                "default/pod-a",
                Ipv4Addr::new(10, 0, 0, 1),
            ),
            workload_update(
                "opaque-workload-b",
                "default/pod-b",
                Ipv4Addr::new(10, 0, 0, 2),
            ),
            service_update,
        ]
        .into_iter();
        <ProxyStateUpdater as Handler<XdsAddress>>::handle(&updater, Box::new(&mut initial))
            .unwrap();

        let mut replacement = vec![workload_update(
            "opaque-workload-a",
            "default/pod-a-replacement",
            Ipv4Addr::new(10, 0, 0, 3),
        )]
        .into_iter();
        <ProxyStateUpdater as Handler<XdsAddress>>::handle(&updater, Box::new(&mut replacement))
            .unwrap();

        {
            let state = state.read().unwrap();
            assert!(
                state
                    .workloads
                    .find_uid(&strng::new("default/pod-a"))
                    .is_none()
            );
            assert!(
                state
                    .workloads
                    .find_uid(&strng::new("default/pod-a-replacement"))
                    .is_some()
            );
            assert!(
                state
                    .workloads
                    .find_uid(&strng::new("default/pod-b"))
                    .is_some()
            );
        }

        let mut remove = vec![XdsUpdate::Remove("opaque-workload-a".into())].into_iter();
        <ProxyStateUpdater as Handler<XdsAddress>>::handle(&updater, Box::new(&mut remove))
            .unwrap();

        let state = state.read().unwrap();
        assert!(
            state
                .workloads
                .find_uid(&strng::new("default/pod-a-replacement"))
                .is_none()
        );
        assert!(
            state
                .workloads
                .find_uid(&strng::new("default/pod-b"))
                .is_some()
        );
        let service = state
            .services
            .get_by_namespaced_host(&NamespacedHostname::from_str("/example.com").unwrap())
            .unwrap();
        assert!(!service.endpoints.contains(&strng::new("default/pod-a")));
        assert!(
            !service
                .endpoints
                .contains(&strng::new("default/pod-a-replacement"))
        );
        assert!(service.endpoints.contains(&strng::new("default/pod-b")));
    }

    #[test]
    fn opaque_service_names_update_and_remove_only_the_mapped_service() {
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        let updater = ProxyStateUpdater::new_no_fetch(state.clone());
        let service_update = |resource_name: &str, hostname: &str, ip: Ipv4Addr| {
            XdsUpdate::Update(XdsResource {
                name: resource_name.into(),
                resource: XdsAddress {
                    r#type: Some(XdsType::Service(XdsService {
                        name: "api".to_string(),
                        namespace: "default".to_string(),
                        hostname: hostname.to_string(),
                        addresses: vec![xds::istio::workload::NetworkAddress {
                            network: String::new(),
                            address: ip.octets().to_vec(),
                        }],
                        ..Default::default()
                    })),
                },
            })
        };
        let service_key =
            |hostname: &str| NamespacedHostname::from_str(&format!("default/{hostname}")).unwrap();

        let mut initial = vec![
            service_update("opaque-service-a", "a.example", Ipv4Addr::new(10, 96, 0, 1)),
            service_update("opaque-service-b", "b.example", Ipv4Addr::new(10, 96, 0, 2)),
        ]
        .into_iter();
        <ProxyStateUpdater as Handler<XdsAddress>>::handle(&updater, Box::new(&mut initial))
            .unwrap();

        let mut replacement = vec![service_update(
            "opaque-service-a",
            "replacement.example",
            Ipv4Addr::new(10, 96, 0, 3),
        )]
        .into_iter();
        <ProxyStateUpdater as Handler<XdsAddress>>::handle(&updater, Box::new(&mut replacement))
            .unwrap();

        {
            let state = state.read().unwrap();
            assert!(
                state
                    .services
                    .get_by_namespaced_host(&service_key("a.example"))
                    .is_none()
            );
            assert!(
                state
                    .services
                    .get_by_namespaced_host(&service_key("replacement.example"))
                    .is_some()
            );
            assert!(
                state
                    .services
                    .get_by_namespaced_host(&service_key("b.example"))
                    .is_some()
            );
        }

        let mut remove = vec![XdsUpdate::Remove("opaque-service-a".into())].into_iter();
        <ProxyStateUpdater as Handler<XdsAddress>>::handle(&updater, Box::new(&mut remove))
            .unwrap();

        let state = state.read().unwrap();
        assert!(
            state
                .services
                .get_by_namespaced_host(&service_key("replacement.example"))
                .is_none()
        );
        assert!(
            state
                .services
                .get_by_namespaced_host(&service_key("b.example"))
                .is_some()
        );
        assert_eq!(state.service_xds_names.len(), 1);
    }

    #[test]
    fn certificate_cache_survives_only_same_identity_refreshes() {
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        let cert_fetcher = Arc::new(RecordingCertFetcher::default());
        let updater = ProxyStateUpdater::new(state.clone(), cert_fetcher.clone());
        let workload_update = |uid: &str, trust_domain: &str| {
            XdsUpdate::Update(XdsResource {
                name: "opaque-workload-resource".into(),
                resource: XdsAddress {
                    r#type: Some(XdsType::Workload(XdsWorkload {
                        uid: uid.to_string(),
                        name: uid.rsplit('/').next().unwrap().to_string(),
                        namespace: "default".to_string(),
                        addresses: vec![Ipv4Addr::new(10, 0, 0, 1).octets().to_vec().into()],
                        trust_domain: trust_domain.to_string(),
                        service_account: "api".to_string(),
                        node: "node-a".to_string(),
                        ..Default::default()
                    })),
                },
            })
        };
        let apply = |update| {
            let mut updates = vec![update].into_iter();
            <ProxyStateUpdater as Handler<XdsAddress>>::handle(&updater, Box::new(&mut updates))
                .unwrap();
        };

        apply(workload_update("default/pod-1", "mesh.example"));
        apply(workload_update("default/pod-1", "mesh.example"));
        assert!(
            cert_fetcher.0.lock().unwrap().is_empty(),
            "a same-UID, same-identity refresh should retain its certificate"
        );

        apply(workload_update("default/pod-1", "other.mesh.example"));
        assert_eq!(
            *cert_fetcher.0.lock().unwrap(),
            vec![strng::new("default/pod-1")],
            "an identity change must clear the old certificate"
        );

        apply(workload_update("default/pod-2", "other.mesh.example"));
        assert_eq!(
            *cert_fetcher.0.lock().unwrap(),
            vec![strng::new("default/pod-1"), strng::new("default/pod-1")],
            "a UID change must clear the previous workload certificate"
        );

        let mut service_update = vec![XdsUpdate::Update(XdsResource {
            name: "opaque-workload-resource".into(),
            resource: XdsAddress {
                r#type: Some(XdsType::Service(XdsService {
                    hostname: "api.example".to_string(),
                    ..Default::default()
                })),
            },
        })]
        .into_iter();
        <ProxyStateUpdater as Handler<XdsAddress>>::handle(&updater, Box::new(&mut service_update))
            .unwrap();
        assert_eq!(
            *cert_fetcher.0.lock().unwrap(),
            vec![
                strng::new("default/pod-1"),
                strng::new("default/pod-1"),
                strng::new("default/pod-2"),
            ],
            "a Workload-to-Service replacement must clear the removed workload certificate"
        );
    }

    #[test]
    fn local_config_reload_clears_xds_resource_name_mappings() {
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        state
            .write()
            .unwrap()
            .workload_xds_names
            .insert("opaque-workload".into(), "default/pod-a".into());
        state.write().unwrap().service_xds_names.insert(
            "opaque-service".into(),
            NamespacedHostname::from_str("default/api.example").unwrap(),
        );
        let client = LocalClient {
            cfg: ConfigSource::File(Default::default()),
            state: state.clone(),
            cert_fetcher: Arc::new(NoCertFetcher()),
            local_node: None,
        };

        client.load_config(LocalConfig::default()).unwrap();

        assert!(state.read().unwrap().workload_xds_names.is_empty());
        assert!(state.read().unwrap().service_xds_names.is_empty());
    }

    #[test]
    fn invalid_authorization_batch_does_not_remove_existing_policy() {
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        let quarantine = Authorization {
            name: "quarantine".into(),
            namespace: "".into(),
            scope: RbacScope::Global,
            action: RbacAction::Deny,
            rules: vec![vec![vec![]]],
            dry_run: false,
        };
        let quarantine_key = quarantine.to_key();
        let mut state_write = state.write().unwrap();
        state_write
            .policies
            .insert(quarantine_key.clone(), quarantine);
        let policy_changes = state_write.policies.subscribe();
        drop(state_write);

        let updater = ProxyStateUpdater::new_no_fetch(state.clone());
        let malformed = XdsAuthorization {
            name: "invalid".to_string(),
            namespace: "default".to_string(),
            scope: i32::MAX,
            action: crate::xds::istio::security::Action::Allow as i32,
            ..Default::default()
        };
        let mut updates = vec![
            XdsUpdate::Remove(quarantine_key.clone()),
            XdsUpdate::Update(XdsResource {
                name: "invalid".into(),
                resource: malformed,
            }),
        ]
        .into_iter();

        let result = <ProxyStateUpdater as Handler<XdsAuthorization>>::handle(
            &updater,
            Box::new(&mut updates),
        );

        assert!(result.is_err());
        let state_read = state.read().unwrap();
        assert!(state_read.policies.get(&quarantine_key).is_some());
        assert!(!policy_changes.has_changed().unwrap());
    }
}
