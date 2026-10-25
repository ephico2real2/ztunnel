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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, mem};

use prost::{DecodeError, EncodeError};
use prost_types::value::Kind;
use prost_types::{Struct, Value};
use serde_json;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tonic::metadata::{AsciiMetadataKey, AsciiMetadataValue};
use tracing::{Instrument, debug, error, info, info_span, warn};

use crate::metrics::{IncrementRecorder, Recorder};
use crate::strng::Strng;
use crate::xds::XdsSessionGate;
use crate::xds::metrics::{ConnectionTerminationReason, Metrics};
use crate::xds::service::discovery::v3::Resource as ProtoResource;
use crate::xds::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use crate::xds::service::discovery::v3::*;
use crate::xds::{ADDRESS_TYPE, AUTHORIZATION_TYPE};
use crate::{identity, strng, tls};

use super::Error;
#[path = "issuer_profile.rs"]
mod issuer_profile;
use crate::xds::ISSUER_PROFILE_TYPE;

const INSTANCE_IP: &str = "INSTANCE_IP";
const INSTANCE_IPS: &str = "INSTANCE_IPS";
const DEFAULT_IP: &str = "1.1.1.1";
const POD_NAME: &str = "POD_NAME";
const POD_NAMESPACE: &str = "POD_NAMESPACE";
const NODE_NAME: &str = "NODE_NAME";
const NAME: &str = "NAME";
const NAMESPACE: &str = "NAMESPACE";
const EMPTY_STR: &str = "";
const ISTIO_METAJSON_PREFIX: &str = "ISTIO_METAJSON_";

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct ResourceKey {
    pub name: Strng,
    pub type_url: Strng,
}

impl Display for ResourceKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.type_url, self.name)
    }
}

#[derive(Debug)]
pub struct RejectedConfig {
    name: Strng,
    reason: anyhow::Error,
}

impl RejectedConfig {
    pub fn new(name: Strng, reason: anyhow::Error) -> Self {
        Self { name, reason }
    }
}

impl Display for RejectedConfig {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.reason)
    }
}

/// handle_single_resource is a helper to process a set of updates with a closure that processes items one-by-one.
/// It handles aggregating errors as NACKS.
pub fn handle_single_resource<T: prost::Message, F: FnMut(XdsUpdate<T>) -> anyhow::Result<()>>(
    updates: impl Iterator<Item = XdsUpdate<T>>,
    mut handle_one: F,
) -> Result<(), Vec<RejectedConfig>> {
    let rejects: Vec<RejectedConfig> = updates
        .filter_map(|res| {
            let name = res.name();
            if let Err(e) = handle_one(res) {
                Some(RejectedConfig::new(name, e))
            } else {
                None
            }
        })
        .collect();
    if rejects.is_empty() {
        Ok(())
    } else {
        Err(rejects)
    }
}

// Handler is responsible for handling a discovery response.
// Handlers can mutate state and return a list of rejected configurations (if there are any).
pub trait Handler<T: prost::Message>: Send + Sync + 'static {
    fn no_on_demand(&self) -> bool {
        false
    }
    fn handle(
        &self,
        res: Box<&mut dyn Iterator<Item = XdsUpdate<T>>>,
    ) -> Result<(), Vec<RejectedConfig>>;
}

// ResponseHandler is responsible for handling a discovery response.
// Handlers can mutate state and return a list of rejected configurations (if there are any).
// This is an internal only trait; public usage uses the Handler type which is typed.
#[async_trait::async_trait]
trait RawHandler: Send + Sync + 'static {
    async fn handle_async(
        &self,
        state: &mut State,
        res: DeltaDiscoveryResponse,
    ) -> Result<(), Vec<RejectedConfig>> {
        self.handle(state, res)
    }

    fn handle(
        &self,
        state: &mut State,
        res: DeltaDiscoveryResponse,
    ) -> Result<(), Vec<RejectedConfig>>;

    fn clear(&self, state: &mut State, type_url: &Strng) -> Result<(), Vec<RejectedConfig>>;
}

// HandlerWrapper is responsible for implementing RawHandler the provided handler.
struct HandlerWrapper<T: prost::Message> {
    h: Box<dyn Handler<T>>,
}

impl<T: 'static + fmt::Debug + prost::Message + Default> RawHandler for HandlerWrapper<T> {
    fn handle(
        &self,
        state: &mut State,
        res: DeltaDiscoveryResponse,
    ) -> Result<(), Vec<RejectedConfig>> {
        let type_url = strng::new(res.type_url);
        let mut updates = Vec::with_capacity(res.resources.len() + res.removed_resources.len());
        let mut decode_failures = Vec::new();
        for raw in &res.resources {
            match decode_proto::<T>(raw) {
                Ok(update) => updates.push(XdsUpdate::Update(update)),
                Err(err) => decode_failures.push(RejectedConfig {
                    name: raw.name.as_str().into(),
                    reason: err.into(),
                }),
            }
        }
        // A malformed response is rejected before any valid resource or removal can
        // mutate proxy state. Applying the valid subset and then NACKing made the
        // cached state disagree with the response status.
        if !decode_failures.is_empty() {
            return Err(decode_failures);
        }
        updates.extend(
            res.removed_resources
                .iter()
                .cloned()
                .map(|name| XdsUpdate::Remove(name.into())),
        );

        // The handler must apply the complete decoded update before the client
        // records names or wakes on-demand waiters. Some typed handlers also
        // validate their whole batch before committing it.
        let mut updates = updates.into_iter();
        self.h.handle(Box::new(&mut updates))?;

        // Update the local xDS cache only after proxy state accepted the response.
        // Match handler order: additions first, removals last.
        for r in res.resources {
            let key = ResourceKey {
                name: r.name.into(),
                type_url: type_url.clone(),
            };
            state.notify_on_demand(&key);
            state.add_resource(key.type_url, key.name, r.version.into());
        }
        for name in res.removed_resources {
            let k = ResourceKey {
                name: name.into(),
                type_url: type_url.clone(),
            };
            debug!("received delete resource {k}");
            if let Some(rm) = state.known_resources.get_mut(&k.type_url) {
                rm.remove(&k.name);
            }
            state.notify_on_demand(&k);
        }

        Ok(())
    }

    fn clear(&self, state: &mut State, type_url: &Strng) -> Result<(), Vec<RejectedConfig>> {
        let names = state
            .known_resources
            .get(type_url)
            .map(|resources| resources.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        if names.is_empty() {
            state.known_resources.remove(type_url);
            return Ok(());
        }

        let updates = names
            .iter()
            .cloned()
            .map(XdsUpdate::Remove)
            .collect::<Vec<_>>();
        let mut updates = updates.into_iter();
        self.h.handle(Box::new(&mut updates))?;
        state.known_resources.remove(type_url);
        for name in names {
            state.notify_on_demand(&ResourceKey {
                name,
                type_url: type_url.clone(),
            });
        }
        Ok(())
    }
}

pub struct Config {
    address: String,
    tls_builder: Box<dyn tls::ControlPlaneClientCertProvider>,
    auth: identity::AuthSource,
    proxy_metadata: HashMap<String, String>,
    handlers: HashMap<Strng, Box<dyn RawHandler>>,
    initial_requests: Vec<DeltaDiscoveryRequest>,
    on_demand: bool,
    session_gate: Option<XdsSessionGate>,
    issuer_profile_initial_timeout: Duration,
    profile_provider: Option<std::sync::Arc<crate::tls::profile_provider::ProfileProvider>>,

    /// alt_hostname provides an alternative accepted SAN for the control plane TLS verification
    alt_hostname: Option<String>,
    xds_headers: Vec<(AsciiMetadataKey, AsciiMetadataValue)>,
}

pub struct State {
    /// Stores all known resources. Map from type_url to name to the version the server last
    /// sent, echoed back in initial_resource_versions on reconnect so the server can skip
    /// re-sending resources whose content is unchanged.
    known_resources: HashMap<Strng, HashMap<Strng, Strng>>,

    /// pending stores a list of all resources that are pending and XDS push
    pending: HashMap<ResourceKey, oneshot::Sender<()>>,

    demand: mpsc::Receiver<(oneshot::Sender<()>, ResourceKey)>,
    demand_tx: mpsc::Sender<(oneshot::Sender<()>, ResourceKey)>,
}

impl State {
    fn notify_on_demand(&mut self, key: &ResourceKey) {
        if let Some(send) = self.pending.remove(key) {
            debug!("on demand notify {}", key.name);
            if send.send(()).is_err() {
                warn!("on demand dropped event for {}", key.name)
            }
        }
    }
    fn add_resource(&mut self, type_url: Strng, name: Strng, version: Strng) {
        self.known_resources
            .entry(type_url)
            .or_default()
            .insert(name, version);
    }

    /// Records a resource that has been requested but not yet received. The version is left
    /// empty — claiming no version means the server will always send the resource — without
    /// clobbering the version of a resource already held.
    fn add_pending_resource(&mut self, type_url: Strng, name: Strng) {
        self.known_resources
            .entry(type_url)
            .or_default()
            .entry(name)
            .or_default();
    }
}

impl Config {
    pub(crate) fn issuer_profile_expected(
        config: &crate::config::Config,
    ) -> anyhow::Result<Option<crate::tls::issuer_profile_wire::Expected>> {
        issuer_profile::configured_expected(config)
    }
    pub fn new(
        config: Arc<crate::config::Config>,
        tls_builder: Box<dyn tls::ControlPlaneClientCertProvider>,
    ) -> Config {
        Config {
            address: config
                .xds_address
                .clone()
                .expect("xds_address must be set to use xds"),
            tls_builder,
            auth: config.auth.clone(),
            handlers: HashMap::new(),
            initial_requests: Vec::new(),
            on_demand: config.xds_on_demand,
            session_gate: None,
            issuer_profile_initial_timeout: Duration::from_secs(10),
            profile_provider: None,
            proxy_metadata: config.proxy_metadata.clone(),
            alt_hostname: config.alt_xds_hostname.clone(),
            xds_headers: config.xds_headers.vec.clone(),
        }
    }

    pub(crate) fn with_configured_issuer_profile_probe(
        mut self,
        config: &crate::config::Config,
    ) -> anyhow::Result<Self> {
        if let Some(expected) = issuer_profile::load_config(config)? {
            self = self.with_issuer_profile_probe(expected, std::time::SystemTime::now);
        }
        Ok(self)
    }
    pub(crate) fn with_issuer_profile_provider(
        mut self,
        expected: crate::tls::issuer_profile_wire::Expected,
        provider: std::sync::Arc<crate::tls::profile_provider::ProfileProvider>,
    ) -> Self {
        self.profile_provider = Some(provider.clone());
        self.handlers.insert(
            ISSUER_PROFILE_TYPE,
            Box::new(issuer_profile::ProviderHandler::new(expected, provider)),
        );
        self.initial_requests
            .push(self.construct_initial_request(ISSUER_PROFILE_TYPE, true));
        self
    }
    fn with_issuer_profile_probe(
        mut self,
        expected: crate::tls::issuer_profile_wire::Expected,
        clock: fn() -> std::time::SystemTime,
    ) -> Self {
        self.handlers.insert(
            ISSUER_PROFILE_TYPE,
            Box::new(issuer_profile::ProbeHandler::new(expected, clock)),
        );
        self.initial_requests
            .push(self.construct_initial_request(ISSUER_PROFILE_TYPE, true));
        self
    }

    pub fn with_watched_handler<F>(self, type_url: Strng, f: impl Handler<F>) -> Config
    where
        F: 'static + fmt::Debug + prost::Message + Default,
    {
        let no_on_demand = f.no_on_demand();
        self.with_handler(type_url.clone(), f)
            .watch(type_url, no_on_demand)
    }

    pub(crate) fn with_session_gate(mut self, gate: XdsSessionGate) -> Self {
        self.session_gate = Some(gate);
        self
    }

    fn with_handler<F>(mut self, type_url: Strng, f: impl Handler<F>) -> Config
    where
        F: 'static + fmt::Debug + prost::Message + Default,
    {
        let h = HandlerWrapper { h: Box::new(f) };
        self.handlers.insert(type_url, Box::new(h));
        self
    }

    fn watch(mut self, type_url: Strng, no_on_demand: bool) -> Config {
        self.initial_requests
            .push(self.construct_initial_request(type_url, no_on_demand));
        self
    }

    fn build_struct<T: IntoIterator<Item = (S, S)>, S: ToString>(a: T) -> Struct {
        let fields = BTreeMap::from_iter(a.into_iter().map(|(k, v)| {
            (
                k.to_string(),
                Value {
                    kind: Some(Kind::StringValue(v.to_string())),
                },
            )
        }));
        Struct { fields }
    }

    fn json_to_struct(json: serde_json::Map<String, serde_json::Value>) -> prost_types::Struct {
        prost_types::Struct {
            fields: json
                .into_iter()
                .map(|(k, v)| (k, Self::json_to_value(v)))
                .collect(),
        }
    }

    fn json_to_value(json: serde_json::Value) -> prost_types::Value {
        use prost_types::value::Kind::*;
        use serde_json::Value::*;

        prost_types::Value {
            kind: Some(match json {
                Null => NullValue(0),
                Bool(v) => BoolValue(v),
                Number(n) => NumberValue(n.as_f64().unwrap_or_else(|| {
                    error!("error parsing JSON number: {}", n);
                    0f64
                })),
                String(s) => StringValue(s),
                Array(v) => ListValue(prost_types::ListValue {
                    values: v.into_iter().map(Self::json_to_value).collect(),
                }),
                Object(v) => StructValue(Self::json_to_struct(v)),
            }),
        }
    }
    fn node(&self) -> Node {
        let ip = std::env::var(INSTANCE_IP);
        let ip = ip.as_deref().unwrap_or(DEFAULT_IP);
        let pod_name = std::env::var(POD_NAME);
        let pod_name = pod_name.as_deref().unwrap_or(EMPTY_STR);
        let ns = std::env::var(POD_NAMESPACE);
        let ns = ns.as_deref().unwrap_or(EMPTY_STR);
        let node_name = std::env::var(NODE_NAME);
        let node_name = node_name.as_deref().unwrap_or(EMPTY_STR);
        let mut metadata = Self::build_struct([
            (NAME, pod_name),
            (NAMESPACE, ns),
            (INSTANCE_IPS, ip),
            (NODE_NAME, node_name),
        ]);
        metadata
            .fields
            .append(&mut Self::build_struct(self.proxy_metadata.clone()).fields);

        // Lookup ISTIO_METAJSON_* environment variables and add them to the node metadata
        for (key, val) in std::env::vars().filter(|(key, _)| key.starts_with(ISTIO_METAJSON_PREFIX))
        {
            if let Ok(v) = serde_json::from_str(&val) {
                metadata.fields.insert(
                    key.trim_start_matches(ISTIO_METAJSON_PREFIX).to_string(),
                    Self::json_to_value(v),
                );
            } else {
                error!("failed to parse {}={}", key, val);
            }
        }

        Node {
            id: format!("ztunnel~{ip}~{pod_name}.{ns}~{ns}.svc.cluster.local"),
            metadata: Some(metadata),
            ..Default::default()
        }
    }
    fn construct_initial_request(
        &self,
        request_type: Strng,
        no_on_demand: bool,
    ) -> DeltaDiscoveryRequest {
        let node = self.node();

        let (sub, unsub) = if (!no_on_demand) && self.on_demand {
            // XDS doesn't have a way to subscribe to zero resources. We workaround this by subscribing and unsubscribing
            // in one event, effectively giving us "subscribe to nothing".
            (vec!["*".to_string()], vec!["*".to_string()])
        } else {
            (vec![], vec![])
        };
        DeltaDiscoveryRequest {
            type_url: request_type.to_string(),
            node: Some(node.clone()),
            resource_names_subscribe: sub,
            resource_names_unsubscribe: unsub,
            ..Default::default()
        }
    }

    pub fn build(self, metrics: Metrics, block_ready: tokio::sync::watch::Sender<()>) -> AdsClient {
        AdsClient::new(self, metrics, block_ready)
    }
}

/// AdsClient provides a (mostly) generic DeltaAggregatedResources XDS client.
///
/// The client works by accepting arbitrary handlers for types, configured by user.
/// These handlers can do whatever they want with incoming responses, but are responsible for maintaining their own state.
/// For example, if a usage wants to keep track of all Foo resources received, it needs to handle the add/removes in the configured handler.
///
/// The client also supports on-demand lookup of resources; see demander() for more information.
///
/// Currently, this is not quite a fully general purpose XDS client, as there is no dependant resource support.
/// This could be added if needed, though.
pub struct AdsClient {
    config: Config,

    state: State,

    pub(crate) metrics: Metrics,
    block_ready: Option<tokio::sync::watch::Sender<()>>,

    connection_id: u32,
    types_to_expect: HashSet<String>,
    session_gate: Option<XdsSessionGate>,
    session_generation: u64,
}

/// Demanded allows awaiting for an on-demand XDS resource
pub struct Demanded {
    b: oneshot::Receiver<()>,
}

impl Demanded {
    /// recv awaits for the requested resource
    /// Note: the actual resource is not directly returned. Instead, callers are notified that the event
    /// has been handled through the configured resource handler.
    pub async fn recv(self) {
        let _ = self.b.await;
    }
}

/// Demander allows requesting XDS resources on-demand
#[derive(Debug, Clone)]
pub struct Demander {
    demand: mpsc::Sender<(oneshot::Sender<()>, ResourceKey)>,
}

#[derive(Debug)]
enum XdsSignal {
    Ack,
    Nack,
}

impl Display for XdsSignal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            XdsSignal::Ack => "ACK",
            XdsSignal::Nack => "NACK",
        })
    }
}

impl Demander {
    /// Demand requests a given workload by name
    pub async fn demand(&self, type_url: Strng, name: Strng) -> Demanded {
        let (tx, rx) = oneshot::channel::<()>();
        self.demand
            .send((tx, ResourceKey { name, type_url }))
            .await
            // TODO: is this guaranteed? How can we handle the failure
            .expect("demand channel should not close");
        Demanded { b: rx }
    }
}

const INITIAL_BACKOFF: Duration = Duration::from_millis(10);
const MAX_BACKOFF: Duration = Duration::from_secs(15);

impl AdsClient {
    fn is_initial_request_on_demand(r: &DeltaDiscoveryRequest) -> bool {
        !r.resource_names_subscribe.is_empty()
    }

    fn new(config: Config, metrics: Metrics, block_ready: tokio::sync::watch::Sender<()>) -> Self {
        let (tx, rx) = mpsc::channel(100);
        let state = State {
            known_resources: Default::default(),
            pending: Default::default(),
            demand: rx,
            demand_tx: tx,
        };
        let types_to_expect: HashSet<String> = config
            .initial_requests
            .iter()
            .filter(|e| !Self::is_initial_request_on_demand(e)) // is_empty implies not ondemand
            .map(|e| e.type_url.clone())
            .collect();
        let session_gate = config.session_gate.clone();
        AdsClient {
            config,
            state,
            metrics,
            block_ready: Some(block_ready),
            connection_id: 0,
            types_to_expect,
            session_gate,
            session_generation: 0,
        }
    }

    /// demander returns a Demander instance which can be used to request resources on-demand
    pub fn demander(&self) -> Option<Demander> {
        if self.config.on_demand {
            Some(Demander {
                demand: self.state.demand_tx.clone(),
            })
        } else {
            None
        }
    }

    async fn run_loop(&mut self, backoff: Duration) -> Duration {
        self.types_to_expect = self
            .config
            .initial_requests
            .iter()
            .filter(|e| !Self::is_initial_request_on_demand(e))
            .map(|e| e.type_url.clone())
            .collect();
        if let Some(gate) = &self.session_gate {
            self.session_generation = gate.begin_session();
        }
        let result = if self.session_gate.is_some() {
            self.clear_xds_state()
        } else {
            Ok(())
        };
        let result = match result {
            Ok(()) => self.run_internal().await,
            Err(err) => Err(err),
        };
        if let Some(provider) = &self.config.profile_provider {
            provider.fail_closed_for_session(self.session_generation);
        }
        if let Some(gate) = &self.session_gate {
            gate.mark_stale(self.session_generation);
        }

        match result {
            Err(e @ Error::Connection(_, _)) => {
                // For connection errors, we add backoff
                let backoff = std::cmp::min(MAX_BACKOFF, backoff * 2);
                warn!(
                    "XDS client connection error: {}, retrying in {:?}",
                    e, backoff
                );
                self.metrics
                    .increment(&ConnectionTerminationReason::ConnectionError);
                tokio::time::sleep(backoff).await;
                backoff
            }
            Err(ref e @ Error::GrpcStatus(ref status)) => {
                let err_detail = e.to_string();
                let backoff = if status.code() == tonic::Code::Unknown
                    || status.code() == tonic::Code::Cancelled
                    || status.code() == tonic::Code::DeadlineExceeded
                    || (status.code() == tonic::Code::Unavailable
                        && status.message().contains("transport is closing"))
                    || (status.code() == tonic::Code::Unavailable
                        && status.message().contains("received prior goaway"))
                {
                    debug!(
                        "XDS client terminated: {}, retrying in {:?}",
                        err_detail, backoff
                    );
                    self.metrics
                        .increment(&ConnectionTerminationReason::Reconnect);
                    INITIAL_BACKOFF
                } else {
                    warn!(
                        "XDS client error: {}, retrying in {:?}",
                        err_detail, backoff
                    );
                    self.metrics.increment(&ConnectionTerminationReason::Error);
                    // For gRPC errors, we add backoff
                    std::cmp::min(MAX_BACKOFF, backoff * 2)
                };
                tokio::time::sleep(backoff).await;
                backoff
            }
            Err(e @ Error::RejectedResponse(_)) => {
                let backoff = std::cmp::min(MAX_BACKOFF, backoff * 2);
                warn!("xDS state rejected, reconnecting in {:?}: {}", backoff, e);
                self.metrics.increment(&ConnectionTerminationReason::Error);
                tokio::time::sleep(backoff).await;
                backoff
            }
            Err(e @ Error::Reset(_)) => {
                let backoff = std::cmp::min(MAX_BACKOFF, backoff * 2);
                warn!(
                    "failed to reset stale xDS state, retrying in {:?}: {}",
                    backoff, e
                );
                self.metrics.increment(&ConnectionTerminationReason::Error);
                tokio::time::sleep(backoff).await;
                backoff
            }
            Err(e) => {
                // For other errors, we connect immediately
                // TODO: we may need more nuance here; if we fail due to invalid initial request we may overload
                // But we want to reconnect from MaxConnectionAge immediately.
                warn!("XDS client error: {}, retrying", e);
                self.metrics.increment(&ConnectionTerminationReason::Error);
                // Reset backoff
                INITIAL_BACKOFF
            }
            Ok(_) => {
                self.metrics
                    .increment(&ConnectionTerminationReason::Complete);
                warn!("XDS client complete");
                // Reset backoff
                INITIAL_BACKOFF
            }
        }
    }

    fn clear_xds_state(&mut self) -> Result<(), Error> {
        let type_urls = self.config.handlers.keys().cloned().collect::<Vec<_>>();
        for type_url in type_urls {
            let Some(handler) = self.config.handlers.get(&type_url) else {
                continue;
            };
            handler
                .clear(&mut self.state, &type_url)
                .map_err(|rejected| {
                    Error::Reset(
                        rejected
                            .into_iter()
                            .map(|r| r.to_string())
                            .collect::<Vec<_>>()
                            .join("; "),
                    )
                })?;
        }
        self.state.known_resources.clear();
        Ok(())
    }

    pub async fn run(mut self) -> Result<(), Error> {
        // This lives inside the running future, so cancellation revokes the
        // provider without making AdsClient a Drop type (builders move config).
        let _profile_lifetime = self
            .config
            .profile_provider
            .as_ref()
            .map(|p| p.runtime_guard());
        let mut backoff = INITIAL_BACKOFF;
        loop {
            self.connection_id += 1;
            let id = self.connection_id;
            backoff = self
                .run_loop(backoff)
                .instrument(info_span!("xds", id))
                .await;
        }
    }

    async fn run_internal(&mut self) -> Result<(), Error> {
        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel::<DeltaDiscoveryRequest>(100);
        // For each type in initial_watches we will send a request on connection to subscribe
        let initial_requests: Vec<DeltaDiscoveryRequest> = self
            .config
            .initial_requests
            .iter()
            .map(|e| {
                let mut req = e.clone();
                req.initial_resource_versions = self
                    .state
                    .known_resources
                    .get(&strng::new(&req.type_url))
                    .map(|resources| {
                        resources
                            .iter()
                            .map(|(name, version)| (name.to_string(), version.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                req
            })
            .collect();

        let outbound = async_stream::stream! {
            for initial in initial_requests {
                debug!(resources=initial.initial_resource_versions.len(), type_url=initial.type_url, "sending initial request");
                yield initial;
            }
            while let Some(message) = discovery_req_rx.recv().await {
                debug!(type_url=message.type_url, "sending request");
                yield message
            }
            warn!("outbound stream complete");
        };

        let addr = self.config.address.clone();
        let is_unix = tls::unix_socket_path(&self.config.address).is_some();

        let tls_config = if is_unix {
            None // Unix domain sockets provide local IPC, TLS is not required
        } else {
            Some(
                self.config
                    .tls_builder
                    .fetch_cert(self.config.alt_hostname.clone())
                    .await?,
            )
        };

        let grpc_channel = tls::grpc_channel(
            self.config.address.clone(),
            self.config.auth.clone(),
            tls_config,
        )?;

        let mut req = tonic::Request::new(outbound);
        self.config.xds_headers.iter().for_each(|(k, v)| {
            req.metadata_mut().insert(k.clone(), v.clone());

            if let Ok(v_str) = v.to_str() {
                debug!("XDS header added: {}={}", k, v_str);
            }
        });

        let ads_connection = AggregatedDiscoveryServiceClient::new(grpc_channel)
            .max_decoding_message_size(200 * 1024 * 1024)
            .delta_aggregated_resources(req)
            .await;

        let mut response_stream = ads_connection
            .map_err(|src| Error::Connection(addr, src))?
            .into_inner();
        debug!("connected established");

        info!("Stream established");
        let profile_initial_deadline = self
            .config
            .handlers
            .contains_key(&ISSUER_PROFILE_TYPE)
            .then(|| tokio::time::Instant::now() + self.config.issuer_profile_initial_timeout);
        let mut profile_changes = self.config.profile_provider.as_ref().map(|p| p.subscribe());
        let mut profile_nack_deadline = None;
        loop {
            tokio::select! {
                _ = async {
                    if let Some(deadline) = profile_nack_deadline { tokio::time::sleep_until(deadline).await; }
                    else { std::future::pending::<()>().await; }
                } => { return Err(Error::RejectedResponse("native issuer profile NACK delivery deadline".into())); }
                changed = async {
                    match profile_changes.as_mut() {
                        Some(changes) => changes.changed().await.ok(),
                        None => std::future::pending().await,
                    }
                } => {
                    if changed.is_some() && profile_nack_deadline.is_none() && !self.types_to_expect.contains(&ISSUER_PROFILE_TYPE.to_string())
                        && self.config.profile_provider.as_ref().is_some_and(|p| !p.available_for_session(self.session_generation)) {
                        return Err(Error::RejectedResponse("native issuer profile/session became unavailable".into()));
                    }
                }
                _ = async {
                    if let Some(deadline)=profile_initial_deadline { tokio::time::sleep_until(deadline).await; }
                    else { std::future::pending::<()>().await; }
                }, if !self.types_to_expect.is_empty() => {
                    if let Some(gate)=&self.session_gate{gate.mark_stale(self.session_generation);}
                    return Err(Error::RejectedResponse("issuer-profile initial snapshot deadline exceeded".into()));
                }
                _demand_event = self.state.demand.recv() => {
                    self.handle_demand_event(_demand_event, &discovery_req_tx).await?;
                }
                msg = response_stream.message() => {
                    let Some(msg) = msg? else {
                        // If we got a None message, the stream ended without error.
                        // This could be an explicit OK response, or if the stream is reset without a gRPC status.
                        return Ok(());
                    };
                    if profile_nack_deadline.is_some() {
                        return Err(Error::RejectedResponse("native issuer profile NACK requires a new complete session".into()));
                    }
                    // Strict mode accepts one complete initial response for
                    // each required type. Any later security delta forces a
                    // reconnect and a fresh full snapshot; applying one type
                    // while the other remains from an older snapshot could
                    // briefly authorize against mixed state.
                    if let Some(gate) = &self.session_gate {
                        let is_security_type = msg.type_url == ADDRESS_TYPE.to_string()
                            || msg.type_url == AUTHORIZATION_TYPE.to_string()
                            || msg.type_url == ISSUER_PROFILE_TYPE.to_string();
                        let native_profile = msg.type_url == ISSUER_PROFILE_TYPE.to_string() && self.config.profile_provider.is_some();
                        if is_security_type && !native_profile && !self.types_to_expect.contains(&msg.type_url) {
                            gate.mark_stale(self.session_generation);
                            warn!(
                                generation = self.session_generation,
                                type_url = %msg.type_url,
                                reason = "full_snapshot_resync",
                                "strict xDS update revoked the session before application"
                            );
                            return Err(Error::RejectedResponse(
                                "strict xDS update requires full snapshot resync".to_string(),
                            ));
                        }
                        if !self.config.handlers.contains_key(&strng::new(&msg.type_url)) {
                            gate.mark_stale(self.session_generation);
                            warn!(
                                generation = self.session_generation,
                                type_url = %msg.type_url,
                                reason = "unsupported_type",
                                "strict xDS session rejected an unsupported response type"
                            );
                            return Err(Error::RejectedResponse(
                                "strict xDS session received an unsupported response type".to_string(),
                            ));
                        }
                    }
                    let is_profile_response=msg.type_url==ISSUER_PROFILE_TYPE.to_string();
                    let received_type = (!self.types_to_expect.is_empty())
                        .then(|| msg.type_url.clone());
                    let signal = self.handle_stream_event(msg, &discovery_req_tx).await?;
                    if let XdsSignal::Nack = signal {
                        // Keep this fenced stream alive long enough for the
                        // peer to read the NACK. The server closes on NACK;
                        // the initial deadline bounds an unresponsive peer.
                        // Never count this response toward readiness.
                        if is_profile_response {
                            if self.config.profile_provider.is_some() { profile_nack_deadline = Some(tokio::time::Instant::now() + Duration::from_secs(1)); }
                            continue;
                        }
                        if self.session_gate.is_some() {
                            return Err(Error::RejectedResponse(
                                received_type.unwrap_or_else(|| "unknown type".to_string()),
                            ));
                        }
                        // Ungated clients retain their last accepted versions
                        // and allow corrected responses on the same stream.
                        // A NACK must not satisfy initial readiness.
                        continue;
                    }
                    if let Some(received_type) = received_type {
                        self.types_to_expect.remove(&received_type);
                        if self.types_to_expect.is_empty() {
                            mem::drop(mem::take(&mut self.block_ready));
                            if let Some(gate) = &self.session_gate {
                                gate.mark_snapshot_ready(self.session_generation);
                            }
                        }
                    }
                }
            }
        }
    }

    async fn handle_stream_event(
        &mut self,
        response: DeltaDiscoveryResponse,
        send: &mpsc::Sender<DeltaDiscoveryRequest>,
    ) -> Result<XdsSignal, Error> {
        let type_url = response.type_url.clone();
        let nonce = response.nonce.clone();
        self.metrics.record(&response, ());
        debug!(
            type_url = type_url, // this is a borrow, it's OK
            size = response.resources.len(),
            removes = response.removed_resources.len(),
            "received response"
        );
        let handler_response: Result<(), Vec<RejectedConfig>> =
            match self.config.handlers.get(&strng::new(&type_url)) {
                Some(h) => h.handle_async(&mut self.state, response).await,
                None if self.session_gate.is_some() => Err(vec![RejectedConfig::new(
                    strng::new(type_url.clone()),
                    anyhow::anyhow!("unsupported xDS response type in fail-closed session"),
                )]),
                None => {
                    error!(%type_url, "unknown type");
                    // TODO: this will just send another discovery request, to server. We should
                    // either send one with an error or not send one at all.
                    Ok(())
                }
            };

        if handler_response.is_err()
            && let Some(gate) = &self.session_gate
        {
            // Revoke synchronously before the bounded outbound channel can
            // block while enqueueing the NACK.
            gate.mark_stale(self.session_generation);
        }

        let (response_type, error) = match handler_response {
            Err(rejects) => {
                let error = rejects
                    .into_iter()
                    .map(|reject| reject.to_string())
                    .collect::<Vec<String>>()
                    .join("; ");
                (XdsSignal::Nack, Some(error))
            }
            _ => (XdsSignal::Ack, None),
        };

        match response_type {
            XdsSignal::Nack => error!(
                type_url=type_url,
                nonce,
                "type"=?response_type,
                error=error,
                "sending response",
            ),
            _ => debug!(
                type_url=type_url,
                nonce,
                "type"=?response_type,
                "sending response",
            ),
        };

        send.send(DeltaDiscoveryRequest {
            type_url,              // this is owned, OK to move
            response_nonce: nonce, // this is owned, OK to move
            error_detail: error.map(|msg| Status {
                message: msg,
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .map_err(|e| Error::RequestFailure(Box::new(e)))
        .map(|_| response_type)
    }

    async fn handle_demand_event(
        &mut self,
        demand_event: Option<(oneshot::Sender<()>, ResourceKey)>,
        send: &mpsc::Sender<DeltaDiscoveryRequest>,
    ) -> Result<(), Error> {
        let Some((tx, demand_event)) = demand_event else {
            return Ok(());
        };
        info!("received on demand request {demand_event}");
        let ResourceKey { type_url, name } = demand_event.clone();
        self.state.pending.insert(demand_event, tx);
        self.state
            .add_pending_resource(type_url.clone(), name.clone());
        send.send(DeltaDiscoveryRequest {
            type_url: type_url.to_string(),
            resource_names_subscribe: vec![name.to_string()],
            ..Default::default()
        })
        .await
        .map_err(|e| Error::RequestFailure(Box::new(e)))?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct XdsResource<T: prost::Message> {
    pub name: Strng,
    pub resource: T,
}

#[derive(Debug)]
pub enum XdsUpdate<T: prost::Message> {
    Update(XdsResource<T>),
    Remove(Strng),
}

impl<T: prost::Message> XdsUpdate<T> {
    pub fn name(&self) -> Strng {
        match self {
            XdsUpdate::Update(r) => r.name.clone(),
            XdsUpdate::Remove(n) => n.clone(),
        }
    }
}

fn decode_proto<T: prost::Message + Default>(
    resource: &ProtoResource,
) -> Result<XdsResource<T>, AdsError> {
    let name = resource.name.as_str().into();
    resource
        .resource
        .as_ref()
        .ok_or(AdsError::MissingResource())
        .and_then(|res| <T>::decode(&res.value[..]).map_err(AdsError::Decode))
        .map(|r| XdsResource { name, resource: r })
}

#[derive(Clone, Debug, Error)]
pub enum AdsError {
    #[error("unknown resource type: {0}")]
    UnknownResourceType(String),
    #[error("decode: {0}")]
    Decode(#[from] DecodeError),
    #[error("XDS payload without resource")]
    MissingResource(),
    #[error("encode: {0}")]
    Encode(#[from] EncodeError),
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
        sync::{
            Arc, RwLock,
            atomic::{AtomicUsize, Ordering},
        },
        time::SystemTime,
    };

    use prost::Message;
    use prost_types::Any;
    use textnonce::TextNonce;
    use tokio::time::sleep;

    use crate::xds::ADDRESS_TYPE;
    use crate::xds::ProxyStateUpdater;
    use crate::xds::istio::security::Authorization as XdsAuthorization;
    use crate::xds::istio::workload::Address as XdsAddress;
    use crate::xds::istio::workload::NetworkAddress as XdsNetworkAddress;
    use crate::xds::istio::workload::Service as XdsService;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::xds::istio::workload::WorkloadType;
    use crate::xds::{AUTHORIZATION_TYPE, istio::workload::address::Type as XdsType};
    use workload::Workload;

    use crate::state::workload::{NamespacedHostname, NetworkAddress};
    use crate::state::{DemandProxyState, ProxyState, workload};
    use crate::test_helpers::{
        helpers::{self},
        test_default_workload,
        xds::AdsServer,
    };

    use super::*;

    const POLL_RATE: Duration = Duration::from_millis(2);
    const TEST_TIMEOUT: Duration = Duration::from_millis(100);

    async fn verify_address(
        ip: IpAddr,
        expected_address: Option<XdsAddress>,
        source: &DemandProxyState,
    ) {
        let start_time = SystemTime::now();
        let converted = match expected_address {
            Some(a) => match a.r#type {
                Some(XdsType::Workload(w)) => Some(Workload::try_from(w).unwrap()),
                Some(XdsType::Service(_s)) => None,
                _ => None,
            },
            _ => None,
        };
        // this is a borrow, Ok not to clone
        let mut matched = false;
        let ip_network_addr = NetworkAddress {
            network: strng::EMPTY,
            address: ip,
        };
        while start_time.elapsed().unwrap() < TEST_TIMEOUT && !matched {
            sleep(POLL_RATE).await;
            let wl = source.fetch_workload_by_address(&ip_network_addr);
            matched = wl.await.as_deref() == converted.as_ref(); // Option<Workload> is Ok to compare without needing to unwrap
        }
        assert!(
            matched,
            "workload lookup for {ip} did not reach expected state: {converted:?}"
        );
    }

    fn get_auth(i: usize) -> ProtoResource {
        let addr = XdsAuthorization {
            name: format!("foo{i}"),
            namespace: "default".to_string(),
            scope: crate::xds::istio::security::Scope::Global as i32,
            action: crate::xds::istio::security::Action::Deny as i32,
            rules: vec![crate::xds::istio::security::Rule {
                clauses: vec![crate::xds::istio::security::Clause {
                    matches: vec![crate::xds::istio::security::Match {
                        destination_ports: vec![80],
                        ..Default::default()
                    }],
                }],
            }],
            dry_run: false,
            extensions: vec![],
        };
        ProtoResource {
            name: format!("foo{i}"),
            aliases: vec![],
            version: "0.0.1".to_string(),
            resource: Some(Any {
                type_url: AUTHORIZATION_TYPE.to_string(),
                value: addr.encode_to_vec(),
            }),
            ttl: None,
            cache_control: None,
        }
    }
    fn get_address(i: usize, addr: std::net::IpAddr) -> ProtoResource {
        let octets = match addr {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        let addr = XdsAddress {
            r#type: Some(XdsType::Workload(XdsWorkload {
                name: format!("foo{i}"),
                uid: format!("default/foo{i}"),
                namespace: "default".to_string(),
                addresses: vec![octets.into()],
                tunnel_protocol: 0,
                trust_domain: "local".to_string(),
                service_account: "default".to_string(),
                node: "default".to_string(),
                workload_type: WorkloadType::Deployment.into(),
                workload_name: "".to_string(),
                native_tunnel: true,
                ..Default::default()
            })),
        };

        ProtoResource {
            name: format!("default/foo{i}"),
            aliases: vec![],
            version: "0.0.1".to_string(),
            resource: Some(Any {
                type_url: ADDRESS_TYPE.to_string(),
                value: addr.encode_to_vec(),
            }),
            ttl: None,
            cache_control: None,
        }
    }

    fn get_address_with_uid_resource_name(i: usize, addr: std::net::IpAddr) -> ProtoResource {
        let mut resource = get_address(i, addr);
        resource.name = format!("default/foo{i}");
        resource
    }

    struct CountingAuthorizationHandler(Arc<AtomicUsize>);

    impl Handler<XdsAuthorization> for CountingAuthorizationHandler {
        fn handle(
            &self,
            updates: Box<&mut dyn Iterator<Item = XdsUpdate<XdsAuthorization>>>,
        ) -> Result<(), Vec<RejectedConfig>> {
            self.0.fetch_add(updates.count(), Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn malformed_response_does_not_apply_valid_updates_or_removals() {
        let calls = Arc::new(AtomicUsize::new(0));
        let wrapper = HandlerWrapper::<XdsAuthorization> {
            h: Box::new(CountingAuthorizationHandler(calls.clone())),
        };
        let (demand_tx, demand) = mpsc::channel(1);
        let stale_name = strng::new("stale");
        let type_url = strng::new(AUTHORIZATION_TYPE);
        let key = ResourceKey {
            name: stale_name.clone(),
            type_url: type_url.clone(),
        };
        let (pending_tx, _pending_rx) = oneshot::channel();
        let mut state = State {
            known_resources: HashMap::from([(
                type_url.clone(),
                HashMap::from([(stale_name.clone(), strng::new("0.0.1"))]),
            )]),
            pending: HashMap::from([(key.clone(), pending_tx)]),
            demand,
            demand_tx,
        };
        let malformed = ProtoResource {
            name: "malformed".to_string(),
            aliases: vec![],
            version: "0.0.1".to_string(),
            resource: Some(Any {
                type_url: AUTHORIZATION_TYPE.to_string(),
                value: vec![0xff],
            }),
            ttl: None,
            cache_control: None,
        };
        let response = DeltaDiscoveryResponse {
            resources: vec![get_auth(0), malformed],
            removed_resources: vec![stale_name.to_string()],
            type_url: AUTHORIZATION_TYPE.to_string(),
            nonce: "malformed-batch".to_string(),
            ..Default::default()
        };

        let result = wrapper.handle(&mut state, response);

        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(state.known_resources[&type_url].contains_key(&stale_name));
        assert!(state.pending.contains_key(&key));
    }

    #[test]
    fn update_then_remove_does_not_retain_version_and_retry_recovers() {
        let proxy_state = Arc::new(RwLock::new(ProxyState::new(None)));
        let wrapper = HandlerWrapper::<XdsAddress> {
            h: Box::new(ProxyStateUpdater::new_no_fetch(proxy_state.clone())),
        };
        let (demand_tx, demand) = mpsc::channel(1);
        let mut state = State {
            known_resources: HashMap::new(),
            pending: HashMap::new(),
            demand,
            demand_tx,
        };
        let resource = get_address(0, "10.0.0.8".parse().unwrap());
        let resource_name = strng::new(&resource.name);
        let type_url = strng::new(ADDRESS_TYPE);

        wrapper
            .handle(
                &mut state,
                DeltaDiscoveryResponse {
                    resources: vec![resource.clone()],
                    removed_resources: vec![resource.name.clone()],
                    type_url: ADDRESS_TYPE.to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(!state.known_resources[&type_url].contains_key(&resource_name));
        assert!(
            proxy_state
                .read()
                .unwrap()
                .workloads
                .find_uid(&resource_name)
                .is_none()
        );

        wrapper
            .handle(
                &mut state,
                DeltaDiscoveryResponse {
                    resources: vec![resource],
                    type_url: ADDRESS_TYPE.to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            state.known_resources[&type_url][&resource_name],
            strng::new("0.0.1")
        );
        assert!(
            proxy_state
                .read()
                .unwrap()
                .workloads
                .find_uid(&resource_name)
                .is_some()
        );
    }

    #[test]
    fn typed_rejection_preserves_proxy_versions_and_waiters_until_corrected_retry() {
        let proxy_state = Arc::new(RwLock::new(ProxyState::new(None)));
        let wrapper = HandlerWrapper::<XdsAddress> {
            h: Box::new(ProxyStateUpdater::new_no_fetch(proxy_state.clone())),
        };
        let (demand_tx, demand) = mpsc::channel(1);
        let mut state = State {
            known_resources: HashMap::new(),
            pending: HashMap::new(),
            demand,
            demand_tx,
        };
        let old = get_address(0, "10.0.0.8".parse().unwrap());
        let old_name = strng::new(&old.name);
        let replacement = get_address(1, "10.0.0.9".parse().unwrap());
        let new_name = strng::new(&replacement.name);
        let type_url = strng::new(ADDRESS_TYPE);
        wrapper
            .handle(
                &mut state,
                DeltaDiscoveryResponse {
                    resources: vec![old],
                    type_url: ADDRESS_TYPE.to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        let key = ResourceKey {
            name: new_name.clone(),
            type_url: type_url.clone(),
        };
        let (pending_tx, mut pending_rx) = oneshot::channel();
        state.pending.insert(key.clone(), pending_tx);
        let invalid = ProtoResource {
            name: "invalid-address".to_string(),
            version: "2".to_string(),
            resource: Some(Any {
                type_url: ADDRESS_TYPE.to_string(),
                value: XdsAddress { r#type: None }.encode_to_vec(),
            }),
            ..Default::default()
        };
        assert!(
            wrapper
                .handle(
                    &mut state,
                    DeltaDiscoveryResponse {
                        resources: vec![replacement.clone(), invalid],
                        removed_resources: vec![old_name.to_string()],
                        type_url: ADDRESS_TYPE.to_string(),
                        ..Default::default()
                    }
                )
                .is_err()
        );
        assert!(
            proxy_state
                .read()
                .unwrap()
                .workloads
                .find_uid(&old_name)
                .is_some()
        );
        assert!(
            proxy_state
                .read()
                .unwrap()
                .workloads
                .find_uid(&new_name)
                .is_none()
        );
        assert_eq!(state.known_resources[&type_url].len(), 1);
        assert!(state.known_resources[&type_url].contains_key(&old_name));
        assert!(state.pending.contains_key(&key));

        wrapper
            .handle(
                &mut state,
                DeltaDiscoveryResponse {
                    resources: vec![replacement],
                    removed_resources: vec![old_name.to_string()],
                    type_url: ADDRESS_TYPE.to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(
            proxy_state
                .read()
                .unwrap()
                .workloads
                .find_uid(&old_name)
                .is_none()
        );
        assert!(
            proxy_state
                .read()
                .unwrap()
                .workloads
                .find_uid(&new_name)
                .is_some()
        );
        assert_eq!(state.known_resources[&type_url].len(), 1);
        assert!(state.known_resources[&type_url].contains_key(&new_name));
        assert!(!state.pending.contains_key(&key));
        assert!(pending_rx.try_recv().is_ok());
    }

    #[test]
    fn stale_session_reset_removes_accepted_resources_and_versions() {
        let proxy_state = Arc::new(RwLock::new(ProxyState::new(None)));
        let updater = ProxyStateUpdater::new_no_fetch(proxy_state.clone());
        let wrapper = HandlerWrapper::<XdsAddress> {
            h: Box::new(updater.clone()),
        };
        let name = "default/pod-1";
        let resource_name = "workload-resource";
        let service_resource_name = "service-resource";
        let resources = vec![
            XdsUpdate::Update(XdsResource {
                name: resource_name.into(),
                resource: XdsAddress {
                    r#type: Some(XdsType::Workload(XdsWorkload {
                        uid: name.to_string(),
                        name: "pod-1".to_string(),
                        namespace: "default".to_string(),
                        addresses: vec![Ipv4Addr::new(10, 0, 0, 1).octets().to_vec().into()],
                        tunnel_protocol: 0,
                        trust_domain: "mesh.example.com".to_string(),
                        service_account: "api".to_string(),
                        workload_type: WorkloadType::Deployment.into(),
                        ..Default::default()
                    })),
                },
            }),
            XdsUpdate::Update(XdsResource {
                name: service_resource_name.into(),
                resource: XdsAddress {
                    r#type: Some(XdsType::Service(XdsService {
                        name: "api".to_string(),
                        namespace: "default".to_string(),
                        hostname: "api.example".to_string(),
                        addresses: vec![XdsNetworkAddress {
                            network: String::new(),
                            address: Ipv4Addr::new(10, 96, 0, 1).octets().to_vec(),
                            length: None,
                        }],
                        ..Default::default()
                    })),
                },
            }),
        ];
        let mut accepted = resources.into_iter();
        <ProxyStateUpdater as Handler<XdsAddress>>::handle(&updater, Box::new(&mut accepted))
            .expect("valid initial resource should be accepted");

        {
            let state = proxy_state.read().unwrap();
            assert!(state.workloads.find_uid(&strng::new(name)).is_some());
            assert!(
                state
                    .services
                    .get_by_namespaced_host(
                        &NamespacedHostname::from_str("default/api.example").unwrap()
                    )
                    .is_some()
            );
        }

        let (demand_tx, demand) = mpsc::channel(1);
        let type_url = strng::new(ADDRESS_TYPE);
        let resource_name = strng::new(resource_name);
        let mut state = State {
            known_resources: HashMap::from([(
                type_url.clone(),
                HashMap::from([
                    (resource_name.clone(), strng::new("0.0.1")),
                    (strng::new(service_resource_name), strng::new("0.0.1")),
                ]),
            )]),
            pending: HashMap::new(),
            demand,
            demand_tx,
        };

        wrapper
            .clear(&mut state, &type_url)
            .expect("clearing known resources should succeed");

        assert!(!state.known_resources.contains_key(&type_url));
        let proxy_state = proxy_state.read().unwrap();
        assert!(
            proxy_state.workloads.find_uid(&strng::new(name)).is_none(),
            "actual workload UID must be removed before a reconnect snapshot is accepted"
        );
        assert!(proxy_state.workload_xds_names.is_empty());
        assert!(proxy_state.service_xds_names.is_empty());
        assert!(
            proxy_state
                .services
                .get_by_namespaced_host(
                    &NamespacedHostname::from_str("default/api.example").unwrap()
                )
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconnect_requires_fresh_snapshot_and_empty_resource_versions() {
        helpers::initialize_telemetry();
        let gate = XdsSessionGate::new();
        let drain_participant = gate.register_drain_participant();
        let (mut connections, client, state, _) =
            AdsServer::spawn_with_session_gate(false, Some(gate.clone())).await;
        let client_task = tokio::spawn(client.run());
        let ip = Ipv4Addr::new(10, 0, 0, 8);

        let mut first = tokio::time::timeout(Duration::from_secs(2), connections.recv())
            .await
            .expect("first ADS stream should connect")
            .expect("first ADS stream should be available");
        for expected_type in [ADDRESS_TYPE, AUTHORIZATION_TYPE] {
            let request = first.rx.recv().await.expect("initial watch request");
            assert_eq!(request.type_url, expected_type);
            assert!(request.initial_resource_versions.is_empty());
        }
        first
            .tx
            .send(Ok(DeltaDiscoveryResponse {
                resources: vec![get_address_with_uid_resource_name(0, ip.into())],
                type_url: ADDRESS_TYPE.to_string(),
                nonce: "initial-address".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap();
        assert!(!gate.is_open(), "one type cannot complete the snapshot");
        first
            .tx
            .send(Ok(DeltaDiscoveryResponse {
                type_url: AUTHORIZATION_TYPE.to_string(),
                nonce: "initial-authorization".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !gate.snapshot().ready {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("both initial resource types should be accepted");
        let first_generation = gate.snapshot().generation;
        gate.mark_drained(first_generation, drain_participant);
        assert!(gate.is_open());
        assert!(
            state
                .read()
                .find_address(
                    &NetworkAddress {
                        network: strng::EMPTY,
                        address: ip.into(),
                    },
                    None
                )
                .is_some()
        );

        for expected_nonce in ["initial-address", "initial-authorization"] {
            let ack = tokio::time::timeout(Duration::from_secs(1), first.rx.recv())
                .await
                .expect("initial xDS response should be acknowledged")
                .expect("initial ADS stream should remain open");
            assert_eq!(ack.response_nonce, expected_nonce);
        }

        let late_ip = Ipv4Addr::new(10, 0, 0, 9);
        first
            .tx
            .send(Ok(DeltaDiscoveryResponse {
                resources: vec![get_address_with_uid_resource_name(1, late_ip.into())],
                type_url: ADDRESS_TYPE.to_string(),
                nonce: "live-address-update".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while gate.is_open() {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("a live security delta must close strict inbound authorization");
        assert!(
            state
                .read()
                .find_address(
                    &NetworkAddress {
                        network: strng::EMPTY,
                        address: late_ip.into(),
                    },
                    None
                )
                .is_none(),
            "a live delta must not be applied under the previous snapshot generation"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(2), first.rx.recv())
                .await
                .expect("strict client must terminate the old ADS stream")
                .is_none(),
            "a live delta must not be ACKed; the client must reconnect for a full snapshot"
        );

        let mut second = tokio::time::timeout(Duration::from_secs(2), connections.recv())
            .await
            .expect("client should reconnect")
            .expect("reconnected ADS stream should be available");
        assert!(
            state
                .read()
                .find_address(
                    &NetworkAddress {
                        network: strng::EMPTY,
                        address: ip.into(),
                    },
                    None
                )
                .is_none(),
            "stale workload must be cleared before reconnect"
        );
        for expected_type in [ADDRESS_TYPE, AUTHORIZATION_TYPE] {
            let request = second.rx.recv().await.expect("resubscribe request");
            assert_eq!(request.type_url, expected_type);
            assert!(
                request.initial_resource_versions.is_empty(),
                "reconnect must request a fresh snapshot, not retain old versions"
            );
        }
        second
            .tx
            .send(Ok(DeltaDiscoveryResponse {
                resources: vec![get_address_with_uid_resource_name(0, ip.into())],
                type_url: ADDRESS_TYPE.to_string(),
                nonce: "resync-address".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap();
        assert!(!gate.is_open(), "fresh Address data alone is insufficient");
        second
            .tx
            .send(Ok(DeltaDiscoveryResponse {
                type_url: AUTHORIZATION_TYPE.to_string(),
                nonce: "resync-authorization".to_string(),
                ..Default::default()
            }))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !gate.snapshot().ready {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("fresh snapshot should become locally ready");
        let second_generation = gate.snapshot().generation;
        assert!(!gate.is_open(), "gate waits for the generation drain ack");
        gate.mark_drained(second_generation, drain_participant);
        assert!(gate.is_open());

        client_task.abort();
    }

    #[tokio::test]
    async fn unknown_type_is_nacked_and_revokes_strict_session() {
        helpers::initialize_telemetry();
        let gate = XdsSessionGate::new();
        let participant = gate.register_drain_participant();
        let (_connections, mut client, _, _) =
            AdsServer::spawn_with_session_gate(false, Some(gate.clone())).await;
        client.session_generation = gate.begin_session();
        gate.mark_snapshot_ready(client.session_generation);
        gate.mark_drained(client.session_generation, participant);
        assert!(gate.is_open());

        let response = DeltaDiscoveryResponse {
            type_url: "type.googleapis.com/example.Unhandled".to_string(),
            nonce: "unknown-type-nonce".to_string(),
            ..Default::default()
        };
        let (send, mut receive) = mpsc::channel(1);
        let result = client.handle_stream_event(response, &send).await.unwrap();

        assert!(matches!(result, XdsSignal::Nack));
        assert!(
            !gate.is_open(),
            "an unknown resource must revoke strict readiness"
        );
        let nack = receive.recv().await.expect("unknown response NACK");
        assert!(nack.error_detail.is_some());
        assert_eq!(nack.response_nonce, "unknown-type-nonce");
    }

    #[tokio::test]
    async fn rejected_response_revokes_session_before_nack_queue_unblocks() {
        helpers::initialize_telemetry();
        let gate = XdsSessionGate::new();
        let drain_participant = gate.register_drain_participant();
        let (_connections, mut client, _, _) =
            AdsServer::spawn_with_session_gate(false, Some(gate.clone())).await;
        client.session_generation = gate.begin_session();
        gate.mark_snapshot_ready(client.session_generation);
        gate.mark_drained(client.session_generation, drain_participant);
        assert!(gate.is_open());

        let invalid_address = XdsAddress { r#type: None };
        let response = DeltaDiscoveryResponse {
            resources: vec![ProtoResource {
                name: "invalid".to_string(),
                resource: Some(Any {
                    type_url: ADDRESS_TYPE.to_string(),
                    value: invalid_address.encode_to_vec(),
                }),
                ..Default::default()
            }],
            type_url: ADDRESS_TYPE.to_string(),
            nonce: "invalid-address".to_string(),
            ..Default::default()
        };
        let (send, mut receive) = mpsc::channel(1);
        send.send(DeltaDiscoveryRequest::default())
            .await
            .expect("fill the bounded outbound queue before handling the rejection");

        let handling =
            tokio::spawn(async move { client.handle_stream_event(response, &send).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while gate.is_open() {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("a rejected response must revoke before waiting to enqueue its NACK");
        assert!(
            !handling.is_finished(),
            "the full outbound queue should keep NACK handling blocked"
        );

        receive.recv().await.expect("release the outbound queue");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), handling)
                .await
                .expect("NACK handler should finish once the queue has space")
                .expect("handler task should complete"),
            Ok(XdsSignal::Nack)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_that_caches_are_warm_before_unblocked() {
        helpers::initialize_telemetry();

        // Setup fake xds server
        let (mut conn_receiver, client, state, mut block) = AdsServer::spawn(false).await;

        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                info!("workload manager: {}", e);
            }
        });

        let mut conn = conn_receiver.recv().await.unwrap();

        let mut auth_seen = false;
        let mut addr_seen = false;

        let timer = tokio::time::sleep(std::time::Duration::from_secs(1));
        futures::pin_mut!(timer);

        loop {
            let req = tokio::select! {
                _ = &mut timer => {
                    panic!("expected requests were not received");
                }
                _ = block.changed() => {
                    // make sure our cache is warm by using our resources
                    state.read()
                    .find_address(&NetworkAddress {
                        network: strng::EMPTY,
                        address: std::net::Ipv4Addr::new(1, 2, 3, 4).into(),
                    }, None)
                    .expect("address not in cache");
                    let conn = crate::rbac::Connection{
                        dst: std::net::SocketAddr::new(std::net::Ipv4Addr::new(1, 2, 3, 4).into(), 80),
                        src_identity: None,
                        src: std::net::SocketAddr::new(std::net::Ipv4Addr::new(1, 2, 3, 4).into(), 80),
                        dst_network: "".into(),
                    };
                    let rbac_ctx = crate::state::ProxyRbacContext {
                        conn: conn.clone(),
                        dest_workload: Arc::new(test_default_workload()),
                    };

                    // rbac should reject port 80
                    let rbac_res = state.assert_rbac(&rbac_ctx).await;
                    assert!(rbac_res.is_err());
                    let conn = crate::rbac::Connection{
                        dst: std::net::SocketAddr::new(std::net::Ipv4Addr::new(1, 2, 3, 4).into(), 81),
                        ..conn
                    };
                    let rbac_ctx = crate::state::ProxyRbacContext {
                        conn,
                        dest_workload: Arc::new(test_default_workload()),
                    };

                    // but allow port 81
                    let rbac_res = state.assert_rbac(&rbac_ctx).await;
                    assert!(rbac_res.is_ok());
                    return;
                }
                req = conn.rx.recv() => {
                    req.unwrap()
                }
            };

            info!("received request: {:?}", req);
            if req.type_url == AUTHORIZATION_TYPE && !auth_seen {
                let response = Ok(DeltaDiscoveryResponse {
                    resources: vec![get_auth(0)],
                    nonce: TextNonce::new().to_string(),
                    system_version_info: "1.0.0".to_string(),
                    type_url: AUTHORIZATION_TYPE.to_string(),
                    removed_resources: vec![],
                });
                conn.tx.send(response).await.unwrap();
                auth_seen = true;
            } else if req.type_url == ADDRESS_TYPE && !addr_seen {
                let response = Ok(DeltaDiscoveryResponse {
                    resources: vec![get_address(0, "1.2.3.4".parse().unwrap())],
                    nonce: TextNonce::new().to_string(),
                    system_version_info: "1.0.0".to_string(),
                    type_url: ADDRESS_TYPE.to_string(),
                    removed_resources: vec![],
                });
                conn.tx.send(response).await.unwrap();
                addr_seen = true;
            }
        }
    }

    #[tokio::test]
    async fn test_on_demand_handling() {
        helpers::initialize_telemetry();

        // Setup fake xds server
        let (mut conn_receiver, client, _, _) = AdsServer::spawn(true).await;

        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                info!("workload manager: {}", e);
            }
        });

        let mut conn = conn_receiver.recv().await.unwrap();

        let mut auth_seen = false;
        let mut addr_seen = false;

        let timer = tokio::time::sleep(std::time::Duration::from_secs(1));
        futures::pin_mut!(timer);

        loop {
            let req = tokio::select! {
                _ = &mut timer => {
                    panic!("expected requests were not received");
                }
                req = conn.rx.recv() => {
                    req.unwrap()
                }
            };

            info!("received request: {:?}", req);
            if req.type_url == AUTHORIZATION_TYPE {
                assert_eq!(req.resource_names_subscribe, Vec::<String>::new());
                assert_eq!(req.resource_names_unsubscribe, Vec::<String>::new());
                auth_seen = true;
            } else if req.type_url == ADDRESS_TYPE {
                assert_eq!(req.resource_names_subscribe, vec!["*"]);
                assert_eq!(req.resource_names_unsubscribe, vec!["*"]);
                addr_seen = true;
            }

            if auth_seen && addr_seen {
                return;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reconnect_echoes_retained_versions() {
        helpers::initialize_telemetry();

        // Setup fake xds server
        let (mut conn_receiver, client, _state, _block) = AdsServer::spawn(false).await;

        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                info!("workload manager: {}", e);
            }
        });

        let mut conn = conn_receiver.recv().await.unwrap();

        // The initial connection claims no retained resources.
        for _ in 0..2 {
            let req = conn.rx.recv().await.unwrap();
            assert!(req.initial_resource_versions.is_empty());
        }

        // First accept one address, then reject a different response atomically.
        // Reconnect must retain only the previously accepted resource version.
        conn.tx
            .send(Ok(DeltaDiscoveryResponse {
                resources: vec![get_address(0, "1.2.3.4".parse().unwrap())],
                nonce: "accepted-address".to_string(),
                type_url: ADDRESS_TYPE.to_string(),
                ..Default::default()
            }))
            .await
            .unwrap();
        let ack = conn.rx.recv().await.unwrap();
        assert_eq!(ack.response_nonce, "accepted-address");
        assert!(ack.error_detail.is_none());

        let malformed = ProtoResource {
            name: "bad".to_string(),
            aliases: vec![],
            version: "9.9.9".to_string(),
            resource: Some(Any {
                type_url: ADDRESS_TYPE.to_string(),
                value: vec![0xFF],
            }),
            ttl: None,
            cache_control: None,
        };
        let response = Ok(DeltaDiscoveryResponse {
            resources: vec![get_address(1, "1.2.3.5".parse().unwrap()), malformed],
            nonce: TextNonce::new().to_string(),
            system_version_info: "1.0.0".to_string(),
            type_url: ADDRESS_TYPE.to_string(),
            removed_resources: vec!["default/foo0".to_string()],
        });
        conn.tx.send(response).await.unwrap();

        let nack = conn.rx.recv().await.unwrap();
        assert_eq!(nack.type_url, ADDRESS_TYPE.to_string());
        assert!(nack.error_detail.is_some());

        // Force a reconnect. The new stream's initial request echoes the version of the
        // retained resource, and does not claim the rejected one (the server must re-send,
        // and thereby retry, it).
        drop(conn);
        let mut conn = conn_receiver.recv().await.unwrap();

        let timer = tokio::time::sleep(std::time::Duration::from_secs(5));
        futures::pin_mut!(timer);
        let mut addr_seen = false;
        let mut auth_seen = false;
        while !(addr_seen && auth_seen) {
            let req = tokio::select! {
                _ = &mut timer => {
                    panic!("expected requests were not received");
                }
                req = conn.rx.recv() => {
                    req.unwrap()
                }
            };
            if req.type_url == ADDRESS_TYPE {
                assert_eq!(
                    req.initial_resource_versions,
                    HashMap::from([("default/foo0".to_string(), "0.0.1".to_string())])
                );
                addr_seen = true;
            } else if req.type_url == AUTHORIZATION_TYPE {
                assert!(req.initial_resource_versions.is_empty());
                auth_seen = true;
            }
        }
    }

    // Tests that when the client processes a large response, the on-demand clients are notified
    // after contents of the cache were updated.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_on_demand_cache_coherency() {
        helpers::initialize_telemetry();

        // Setup fake xds server
        let (mut conn_receiver, client, state, _) = AdsServer::spawn(true).await;

        let demander = client.demander().unwrap();

        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                info!("workload manager: {}", e);
            }
        });
        let result = demander.demand(ADDRESS_TYPE, "default/foo0".into()).await;

        let mut conn = conn_receiver.recv().await.unwrap();

        let timer = tokio::time::sleep(std::time::Duration::from_secs(5));
        futures::pin_mut!(timer);

        loop {
            let req = tokio::select! {
                _ = &mut timer => {
                    panic!("expected requests were not received");
                }
                req = conn.rx.recv() => {
                    req.unwrap()
                }
            };

            info!("received request: {:?}", req);
            if req.type_url == ADDRESS_TYPE && req.resource_names_subscribe == vec!["default/foo0"]
            {
                let mut resources = vec![];

                // send back a big response, to expose the timing issue.
                let mut addr_range = ipnet::Ipv4Net::new(Ipv4Addr::new(1, 0, 0, 0), 8)
                    .unwrap()
                    .hosts();
                for i in 0..10_000 {
                    resources.push(get_address(i, addr_range.next().unwrap().into()));
                }

                let response = Ok(DeltaDiscoveryResponse {
                    resources,
                    nonce: TextNonce::new().to_string(),
                    system_version_info: "1.0.0".to_string(),
                    type_url: ADDRESS_TYPE.to_string(),
                    removed_resources: vec![],
                });

                tokio::spawn(async move { conn.tx.send(response).await });

                // wait for on demand to be notified. this means that the cache was updated with
                // our resource if it exists (and in our case we know it exists).
                result.recv().await;

                state
                    .read()
                    .find_address(
                        &NetworkAddress {
                            network: strng::EMPTY,
                            address: std::net::Ipv4Addr::new(1, 0, 0, 1).into(),
                        },
                        None,
                    )
                    .expect("demander return but resource not in cache");
                return;
            }
        }
    }

    #[tokio::test]
    async fn test_add_abort_remove() {
        helpers::initialize_telemetry();

        // TODO: Load this from a file?
        let ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let mut resources = vec![];
        let addresses = vec![XdsAddress {
            r#type: Some(XdsType::Workload(XdsWorkload {
                uid: "pod-1".to_string(),
                name: "test-workload".to_string(),
                namespace: "default".to_string(),
                addresses: vec![ip.octets().to_vec().into()],
                tunnel_protocol: 0,
                trust_domain: "local".to_string(),
                service_account: "default".to_string(),
                node: "default".to_string(),
                workload_type: WorkloadType::Deployment.into(),
                workload_name: "".to_string(),
                native_tunnel: true,
                ..Default::default()
            })),
        }];
        for addr in addresses.clone().iter() {
            match &addr.r#type {
                Some(XdsType::Workload(w)) => resources.push(ProtoResource {
                    name: w.uid.clone(),
                    aliases: vec![],
                    version: "0.0.1".to_string(),
                    resource: Some(Any {
                        type_url: ADDRESS_TYPE.to_string(),
                        value: addr.encode_to_vec(),
                    }),
                    ttl: None,
                    cache_control: None,
                }),
                Some(XdsType::Service(_s)) => (),
                _ => (),
            }
        }

        let initial_response = Ok(DeltaDiscoveryResponse {
            resources,
            nonce: TextNonce::new().to_string(),
            system_version_info: "1.0.0".to_string(),
            type_url: ADDRESS_TYPE.to_string(),
            removed_resources: vec![],
        });

        let abort_response = Err(tonic::Status::aborted("Aborting for test."));

        let removed_resource_response: Result<DeltaDiscoveryResponse, tonic::Status> =
            Ok(DeltaDiscoveryResponse {
                resources: vec![],
                nonce: TextNonce::new().to_string(),
                system_version_info: "1.0.0".to_string(),
                type_url: ADDRESS_TYPE.to_string(),
                removed_resources: vec!["pod-1".into()],
            });

        // Setup fake xds server
        let (mut conn_receiver, client, state, _) = AdsServer::spawn(false).await;

        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                info!("workload manager: {}", e);
            }
        });

        let conn = conn_receiver.recv().await.unwrap();

        conn.tx
            .send(initial_response)
            .await
            .expect("failed to send server response");
        sleep(Duration::from_millis(50)).await;
        verify_address(IpAddr::V4(ip), Some(addresses[0].clone()), &state).await;
        conn.tx
            .send(abort_response)
            .await
            .expect("failed to send server response");
        sleep(Duration::from_millis(50)).await;
        verify_address(IpAddr::V4(ip), Some(addresses[0].clone()), &state).await;

        // original connection should close and client re-connect
        let conn = conn_receiver.recv().await.unwrap();
        conn.tx
            .send(removed_resource_response)
            .await
            .expect("failed to send server response");
        sleep(Duration::from_millis(50)).await;
        verify_address(IpAddr::V4(ip), None, &state).await;
    }

    #[test]
    fn test_json_to_value() {
        use prost_types::value::Kind::*;

        // JSON map
        let mut v = serde_json::json!({ "app": "foo", "version": "v1" });
        assert_eq!(
            Config::json_to_value(v).kind.unwrap(),
            StructValue(prost_types::Struct {
                fields: vec![
                    (
                        "app".to_string(),
                        prost_types::Value {
                            kind: Some(Kind::StringValue("foo".to_string())),
                        }
                    ),
                    (
                        "version".to_string(),
                        prost_types::Value {
                            kind: Some(Kind::StringValue("v1".to_string())),
                        }
                    ),
                ]
                .into_iter()
                .collect()
            }),
        );

        // JSON array
        v = serde_json::json!(["foo", "bar"]);
        assert_eq!(
            Config::json_to_value(v).kind.unwrap(),
            ListValue(prost_types::ListValue {
                values: vec![
                    prost_types::Value {
                        kind: Some(Kind::StringValue("foo".to_string())),
                    },
                    prost_types::Value {
                        kind: Some(Kind::StringValue("bar".to_string())),
                    },
                ]
            })
        );

        // JSON bool
        v = serde_json::json!(true);
        assert_eq!(Config::json_to_value(v).kind.unwrap(), BoolValue(true));

        // JSON Number
        v = serde_json::json!(1);
        assert_eq!(Config::json_to_value(v).kind.unwrap(), NumberValue(1f64));

        // JSON null
        v = serde_json::json!(());
        assert_eq!(Config::json_to_value(v).kind.unwrap(), NullValue(0));
    }

    #[test]
    fn test_unix_uri_scheme_detection() {
        use crate::tls::unix_socket_path;

        // unix:///path extracts the socket path
        assert_eq!(
            unix_socket_path("unix:///run/xds.sock"),
            Some("/run/xds.sock")
        );

        // unix:/path also works
        assert_eq!(
            unix_socket_path("unix:/run/xds.sock"),
            Some("/run/xds.sock")
        );

        // relative path rejected
        assert_eq!(unix_socket_path("unix://run/xds.sock"), None);

        // https is not a unix socket
        assert_eq!(unix_socket_path("https://istiod:15012"), None);

        // plain hostname is not a unix socket
        assert_eq!(unix_socket_path("istiod:15012"), None);
    }
    fn issuer_profile_probe_fixture() -> (Vec<u8>, crate::tls::issuer_profile_wire::Expected) {
        use crate::tls::issuer_profile_wire::Expected;
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../tls/issuer-profile-v1.json")).unwrap();
        (
            serde_json::to_vec(&f["wire"]).unwrap(),
            Expected {
                cluster: "cmtc-a".into(),
                node: "cmtc-a-worker".into(),
                source_namespace: "cmtc-system".into(),
                source_name: "issuer-approval".into(),
                source_uid: "fixture-source-uid".into(),
                output_namespace: "cmtc-system".into(),
                output_name: "issuer-publication".into(),
                output_uid: "fixture-output-uid".into(),
                root_pins: vec![
                    "49a85f5a391f5585f5a91dfdaa9ce2ced3c9c9c69f02f47ad37b4b36d5e5beaf".into(),
                ],
                minimum_generation: 7,
                minimum_sequence: 10,
                approval_digest_at_minimum: Some(
                    "63d2ff33b79505477b45c873524f96641bc605242686a8c99274cb8b3b9b065e".into(),
                ),
                publication_digest_at_minimum: Some(
                    "7b8c9915b1a1b30f795d4dd42e61584f05f5edf00be23094bc4accb4a90a9c2f".into(),
                ),
            },
        )
    }
    fn issuer_profile_probe_clock() -> SystemTime {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../tls/issuer-profile-v1.json")).unwrap();
        std::time::UNIX_EPOCH + Duration::from_secs(f["nowUnix"].as_str().unwrap().parse().unwrap())
    }
    fn issuer_profile_probe_response(body: Vec<u8>) -> DeltaDiscoveryResponse {
        let wire: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let version = format!(
            "{}/{}",
            wire["sequence"].as_str().unwrap(),
            wire["publicationDigest"].as_str().unwrap()
        );
        let message = crate::xds::cilium::ztunnel::v1::IssuerProfile {
            transport_version: 1,
            strict_der_profile_json: body,
        };
        DeltaDiscoveryResponse {
            type_url: ISSUER_PROFILE_TYPE.to_string(),
            nonce: "profile-probe-nonce".into(),
            system_version_info: version.clone(),
            resources: vec![ProtoResource {
                name: "cilium/issuer-profile/cmtc-a-worker".into(),
                version,
                resource: Some(Any {
                    type_url: ISSUER_PROFILE_TYPE.to_string(),
                    value: message.encode_to_vec(),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
    }
    async fn issuer_profile_initial_requests(
        connection: &mut crate::test_helpers::xds::AdsConnection,
    ) {
        for expected in [ADDRESS_TYPE, AUTHORIZATION_TYPE, ISSUER_PROFILE_TYPE] {
            let request = tokio::time::timeout(Duration::from_secs(2), connection.rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(request.type_url, expected);
            assert!(request.initial_resource_versions.is_empty());
        }
    }
    async fn issuer_profile_send_address_authorization(
        connection: &mut crate::test_helpers::xds::AdsConnection,
    ) {
        for (type_url, nonce) in [
            (ADDRESS_TYPE, "address-for-probe"),
            (AUTHORIZATION_TYPE, "authorization-for-probe"),
        ] {
            connection
                .tx
                .send(Ok(DeltaDiscoveryResponse {
                    type_url: type_url.to_string(),
                    nonce: nonce.into(),
                    ..Default::default()
                }))
                .await
                .unwrap();
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn issuer_profile_native_tls_ads_never_acks_without_durable_provider_commit() {
        helpers::initialize_telemetry();
        let mut completed = 0;
        for case in [
            "valid-uncommitted",
            "wrong-inner-type",
            "wrong-transport-version",
            "rollback",
            "expired",
            "unavailable",
            "wrong-resource-version",
            "oversized",
        ] {
            eprintln!("issuer-profile native TLS case: {case}");
            let gate = XdsSessionGate::new();
            let (mut connections, mut client, _state, ready) =
                AdsServer::spawn_with_session_gate(false, Some(gate.clone())).await;
            let (body, expected) = issuer_profile_probe_fixture();
            client.config = client
                .config
                .with_issuer_profile_probe(expected, issuer_profile_probe_clock);
            client.config.issuer_profile_initial_timeout = Duration::from_secs(2);
            let task = tokio::spawn(client.run());
            let mut first = tokio::time::timeout(Duration::from_secs(2), connections.recv())
                .await
                .unwrap()
                .unwrap();
            issuer_profile_initial_requests(&mut first).await;
            issuer_profile_send_address_authorization(&mut first).await;
            let mut response = issuer_profile_probe_response(body.clone());
            match case {
                "wrong-inner-type" => {
                    response.resources[0].resource.as_mut().unwrap().type_url =
                        ADDRESS_TYPE.to_string()
                }
                "wrong-transport-version" => {
                    let profile = crate::xds::cilium::ztunnel::v1::IssuerProfile {
                        transport_version: 2,
                        strict_der_profile_json: body.clone(),
                    };
                    response.resources[0].resource.as_mut().unwrap().value =
                        profile.encode_to_vec();
                }
                "wrong-resource-version" => response.resources[0].version = "10/foreign".into(),
                "oversized" => {
                    response.resources[0].resource.as_mut().unwrap().value =
                        vec![0; crate::tls::issuer_profile_wire::MAX_WIRE_BYTES + 65]
                }
                "rollback" | "expired" | "unavailable" => {
                    let mut wire: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    if case == "rollback" {
                        wire["sequence"] = "9".into();
                    } else if case == "expired" {
                        wire["validUntilUnix"] = wire["publishedUnix"].clone();
                    } else {
                        wire["state"] = "withdrawn".into();
                        wire["reason"] = "SourceUnavailable".into();
                        wire["sequence"] = "11".into();
                        wire["rootDER"] = serde_json::Value::Null;
                        wire["rootSHA256"] = "".into();
                        wire["clusters"] = serde_json::json!([]);
                        wire["validUntilUnix"] = wire["publishedUnix"].clone();
                    }
                    response = issuer_profile_probe_response(serde_json::to_vec(&wire).unwrap());
                }
                _ => {}
            }
            first.tx.send(Ok(response)).await.unwrap();
            let nack = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let request = first
                        .rx
                        .recv()
                        .await
                        .expect("native TLS ADS must deliver the NACK");
                    if request.type_url == ISSUER_PROFILE_TYPE.to_string() {
                        break request;
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(nack.response_nonce, "profile-probe-nonce");
            let rejection = nack.error_detail.expect("profile activation must NACK");
            if case == "valid-uncommitted" || case == "unavailable" {
                assert!(
                    rejection
                        .message
                        .contains("durable provider commit unavailable"),
                    "{}",
                    rejection.message
                );
            }
            assert!(!gate.is_open());
            assert!(
                ready.has_changed().is_ok(),
                "profile NACK must not release readiness"
            );
            // Corrected delivery after reconnect still reaches the explicit
            // durable/provider barrier; it never fakes a successful activation.
            first
                .tx
                .send(Err(tonic::Status::unavailable(
                    "force fresh profile session",
                )))
                .await
                .unwrap();
            let mut recovered = tokio::time::timeout(Duration::from_secs(2), connections.recv())
                .await
                .unwrap()
                .unwrap();
            issuer_profile_initial_requests(&mut recovered).await;
            recovered
                .tx
                .send(Ok(issuer_profile_probe_response(body)))
                .await
                .unwrap();
            let nack = tokio::time::timeout(Duration::from_secs(2), recovered.rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(nack.type_url, ISSUER_PROFILE_TYPE.to_string());
            assert!(
                nack.error_detail
                    .unwrap()
                    .message
                    .contains("durable provider commit unavailable")
            );
            assert!(!gate.is_open());
            assert!(ready.has_changed().is_ok());
            task.abort();
            let _ = task.await;
            completed += 1;
        }
        assert_eq!(completed, 8);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn issuer_profile_missing_snapshot_and_disconnect_keep_admission_closed() {
        helpers::initialize_telemetry();
        let gate = XdsSessionGate::new();
        let (mut connections, mut client, _state, ready) =
            AdsServer::spawn_with_session_gate(false, Some(gate.clone())).await;
        let (_, expected) = issuer_profile_probe_fixture();
        client.config = client
            .config
            .with_issuer_profile_probe(expected, issuer_profile_probe_clock);
        client.config.issuer_profile_initial_timeout = Duration::from_millis(100);
        let task = tokio::spawn(client.run());
        let mut first = tokio::time::timeout(Duration::from_secs(2), connections.recv())
            .await
            .unwrap()
            .unwrap();
        issuer_profile_initial_requests(&mut first).await;
        issuer_profile_send_address_authorization(&mut first).await;
        assert!(!gate.is_open());
        assert!(ready.has_changed().is_ok());
        let mut second = tokio::time::timeout(Duration::from_secs(2), connections.recv())
            .await
            .unwrap()
            .unwrap();
        issuer_profile_initial_requests(&mut second).await;
        assert!(!gate.is_open());
        assert!(
            ready.has_changed().is_ok(),
            "missing trust response cannot satisfy initial sync"
        );
        second
            .tx
            .send(Err(tonic::Status::unavailable("disconnect")))
            .await
            .unwrap();
        let mut third = tokio::time::timeout(Duration::from_secs(2), connections.recv())
            .await
            .unwrap()
            .unwrap();
        issuer_profile_initial_requests(&mut third).await;
        assert!(!gate.is_open());
        assert!(ready.has_changed().is_ok());
        task.abort();
        let _ = task.await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_provider_tls_ads_commits_renews_nacks_rollback_and_recovers_full_epoch() {
        use crate::tls::profile_checkpoint::OpenMode;
        use crate::tls::profile_provider::ProfileProvider;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let gate = XdsSessionGate::new();
        let (mut connections, mut client, _state, _ready) =
            AdsServer::spawn_with_session_gate(false, Some(gate.clone())).await;
        let (body, expected) = issuer_profile_probe_fixture();
        let provider = ProfileProvider::open_with_clock(
            dir.path(),
            &expected,
            OpenMode::BootstrapEmptyDirectory,
            gate.clone(),
            issuer_profile_probe_clock,
        )
        .unwrap();
        client.config = client
            .config
            .with_issuer_profile_provider(expected, provider.clone());
        client.config.issuer_profile_initial_timeout = Duration::from_secs(2);
        let supervisor = tokio::spawn(provider.clone().supervise());
        let task = tokio::spawn(client.run());
        let mut connection = tokio::time::timeout(Duration::from_secs(2), connections.recv())
            .await
            .unwrap()
            .unwrap();
        issuer_profile_initial_requests(&mut connection).await;
        issuer_profile_send_address_authorization(&mut connection).await;
        connection
            .tx
            .send(Ok(issuer_profile_probe_response(body.clone())))
            .await
            .unwrap();
        let ack = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let req = connection.rx.recv().await.unwrap();
                if req.type_url == ISSUER_PROFILE_TYPE.to_string() {
                    break req;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(ack.response_nonce, "profile-probe-nonce");
        assert!(ack.error_detail.is_none());
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("profile-state.json")).unwrap())
                .unwrap();
        assert_eq!(
            saved["state"]["floors"]["sequence"], 10,
            "state must be durable before ACK is observable"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while !gate.is_open() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let old_lease = provider.acquire().unwrap();
        let old_epoch = old_lease.epoch();
        let mut wire: serde_json::Value = serde_json::from_slice(&body).unwrap();
        wire["sequence"] = "11".into();
        wire["publicationDigest"] = "c".repeat(64).into();
        let renewal = serde_json::to_vec(&wire).unwrap();
        connection
            .tx
            .send(Ok(issuer_profile_probe_response(renewal.clone())))
            .await
            .unwrap();
        let ack = tokio::time::timeout(Duration::from_secs(2), connection.rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ack.type_url, ISSUER_PROFILE_TYPE.to_string());
        assert!(ack.error_detail.is_none());
        assert_eq!(
            provider.acquire().unwrap().epoch(),
            old_epoch,
            "durable same-authority lease renewal must not churn live TLS"
        );
        connection
            .tx
            .send(Ok(issuer_profile_probe_response(body)))
            .await
            .unwrap();
        let nack = tokio::time::timeout(Duration::from_secs(2), connection.rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(nack.type_url, ISSUER_PROFILE_TYPE.to_string());
        assert!(nack.error_detail.is_some());
        assert!(!gate.is_open());
        assert!(old_lease.check_current().is_err());
        connection
            .tx
            .send(Err(tonic::Status::unavailable(
                "recover authenticated session",
            )))
            .await
            .unwrap();
        let mut recovery = tokio::time::timeout(Duration::from_secs(2), connections.recv())
            .await
            .unwrap()
            .unwrap();
        issuer_profile_initial_requests(&mut recovery).await;
        recovery
            .tx
            .send(Ok(issuer_profile_probe_response(renewal)))
            .await
            .unwrap();
        let ack = tokio::time::timeout(Duration::from_secs(2), recovery.rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(ack.error_detail.is_none());
        assert!(
            provider.acquire().is_err(),
            "fresh profile alone is not a complete new epoch"
        );
        issuer_profile_send_address_authorization(&mut recovery).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !gate.is_open() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_ne!(provider.acquire().unwrap().epoch(), old_epoch);
        task.abort();
        let _ = task.await;
        assert!(
            !gate.is_open(),
            "task cancellation must revoke the actual provider"
        );
        supervisor.abort();
        let _ = supervisor.await;
    }
}
