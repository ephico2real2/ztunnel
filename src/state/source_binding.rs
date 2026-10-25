// Copyright Istio Authors
// SPDX-License-Identifier: Apache-2.0

//! Process-local binding of a direct HBONE TLS peer to one native workload
//! observation. This joins facts; it does not attest source-IP anti-spoofing,
//! remote egress policy, or release Cilium's effective-policy quarantine.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use tokio::sync::watch;
use tokio_util::task::AbortOnDropHandle;

use super::workload::{HealthStatus, InboundProtocol, NetworkMode, Workload, network_addr};
use super::{DemandProxyState, ProxyRbacContext, ProxyState};
use crate::config::MeshEgressConfig;
use crate::proxy::AuthorizationRejectionError;
use crate::rbac::Connection;

fn reject(reason: &'static str) -> AuthorizationRejectionError {
    AuthorizationRejectionError::NativeSourceBinding(reason.into())
}

/// An ephemeral observation, never a persisted ACK, lease, numeric identity or
/// source authorization. The mutation observation and Arc identity detect ABA even when all
/// visible fields (including Pod UID and service account) are identical.
#[derive(Clone)]
pub(crate) struct DirectSource {
    workload: Arc<Workload>,
    connection: Connection,
    session: u64,
    observation: u64,
}
impl fmt::Debug for DirectSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectSource")
            .field("uid", &self.workload.uid)
            .field("cluster", &self.workload.cluster_id)
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}
impl PartialEq for DirectSource {
    fn eq(&self, other: &Self) -> bool {
        self.session == other.session
            && self.observation == other.observation
            && self.connection == other.connection
            && Arc::ptr_eq(&self.workload, &other.workload)
    }
}
impl Eq for DirectSource {}
impl Hash for DirectSource {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.session.hash(state);
        self.observation.hash(state);
        self.connection.hash(state);
        Arc::as_ptr(&self.workload).hash(state);
    }
}

fn direct_workload(w: &Workload) -> bool {
    !w.uid.is_empty()
        && !w.namespace.is_empty()
        && !w.service_account.is_empty()
        && !w.trust_domain.is_empty()
        && !w.cluster_id.is_empty()
        && !w.node.is_empty()
        && w.network_mode == NetworkMode::Standard
        && w.protocol == InboundProtocol::HBONE
        && w.status == HealthStatus::Healthy
        && w.waypoint.is_none()
        && w.network_gateway.is_none()
        && w.application_tunnel.is_none()
        && !w.native_tunnel
        && w.hostname.is_empty()
}

impl DirectSource {
    fn capture(
        state: &ProxyState,
        conn: &Connection,
        session: u64,
        ranges: &MeshEgressConfig,
    ) -> Result<Self, AuthorizationRejectionError> {
        let identity = conn
            .src_identity
            .as_ref()
            .ok_or_else(|| reject("TLS peer URI missing"))?;
        let (source, observation) = state
            .workloads
            .unique_address_observation(&network_addr(conn.dst_network.clone(), conn.src.ip()))
            .ok_or_else(|| reject("source IP has no unique native workload"))?;
        if !direct_workload(&source) {
            return Err(reject("source is not a supported direct HBONE workload"));
        }
        if source.identity() != *identity {
            return Err(reject("kernel peer IP and verified TLS URI disagree"));
        }
        let cluster = ranges
            .cluster_for_workload_ip(&source.cluster_id, &source.trust_domain, conn.src.ip())
            .map_err(|_| reject("source cluster/domain/IP not independently configured"))?;
        // cluster_for_workload_ip also admits gateway ranges; direct-source
        // authorization deliberately does not. No forwarded network is trusted.
        if !cluster
            .pod_cidrs
            .iter()
            .any(|cidr| cidr.contains(&conn.src.ip()))
        {
            return Err(reject("source is outside the approved direct Pod ranges"));
        }
        Ok(Self {
            workload: source,
            connection: conn.clone(),
            session,
            observation,
        })
    }

    fn current(
        &self,
        state: &ProxyState,
        conn: &Connection,
        session: u64,
        ranges: &MeshEgressConfig,
    ) -> Result<(), AuthorizationRejectionError> {
        // The application port replaces the original HBONE destination port.
        // Source socket, destination network, and verified URI must not change.
        if self.session != session
            || self.connection.src != conn.src
            || self.connection.src_identity != conn.src_identity
            || self.connection.dst_network != conn.dst_network
        {
            return Err(reject("captured TLS peer/session changed"));
        }
        let current = Self::capture(state, conn, session, ranges)?;
        if self.observation != current.observation
            || !Arc::ptr_eq(&self.workload, &current.workload)
        {
            return Err(reject(
                "source workload observation changed; reconnect required",
            ));
        }
        Ok(())
    }
}

impl DemandProxyState {
    /// Internal configuration only: derived from the existing strict mesh mode.
    /// There is no user-supplied "source authenticated" boolean or header.
    pub(crate) fn with_native_source_ranges(mut self, ranges: Option<MeshEgressConfig>) -> Self {
        self.native_source_ranges = ranges.map(Arc::new);
        self
    }
    pub(crate) fn native_source_required(&self) -> bool {
        self.native_source_ranges.is_some()
    }
    pub(crate) fn capture_native_source(
        &self,
        conn: &Connection,
    ) -> Result<Option<Arc<DirectSource>>, AuthorizationRejectionError> {
        let Some(ranges) = &self.native_source_ranges else {
            return Ok(None);
        };
        let session = self
            .xds_snapshot_generation()
            .ok_or(AuthorizationRejectionError::XdsSessionUnavailable)?;
        let source = DirectSource::capture(&self.read(), conn, session, ranges)?;
        if self.xds_snapshot_generation() != Some(session) {
            return Err(AuthorizationRejectionError::XdsSessionUnavailable);
        }
        Ok(Some(Arc::new(source)))
    }

    pub(crate) fn validate_native_source(
        &self,
        ctx: &ProxyRbacContext,
        state: &ProxyState,
    ) -> Result<(), AuthorizationRejectionError> {
        let Some(ranges) = &self.native_source_ranges else {
            return Ok(());
        };
        let source = ctx
            .native_source
            .as_ref()
            .ok_or_else(|| reject("captured TLS source absent"))?;
        let session = self
            .xds_snapshot_generation()
            .ok_or(AuthorizationRejectionError::XdsSessionUnavailable)?;
        source.current(state, &ctx.conn, session, ranges)?;
        let destination = state
            .workloads
            .find_uid(&ctx.dest_workload.uid)
            .ok_or_else(|| reject("destination workload removed"))?;
        if !Arc::ptr_eq(&destination, &ctx.dest_workload)
            || !direct_workload(&destination)
            || destination.network != ctx.conn.dst_network
            || !destination.workload_ips.contains(&ctx.conn.dst.ip())
        {
            return Err(reject("destination observation or direct address changed"));
        }
        if self.xds_snapshot_generation() != Some(session) {
            return Err(AuthorizationRejectionError::XdsSessionUnavailable);
        }
        Ok(())
    }

    async fn wait_native_source_invalid(&self, source: Arc<DirectSource>) {
        // Subscribe before checking to cover a delta between capture and spawn.
        let mut changed = self.read().workloads.new_subscriber();
        let gate = self.xds_session();
        let mut sessions = gate.as_ref().map(crate::xds::XdsSessionGate::subscribe);
        loop {
            let valid = self.native_source_ranges.as_ref().is_some_and(|ranges| {
                self.xds_snapshot_generation().is_some_and(|session| {
                    source
                        .current(&self.read(), &source.connection, session, ranges)
                        .is_ok()
                })
            });
            if !valid {
                tracing::warn!(component="native-source-binding", stage="source-invalidated",
                    workload_uid=%source.workload.uid, cluster=%source.workload.cluster_id,
                    session_generation=source.session,
                    "direct source witness invalidated; cancelling outer HBONE and inner streams");
                return;
            }
            tokio::select! {
                result = changed.changed() => { if result.is_err() { return; } },
                _ = async {
                    match sessions.as_mut() {
                        Some(receiver) => { let _ = receiver.changed().await; },
                        None => std::future::pending().await,
                    }
                } => {},
            }
        }
    }

    /// Merge source invalidation with existing immediate shutdown. The owner
    /// must live as long as the outer H2 driver. Dropping it aborts the task,
    /// drops its sole sender and wakes *all* child stream shutdown receivers.
    /// Ordinary transport shutdown is propagated unchanged.
    pub(crate) fn native_source_shutdown(
        &self,
        source: Option<Arc<DirectSource>>,
        mut shutdown: watch::Receiver<()>,
    ) -> (watch::Receiver<()>, Option<AbortOnDropHandle<()>>) {
        let Some(source) = source else {
            return (shutdown, None);
        };
        let (send, recv) = watch::channel(());
        let state = self.clone();
        let task = tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.changed() => {},
                _ = state.wait_native_source_invalid(source) => {},
            }
            send.send_replace(());
        });
        (recv, Some(AbortOnDropHandle::new(task)))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::MeshClusterRanges;
    use crate::identity::Identity;
    use crate::rbac::{Authorization, RbacAction, RbacMatch, RbacScope, StringMatch};
    use crate::strng;
    use crate::test_helpers::test_default_workload;
    use crate::xds::XdsSessionGate;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use std::sync::RwLock;
    use std::time::Duration;

    pub(crate) fn fixture(
        conn: Connection,
    ) -> (DemandProxyState, ProxyRbacContext, XdsSessionGate) {
        let source_identity = conn.src_identity.as_ref().unwrap();
        let Identity::Spiffe {
            trust_domain,
            namespace,
            service_account,
        } = source_identity;
        let source = Arc::new(Workload {
            uid: "source-pod-uid".into(),
            name: "source".into(),
            node: "node-a".into(),
            namespace: namespace.clone(),
            service_account: service_account.clone(),
            trust_domain: trust_domain.clone(),
            cluster_id: "cmtc-a".into(),
            workload_ips: vec![conn.src.ip()],
            network: conn.dst_network.clone(),
            protocol: InboundProtocol::HBONE,
            ..test_default_workload()
        });
        let destination = Arc::new(Workload {
            uid: "destination-pod-uid".into(),
            name: "destination".into(),
            node: "node-b".into(),
            namespace: "orders".into(),
            service_account: "api".into(),
            trust_domain: "cmtc-b.mesh.example".into(),
            cluster_id: "cmtc-b".into(),
            workload_ips: vec![conn.dst.ip()],
            network: conn.dst_network.clone(),
            protocol: InboundProtocol::HBONE,
            authorization_policies: vec!["orders/native-fixture".into()],
            ..test_default_workload()
        });
        let mut state = ProxyState::new(None);
        state.workloads.insert(source);
        state.workloads.insert(destination.clone());
        state.policies.insert(
            "orders/native-fixture".into(),
            Authorization {
                name: "native-fixture".into(),
                namespace: "orders".into(),
                scope: RbacScope::WorkloadSelector,
                action: RbacAction::Allow,
                dry_run: false,
                rules: vec![vec![vec![RbacMatch {
                    principals: vec![StringMatch::Exact(
                        source_identity
                            .to_strng()
                            .strip_prefix("spiffe://")
                            .unwrap()
                            .into(),
                    )],
                    source_ips: vec![ipnet::IpNet::from(conn.src.ip())],
                    destination_ips: vec![ipnet::IpNet::from(conn.dst.ip())],
                    destination_ports: vec![conn.dst.port()],
                    ..Default::default()
                }]]],
            },
        );
        let gate = XdsSessionGate::new();
        let generation = gate.begin_session();
        gate.mark_snapshot_ready(generation);
        let state = DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            crate::test_helpers::helpers::test_proxy_metrics(),
        )
        .with_require_inbound_mtls(true)
        .with_xds_session(Some(gate.clone()))
        .with_native_source_ranges(Some(MeshEgressConfig {
            clusters: vec![MeshClusterRanges {
                cluster_id: "cmtc-a".into(),
                trust_domain: trust_domain.to_string(),
                pod_cidrs: vec![ipnet::IpNet::from(conn.src.ip())],
                service_cidrs: vec![],
                gateway_cidrs: vec![],
            }],
            exceptions: vec![],
        }));
        let native_source = state.capture_native_source(&conn).unwrap();
        (
            state,
            ProxyRbacContext {
                conn,
                dest_workload: destination,
                native_source,
            },
            gate,
        )
    }
    pub(crate) fn remove_workload(
        state: &DemandProxyState,
        uid: &crate::strng::Strng,
    ) -> Option<Workload> {
        state.state.write().unwrap().workloads.remove(uid)
    }
    pub(crate) fn insert_workload(state: &DemandProxyState, workload: Arc<Workload>) {
        state.state.write().unwrap().workloads.insert(workload);
    }
    fn connection() -> Connection {
        Connection {
            src: "10.1.0.10:12345".parse().unwrap(),
            dst: "10.2.0.10:8080".parse().unwrap(),
            dst_network: strng::EMPTY,
            src_identity: Some(Identity::Spiffe {
                trust_domain: "cmtc-a.mesh.example".into(),
                namespace: "orders".into(),
                service_account: "api".into(),
            }),
        }
    }
    #[tokio::test]
    async fn direct_native_source_rejects_missing_unknown_ambiguous_and_uri_mismatch() {
        let (state, ctx, _) = fixture(connection());
        assert!(state.assert_rbac(&ctx).await.is_ok());
        let no_witness = ProxyRbacContext::new(ctx.conn.clone(), ctx.dest_workload.clone());
        assert!(state.assert_rbac(&no_witness).await.is_err());
        let mut no_tls = ctx.conn.clone();
        no_tls.src_identity = None;
        assert!(state.capture_native_source(&no_tls).is_err());
        let mut unknown = ctx.conn.clone();
        unknown.src.set_ip("10.1.0.99".parse().unwrap());
        assert!(state.capture_native_source(&unknown).is_err());
        let mut wrong_uri = ctx.conn.clone();
        wrong_uri.src_identity = Some(Identity::Spiffe {
            trust_domain: "cmtc-a.mesh.example".into(),
            namespace: "orders".into(),
            service_account: "other".into(),
        });
        assert!(state.capture_native_source(&wrong_uri).is_err());
        let source = state
            .read()
            .workloads
            .find_uid(&"source-pod-uid".into())
            .unwrap();
        let mut duplicate = (*source).clone();
        duplicate.uid = "other-pod-same-address".into();
        state
            .state
            .write()
            .unwrap()
            .workloads
            .insert(Arc::new(duplicate));
        assert!(state.capture_native_source(&ctx.conn).is_err());
        assert!(state.assert_rbac(&ctx).await.is_err());
        state
            .state
            .write()
            .unwrap()
            .workloads
            .remove(&"other-pod-same-address".into());
        assert!(state.assert_rbac(&ctx).await.is_ok());
    }
    #[tokio::test]
    async fn same_service_account_cannot_inherit_allowed_source_ip_or_old_connection() {
        let (mut state, ctx, _) = fixture(connection());
        // The independently supplied fixture ranges include the second Pod.
        Arc::make_mut(state.native_source_ranges.as_mut().unwrap()).clusters[0].pod_cidrs =
            vec!["10.1.0.0/24".parse().unwrap()];
        let source = state
            .read()
            .workloads
            .find_uid(&"source-pod-uid".into())
            .unwrap();
        let mut other = (*source).clone();
        other.uid = "other-label-identity".into();
        other.workload_ips = vec!["10.1.0.11".parse().unwrap()];
        state
            .state
            .write()
            .unwrap()
            .workloads
            .insert(Arc::new(other));
        let mut other_ctx = ctx.clone();
        other_ctx.conn.src.set_ip("10.1.0.11".parse().unwrap());
        other_ctx.native_source = state.capture_native_source(&other_ctx.conn).unwrap();
        assert!(
            state.assert_rbac(&other_ctx).await.is_err(),
            "same SA cannot replace exact SourceIps match"
        );
        state.state.write().unwrap().workloads.remove(&source.uid);
        state
            .state
            .write()
            .unwrap()
            .workloads
            .insert(source.clone()); // SAME Arc ABA
        assert!(state.assert_rbac(&ctx).await.is_err());
        let mut fresh = ctx.clone();
        fresh.native_source = state.capture_native_source(&fresh.conn).unwrap();
        assert!(
            state.assert_rbac(&fresh).await.is_ok(),
            "fresh outer TLS may bind current observation"
        );
    }
    #[tokio::test]
    async fn unsupported_source_modes_cluster_domain_and_gateway_ranges_are_closed() {
        for case in 0..8 {
            let (state, ctx, _) = fixture(connection());
            let source = state
                .read()
                .workloads
                .find_uid(&"source-pod-uid".into())
                .unwrap();
            let mut changed = (*source).clone();
            match case {
                0 => changed.cluster_id = "unapproved-cluster".into(),
                1 => changed.trust_domain = "other.mesh".into(),
                2 => changed.protocol = InboundProtocol::TCP,
                3 => changed.network_mode = NetworkMode::HostNetwork,
                4 => changed.native_tunnel = true,
                5 => changed.status = HealthStatus::Unhealthy,
                6 => changed.hostname = "alias.example".into(),
                7 => changed.node = strng::EMPTY,
                _ => unreachable!(),
            }
            state
                .state
                .write()
                .unwrap()
                .workloads
                .insert(Arc::new(changed));
            assert!(
                state.capture_native_source(&ctx.conn).is_err(),
                "case {case}"
            );
        }
        let (mut state, ctx, _) = fixture(connection());
        let ranges = Arc::make_mut(state.native_source_ranges.as_mut().unwrap());
        ranges.clusters[0].gateway_cidrs = std::mem::take(&mut ranges.clusters[0].pod_cidrs);
        assert!(state.capture_native_source(&ctx.conn).is_err());
    }
    #[tokio::test]
    async fn deletion_wakes_idle_source_owner_and_restore_requires_new_witness() {
        let (state, ctx, _) = fixture(connection());
        let (_global, global) = watch::channel(());
        let (mut shutdown, owner) = state.native_source_shutdown(ctx.native_source.clone(), global);
        let old = state
            .state
            .write()
            .unwrap()
            .workloads
            .remove(&"source-pod-uid".into())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), shutdown.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(state.assert_rbac(&ctx).await.is_err());
        state.state.write().unwrap().workloads.insert(Arc::new(old));
        assert!(state.assert_rbac(&ctx).await.is_err());
        drop(owner);
        let mut fresh = ctx.clone();
        fresh.native_source = state.capture_native_source(&ctx.conn).unwrap();
        assert!(state.assert_rbac(&fresh).await.is_ok());
    }
    #[tokio::test]
    async fn stale_session_and_source_owner_cancellation_wake_all_shutdown_receivers() {
        let (state, ctx, gate) = fixture(connection());
        let (_global, global) = watch::channel(());
        let (mut outer, owner) = state.native_source_shutdown(ctx.native_source.clone(), global);
        let mut inner = outer.clone();
        gate.mark_stale(gate.snapshot().generation);
        tokio::time::timeout(Duration::from_secs(2), outer.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(inner.changed().await.is_ok());
        assert!(state.capture_native_source(&ctx.conn).is_err());
        drop(owner);
        let (state, ctx, _) = fixture(connection());
        let (_global, global) = watch::channel(());
        let (mut receiver, owner) = state.native_source_shutdown(ctx.native_source.clone(), global);
        drop(owner);
        tokio::time::timeout(Duration::from_secs(2), receiver.changed())
            .await
            .unwrap()
            .unwrap_err();
    }
    #[tokio::test]
    async fn real_policy_watcher_drains_on_workload_only_delta_and_allows_fresh_observation() {
        let (state, mut ctx, gate) = fixture(connection());
        let manager = crate::proxy::connection_manager::ConnectionManager::default();
        let (stop, stopped) = crate::drain::new();
        let watcher = crate::proxy::connection_manager::PolicyWatcher::new(
            state.clone(),
            stopped,
            manager.clone(),
        );
        let watcher = tokio::spawn(watcher.run());
        tokio::time::timeout(Duration::from_secs(2), async {
            while !gate.is_open() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        ctx.native_source = state.capture_native_source(&ctx.conn).unwrap();
        let mut guard = manager.assert_rbac(&state, &ctx, None).await.unwrap();
        let changed = guard.watcher();
        let application = tokio::spawn(async move {
            drop(changed.wait_for_drain().await);
        });
        assert_eq!(manager.connections().len(), 1);
        let previous = remove_workload(&state, &"source-pod-uid".into()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), application)
            .await
            .unwrap()
            .unwrap();
        drop(guard);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !manager.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(state.assert_rbac(&ctx).await.is_err());
        insert_workload(&state, Arc::new(previous));
        assert!(state.assert_rbac(&ctx).await.is_err());
        ctx.native_source = state.capture_native_source(&ctx.conn).unwrap();
        let guard = manager.assert_rbac(&state, &ctx, None).await.unwrap();
        drop(guard);
        stop.start_drain_and_wait(crate::drain::DrainMode::Immediate)
            .await;
        tokio::time::timeout(Duration::from_secs(2), watcher)
            .await
            .unwrap()
            .unwrap();
    }
}
