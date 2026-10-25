// Copyright Istio Authors
// SPDX-License-Identifier: Apache-2.0
//! Process-local source observation, not a kernel capture/SIP receipt or
//! effective egress authorization. Native Cilium gates remain separate.
use super::{
    DemandProxyState,
    workload::{HealthStatus, InboundProtocol, NetworkMode, Workload, network_addr},
};
use crate::{config::Config, proxy::AuthorizationRejectionError, strng::Strng};
use std::{
    future::Future,
    io,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
fn reject(reason: &'static str) -> AuthorizationRejectionError {
    AuthorizationRejectionError::NativeSourceBinding(reason.into())
}
#[derive(Clone)]
pub(crate) struct OutboundSource {
    state: DemandProxyState,
    workload: Arc<Workload>,
    address: IpAddr,
    observation: u64,
    session: u64,
}
impl OutboundSource {
    pub(crate) fn capture(
        state: &DemandProxyState,
        cfg: &Config,
        workload: Arc<Workload>,
        address: IpAddr,
        original_uid: Option<&Strng>,
    ) -> Result<Option<Arc<Self>>, AuthorizationRejectionError> {
        if !cfg.require_mesh_hbone {
            return Ok(None);
        }
        if original_uid != Some(&workload.uid)
            || workload.uid.is_empty()
            || workload.namespace.is_empty()
            || workload.service_account.is_empty()
            || workload.trust_domain.is_empty()
            || workload.cluster_id.as_str() != cfg.cluster_id
            || cfg.local_node.as_deref() != Some(workload.node.as_str())
            || workload.network != cfg.network
            || workload.network_mode != NetworkMode::Standard
            || workload.protocol != InboundProtocol::HBONE
            || workload.status != HealthStatus::Healthy
            || workload.waypoint.is_some()
            || workload.network_gateway.is_some()
            || workload.application_tunnel.is_some()
            || workload.native_tunnel
            || !workload.hostname.is_empty()
        {
            return Err(reject(
                "outbound source does not match original local ZDS workload",
            ));
        }
        let cluster = cfg
            .mesh_egress
            .cluster_for_workload_ip(&workload.cluster_id, &workload.trust_domain, address)
            .map_err(|_| reject("outbound source cluster/domain/IP is not approved"))?;
        if !cluster
            .pod_cidrs
            .iter()
            .any(|range| range.contains(&address))
        {
            return Err(reject("outbound source is outside approved Pod ranges"));
        }
        let session = state
            .xds_snapshot_generation()
            .ok_or(AuthorizationRejectionError::XdsSessionUnavailable)?;
        let (current, observation) = state
            .read()
            .workloads
            .unique_address_observation(&network_addr(workload.network.clone(), address))
            .ok_or_else(|| reject("outbound source address has no unique workload"))?;
        if !Arc::ptr_eq(&current, &workload) {
            return Err(reject(
                "outbound source changed during request construction",
            ));
        }
        let witness = Arc::new(Self {
            state: state.clone(),
            workload,
            address,
            observation,
            session,
        });
        witness.check()?;
        Ok(Some(witness))
    }
    pub(crate) fn same_observation(&self, other: &Self) -> bool {
        self.session == other.session
            && self.observation == other.observation
            && self.address == other.address
            && Arc::ptr_eq(&self.workload, &other.workload)
    }
    pub(crate) fn check(&self) -> Result<(), AuthorizationRejectionError> {
        if self.state.xds_snapshot_generation() != Some(self.session) {
            return Err(AuthorizationRejectionError::XdsSessionUnavailable);
        }
        let observed = self
            .state
            .read()
            .workloads
            .unique_address_observation(&network_addr(self.workload.network.clone(), self.address));
        if !observed.is_some_and(|(current, observation)| {
            observation == self.observation && Arc::ptr_eq(&current, &self.workload)
        }) {
            return Err(reject(
                "outbound source removed or replaced; reconnect required",
            ));
        }
        if self.state.xds_snapshot_generation() != Some(self.session) {
            return Err(AuthorizationRejectionError::XdsSessionUnavailable);
        }
        Ok(())
    }
    pub(crate) async fn invalidated(self: Arc<Self>) {
        let mut workloads = self.state.read().workloads.new_subscriber();
        let gate = self.state.xds_session();
        let mut sessions = gate.as_ref().map(crate::xds::XdsSessionGate::subscribe);
        loop {
            if let Err(error) = self.check() {
                tracing::warn!(component="native-outbound-source",stage="source-invalidated",workload_uid=%self.workload.uid,cluster=%self.workload.cluster_id,session_generation=self.session,%error,"source invalidated; closing active and idle HBONE transport");
                return;
            }
            tokio::select! { result=workloads.changed()=>{if result.is_err(){return;}}, _=async{match sessions.as_mut(){Some(receiver)=>{let _=receiver.changed().await;},None=>std::future::pending().await,}}=>{}, }
        }
    }
}
/// The H2 idle read polls this guard. No detached task/FD is retained. Check
/// above TLS, including before delivering already decrypted plaintext.
pub(crate) struct SourceIo<IO> {
    io: Option<IO>,
    source: Option<Arc<OutboundSource>>,
    invalid: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}
impl<IO> SourceIo<IO> {
    pub(crate) fn new(io: IO, source: Option<Arc<OutboundSource>>) -> io::Result<Self> {
        if let Some(source) = &source {
            source
                .check()
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;
        }
        let invalid = source.clone().map(|source| {
            Box::pin(source.invalidated()) as Pin<Box<dyn Future<Output = ()> + Send>>
        });
        Ok(Self {
            io: Some(io),
            source,
            invalid,
        })
    }
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        let invalid = self.io.is_none()
            || self
                .source
                .as_ref()
                .is_some_and(|source| source.check().is_err())
            || self
                .invalid
                .as_mut()
                .is_some_and(|future| future.as_mut().poll(cx).is_ready());
        if invalid {
            self.io.take();
            self.invalid.take();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "native outbound source expired",
            ));
        }
        Ok(())
    }
}
impl<IO: AsyncRead + Unpin> AsyncRead for SourceIo<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check(cx)?;
        let before = buf.filled().len();
        let result = Pin::new(this.io.as_mut().expect("checked source I/O")).poll_read(cx, buf);
        if let Err(error) = this.check(cx) {
            buf.filled_mut()[before..].fill(0);
            buf.set_filled(before);
            return Poll::Ready(Err(error));
        }
        result
    }
}
impl<IO: AsyncWrite + Unpin> AsyncWrite for SourceIo<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check(cx)?;
        let result = Pin::new(this.io.as_mut().expect("checked source I/O")).poll_write(cx, buf);
        this.check(cx)?;
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check(cx)?;
        let result = Pin::new(this.io.as_mut().expect("checked source I/O")).poll_flush(cx);
        this.check(cx)?;
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check(cx)?;
        Pin::new(this.io.as_mut().expect("checked source I/O")).poll_shutdown(cx)
    }
}

impl std::fmt::Debug for OutboundSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundSource")
            .field("uid", &self.workload.uid)
            .field("session", &self.session)
            .field("observation", &self.observation)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{identity::Identity, rbac::Connection, state::source_binding};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub(super) fn fixture() -> (
        DemandProxyState,
        Config,
        Arc<Workload>,
        crate::xds::XdsSessionGate,
    ) {
        let conn = Connection {
            src: "10.1.0.10:12345".parse().unwrap(),
            dst: "10.2.0.10:8080".parse().unwrap(),
            dst_network: "".into(),
            src_identity: Some(Identity::Spiffe {
                trust_domain: "cmtc-a.mesh.example".into(),
                namespace: "orders".into(),
                service_account: "api".into(),
            }),
        };
        let (state, _, gate) = source_binding::tests::fixture(conn);
        let source = state
            .read()
            .workloads
            .find_uid(&"source-pod-uid".into())
            .unwrap();
        let mut cfg = crate::config::parse_config().unwrap();
        cfg.require_mesh_hbone = true;
        cfg.cluster_id = "cmtc-a".into();
        cfg.local_node = Some("node-a".into());
        cfg.network = source.network.clone();
        cfg.mesh_egress = state
            .native_source_ranges
            .as_ref()
            .unwrap()
            .as_ref()
            .clone();
        (state, cfg, source, gate)
    }
    pub(super) fn witness(
        state: &DemandProxyState,
        cfg: &Config,
        source: &Arc<Workload>,
    ) -> Arc<OutboundSource> {
        OutboundSource::capture(
            state,
            cfg,
            source.clone(),
            source.workload_ips[0],
            Some(&source.uid),
        )
        .unwrap()
        .unwrap()
    }
    #[tokio::test]
    async fn native_outbound_source_rejects_wrong_uid_cluster_node_domain_and_ambiguous_ip() {
        for case in [
            "no-uid",
            "wrong-uid",
            "wrong-cluster",
            "wrong-node",
            "wrong-domain",
            "wrong-ip",
            "ambiguous-ip",
            "removed",
            "stale-session",
        ] {
            let (state, mut cfg, source, gate) = fixture();
            let wrong_uid: Strng = "other-pod".into();
            let mut uid = Some(&source.uid);
            let mut ip = source.workload_ips[0];
            match case {
                "no-uid" => uid = None,
                "wrong-uid" => uid = Some(&wrong_uid),
                "wrong-cluster" => cfg.cluster_id = "cmtc-b".into(),
                "wrong-node" => cfg.local_node = Some("node-other".into()),
                "wrong-domain" => cfg.mesh_egress.clusters[0].trust_domain = "foreign.mesh".into(),
                "wrong-ip" => ip = "10.1.0.11".parse().unwrap(),
                "ambiguous-ip" => {
                    let mut duplicate = (*source).clone();
                    duplicate.uid = "same-ip-other-pod".into();
                    state
                        .state
                        .write()
                        .unwrap()
                        .workloads
                        .insert(Arc::new(duplicate));
                }
                "removed" => {
                    state.state.write().unwrap().workloads.remove(&source.uid);
                }
                "stale-session" => {
                    gate.begin_session();
                }
                _ => unreachable!(),
            }
            assert!(
                OutboundSource::capture(&state, &cfg, source.clone(), ip, uid).is_err(),
                "{case}"
            );
        }
    }
    #[tokio::test]
    async fn native_outbound_source_aba_and_fresh_observation_recovery() {
        let (state, cfg, source, _) = fixture();
        let old = witness(&state, &cfg, &source);
        assert!(old.check().is_ok());
        state
            .state
            .write()
            .unwrap()
            .workloads
            .insert(source.clone());
        assert!(
            old.check().is_err(),
            "same Arc remove/reinsert must not revive old observation"
        );
        let new = witness(&state, &cfg, &source);
        assert!(new.check().is_ok());
        assert!(old.check().is_err());
        let waiter = tokio::spawn(old.invalidated());
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn native_outbound_source_real_tcp_idle_and_active_close_on_withdrawal() {
        for active in [false, true] {
            let (state, cfg, source, _) = fixture();
            let captured = witness(&state, &cfg, &source);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let mut guarded = SourceIo::new(stream, Some(captured)).unwrap();
            if active {
                peer.write_all(b"positive").await.unwrap();
                let mut buf = [0; 8];
                guarded.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"positive");
            }
            let waiting = tokio::spawn(async move {
                let mut buf = [0; 1];
                guarded.read(&mut buf).await
            });
            tokio::task::yield_now().await;
            state.state.write().unwrap().workloads.remove(&source.uid);
            let error = tokio::time::timeout(Duration::from_secs(1), waiting)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            let mut buf = [0; 1];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), peer.read(&mut buf))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
    }
    #[tokio::test]
    async fn native_outbound_source_discards_buffered_plaintext_and_preserves_legacy_io() {
        let (state, cfg, source, _) = fixture();
        let captured = witness(&state, &cfg, &source);
        let (io, mut peer) = tokio::io::duplex(128);
        peer.write_all(b"must-not-deliver").await.unwrap();
        let mut guarded = SourceIo::new(io, Some(captured)).unwrap();
        state.state.write().unwrap().workloads.remove(&source.uid);
        let mut output = [0u8; 32];
        assert_eq!(
            guarded.read(&mut output).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(output, [0; 32]);
        let (io, mut peer) = tokio::io::duplex(128);
        let mut legacy = SourceIo::new(io, None).unwrap();
        peer.write_all(b"legacy").await.unwrap();
        let mut output = [0; 6];
        legacy.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"legacy");
    }
    #[tokio::test]
    async fn native_outbound_source_bound_lookup_cannot_adopt_same_name_replacement() {
        let (state, cfg, source, _) = fixture();
        let info = Arc::new(crate::state::WorkloadInfo::new(
            source.name.to_string(),
            source.namespace.to_string(),
            source.service_account.to_string(),
        ));
        let unbound = crate::proxy::LocalWorkloadInformation::new(
            info.clone(),
            state.clone(),
            crate::identity::mock::new_secret_manager(Duration::from_secs(10)),
            Arc::new(cfg.clone()),
        );
        assert!(
            unbound.get_workload().await.is_err(),
            "strict lookup cannot adopt an unbound ZDS owner"
        );
        let mut legacy_cfg = cfg.clone();
        legacy_cfg.require_mesh_hbone = false;
        let legacy = crate::proxy::LocalWorkloadInformation::new(
            info.clone(),
            state.clone(),
            crate::identity::mock::new_secret_manager(Duration::from_secs(10)),
            Arc::new(legacy_cfg),
        );
        assert_eq!(legacy.get_workload().await.unwrap().uid, source.uid);
        let local = crate::proxy::LocalWorkloadInformation::new(
            info.clone(),
            state.clone(),
            crate::identity::mock::new_secret_manager(Duration::from_secs(10)),
            Arc::new(cfg),
        )
        .with_uid(Some(source.uid.clone()));
        assert_eq!(local.get_workload().await.unwrap().uid, source.uid);
        let fetcher = local.as_fetcher();
        let mut replacement = (*source).clone();
        replacement.uid = "replacement-pod-uid".into();
        state.state.write().unwrap().workloads.remove(&source.uid);
        state
            .state
            .write()
            .unwrap()
            .workloads
            .insert(Arc::new(replacement));
        assert!(local.get_workload().await.is_err());
        assert!(fetcher.get_workload().await.is_err());
        // Exact original UID is independently pinned, not a name-matching fallback.
        state
            .state
            .write()
            .unwrap()
            .workloads
            .remove(&"replacement-pod-uid".into());
        state
            .state
            .write()
            .unwrap()
            .workloads
            .insert(source.clone());
        assert_eq!(local.get_workload().await.unwrap().uid, source.uid);
    }
    #[tokio::test]
    async fn native_outbound_source_pooled_transport_is_discarded_before_driver_observes_aba() {
        let (state, cfg, source, _) = fixture();
        let captured = witness(&state, &cfg, &source);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let serving = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server).await.unwrap();
            while conn.accept().await.is_some() {}
        });
        let key = crate::proxy::h2::client::WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            dst: "10.2.0.10:15008".parse().unwrap(),
            src: source.workload_ips[0],
        };
        let (_drain, drain_rx) = tokio::sync::watch::channel(false);
        let mut transport = crate::proxy::h2::client::spawn_connection(
            Arc::new(cfg.clone()),
            SourceIo::new(client, Some(captured.clone())).unwrap(),
            drain_rx,
            key,
            None,
            Default::default(),
        )
        .await
        .unwrap();
        transport.bind_source(Some(captured.clone()));
        assert!(transport.ready_to_use());
        assert!(transport.serves_source(Some(&captured)));
        assert!(
            !transport.serves_source(None),
            "a witnessed transport never serves an unwitnessed request"
        );

        // Same-Arc remove/reinsert (ABA). No await: the H2 driver has not been
        // polled, so only the checkout check can observe the withdrawal.
        state
            .state
            .write()
            .unwrap()
            .workloads
            .insert(source.clone());
        assert!(
            !transport.ready_to_use(),
            "checkout must discard the stale transport and open a fresh one"
        );
        let fresh = witness(&state, &cfg, &source);
        assert!(fresh.check().is_ok());
        assert!(!transport.serves_source(Some(&fresh)));
        let request = http::Request::builder()
            .method("CONNECT")
            .uri("10.2.0.10:8080")
            .version(http::Version::HTTP_2)
            .body(())
            .unwrap();
        assert!(matches!(
            transport.send_request(request).await,
            Err(crate::proxy::Error::NativeOutboundSourceInvalidated)
        ));
        serving.abort();
        let _ = serving.await;
    }
    #[tokio::test]
    async fn native_outbound_source_h2_idle_and_active_driver_drains_on_source_replacement() {
        for active in [false, true] {
            let (state, cfg, source, _) = fixture();
            let captured = witness(&state, &cfg, &source);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (server, _) = listener.accept().await.unwrap();
            let serving = tokio::spawn(async move {
                let mut conn = h2::server::handshake(server).await.unwrap();
                let mut streams = Vec::new();
                while let Some(Ok(request)) = conn.accept().await {
                    let (request, mut response) = request;
                    let mut stream = response
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    stream
                        .send_data(bytes::Bytes::from_static(b"positive"), false)
                        .unwrap();
                    streams.push((stream, request.into_body()));
                }
            });
            let (mut sender, driver) =
                h2::client::handshake(SourceIo::new(client, Some(captured)).unwrap())
                    .await
                    .unwrap();
            let driver = tokio::spawn(driver);
            let mut body_held = None;
            let mut send_held = None;
            if active {
                let request = http::Request::builder()
                    .method("CONNECT")
                    .uri("10.2.0.10:8080")
                    .body(())
                    .unwrap();
                sender = sender.ready().await.unwrap();
                let (response, send) = sender.send_request(request, false).unwrap();
                let mut body = response.await.unwrap().into_body();
                assert_eq!(
                    body.data().await.unwrap().unwrap(),
                    bytes::Bytes::from_static(b"positive")
                );
                body_held = Some(body);
                send_held = Some(send);
            }
            state
                .state
                .write()
                .unwrap()
                .workloads
                .insert(source.clone());
            let result = tokio::time::timeout(Duration::from_secs(1), driver)
                .await
                .unwrap()
                .unwrap();
            assert!(
                result.is_err(),
                "source invalidation must stop the idle/active H2 transport"
            );
            assert!(sender.ready().await.is_err());
            if let Some(mut body) = body_held {
                assert!(
                    !matches!(body.data().await, Some(Ok(_))),
                    "withdrawn source cannot receive another payload"
                );
            }
            drop(send_held);
            serving.abort();
            let _ = serving.await;
        }
    }
}

#[cfg(test)]
mod interruption_metrics_tests {
    use super::*;
    use prometheus_client::{encoding::text::encode, registry::Registry};
    #[tokio::test]
    async fn native_outbound_source_withdrawal_is_identity_failure_not_policy_deny() {
        let (state, cfg, source, _) = super::tests::fixture();
        let witness = super::tests::witness(&state, &cfg, &source);
        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(crate::metrics::sub_registry(
            &mut registry,
        )));
        let connection = crate::proxy::ConnectionResultBuilder::new(
            "10.1.0.10:12345".parse().unwrap(),
            "10.2.0.10:8080".parse().unwrap(),
            None,
            std::time::Instant::now(),
            crate::proxy::ConnectionOpen {
                reporter: crate::proxy::metrics::Reporter::source,
                source: Some(source.clone()),
                derived_source: None,
                destination: None,
                destination_service: None,
                connection_security_policy: crate::proxy::metrics::SecurityPolicy::mutual_tls,
            },
            metrics,
        )
        .with_native_source(Some(witness))
        .build();
        state.state.write().unwrap().workloads.remove(&source.uid);
        drop(connection);
        let mut text = String::new();
        encode(&mut text, &registry).unwrap();
        let closes = text
            .lines()
            .filter(|line| line.starts_with("istio_tcp_connections_closed_total{"))
            .collect::<Vec<_>>();
        assert_eq!(closes.len(), 1);
        assert!(closes[0].contains("response_flags=\"IDENTITY_ERROR\""));
        assert!(closes[0].ends_with(" 1"));
        assert!(!closes[0].contains("response_flags=\"DENY\""));
    }
    struct InvalidatingRead {
        state: DemandProxyState,
        uid: Strng,
    }
    impl AsyncRead for InvalidatingRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            buf.put_slice(b"buffered");
            self.state
                .state
                .write()
                .unwrap()
                .workloads
                .remove(&self.uid);
            Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn native_outbound_source_post_read_check_erases_new_plaintext() {
        use tokio::io::AsyncReadExt;
        let (state, cfg, source, _) = super::tests::fixture();
        let witness = super::tests::witness(&state, &cfg, &source);
        let io = InvalidatingRead {
            state,
            uid: source.uid.clone(),
        };
        let mut guarded = SourceIo::new(io, Some(witness)).unwrap();
        let mut output = [0u8; 8];
        assert!(guarded.read(&mut output).await.is_err());
        assert_eq!(output, [0; 8]);
    }
}
