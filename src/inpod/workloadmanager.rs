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

use crate::drain::DrainWatcher;
use crate::readiness;
use backoff::{ExponentialBackoff, backoff::Backoff};
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixStream;
use tracing::{debug, error, info, warn};

use super::Error;
use super::statemanager::WorkloadProxyManagerState;

use super::protocol::WorkloadStreamProcessor;

const RETRY_DURATION: Duration = Duration::from_secs(5);

const CONNECTION_FAILURE_RETRY_DELAY_MAX_INTERVAL: Duration = Duration::from_secs(15);

struct WorkloadProxyNetworkHandler {
    uds: PathBuf,
}

struct WorkloadProxyReadinessHandler {
    ready: readiness::Ready,
    // Manually drop as we don't want to mark ready if we are dropped.
    // This can happen when the server drains.
    block_ready: Option<std::mem::ManuallyDrop<readiness::BlockReady>>,
    backoff: ExponentialBackoff,
}

pub struct WorkloadProxyManager {
    state: super::statemanager::WorkloadProxyManagerState,
    networking: WorkloadProxyNetworkHandler,
    // readiness - we are only ready when we are connected. if we get disconnected, we become not ready.
    readiness: WorkloadProxyReadinessHandler,
}

struct WorkloadProxyManagerProcessor<'a> {
    state: &'a mut super::statemanager::WorkloadProxyManagerState,
    readiness: &'a mut WorkloadProxyReadinessHandler,

    next_pending_retry: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

impl WorkloadProxyReadinessHandler {
    fn new(ready: readiness::Ready, reconnect_backoff: Option<ExponentialBackoff>) -> Self {
        let backoff = reconnect_backoff.unwrap_or(ExponentialBackoff {
            initial_interval: Duration::from_millis(5),
            max_interval: CONNECTION_FAILURE_RETRY_DELAY_MAX_INTERVAL,
            multiplier: 2.0,
            randomization_factor: 0.2,
            ..Default::default()
        });

        let mut r = Self {
            ready,
            block_ready: None,
            backoff,
        };
        r.not_ready();
        r
    }
    fn mark_ready(&mut self) {
        // take the block ready out of the ManuallyDrop, and drop it.
        if self.block_ready.is_some() {
            debug!("workload proxy manager is ready");
            let block_ready: Option<readiness::BlockReady> = self
                .block_ready
                .take()
                .map(std::mem::ManuallyDrop::into_inner);

            std::mem::drop(block_ready);
        }

        self.backoff.reset()
    }

    fn not_ready(&mut self) {
        debug!("workload proxy manager is NOT ready");
        if self.block_ready.is_none() {
            self.block_ready = Some(std::mem::ManuallyDrop::new(
                self.ready.register_task("workload proxy manager"),
            ));
        }
    }
}

impl WorkloadProxyNetworkHandler {
    fn new(uds: PathBuf) -> std::io::Result<Self> {
        Ok(Self { uds })
    }

    async fn connect(&self) -> UnixStream {
        let mut backoff = Duration::from_millis(10);

        debug!("connecting to server: {:?}", self.uds);

        loop {
            match super::packet::connect(&self.uds).await {
                Err(e) => {
                    backoff =
                        std::cmp::min(CONNECTION_FAILURE_RETRY_DELAY_MAX_INTERVAL, backoff * 2);
                    warn!(
                        "failed to connect to the Istio CNI node agent over {:?}, is the node agent healthy? details: {:?}. retrying in {:?}",
                        &self.uds, e, backoff
                    );
                    tokio::time::sleep(backoff).await;
                    continue;
                }

                Ok(conn) => {
                    return conn;
                }
            };
        }
    }
}

impl WorkloadProxyManager {
    pub fn verify_syscalls() -> anyhow::Result<()> {
        // verify that we are capable, so we can fail early if not.
        super::netns::InpodNetns::capable()
            .map_err(|e| anyhow::anyhow!("failed to set netns: {:?}", e))?;
        // verify that we can set the socket mark, so we can fail early if not.
        Self::verify_set_mark().map_err(|e| anyhow::anyhow!("failed to set socket mark: {:?}", e))
    }

    fn verify_set_mark() -> anyhow::Result<()> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        crate::socket::set_mark(&socket, 1337).map_err(|e| anyhow::anyhow!("failed to set mark on socket. make sure ztunnel has CAP_NET_RAW, CAP_NET_ADMIN. error: {:?}", e))
    }

    pub fn new(
        uds: PathBuf,
        state: WorkloadProxyManagerState,
        ready: readiness::Ready,
    ) -> std::io::Result<WorkloadProxyManager> {
        let networking = WorkloadProxyNetworkHandler::new(uds)?;

        let mgr = WorkloadProxyManager {
            state,
            networking,
            readiness: WorkloadProxyReadinessHandler::new(ready, None),
        };
        Ok(mgr)
    }

    pub async fn run(mut self, drain: DrainWatcher) -> Result<(), anyhow::Error> {
        self.run_internal(drain).await?;

        // We broke the loop, this can only happen when drain was signaled
        // or we got a terminal protocol error. Drain our proxies.
        debug!("workload proxy manager waiting for proxies to drain");
        self.state.drain().await;
        debug!("workload proxy manager proxies drained");
        Ok(())
    }

    // This func will run and attempt to (re)connect to the node agent over uds, until
    // - a drain is signaled
    // - we have a ProtocolError (we have a serious version mismatch)
    // We should never _have_ a protocol error as the gRPC proto should be forwards+backwards compatible,
    // so this is mostly a safeguard
    async fn run_internal(&mut self, drain: DrainWatcher) -> Result<(), anyhow::Error> {
        // for now just drop block_ready, until we support knowing that our state is in sync.
        debug!("workload proxy manager is running");
        // hold the  release shutdown until we are done with `state.drain` below.

        let _rs = loop {
            // Accept a connection
            let stream = tokio::select! {
                biased; // check the drain first
                rs = drain.clone().wait_for_drain() => {
                    info!("drain requested");
                    break rs;
                }
                res =  self.networking.connect() => res,
            };

            info!("handling new stream");

            // TODO: add metrics?

            let processor = WorkloadStreamProcessor::new(stream, drain.clone());
            let mut processor_helper =
                WorkloadProxyManagerProcessor::new(&mut self.state, &mut self.readiness);
            match processor_helper.process(processor).await {
                Ok(()) => {
                    info!("process stream ended with eof");
                }
                // If we successfully accepted a connection, but the first thing we try (announce)
                // fails, it can mean 2 things:
                // 1. The connection was killed because the node agent happened to restart at a bad time
                // 2. The connection was killed because we have a protocol mismatch with the node agent.
                //
                // For case 1, we must keep retrying. For case 2 we shouldn't retry, as we will spam
                // an incompatible server with messages and connections it can't understand.
                //
                // We also cannot easily tell these cases apart due to the simplistic protocol in use here,
                // so a happy medium is to backoff if we get announce errors - they could be legit or
                // non-legit disconnections, we can't tell.
                Err(Error::AnnounceError(e)) => {
                    self.readiness.not_ready();
                    // This will retry infinitely for as long as the socket doesn't EOF, but not immediately.
                    let wait = self
                        .readiness
                        .backoff
                        .next_backoff()
                        .unwrap_or(CONNECTION_FAILURE_RETRY_DELAY_MAX_INTERVAL);
                    error!("node agent announcement failed ({e}), retrying in {wait:?}");
                    tokio::time::sleep(wait).await;
                    continue;
                }
                Err(Error::ProtocolError(e)) => {
                    error!("protocol mismatch error while processing stream, shutting down");
                    self.readiness.not_ready();
                    return Err(anyhow::anyhow!("protocol error {:?}", e));
                }
                Err(e) => {
                    // for other errors, just retry
                    warn!("process stream ended: {:?}", e);
                }
            };

            self.readiness.not_ready();
        };

        Ok(())
    }
}

impl<'a> WorkloadProxyManagerProcessor<'a> {
    fn new(
        state: &'a mut super::statemanager::WorkloadProxyManagerState,
        readiness: &'a mut WorkloadProxyReadinessHandler,
    ) -> Self {
        state.reset_snapshot();
        Self {
            state,
            readiness,
            next_pending_retry: None,
        }
    }

    async fn read_message_and_retry_proxies(
        &mut self,
        processor: &mut WorkloadStreamProcessor,
    ) -> anyhow::Result<Option<crate::inpod::WorkloadMessage>> {
        let readmsg = processor.read_message();
        // Note: readmsg future is NOT cancel safe, so we want to make sure this function doesn't exit
        // return without completing it.
        futures::pin_mut!(readmsg);
        loop {
            match self.next_pending_retry.take() {
                None => {
                    return readmsg.await;
                }
                Some(timer) => {
                    match futures_util::future::select(timer, readmsg).await {
                        futures_util::future::Either::Left((_, readmsg_fut)) => {
                            self.retry_proxies().await;
                            // we have an uncompleted future. It might be in the middle of recvmsg.
                            // to make sure we don't drop messages, we complete the original
                            // future and not start a new one.
                            readmsg = readmsg_fut;
                        }
                        futures_util::future::Either::Right((res, timer)) => {
                            // we have a message before the timer expired
                            // put the timer back so we will wait for the time remaining next time.
                            self.next_pending_retry = Some(timer);
                            return res;
                        }
                    };
                }
            }
        }
    }

    async fn retry_proxies(&mut self) {
        self.state.retry_pending().await;
        if self.state.have_pending() {
            self.schedule_retry();
        } else {
            self.next_pending_retry.take();
            self.check_ready();
        }
    }

    pub async fn process(&mut self, mut processor: WorkloadStreamProcessor) -> Result<(), Error> {
        processor.set_proxy_epoch(self.state.proxy_epoch());
        processor
            .send_hello()
            .await
            .map_err(|_| Error::AnnounceError("could not announce to node agent".into()))?;

        loop {
            let msg = match self.read_message_and_retry_proxies(&mut processor).await {
                Ok(Some(msg)) => Ok(msg),
                Ok(None) => {
                    return Ok(());
                }
                Err(e) => {
                    error!("failed to read message: {:?}", e);

                    // TODO: make it clear that the error is from reading the message, and not from processing it.
                    //                .map_err(|e| Error::ReceiveMessageError(e.to_string()))?;
                    processor
                        .send_nack(anyhow::anyhow!("failure to read message : {:?}", e))
                        .await
                        .map_err(|e: std::io::Error| Error::SendNackError(e.to_string()))?;
                    Err(Error::ReceiveMessageError(e.to_string()))
                }
            }?;

            debug!("received message: {:?}", msg);

            // A typed drain has a distinct correlated response. Generic ACKs
            // never carry native membership-retirement authority.
            let result = match msg {
                super::WorkloadMessage::Drain(req) => {
                    match self.state.process_bound_drain(req).await {
                        Ok(receipt) => {
                            processor
                                .send_drained(receipt)
                                .await
                                .map_err(|e| Error::SendAckError(e.to_string()))?;
                            continue;
                        }
                        Err(error) => Err(error),
                    }
                }
                super::WorkloadMessage::BoundAdd(data, binding) => {
                    self.state.process_bound_add(data, binding).await
                }
                legacy => self.state.process_msg(legacy).await,
            };
            match result {
                Ok(()) => {
                    self.check_ready();
                    processor
                        .send_ack()
                        .await
                        .map_err(|e| Error::SendAckError(e.to_string()))?;
                }
                Err(Error::ProxyError(uid, e)) => {
                    error!(%uid, "failed to start proxy: {:?}", e);
                    // setup the retry timer:
                    self.schedule_retry();
                    // proxy error is a transient error, so report it but don't disconnect
                    // TODO: raise metrics
                    processor
                        .send_nack(anyhow::anyhow!("failure to start proxy : {:?}", e))
                        .await
                        .map_err(|e| Error::SendNackError(e.to_string()))?;
                }
                Err(e) => {
                    // TODO: raise metrics
                    error!("failed to process message: {:?}", e);
                    processor
                        .send_nack(anyhow::anyhow!("failure to process message : {:?}", e))
                        .await
                        .map_err(|e| Error::SendNackError(e.to_string()))?;
                    // other errors are not recoverable, so exit function the function to re-connect.
                    // also, these errors should never happen, so log/metrics/document them.
                    return Err(e);
                }
            };
        }
    }

    fn schedule_retry(&mut self) {
        if self.next_pending_retry.is_none() {
            info!(uids=?self.state.pending_uids(), "scheduling retry");
            self.next_pending_retry = Some(Box::pin(tokio::time::sleep(RETRY_DURATION)));
        }
    }

    fn check_ready(&mut self) {
        if self.state.ready() {
            self.readiness.mark_ready();
        } else {
            self.readiness.not_ready();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use super::super::protocol::WorkloadStreamProcessor;

    use tokio::io::AsyncWriteExt;

    use super::*;

    use crate::inpod::test_helpers::{
        self, create_proxy_conflict, new_netns, read_hello, read_msg, send_snap_sent,
        send_workload_added, send_workload_del, uid,
    };

    use crate::drain::DrainTrigger;
    use crate::inpod::istio::zds;
    use std::{collections::HashSet, sync::Arc};

    fn assert_end_stream(res: Result<(), Error>) {
        match res {
            Err(Error::ReceiveMessageError(e)) => {
                assert!(e.contains("EOF"));
            }
            Ok(()) => {}
            Err(e) => panic!("expected error due to EOF {e:?}"),
        }
    }

    fn assert_announce_error(res: Result<(), Error>) {
        match res {
            Err(Error::AnnounceError(_)) => {}
            _ => panic!("expected announce error"),
        }
    }

    fn workload_info() -> Option<zds::WorkloadInfo> {
        Some(zds::WorkloadInfo {
            name: "name".to_string(),
            namespace: "ns".to_string(),
            service_account: "sa".to_string(),
        })
    }

    struct Fixture {
        state: WorkloadProxyManagerState,
        inpod_metrics: Arc<crate::inpod::Metrics>,
        drain_rx: DrainWatcher,
        _drain_tx: DrainTrigger,
    }

    macro_rules! fixture {
        () => {{
            if !crate::test_helpers::can_run_privilged_test() {
                eprintln!("This test requires root; skipping");
                return;
            }
            let f = test_helpers::Fixture::default();
            let state = WorkloadProxyManagerState::new(
                f.proxy_factory,
                f.ipc,
                f.inpod_metrics.clone(),
                Default::default(),
            );
            Fixture {
                state,
                inpod_metrics: f.inpod_metrics,
                drain_rx: f.drain_rx,
                _drain_tx: f.drain_tx,
            }
        }};
    }

    #[tokio::test]
    async fn test_process_add() {
        let f = fixture!();
        let (s1, mut s2) = UnixStream::pair().unwrap();
        let processor = WorkloadStreamProcessor::new(s1, f.drain_rx.clone());
        let mut state = f.state;

        let server = tokio::spawn(async move {
            read_hello(&mut s2).await;
            send_workload_added(&mut s2, uid(0), workload_info(), new_netns()).await;
            read_msg(&mut s2).await;
        });

        let mut readiness = WorkloadProxyReadinessHandler::new(readiness::Ready::new(), None);
        let mut processor_helper = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);

        let res = processor_helper.process(processor).await;
        // make sure that the error is due to eof:
        assert_end_stream(res);
        assert!(!readiness.ready.pending().is_empty());
        state.drain().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_process_failed_announce() {
        let f = fixture!();
        let (s1, mut s2) = UnixStream::pair().unwrap();
        let processor = WorkloadStreamProcessor::new(s1, f.drain_rx.clone());
        let mut state = f.state;

        // fake server that simply slams the socket shut and bails
        let server = tokio::spawn(async move {
            let _ = s2.shutdown().await;
        });

        let mut readiness = WorkloadProxyReadinessHandler::new(readiness::Ready::new(), None);
        let mut processor_helper = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);

        let res = processor_helper.process(processor).await;
        // make sure that the error is due to announce fail:
        assert_announce_error(res);
        assert!(!readiness.ready.pending().is_empty());
        state.drain().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_process_failed() {
        let f = fixture!();
        let (s1, mut s2) = UnixStream::pair().unwrap();
        let processor: WorkloadStreamProcessor =
            WorkloadStreamProcessor::new(s1, f.drain_rx.clone());
        let mut state = f.state;

        let podns = new_netns();
        let socket = create_proxy_conflict(&podns);

        let server = tokio::spawn(async move {
            read_hello(&mut s2).await;
            send_workload_added(&mut s2, uid(0), workload_info(), podns).await;
            read_msg(&mut s2).await;
            send_snap_sent(&mut s2).await;
            read_msg(&mut s2).await;
        });

        let mut readiness = WorkloadProxyReadinessHandler::new(readiness::Ready::new(), None);
        let mut processor_helper = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);

        let res = processor_helper.process(processor).await;
        assert_end_stream(res);
        std::mem::drop(socket);
        server.await.unwrap();

        // not ready as we have a failing proxy
        assert!(!processor_helper.readiness.ready.pending().is_empty());
        assert!(processor_helper.next_pending_retry.is_some());

        // now make sure that re-trying works:
        // all should be ready:
        processor_helper.retry_proxies().await;
        assert!(processor_helper.readiness.ready.pending().is_empty());
        assert!(processor_helper.next_pending_retry.is_none());

        state.drain().await;
    }

    #[tokio::test]
    async fn test_process_add_and_del() {
        let f = fixture!();
        let m = f.inpod_metrics;
        let mut state = f.state;
        let (s1, mut s2) = UnixStream::pair().unwrap();
        let processor: WorkloadStreamProcessor =
            WorkloadStreamProcessor::new(s1, f.drain_rx.clone());

        let podns = new_netns();
        let server = tokio::spawn(async move {
            read_hello(&mut s2).await;
            send_workload_added(&mut s2, uid(0), workload_info(), podns).await;
            read_msg(&mut s2).await;
            send_snap_sent(&mut s2).await;
            read_msg(&mut s2).await;
            send_workload_del(&mut s2, uid(0)).await;
            read_msg(&mut s2).await;
        });

        let mut readiness = WorkloadProxyReadinessHandler::new(readiness::Ready::new(), None);
        let mut processor_helper = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);

        let res = processor_helper.process(processor).await;
        server.await.unwrap();
        // make sure that the error is due to eof:
        assert_end_stream(res);

        assert_eq!(state.workload_states().len(), 0);
        assert_eq!(m.active_proxy_count.get(), 0);
        assert!(readiness.ready.pending().is_empty());

        state.drain().await;
    }

    #[tokio::test]
    async fn test_process_snapshot_with_missing_workload() {
        let f = fixture!();
        let m = f.inpod_metrics;
        let (s1, mut s2) = UnixStream::pair().unwrap();
        let processor = WorkloadStreamProcessor::new(s1, f.drain_rx.clone());
        let mut state = f.state;

        let server = tokio::spawn(async move {
            read_hello(&mut s2).await;
            send_workload_added(&mut s2, uid(0), workload_info(), new_netns()).await;
            read_msg(&mut s2).await;
            send_workload_added(&mut s2, uid(1), workload_info(), new_netns()).await;
            read_msg(&mut s2).await;
            send_snap_sent(&mut s2).await;
            read_msg(&mut s2).await;
        });

        let mut readiness = WorkloadProxyReadinessHandler::new(readiness::Ready::new(), None);

        let mut processor_helper = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);
        let res = processor_helper.process(processor).await;

        assert_end_stream(res);
        server.await.unwrap();
        assert!(readiness.ready.pending().is_empty());

        // first proxy should be here:
        assert_eq!(state.workload_states().len(), 2);
        let key_set: HashSet<crate::inpod::WorkloadUid> =
            state.workload_states().keys().cloned().collect();
        let expected_key_set: HashSet<crate::inpod::WorkloadUid> =
            [0, 1].into_iter().map(uid).collect();
        assert_eq!(key_set, expected_key_set);
        assert_eq!(m.active_proxy_count.get(), 2);

        // second connection - don't send the one of the proxies here, to see ztunnel reconciles and removes it:
        let (s1, mut s2) = UnixStream::pair().unwrap();
        let processor = WorkloadStreamProcessor::new(s1, f.drain_rx.clone());

        let server = tokio::spawn(async move {
            read_hello(&mut s2).await;
            send_workload_added(&mut s2, uid(1), workload_info(), new_netns()).await;
            read_msg(&mut s2).await;
            send_snap_sent(&mut s2).await;
            read_msg(&mut s2).await;
        });

        let mut processor_helper = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);
        let res = processor_helper.process(processor).await;

        assert_end_stream(res);
        server.await.unwrap();

        // only second workload should remain
        assert_eq!(state.workload_states().len(), 1);
        assert_eq!(state.workload_states().keys().next(), Some(&uid(1)));
        assert_eq!(m.active_proxy_count.get(), 1);
        assert!(readiness.ready.pending().is_empty());

        state.drain().await;
    }
    fn receipt_packet_pair() -> (UnixStream, UnixStream) {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
        let (a, b) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        (
            UnixStream::from_std(std::os::unix::net::UnixStream::from(a)).unwrap(),
            UnixStream::from_std(std::os::unix::net::UnixStream::from(b)).unwrap(),
        )
    }
    async fn write_native_request(s: &mut UnixStream, payload: zds::workload_request::Payload) {
        use prost::Message;
        let bytes = zds::WorkloadRequest {
            payload: Some(payload),
        }
        .encode_to_vec();
        s.write_all(&bytes).await.unwrap();
    }
    async fn send_bound_add(
        s: &mut UnixStream,
        binding: zds::WorkloadBinding,
        fd: &std::os::fd::OwnedFd,
    ) {
        use prost::Message;
        use std::os::fd::AsRawFd;
        let fds = [fd.as_raw_fd()];
        let rights = [nix::sys::socket::ControlMessage::ScmRights(&fds)];
        let bytes = zds::WorkloadRequest {
            payload: Some(zds::workload_request::Payload::Add(zds::AddWorkload {
                uid: binding.pod_uid.clone(),
                workload_info: workload_info(),
                binding: Some(binding),
            })),
        }
        .encode_to_vec();
        let iov = [std::io::IoSlice::new(&bytes)];
        let count = s
            .async_io(tokio::io::Interest::WRITABLE, || {
                nix::sys::socket::sendmsg::<()>(
                    s.as_raw_fd(),
                    &iov,
                    &rights,
                    nix::sys::socket::MsgFlags::empty(),
                    None,
                )
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
            })
            .await
            .unwrap();
        assert_eq!(count, bytes.len());
    }
    #[tokio::test]
    async fn typed_native_seqpacket_add_wrong_incarnation_nack_and_original_execution_recovery() {
        // This is an explicitly privileged test: lack of the required private
        // Linux netns capability must fail, not count as skipped acceptance.
        assert!(crate::test_helpers::can_run_privilged_test());
        let f = test_helpers::Fixture::default();
        let mut state = WorkloadProxyManagerState::new(
            f.proxy_factory,
            f.ipc,
            f.inpod_metrics,
            Default::default(),
        );
        let epoch = state.proxy_epoch();
        let fd = new_netns();
        let stat = nix::sys::stat::fstat(&fd).unwrap();
        let binding = zds::WorkloadBinding {
            version: 1,
            source_epoch: "source-execution".into(),
            cluster_id: 1,
            namespace_uid: "namespace-uid".into(),
            pod_uid: "pod-uid".into(),
            endpoint_id: 17,
            incarnation: 1,
            capture_generation: 7,
            netns_dev: stat.st_dev,
            netns_ino: stat.st_ino,
            proxy_epoch: epoch.to_vec(),
        };
        let (a, mut b) = receipt_packet_pair();
        let original = binding.clone();
        let peer = tokio::spawn(async move {
            let hello = read_hello(&mut b).await;
            assert_eq!(hello.version, zds::Version::V2Drain as i32);
            assert_eq!(hello.proxy_epoch, epoch);
            send_bound_add(&mut b, original.clone(), &fd).await;
            assert!(
                matches!(read_msg(&mut b).await.payload,Some(zds::workload_response::Payload::Ack(a)) if a.error.is_empty())
            );
            // A wrong incarnation must NACK without stopping the live original.
            let mut bad = original;
            bad.incarnation += 1;
            write_native_request(
                &mut b,
                zds::workload_request::Payload::Drain(zds::DrainWorkload {
                    binding: Some(bad),
                    drain_generation: 9,
                    nonce: vec![4; 32],
                }),
            )
            .await;
            let reply = read_msg(&mut b).await;
            assert!(
                matches!(reply.payload,Some(zds::workload_response::Payload::Ack(a)) if !a.error.is_empty())
            );
        });
        let mut readiness = WorkloadProxyReadinessHandler::new(readiness::Ready::new(), None);
        let mut dispatch = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);
        assert!(
            dispatch
                .process(WorkloadStreamProcessor::new(a, f.drain_rx.clone()))
                .await
                .is_err()
        );
        peer.await.unwrap();
        assert_eq!(state.workload_states().len(), 1);

        // Add a real held socket to the actual native owner's retained task set.
        // The typed wire dispatcher must not reply until that socket task joins.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut socket_peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (owned_socket, _) = listener.accept().await.unwrap();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        state.append_owned_receipt_test_task(
            &super::super::WorkloadUid::new(binding.pod_uid.clone()),
            tokio::spawn(async move {
                release_rx.await.unwrap();
                drop(owned_socket);
                Ok(())
            }),
        );
        // Reconnect the SAME proxy execution. It retains original ADD ownership.
        let (a, mut b) = receipt_packet_pair();
        let original = binding.clone();
        let peer = tokio::spawn(async move {
            assert_eq!(read_hello(&mut b).await.proxy_epoch, epoch);
            let req = zds::DrainWorkload {
                binding: Some(original),
                drain_generation: 9,
                nonce: vec![5; 32],
            };
            write_native_request(&mut b, zds::workload_request::Payload::Drain(req.clone())).await;
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(30), read_msg(&mut b))
                    .await
                    .is_err(),
                "native receipt escaped before actual owned socket task joined"
            );
            let mut byte = [0];
            assert!(
                matches!(socket_peer.try_read(&mut byte),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock)
            );
            release_tx.send(()).unwrap();
            use tokio::io::AsyncReadExt;
            assert_eq!(socket_peer.read(&mut byte).await.unwrap(), 0);
            let reply = read_msg(&mut b).await;
            match reply.payload.unwrap() {
                zds::workload_response::Payload::Drained(got) => {
                    assert_eq!(got.binding, req.binding);
                    assert_eq!(got.drain_generation, 9);
                    assert_eq!(got.nonce, req.nonce);
                }
                _ => panic!("generic ACK cannot qualify drain"),
            }
        });
        let mut dispatch = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);
        assert_end_stream(
            dispatch
                .process(WorkloadStreamProcessor::new(a, f.drain_rx.clone()))
                .await,
        );
        peer.await.unwrap();
        assert!(state.workload_states().is_empty());
        state.drain().await;
    }
    #[tokio::test]
    async fn typed_native_ack_loss_refreshes_same_owner_and_rejects_old_capture_generation() {
        assert!(crate::test_helpers::can_run_privilged_test());
        let f = test_helpers::Fixture::default();
        let mut state = WorkloadProxyManagerState::new(
            f.proxy_factory,
            f.ipc,
            f.inpod_metrics,
            Default::default(),
        );
        let epoch = state.proxy_epoch();
        let fd = new_netns();
        let stat = nix::sys::stat::fstat(&fd).unwrap();
        let original = zds::WorkloadBinding {
            version: 1,
            source_epoch: "ack-loss-source".into(),
            cluster_id: 1,
            namespace_uid: "namespace-uid".into(),
            pod_uid: "ack-loss-pod".into(),
            endpoint_id: 18,
            incarnation: 1,
            capture_generation: 7,
            netns_dev: stat.st_dev,
            netns_ino: stat.st_ino,
            proxy_epoch: epoch.to_vec(),
        };
        let (a, mut b) = receipt_packet_pair();
        let first = original.clone();
        let first_fd = fd.try_clone().unwrap();
        let peer = tokio::spawn(async move {
            assert_eq!(read_hello(&mut b).await.proxy_epoch, epoch);
            send_bound_add(&mut b, first, &first_fd).await;
            // The kernel queued a real ADD+FD, but the source loses the stream
            // without observing the ACK. Original native task ownership remains.
            drop(b);
        });
        let mut readiness = WorkloadProxyReadinessHandler::new(readiness::Ready::new(), None);
        let mut dispatch = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);
        let result = dispatch
            .process(WorkloadStreamProcessor::new(a, f.drain_rx.clone()))
            .await;
        assert!(matches!(result, Ok(()) | Err(Error::SendAckError(_))));
        peer.await.unwrap();
        assert_eq!(state.workload_states().len(), 1);
        // The source performs fresh API/sandbox checks and a new capture
        // generation; the SAME proxy execution refreshes its original owner.
        let mut fresh = original.clone();
        fresh.capture_generation += 1;
        let (a, mut b) = receipt_packet_pair();
        let next = fresh.clone();
        let peer = tokio::spawn(async move {
            assert_eq!(read_hello(&mut b).await.proxy_epoch, epoch);
            send_bound_add(&mut b, next, &fd).await;
            assert!(
                matches!(read_msg(&mut b).await.payload,Some(zds::workload_response::Payload::Ack(a)) if a.error.is_empty())
            );
            write_native_request(
                &mut b,
                zds::workload_request::Payload::Drain(zds::DrainWorkload {
                    binding: Some(original),
                    drain_generation: 10,
                    nonce: vec![6; 32],
                }),
            )
            .await;
            assert!(
                matches!(read_msg(&mut b).await.payload,Some(zds::workload_response::Payload::Ack(a)) if !a.error.is_empty())
            );
        });
        let mut dispatch = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);
        assert!(matches!(
            dispatch
                .process(WorkloadStreamProcessor::new(a, f.drain_rx.clone()))
                .await,
            Err(Error::DrainRequestError(_))
        ));
        peer.await.unwrap();
        assert_eq!(state.workload_states().len(), 1);
        let (a, mut b) = receipt_packet_pair();
        let peer = tokio::spawn(async move {
            assert_eq!(read_hello(&mut b).await.proxy_epoch, epoch);
            let req = zds::DrainWorkload {
                binding: Some(fresh),
                drain_generation: 10,
                nonce: vec![7; 32],
            };
            write_native_request(&mut b, zds::workload_request::Payload::Drain(req.clone())).await;
            match read_msg(&mut b).await.payload.unwrap() {
                zds::workload_response::Payload::Drained(got) => {
                    assert_eq!(got.binding, req.binding);
                    assert_eq!(got.nonce, req.nonce);
                    assert_eq!(got.drain_generation, 10);
                }
                _ => panic!("native typed receipt required"),
            }
        });
        let mut dispatch = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);
        assert_end_stream(
            dispatch
                .process(WorkloadStreamProcessor::new(a, f.drain_rx.clone()))
                .await,
        );
        peer.await.unwrap();
        assert!(state.workload_states().is_empty());
        state.drain().await;
    }

    #[tokio::test]
    async fn typed_native_unknown_or_restarted_execution_never_returns_empty_drain_receipt() {
        assert!(crate::test_helpers::can_run_privilged_test());
        let f = test_helpers::Fixture::default();
        let mut state = WorkloadProxyManagerState::new(
            f.proxy_factory,
            f.ipc,
            f.inpod_metrics,
            Default::default(),
        );
        let epoch = state.proxy_epoch();
        let mut readiness = WorkloadProxyReadinessHandler::new(readiness::Ready::new(), None);
        for stale_execution in [true, false] {
            let (a, mut b) = receipt_packet_pair();
            let peer = tokio::spawn(async move {
                assert_eq!(read_hello(&mut b).await.proxy_epoch, epoch);
                let mut presented_epoch = epoch;
                if stale_execution {
                    presented_epoch[0] ^= 1;
                }
                let binding = zds::WorkloadBinding {
                    version: 1,
                    source_epoch: "old-source".into(),
                    cluster_id: 1,
                    namespace_uid: "namespace-uid".into(),
                    pod_uid: "old-pod".into(),
                    endpoint_id: 19,
                    incarnation: 1,
                    capture_generation: 7,
                    netns_dev: 1,
                    netns_ino: 2,
                    proxy_epoch: presented_epoch.to_vec(),
                };
                write_native_request(
                    &mut b,
                    zds::workload_request::Payload::Drain(zds::DrainWorkload {
                        binding: Some(binding),
                        drain_generation: 11,
                        nonce: vec![9; 32],
                    }),
                )
                .await;
                let reply = read_msg(&mut b).await;
                match reply.payload.unwrap() {
                    zds::workload_response::Payload::Ack(nack) => {
                        assert!(nack.error.contains(if stale_execution {
                            "proxy execution"
                        } else {
                            "no such ADD owner"
                        }))
                    }
                    _ => panic!("unknown/restarted owner must NACK, never claim an empty drain"),
                }
            });
            let mut dispatch = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);
            assert!(matches!(
                dispatch
                    .process(WorkloadStreamProcessor::new(a, f.drain_rx.clone()))
                    .await,
                Err(Error::DrainRequestError(_))
            ));
            peer.await.unwrap();
            assert!(state.workload_states().is_empty());
        }
        state.drain().await;
    }
    /// The order after an agent restart: a new source connects, its snapshot
    /// omits a bound workload (the agent re-admits it later), and this proxy
    /// stops that workload before acknowledging the snapshot. That stop is the
    /// owner's drain, so the new source's ADD for the same sandbox is accepted,
    /// while the drained incarnation itself can never be installed again.
    #[tokio::test]
    async fn typed_native_snapshot_omission_drains_owner_for_a_new_source() {
        assert!(crate::test_helpers::can_run_privilged_test());
        let f = test_helpers::Fixture::default();
        let state = WorkloadProxyManagerState::new(
            f.proxy_factory,
            f.ipc,
            f.inpod_metrics,
            Default::default(),
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snapshot-drain.sock");
        let listener = crate::inpod::packet::bind(&path).unwrap();
        let (stop, watch) = crate::drain::new();
        let manager = WorkloadProxyManager::new(path, state, readiness::Ready::new()).unwrap();
        let running = tokio::spawn(manager.run(watch));
        let accept = || async {
            tokio::time::timeout(std::time::Duration::from_secs(3), listener.accept())
                .await
                .unwrap()
                .unwrap()
                .0
        };
        let acked = |response: zds::WorkloadResponse| matches!(response.payload, Some(zds::workload_response::Payload::Ack(a)) if a.error.is_empty());
        let refused = |response: zds::WorkloadResponse, reason: &str| matches!(response.payload, Some(zds::workload_response::Payload::Ack(a)) if a.error.contains(reason));

        let mut peer = accept().await;
        let hello = read_hello(&mut peer).await;
        let fd = new_netns();
        let stat = nix::sys::stat::fstat(&fd).unwrap();
        let original = zds::WorkloadBinding {
            version: 1,
            source_epoch: "agent-before-restart".into(),
            cluster_id: 1,
            namespace_uid: "namespace-uid".into(),
            pod_uid: "restored-pod".into(),
            endpoint_id: 21,
            incarnation: 1,
            capture_generation: 3,
            netns_dev: stat.st_dev,
            netns_ino: stat.st_ino,
            proxy_epoch: hello.proxy_epoch.clone(),
        };
        send_bound_add(&mut peer, original.clone(), &fd).await;
        assert!(acked(read_msg(&mut peer).await));
        send_snap_sent(&mut peer).await;
        assert!(acked(read_msg(&mut peer).await));
        drop(peer);

        // The restarted agent: same proxy execution, a snapshot without the Pod.
        let mut peer = accept().await;
        assert_eq!(read_hello(&mut peer).await.proxy_epoch, hello.proxy_epoch);
        send_snap_sent(&mut peer).await;
        assert!(
            acked(read_msg(&mut peer).await),
            "the snapshot ACK follows the omitted proxy's stop"
        );

        send_bound_add(&mut peer, original.clone(), &fd).await;
        assert!(
            refused(
                read_msg(&mut peer).await,
                "completed incarnation cannot be revived"
            ),
            "the drained incarnation itself is never installed again"
        );
        drop(peer);

        let mut peer = accept().await;
        assert_eq!(read_hello(&mut peer).await.proxy_epoch, hello.proxy_epoch);
        let readmitted = zds::WorkloadBinding {
            source_epoch: "agent-after-restart".into(),
            capture_generation: 1,
            ..original.clone()
        };
        send_bound_add(&mut peer, readmitted, &fd).await;
        assert!(
            acked(read_msg(&mut peer).await),
            "the new source re-admits the same sandbox without a drain it cannot produce"
        );
        drop(peer);
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stop.start_drain_and_wait(crate::drain::DrainMode::Immediate),
        )
        .await
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn typed_native_outer_manager_preserves_owner_through_request_rejection_and_reconnect() {
        assert!(crate::test_helpers::can_run_privilged_test());
        let f = test_helpers::Fixture::default();
        let state = WorkloadProxyManagerState::new(
            f.proxy_factory,
            f.ipc,
            f.inpod_metrics,
            Default::default(),
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("native-drain.sock");
        let listener = crate::inpod::packet::bind(&path).unwrap();
        let (stop, watch) = crate::drain::new();
        let manager = WorkloadProxyManager::new(path, state, readiness::Ready::new()).unwrap();
        let running = tokio::spawn(manager.run(watch));
        let (mut peer, _) =
            tokio::time::timeout(std::time::Duration::from_secs(3), listener.accept())
                .await
                .unwrap()
                .unwrap();
        let hello = read_hello(&mut peer).await;
        assert_eq!(hello.version, zds::Version::V2Drain as i32);
        assert_eq!(hello.proxy_epoch.len(), 32);
        let fd = new_netns();
        let stat = nix::sys::stat::fstat(&fd).unwrap();
        let binding = zds::WorkloadBinding {
            version: 1,
            source_epoch: "outer-manager-source".into(),
            cluster_id: 1,
            namespace_uid: "namespace-uid".into(),
            pod_uid: "outer-manager-pod".into(),
            endpoint_id: 20,
            incarnation: 1,
            capture_generation: 7,
            netns_dev: stat.st_dev,
            netns_ino: stat.st_ino,
            proxy_epoch: hello.proxy_epoch.clone(),
        };
        send_bound_add(&mut peer, binding.clone(), &fd).await;
        assert!(
            matches!(read_msg(&mut peer).await.payload,Some(zds::workload_response::Payload::Ack(a)) if a.error.is_empty())
        );
        send_snap_sent(&mut peer).await;
        assert!(
            matches!(read_msg(&mut peer).await.payload,Some(zds::workload_response::Payload::Ack(a)) if a.error.is_empty())
        );
        let mut wrong = binding.clone();
        wrong.namespace_uid = "replacement-namespace".into();
        write_native_request(
            &mut peer,
            zds::workload_request::Payload::Drain(zds::DrainWorkload {
                binding: Some(wrong),
                drain_generation: 12,
                nonce: vec![10; 32],
            }),
        )
        .await;
        assert!(
            matches!(read_msg(&mut peer).await.payload,Some(zds::workload_response::Payload::Ack(a)) if !a.error.is_empty())
        );
        drop(peer);
        // This goes through run_internal, not a manually constructed second
        // processor. A fatal ProtocolError would end the real manager here.
        let (mut peer, _) =
            tokio::time::timeout(std::time::Duration::from_secs(3), listener.accept())
                .await
                .unwrap()
                .unwrap();
        let renewed = read_hello(&mut peer).await;
        assert_eq!(renewed.proxy_epoch, hello.proxy_epoch);
        assert!(!running.is_finished());
        // Resetting snapshot readiness must retain the original immutable owner.
        // First reject an unacknowledged same-UID/new-sandbox replacement.
        let another_fd = new_netns();
        let another = nix::sys::stat::fstat(&another_fd).unwrap();
        let mut replacement = binding.clone();
        replacement.netns_dev = another.st_dev;
        replacement.netns_ino = another.st_ino;
        replacement.incarnation += 1;
        send_bound_add(&mut peer, replacement, &another_fd).await;
        assert!(
            matches!(read_msg(&mut peer).await.payload,Some(zds::workload_response::Payload::Ack(a)) if !a.error.is_empty())
        );
        drop(peer);
        let (mut peer, _) =
            tokio::time::timeout(std::time::Duration::from_secs(3), listener.accept())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(read_hello(&mut peer).await.proxy_epoch, hello.proxy_epoch);
        let req = zds::DrainWorkload {
            binding: Some(binding),
            drain_generation: 12,
            nonce: vec![11; 32],
        };
        write_native_request(
            &mut peer,
            zds::workload_request::Payload::Drain(req.clone()),
        )
        .await;
        let response = tokio::time::timeout(std::time::Duration::from_secs(3), read_msg(&mut peer))
            .await
            .unwrap();
        match response.payload.unwrap() {
            zds::workload_response::Payload::Drained(receipt) => {
                assert_eq!(receipt.binding, req.binding);
                assert_eq!(receipt.drain_generation, req.drain_generation);
                assert_eq!(receipt.nonce, req.nonce);
            }
            _ => panic!("only an exact original-owner drain receipt qualifies"),
        }
        drop(peer);
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stop.start_drain_and_wait(crate::drain::DrainMode::Immediate),
        )
        .await
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
