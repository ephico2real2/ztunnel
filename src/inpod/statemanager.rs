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

use crate::drain;
use crate::drain::DrainTrigger;
use futures::FutureExt;
use std::sync::Arc;
use tracing::{Instrument, debug, info};

use super::{Error, WorkloadMessage, metrics::Metrics};

use crate::proxyfactory::ProxyFactory;
use crate::state::WorkloadInfo;

use super::config::InPodConfig;

use super::WorkloadUid;
use super::netns::{InpodNetns, NetnsID};

// Note: we can't drain on drop, as drain is async (it waits for the drain to finish).
pub(super) struct WorkloadState {
    drain: DrainTrigger,
    netns_id: NetnsID,
    tasks: Vec<tokio::task::JoinHandle<Result<(), crate::proxy::Error>>>,
    connections: Option<crate::proxy::connection_manager::ConnectionManager>,
}

type DrainCompletion =
    futures::future::Shared<futures::future::BoxFuture<'static, Result<(), Arc<str>>>>;

#[derive(Default)]
struct DrainingTasks {
    draining: Vec<(WorkloadUid, DrainCompletion)>,
}

impl DrainingTasks {
    fn shutdown_workload(&mut self, uid: WorkloadUid, workload: WorkloadState) {
        self.shutdown_workload_with_mode(uid, workload, drain::DrainMode::Immediate)
    }
    fn shutdown_workload_with_mode(
        &mut self,
        uid: WorkloadUid,
        workload: WorkloadState,
        mode: drain::DrainMode,
    ) {
        // The task owns the stop signal and actual JoinHandles even if the
        // caller or its ZDS connection is canceled while awaiting this barrier.
        let task = tokio::spawn(async move {
            let (_, results) = tokio::join!(
                workload.drain.start_drain_and_wait(mode),
                futures::future::join_all(workload.tasks),
            );
            for result in results {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => return Err(Arc::<str>::from(error.to_string())),
                    Err(error) => return Err(Arc::<str>::from(error.to_string())),
                }
            }
            if workload
                .connections
                .as_ref()
                .is_some_and(|connections| !connections.is_empty())
            {
                return Err(Arc::<str>::from(
                    "owned connection registry is not empty after task shutdown",
                ));
            }
            Ok(())
        });
        let completion = async move {
            match task.await {
                Ok(result) => result,
                Err(error) => Err(Arc::<str>::from(error.to_string())),
            }
        }
        .boxed()
        .shared();
        // Completed successes require no further ownership. Keep failures so
        // retrying an unknown UID cannot manufacture a successful drain.
        self.draining
            .retain(|(_, completion)| !matches!(completion.clone().now_or_never(), Some(Ok(()))));
        self.draining.push((uid, completion));
    }
    async fn wait_workload(&self, uid: &WorkloadUid) -> Result<(), Error> {
        let pending = self
            .draining
            .iter()
            .filter(|(owner, _)| owner == uid)
            .map(|(_, future)| future.clone());
        for result in futures::future::join_all(pending).await {
            result
                .map_err(|error| Error::ProtocolError(format!("workload drain failed: {error}")))?;
        }
        Ok(())
    }
    async fn join(self) -> Result<(), Error> {
        for result in
            futures::future::join_all(self.draining.into_iter().map(|(_, future)| future)).await
        {
            result
                .map_err(|error| Error::ProtocolError(format!("workload drain failed: {error}")))?;
        }
        Ok(())
    }
}

pub struct WorkloadProxyManagerState {
    proxy_gen: ProxyFactory,
    owners: super::drain_receipt::DrainOwners,
    proxy_epoch: [u8; 32],
    metrics: Arc<Metrics>,
    admin_handler: Arc<super::admin::WorkloadManagerAdminHandler>,
    // use hashbrown for extract_if
    workload_states: hashbrown::HashMap<WorkloadUid, WorkloadState>,

    // workloads we wanted to start but couldn't because we had an error starting them.
    // This happened to use mainly in testing when we redeploy ztunnel, and the old pod was
    // not completely drained yet.
    pending_workloads: hashbrown::HashMap<WorkloadUid, (WorkloadInfo, InpodNetns)>,
    draining: DrainingTasks,

    // new connection stuff
    snapshot_received: bool,
    snapshot_names: std::collections::HashSet<WorkloadUid>,

    inpod_config: InPodConfig,
}

impl WorkloadProxyManagerState {
    pub fn new(
        proxy_gen: ProxyFactory,
        inpod_config: InPodConfig,
        metrics: Arc<Metrics>,
        admin_handler: Arc<super::admin::WorkloadManagerAdminHandler>,
    ) -> Self {
        WorkloadProxyManagerState {
            proxy_gen,
            owners: Default::default(),
            proxy_epoch: rand::random(),
            metrics,
            admin_handler,
            workload_states: Default::default(),
            pending_workloads: Default::default(),
            draining: Default::default(),

            snapshot_received: false,
            snapshot_names: Default::default(),
            inpod_config,
        }
    }

    #[cfg(test)] // only used in tests, so added this to avoid warning
    pub(super) fn workload_states(&self) -> &hashbrown::HashMap<WorkloadUid, WorkloadState> {
        &self.workload_states
    }

    // Call this on new connection
    pub fn reset_snapshot(&mut self) {
        self.snapshot_names.clear();
        self.pending_workloads.clear();
        self.snapshot_received = false;
    }

    pub async fn process_msg(&mut self, msg: WorkloadMessage) -> Result<(), Error> {
        match msg {
            WorkloadMessage::AddWorkload(poddata) => {
                if self.owners.contains(&poddata.workload_uid) {
                    return Err(Error::DrainRequestError(
                        "unbound ADD cannot replace an original bound owner".into(),
                    ));
                }
                self.process_add(poddata).await
            }
            WorkloadMessage::BoundAdd(_, _) | WorkloadMessage::Drain(_) => Err(
                Error::ProtocolError("typed request requires native receipt dispatcher".into()),
            ),
            WorkloadMessage::KeepWorkload(workload_uid) => {
                if self.owners.contains(&workload_uid) {
                    return Err(Error::DrainRequestError(
                        "KEEP cannot validate an original bound sandbox".into(),
                    ));
                }
                info!(
                    uid = workload_uid.0,
                    "pod keep received. will not delete it when snapshot is sent"
                );
                if self.snapshot_received {
                    // this can only happen before snapshot is received.
                    return Err(Error::ProtocolError(
                        "pod keep received after snapshot".into(),
                    ));
                }
                self.snapshot_names.insert(workload_uid);
                Ok(())
            }
            WorkloadMessage::DelWorkload(workload_uid) => {
                if self.owners.contains(&workload_uid) {
                    return Err(Error::DrainRequestError(
                        "bound owner requires typed workload drain".into(),
                    ));
                }
                info!(
                    uid = workload_uid.0,
                    "pod delete request, shutting down proxy"
                );
                self.snapshot_names.remove(&workload_uid);
                self.del_workload(&workload_uid).await
            }

            WorkloadMessage::WorkloadSnapshotSent => {
                info!("received snapshot sent");
                if self.snapshot_received {
                    return Err(Error::ProtocolError("pod snapshot received already".into()));
                }
                self.reconcile().await?;
                // mark ready
                self.snapshot_received = true;
                Ok(())
            }
        }
    }

    pub(super) fn proxy_epoch(&self) -> [u8; 32] {
        self.proxy_epoch
    }
    #[cfg(test)]
    pub(super) fn append_owned_receipt_test_task(
        &mut self,
        uid: &WorkloadUid,
        task: tokio::task::JoinHandle<Result<(), crate::proxy::Error>>,
    ) {
        self.workload_states
            .get_mut(uid)
            .expect("real bound ADD must have started native proxy")
            .tasks
            .push(task);
    }

    async fn process_add(&mut self, poddata: super::WorkloadData) -> Result<(), Error> {
        info!(
            uid = poddata.workload_uid.0,
            name = poddata
                .workload_info
                .as_ref()
                .map(|w| w.name.as_str())
                .unwrap_or_default(),
            namespace = poddata
                .workload_info
                .as_ref()
                .map(|w| w.namespace.as_str())
                .unwrap_or_default(),
            "pod received, starting proxy",
        );
        let Some(wli) = poddata.workload_info else {
            return Err(Error::ProtocolError(
                "workload_info is required but not present".into(),
            ));
        };
        if !self.snapshot_received {
            debug!("got workload add before snapshot");
            self.snapshot_names.insert(poddata.workload_uid.clone());
        }
        let netns = InpodNetns::new(self.inpod_config.cur_netns(), poddata.netns).map_err(|e| {
            Error::ProxyError(poddata.workload_uid.0.clone(), crate::proxy::Error::Io(e))
        })?;
        let info = WorkloadInfo {
            name: wli.name,
            namespace: wli.namespace,
            service_account: wli.service_account,
        };
        self.add_workload(&poddata.workload_uid, info, netns)
            .await
            .map_err(|e| Error::ProxyError(poddata.workload_uid.0, e))
    }
    pub(super) async fn process_bound_add(
        &mut self,
        data: super::WorkloadData,
        binding: super::istio::zds::WorkloadBinding,
    ) -> Result<(), Error> {
        use std::os::fd::AsFd;
        let st = nix::sys::stat::fstat(data.netns.as_fd())
            .map_err(|e| Error::DrainRequestError(e.to_string()))?;
        super::drain_receipt::validate_binding(
            &binding,
            &self.proxy_epoch,
            &data.workload_uid,
            NetnsID {
                dev: st.st_dev,
                inode: st.st_ino,
            },
        )
        .map_err(|e| Error::DrainRequestError(e.to_string()))?;
        self.owners
            .check_add(&data.workload_uid, &binding)
            .map_err(|e| Error::DrainRequestError(e.to_string()))?;
        let uid = data.workload_uid.clone();
        let result = self.process_add(data).await;
        if result.is_ok() {
            self.owners.installed(uid, binding);
        } else {
            // A failed bound ADD is retried by the native source with a fresh
            // checked FD. The legacy retry loop must not start an unbound proxy.
            self.pending_workloads.remove(&uid);
        }
        result
    }
    pub(super) async fn process_bound_drain(
        &mut self,
        req: super::istio::zds::DrainWorkload,
    ) -> Result<super::istio::zds::WorkloadDrained, Error> {
        let uid = self
            .owners
            .begin(&req, &self.proxy_epoch)
            .map_err(|e| Error::DrainRequestError(e.to_string()))?;
        self.snapshot_names.remove(&uid);
        // This awaits the actual retained proxy/DNS task, all socket/stream
        // lifetimes and pool drivers, and verifies empty owned registries.
        self.del_workload(&uid)
            .await
            .map_err(|e| Error::DrainRequestError(e.to_string()))?;
        self.owners
            .complete(&req)
            .map_err(|e| Error::DrainRequestError(e.to_string()))
    }

    // reconcile existing state to snaphsot. drains any workloads not in the snapshot
    // this can happen if workloads were removed while we were disconnected.
    async fn reconcile(&mut self) -> Result<(), Error> {
        for (uid, workload_state) in self
            .workload_states
            .extract_if(|uid, _| !self.snapshot_names.contains(uid))
        {
            self.draining.shutdown_workload(uid, workload_state);
        }
        self.snapshot_names.clear();
        self.update_proxy_count_metrics();
        // A snapshot ACK also requires removed workloads to be fully stopped.
        for result in futures::future::join_all(
            self.draining
                .draining
                .iter()
                .map(|(_, future)| future.clone()),
        )
        .await
        {
            result
                .map_err(|error| Error::ProtocolError(format!("snapshot drain failed: {error}")))?;
        }
        Ok(())
    }

    pub async fn drain(mut self) {
        for (uid, workload) in self.workload_states.drain() {
            self.draining
                .shutdown_workload_with_mode(uid, workload, drain::DrainMode::Graceful);
        }
        if let Err(error) = self.draining.join().await {
            tracing::error!(%error,"workload shutdown barrier failed");
        }
    }

    async fn add_workload(
        &mut self,
        workload_uid: &WorkloadUid,
        workload_info: WorkloadInfo,
        netns: InpodNetns,
    ) -> Result<(), crate::proxy::Error> {
        match self
            .add_workload_inner(workload_uid, &workload_info, netns.clone())
            .await
        {
            Ok(()) => {
                // If the workload is already pending, make sure we drop it, so we don't retry.
                self.pending_workloads.remove(workload_uid);
                self.update_proxy_count_metrics();
                Ok(())
            }
            Err(e) => {
                self.pending_workloads
                    .insert(workload_uid.clone(), (workload_info, netns));
                self.update_proxy_count_metrics();
                Err(e)
            }
        }
    }
    async fn add_workload_inner(
        &mut self,
        workload_uid: &WorkloadUid,
        workload_info: &WorkloadInfo,
        netns: InpodNetns,
    ) -> Result<(), crate::proxy::Error> {
        self.draining
            .wait_workload(workload_uid)
            .await
            .map_err(|error| crate::proxy::Error::Anyhow(error.into()))?;
        // check if we have a proxy already
        let maybe_existing = self.workload_states.get(workload_uid);
        if let Some(existing) = maybe_existing {
            if existing.netns_id != netns.workload_netns_id() {
                // inodes are different, we have a new netns.
                // this can happen when there's a CNI failure (that's unrelated to us) which triggers
                // pod sandobx to be re-created with a fresh new netns.
                // drain the old proxy and add this one.
                self.del_workload(workload_uid)
                    .await
                    .map_err(|error| crate::proxy::Error::Anyhow(error.into()))?;
            } else {
                // idempotency - no error if we already have a proxy for the workload
                // check if the inodes match. if they don't, we have a new netns
                // we need to drain the previous proxy and add this one.
                return Ok(());
            }
        }
        self.admin_handler
            .proxy_pending(workload_uid, workload_info);

        let workload_netns_id = netns.workload_netns_id();

        debug!(
            workload=?workload_uid,
            workload_info=?workload_info,
            netns_id=?workload_netns_id,
            "starting proxy",
        );

        // We create a per workload drain here. If the main loop in WorkloadProxyManager::run drains,
        // we drain all these per-workload drains before exiting the loop
        let (drain_tx, drain_rx) = drain::new();

        let proxies = self
            .proxy_gen
            .new_proxies_from_factory(
                Some(drain_rx),
                workload_info.clone(),
                Arc::from(self.inpod_config.socket_factory(netns)),
            )
            .await?;

        let uid = workload_uid.clone();

        let connections = proxies.connection_manager.clone();
        self.admin_handler
            .proxy_up(&uid, workload_info, proxies.connection_manager);

        let metrics = self.metrics.clone();
        let admin_handler = self.admin_handler.clone();

        metrics.proxies_started.inc();
        let mut tasks = Vec::new();
        if let Some(proxy) = proxies.proxy {
            tasks.push(tokio::spawn(
                async move {
                    let result=proxy.run_checked().await;
                    debug!("proxy for workload {:?} exited", uid);
                    metrics.proxies_stopped.inc();
                    admin_handler.proxy_down(&uid);
                    result
                }
                .instrument(tracing::info_span!("proxy", wl=%format!("{}/{}", workload_info.namespace, workload_info.name))),
            ));
        }
        if let Some(proxy) = proxies.dns_proxy {
            tasks.push(tokio::spawn(async move{proxy.run().await;Ok(())}.instrument(tracing::info_span!("dns_proxy", wl=%format!("{}/{}", workload_info.namespace, workload_info.name)))));
        }

        self.workload_states.insert(
            workload_uid.clone(),
            WorkloadState {
                drain: drain_tx,
                netns_id: workload_netns_id,
                tasks,
                connections,
            },
        );

        Ok(())
    }

    pub fn have_pending(&self) -> bool {
        !self.pending_workloads.is_empty()
    }

    pub fn pending_uids(&self) -> Vec<String> {
        self.pending_workloads.keys().map(|k| k.0.clone()).collect()
    }

    pub fn ready(&self) -> bool {
        // We are ready after we received our first snapshot and don't have any proxies that failed to start.
        self.snapshot_received && !self.have_pending()
    }

    pub async fn retry_pending(&mut self) {
        let current_pending_workloads = std::mem::take(&mut self.pending_workloads);

        for (uid, (info, netns)) in current_pending_workloads {
            info!(uid = uid.0, "retrying workload");
            match self.add_workload(&uid, info, netns).await {
                Ok(()) => {}
                Err(e) => {
                    info!(uid = uid.0, "retrying workload failed: {}", e);
                }
            }
        }
    }

    async fn del_workload(&mut self, workload_uid: &WorkloadUid) -> Result<(), Error> {
        self.pending_workloads.remove(workload_uid);
        if let Some(workload) = self.workload_states.remove(workload_uid) {
            self.draining
                .shutdown_workload(workload_uid.clone(), workload);
            self.update_proxy_count_metrics();
        }
        // A retry must wait for a prior canceled delete's retained task too.
        self.draining.wait_workload(workload_uid).await
    }

    fn update_proxy_count_metrics(&self) {
        self.metrics
            .active_proxy_count
            .set(self.workload_states.len().try_into().unwrap_or(-1));
        self.metrics
            .pending_proxy_count
            .set(self.pending_workloads.len().try_into().unwrap_or(-1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inpod::WorkloadData;
    use crate::inpod::test_helpers::{self, create_proxy_conflict, new_netns, uid};

    use crate::inpod::istio::zds;
    use matches::assert_matches;
    use std::sync::Arc;
    use std::time::Duration;

    struct Fixture {
        state: WorkloadProxyManagerState,
        metrics: Arc<crate::inpod::Metrics>,
    }

    fn workload_info() -> Option<zds::WorkloadInfo> {
        Some(zds::WorkloadInfo {
            name: "name".to_string(),
            namespace: "ns".to_string(),
            service_account: "sa".to_string(),
        })
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
                metrics: f.inpod_metrics,
            }
        }};
    }

    #[tokio::test]
    async fn add_workload_starts_a_proxy() {
        let fixture = fixture!();
        let mut state = fixture.state;
        let data = WorkloadData {
            netns: new_netns(),
            workload_uid: uid(0),
            workload_info: workload_info(),
        };
        state
            .process_msg(WorkloadMessage::AddWorkload(data))
            .await
            .unwrap();
        state.drain().await;
    }

    #[tokio::test]
    async fn idemepotency_add_workload_starts_only_one_proxy() {
        let fixture = fixture!();
        let mut state = fixture.state;
        let ns = new_netns();
        let data = WorkloadData {
            netns: ns.try_clone().unwrap(),
            workload_uid: uid(0),
            workload_info: workload_info(),
        };
        state
            .process_msg(WorkloadMessage::AddWorkload(data))
            .await
            .unwrap();
        let data = WorkloadData {
            netns: ns,
            workload_uid: uid(0),
            workload_info: workload_info(),
        };
        state
            .process_msg(WorkloadMessage::AddWorkload(data))
            .await
            .unwrap();
        state.drain().await;
    }

    #[tokio::test]
    async fn idemepotency_add_workload_fails() {
        let fixture = fixture!();
        let m = fixture.metrics.clone();
        let mut state = fixture.state;
        let ns = new_netns();
        // to make the proxy fail, bind to its ports in its netns
        let sock = create_proxy_conflict(&ns);

        let data = WorkloadData {
            netns: ns,
            workload_uid: uid(0),
            workload_info: workload_info(),
        };

        let ret = state.process_msg(WorkloadMessage::AddWorkload(data)).await;
        assert!(ret.is_err());
        assert!(state.have_pending());

        std::mem::drop(sock);
        // Unfortunate but necessary. When we close a socket in listener, the port is not synchronously freed.
        // This can lead to our retry failing due to a conflict. There doesn't seem to be a great way to reliably detect this.
        // Sleeping 10ms, however, is quite small and seems very reliable.
        tokio::time::sleep(Duration::from_millis(10)).await;

        state.retry_pending().await;
        assert!(!state.have_pending());
        state.drain().await;
        assert_eq!(m.proxies_started.get(), 1);
    }

    #[tokio::test]
    async fn workload_added_while_pending() {
        // Regression test for https://github.com/istio/istio/issues/52858
        // Workload is added and fails, so put on the pending queue. Then it is added and succeeds.
        // The bug is that when we retry with the failed netns, we (1) never succeed and (2) drop the running proxy.
        let fixture = fixture!();
        let m = fixture.metrics.clone();
        let mut state = fixture.state;
        let ns1 = new_netns();
        let ns2 = new_netns();
        // to make the proxy fail, bind to its ports in its netns
        let _sock = create_proxy_conflict(&ns1);

        // Add the pod in netns1
        let ret = state
            .process_msg(WorkloadMessage::AddWorkload(WorkloadData {
                netns: ns1,
                workload_uid: uid(0),
                workload_info: workload_info(),
            }))
            .await;
        assert!(ret.is_err());
        assert!(state.have_pending());

        // Add it again with another netns. The original pod should still be present in the retry queue with ns1
        state
            .process_msg(WorkloadMessage::AddWorkload(WorkloadData {
                netns: ns2,
                workload_uid: uid(0),
                workload_info: workload_info(),
            }))
            .await
            .expect("should start");

        state.retry_pending().await;
        assert!(!state.have_pending());
        state.drain().await;
        assert_eq!(m.proxies_started.get(), 1);
    }

    #[tokio::test]
    async fn idempotency_add_workload_fails_and_then_deleted() {
        let fixture = fixture!();
        let mut state = fixture.state;

        let ns = new_netns();
        // to make the proxy fail, bind to its ports in its netns
        let _sock = create_proxy_conflict(&ns);

        let data = WorkloadData {
            netns: ns,
            workload_uid: uid(0),
            workload_info: workload_info(),
        };
        state
            .process_msg(WorkloadMessage::WorkloadSnapshotSent)
            .await
            .unwrap();

        let ret = state.process_msg(WorkloadMessage::AddWorkload(data)).await;
        assert!(ret.is_err());
        assert!(state.have_pending());

        state
            .process_msg(WorkloadMessage::DelWorkload(uid(0)))
            .await
            .unwrap();

        assert!(!state.have_pending());
        state.drain().await;
    }

    #[tokio::test]
    async fn del_workload_before_snapshot_removes_from_snapshot_and_pending() {
        let fixture = fixture!();
        let mut state = fixture.state;

        let ns = new_netns();

        // to make the proxy fail, bind to its ports in its netns
        let _sock = create_proxy_conflict(&ns);

        let data = WorkloadData {
            netns: ns,
            workload_uid: uid(0),
            workload_info: workload_info(),
        };

        let ret = state.process_msg(WorkloadMessage::AddWorkload(data)).await;

        assert!(state.snapshot_names.len() == 1);
        assert!(ret.is_err());
        assert!(state.have_pending());

        state
            .process_msg(WorkloadMessage::DelWorkload(uid(0)))
            .await
            .unwrap();

        assert!(state.snapshot_names.is_empty());

        state
            .process_msg(WorkloadMessage::WorkloadSnapshotSent)
            .await
            .unwrap();

        assert!(state.snapshot_names.is_empty());
        assert!(!state.have_pending());
        state.drain().await;
    }

    #[tokio::test]
    async fn add_delete_add_workload_starts_only_one_proxy() {
        let fixture = fixture!();
        let mut state = fixture.state;

        let ns = new_netns();
        let data = WorkloadData {
            netns: ns.try_clone().unwrap(),
            workload_uid: uid(0),
            workload_info: workload_info(),
        };

        let workload_uid = data.workload_uid.clone();

        let msg1 = WorkloadMessage::AddWorkload(data);
        let msg2 = WorkloadMessage::DelWorkload(workload_uid.clone());
        let msg3 = WorkloadMessage::AddWorkload(WorkloadData {
            netns: ns,
            workload_uid,
            workload_info: workload_info(),
        });

        state
            .process_msg(WorkloadMessage::WorkloadSnapshotSent)
            .await
            .unwrap();
        state.process_msg(msg1).await.unwrap();
        state.process_msg(msg2).await.unwrap();
        // give a bit of time for the proxy to drain
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        state.process_msg(msg3).await.unwrap();
        state.drain().await;
    }

    #[tokio::test]
    async fn proxy_added_then_kept_with_new_snapshot() {
        let fixture = fixture!();
        let m = fixture.metrics.clone();
        let mut state = fixture.state;

        let data = WorkloadData {
            netns: new_netns(),
            workload_uid: uid(0),
            workload_info: workload_info(),
        };

        let workload_uid = data.workload_uid.clone();

        let msg1 = WorkloadMessage::AddWorkload(data);
        let msg2 = WorkloadMessage::KeepWorkload(workload_uid.clone());

        state.process_msg(msg1).await.unwrap();
        state
            .process_msg(WorkloadMessage::WorkloadSnapshotSent)
            .await
            .unwrap();
        state.reset_snapshot();
        state.process_msg(msg2).await.unwrap();
        state
            .process_msg(WorkloadMessage::WorkloadSnapshotSent)
            .await
            .unwrap();

        assert_eq!(m.proxies_started.get(), 1);

        state.drain().await;
    }

    #[tokio::test]
    async fn add_with_different_netns_keeps_latest_proxy() {
        let fixture = fixture!();
        let m = fixture.metrics.clone();
        let mut state = fixture.state;

        let data = WorkloadData {
            netns: new_netns(),
            workload_uid: uid(0),
            workload_info: workload_info(),
        };
        let workload_uid = data.workload_uid.clone();

        let add1 = WorkloadMessage::AddWorkload(data);
        let add2 = WorkloadMessage::AddWorkload(WorkloadData {
            netns: new_netns(),
            workload_uid,
            workload_info: workload_info(),
        });

        state.process_msg(add1).await.unwrap();
        state.process_msg(add2).await.unwrap();
        state.drain().await;

        assert_eq!(m.proxies_started.get(), 2);
        assert_eq!(m.active_proxy_count.get(), 1);
    }

    #[tokio::test]
    async fn no_workload_info_rejected() {
        let fixture = fixture!();
        let mut state = fixture.state;

        let data = WorkloadData {
            netns: new_netns(),
            workload_uid: uid(0),
            workload_info: None,
        };

        let add = WorkloadMessage::AddWorkload(data);

        assert_matches!(state.process_msg(add).await, Err(_));
    }
}

#[cfg(test)]
mod owned_drain_tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canceled_delete_waiter_retains_real_socket_task_and_retry_waits() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        let (signal, watch) = drain::new();
        let (release_tx, release) = tokio::sync::oneshot::channel();
        let (stopped_tx, stopped) = tokio::sync::oneshot::channel();
        let child = tokio::spawn(async move {
            let stop = watch.wait_for_drain().await;
            let _ = stopped_tx.send(());
            release.await.unwrap();
            drop(socket);
            drop(stop);
            Ok(())
        });
        let mut drains = DrainingTasks::default();
        let uid = WorkloadUid::new("owned-pod".into());
        drains.shutdown_workload(
            uid.clone(),
            WorkloadState {
                drain: signal,
                netns_id: NetnsID { inode: 1, dev: 1 },
                tasks: vec![child],
                connections: None,
            },
        );
        stopped.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), drains.wait_workload(&uid))
                .await
                .is_err()
        );
        // Canceling that caller did not discard the actual owned shutdown task.
        assert!(drains.draining[0].1.clone().now_or_never().is_none());
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), drains.wait_workload(&uid))
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        drains.join().await.unwrap();
    }

    #[tokio::test]
    async fn failed_owned_task_poison_is_not_erased_by_repeated_delete() {
        let (signal, watch) = drain::new();
        drop(watch);
        let child = tokio::spawn(async {
            Err(crate::proxy::Error::Anyhow(anyhow::anyhow!(
                "injected owned-task failure"
            )))
        });
        let uid = WorkloadUid::new("failed-pod".into());
        let mut drains = DrainingTasks::default();
        drains.shutdown_workload(
            uid.clone(),
            WorkloadState {
                drain: signal,
                netns_id: NetnsID { inode: 1, dev: 1 },
                tasks: vec![child],
                connections: None,
            },
        );
        assert!(drains.wait_workload(&uid).await.is_err());
        assert!(drains.wait_workload(&uid).await.is_err());
        assert!(drains.join().await.is_err());
    }
    #[tokio::test]
    async fn leftover_owned_connection_registry_prevents_successful_barrier() {
        let manager = crate::proxy::connection_manager::ConnectionManager::default();
        let guard = manager.track_outbound(
            "10.0.0.1:42000".parse().unwrap(),
            "10.0.0.2:8080".parse().unwrap(),
            "10.0.0.2:8080".parse().unwrap(),
            crate::state::workload::OutboundProtocol::HBONE,
            true,
        );
        let (signal, watch) = drain::new();
        drop(watch);
        let uid = WorkloadUid::new("leftover-registry".into());
        let mut drains = DrainingTasks::default();
        drains.shutdown_workload(
            uid.clone(),
            WorkloadState {
                drain: signal,
                netns_id: NetnsID { inode: 1, dev: 1 },
                tasks: vec![],
                connections: Some(manager),
            },
        );
        assert!(drains.wait_workload(&uid).await.is_err());
        drop(guard);
        assert!(
            drains.wait_workload(&uid).await.is_err(),
            "a later empty registry cannot erase a failed barrier result"
        );
    }
}
