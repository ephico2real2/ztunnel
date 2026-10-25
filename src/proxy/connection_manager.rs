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

use crate::proxy::Error;

use crate::state::DemandProxyState;
use crate::state::ProxyRbacContext;
use serde::{Serialize, Serializer};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt::Formatter;
use std::net::SocketAddr;

use crate::drain;
use crate::drain::{DrainTrigger, DrainWatcher};
use crate::state::workload::{InboundProtocol, OutboundProtocol};
use std::sync::Arc;
use std::sync::RwLock;
use tracing::{debug, error, info, warn};

struct ConnectionDrain {
    // TODO: this should almost certainly be changed to a type which has counted references exposed.
    // tokio::sync::watch can be subscribed without taking a write lock and exposes references
    // and also a receiver_count method
    tx: DrainTrigger,
    rx: DrainWatcher,
    count: usize,
}

impl ConnectionDrain {
    fn new() -> Self {
        let (tx, rx) = drain::new();
        ConnectionDrain { tx, rx, count: 1 }
    }

    /// drain drops the internal reference to rx and then signals drain on the tx
    // always inline, this is for convenience so that we don't forget to drop the rx but there's really no reason it needs to grow the stack
    #[inline(always)]
    async fn drain(self) {
        drop(self.rx); // very important, drain cannot complete if there are outstand rx
        self.tx
            .start_drain_and_wait(drain::DrainMode::Immediate)
            .await;
    }
}

#[derive(Clone)]
pub struct ConnectionManager {
    drains: Arc<RwLock<HashMap<InboundConnection, ConnectionDrain>>>,
    outbound_connections: Arc<RwLock<HashSet<OutboundConnection>>>,
    // Only strict mesh outbound flows need to participate in xDS session drains.
    outbound_drains: Arc<RwLock<HashMap<OutboundConnection, ConnectionDrain>>>,
}

impl std::fmt::Debug for ConnectionManager {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionManager").finish()
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        ConnectionManager {
            drains: Arc::new(RwLock::new(HashMap::new())),
            outbound_connections: Arc::new(RwLock::new(HashSet::new())),
            outbound_drains: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

pub struct ConnectionGuard {
    released: bool,
    cm: ConnectionManager,
    conn: InboundConnection,
    watch: Option<DrainWatcher>,
}

// For reasons that I don't fully understand, this uses an obscene amount of stack space when written as a normal function,
// amounting to ~1kb overhead per connection.
// Inlining it removes this entirely, and the macro ensures we do it consistently across the various areas we use it.
#[macro_export]
macro_rules! handle_connection {
    ($connguard:expr, $future:expr) => {{
        let watch = $connguard.watcher();
        tokio::select! {
            res = $future => {
                $connguard.release();
                res
            }
            _signaled = watch.wait_for_drain() => Err(Error::AuthorizationPolicyLateRejection)
        }
    }};
}

impl ConnectionGuard {
    pub fn watcher(&mut self) -> drain::DrainWatcher {
        self.watch.take().expect("watch cannot be taken twice")
    }
    pub fn release(mut self) {
        self.released = true;
        self.cm.release(&self.conn);
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if !self.released {
            debug!("rbac context {:?} auto-dropped", &self.conn);
            self.cm.release(&self.conn)
        }
    }
}

pub struct OutboundConnectionGuard {
    cm: ConnectionManager,
    conn: OutboundConnection,
    watch: Option<DrainWatcher>,
}

impl OutboundConnectionGuard {
    pub fn watcher(&mut self) -> Option<DrainWatcher> {
        self.watch.take()
    }
}

impl Drop for OutboundConnectionGuard {
    fn drop(&mut self) {
        self.cm.release_outbound(&self.conn)
    }
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundConnection {
    pub src: SocketAddr,
    pub original_dst: SocketAddr,
    pub actual_dst: SocketAddr,
    pub protocol: OutboundProtocol,
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundConnectionDump {
    pub src: SocketAddr,
    pub original_dst: Option<String>,
    pub actual_dst: SocketAddr,
    pub protocol: InboundProtocol,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundConnection {
    #[serde(flatten)]
    pub ctx: ProxyRbacContext,
    pub dest_service: Option<String>,
}

impl ConnectionManager {
    pub fn track_outbound(
        &self,
        src: SocketAddr,
        original_dst: SocketAddr,
        actual_dst: SocketAddr,
        protocol: OutboundProtocol,
        drain_on_xds_change: bool,
    ) -> OutboundConnectionGuard {
        let c = OutboundConnection {
            src,
            original_dst,
            actual_dst,
            protocol,
        };

        self.outbound_connections
            .write()
            .expect("mutex")
            .insert(c.clone());

        let watch = if drain_on_xds_change {
            Some(self.register_outbound(&c))
        } else {
            None
        };

        OutboundConnectionGuard {
            cm: self.clone(),
            conn: c,
            watch,
        }
    }

    fn register_outbound(&self, connection: &OutboundConnection) -> DrainWatcher {
        match self
            .outbound_drains
            .write()
            .expect("mutex")
            .entry(connection.clone())
        {
            Entry::Occupied(mut entry) => {
                entry.get_mut().count += 1;
                entry.get().rx.clone()
            }
            Entry::Vacant(entry) => {
                let drain = ConnectionDrain::new();
                let watch = drain.rx.clone();
                entry.insert(drain);
                watch
            }
        }
    }

    pub async fn assert_rbac(
        &self,
        state: &DemandProxyState,
        ctx: &ProxyRbacContext,
        dest_service: Option<String>,
    ) -> Result<ConnectionGuard, Error> {
        // Register before our initial assert. This prevents a race if policy changes between assert() and
        // track()
        let conn = InboundConnection {
            ctx: ctx.clone(),
            dest_service,
        };
        let Some(watch) = self.register(&conn) else {
            warn!("failed to track {conn:?}");
            debug_assert!(false, "failed to track {conn:?}");
            return Err(Error::ConnectionTrackingFailed);
        };
        if let Err(err) = state.assert_rbac(ctx).await {
            self.release(&conn);
            return Err(Error::AuthorizationPolicyRejection(err));
        }
        Ok(ConnectionGuard {
            cm: self.clone(),
            conn,
            watch: Some(watch),
            released: false,
        })
    }
    // register a connection with the connection manager
    // this must be done before a connection can be tracked
    // allows policy to be asserted against the connection
    // even no tasks have a receiver channel yet
    fn register(&self, c: &InboundConnection) -> Option<DrainWatcher> {
        match self.drains.write().expect("mutex").entry(c.clone()) {
            Entry::Occupied(mut cd) => {
                cd.get_mut().count += 1;
                let rx = cd.get().rx.clone();
                Some(rx)
            }
            Entry::Vacant(entry) => {
                let drain = ConnectionDrain::new();
                let rx = drain.rx.clone();
                entry.insert(drain);
                Some(rx)
            }
        }
    }

    // releases tracking on a connection
    // uses a counter to determine if there are other tracked connections or not so it may retain the tx/rx channels when necessary
    pub fn release(&self, c: &InboundConnection) {
        let mut drains = self.drains.write().expect("mutex");
        if let Some((k, mut v)) = drains.remove_entry(c)
            && v.count > 1
        {
            // something else is tracking this connection, decrement count but retain
            v.count -= 1;
            drains.insert(k, v);
        }
    }

    fn release_outbound(&self, c: &OutboundConnection) {
        self.outbound_connections.write().expect("mutex").remove(c);
        let mut drains = self.outbound_drains.write().expect("mutex");
        if let Some((key, mut drain)) = drains.remove_entry(c)
            && drain.count > 1
        {
            drain.count -= 1;
            drains.insert(key, drain);
        }
    }

    // signal all connections listening to this channel to take action (typically terminate traffic)
    async fn close(&self, c: &InboundConnection) {
        let drain = { self.drains.write().expect("mutex").remove(c) };
        if let Some(cd) = drain {
            cd.drain().await;
        } else {
            // this is bad, possibly drain called twice
            error!("requested drain on a Connection which wasn't initialized");
        }
    }

    /// Closes every inbound stream and strict mesh outbound flow before a
    /// refreshed xDS session can authorize new connections.
    async fn close_all(&self) -> usize {
        let connections = self.connections();
        let protected_outbound = self.protected_outbound_connections();
        let count = connections.len() + protected_outbound.len();
        tokio::join!(
            futures::future::join_all(
                connections
                    .into_iter()
                    .map(|connection| async move { self.close(&connection).await }),
            ),
            futures::future::join_all(
                protected_outbound
                    .into_iter()
                    .map(|connection| async move { self.close_outbound(&connection).await })
            ),
        );
        count
    }

    async fn close_outbound(&self, connection: &OutboundConnection) {
        let drain = self
            .outbound_drains
            .write()
            .expect("mutex")
            .remove(connection);
        if let Some(drain) = drain {
            drain.drain().await;
        }
    }

    fn protected_outbound_connections(&self) -> Vec<OutboundConnection> {
        self.outbound_drains
            .read()
            .expect("mutex")
            .keys()
            .cloned()
            .collect()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.drains.read().expect("mutex").is_empty()
            && self.outbound_connections.read().expect("mutex").is_empty()
            && self.outbound_drains.read().expect("mutex").is_empty()
    }

    //  get a list of all connections being tracked
    pub fn connections(&self) -> Vec<InboundConnection> {
        // potentially large copy under read lock, could require optimization
        self.drains.read().expect("mutex").keys().cloned().collect()
    }
}

#[derive(serde::Serialize)]
struct ConnectionManagerDump {
    inbound: Vec<InboundConnectionDump>,
    outbound: Vec<OutboundConnection>,
}

impl Serialize for ConnectionManager {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let inbound: Vec<_> = self
            .drains
            .read()
            .expect("mutex")
            .keys()
            .cloned()
            .map(|c| InboundConnectionDump {
                src: c.ctx.conn.src,
                original_dst: c.dest_service,
                actual_dst: c.ctx.conn.dst,
                protocol: if c.ctx.conn.src_identity.is_some() {
                    InboundProtocol::HBONE
                } else {
                    InboundProtocol::TCP
                },
            })
            .collect();
        let outbound: Vec<_> = self
            .outbound_connections
            .read()
            .expect("mutex")
            .iter()
            .cloned()
            .collect();
        let dump = ConnectionManagerDump { inbound, outbound };
        dump.serialize(serializer)
    }
}

pub struct PolicyWatcher {
    state: DemandProxyState,
    stop: DrainWatcher,
    connection_manager: ConnectionManager,
    drain_participant: Option<crate::xds::DrainParticipant>,
    workloads_changed: tokio::sync::watch::Receiver<()>,
    policies_changed: tokio::sync::watch::Receiver<()>,
}

impl PolicyWatcher {
    pub fn new(
        state: DemandProxyState,
        stop: DrainWatcher,
        connection_manager: ConnectionManager,
    ) -> Self {
        // Subscribe before the watcher task is spawned so policy changes cannot
        // be lost between construction and its first poll.
        let policies_changed = state.read().policies.subscribe();
        let workloads_changed = state.read().workloads.new_subscriber();
        let drain_participant = state
            .xds_session()
            .map(|gate| gate.register_drain_participant());
        PolicyWatcher {
            state,
            stop,
            connection_manager,
            drain_participant,
            policies_changed,
            workloads_changed,
        }
    }

    pub async fn run(self) {
        let mut policies_changed = self.policies_changed;
        let mut workloads_changed = self.workloads_changed;
        let session_gate = self.state.xds_session();
        let mut session_changes = session_gate.as_ref().map(|gate| gate.subscribe());
        if let (Some(gate), Some(participant)) = (&session_gate, self.drain_participant) {
            let snapshot = gate.snapshot();
            if gate.needs_drain(snapshot.generation, participant) {
                let closed = self.connection_manager.close_all().await;
                gate.mark_drained(snapshot.generation, participant);
                info!(
                    session_generation = snapshot.generation,
                    closed_connections = closed,
                    "drained inbound connections for initial xDS session state"
                );
            }
        }
        loop {
            tokio::select! {
                _ = self.stop.clone().wait_for_drain() => {
                    break;
                }
                changed = async {
                    match session_changes.as_mut() {
                        Some(receiver) => receiver.changed().await.ok(),
                        None => std::future::pending().await,
                    }
                } => {
                    if changed.is_some()
                        && let (Some(gate), Some(participant)) = (&session_gate, self.drain_participant)
                    {
                        let snapshot = gate.snapshot();
                        if gate.needs_drain(snapshot.generation, participant) {
                            let closed = self.connection_manager.close_all().await;
                            gate.mark_drained(snapshot.generation, participant);
                            info!(
                                session_generation = snapshot.generation,
                                closed_connections = closed,
                                "drained inbound connections for xDS session transition"
                            );
                        }
                    }
                }
                _ = async {
                    tokio::select! {
                        _ = policies_changed.changed() => {},
                        _ = workloads_changed.changed() => {},
                    }
                } => {
                    let connections = self.connection_manager.connections();
                    for conn in connections {
                        if self.state.assert_rbac(&conn.ctx).await.is_err() {
                            self.connection_manager.close(&conn).await;
                            info!("connection {} closed because it's no longer allowed after a policy/workload update", conn.ctx);
                        }
                    }
                }
            }
        }
        if let (Some(gate), Some(participant)) = (&session_gate, self.drain_participant) {
            self.connection_manager.close_all().await;
            gate.unregister_drain_participant(participant);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::drain;
    use crate::drain::DrainWatcher;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use prometheus_client::registry::Registry;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    use crate::identity::Identity;
    use crate::rbac::{Authorization as RbacAuthorization, Connection, RbacAction, RbacScope};
    use crate::state::{DemandProxyState, ProxyState};
    use crate::test_helpers::test_default_workload;
    use crate::xds::ProxyStateUpdateMutator;
    use crate::xds::istio::security::{Action, Authorization, Scope};

    use super::{ConnectionGuard, ConnectionManager, InboundConnection, PolicyWatcher};

    #[tokio::test]
    async fn test_connection_manager_close() {
        // setup a new ConnectionManager
        let cm = ConnectionManager::default();
        // ensure drains is empty
        assert_eq!(cm.drains.read().unwrap().len(), 0);
        assert_eq!(cm.connections().len(), 0);

        let register = |cm: &ConnectionManager, c: &InboundConnection| {
            let cm = cm.clone();
            let c = c.clone();

            let watch = cm.register(&c).unwrap();
            ConnectionGuard {
                cm,
                conn: c,
                watch: Some(watch),
                released: false,
            }
        };

        // track a new connection
        let rbac_ctx1 = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                native_source: None,
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 1).into(),
                        80,
                    ),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload: Arc::new(test_default_workload()),
            },
            dest_service: None,
        };

        // ensure drains contains exactly 1 item
        let mut close1 = register(&cm, &rbac_ctx1);
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(rbac_ctx1.clone()));

        // setup a second track on the same connection
        let mut another_close1 = register(&cm, &rbac_ctx1);

        // ensure drains contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(rbac_ctx1.clone()));

        // track a second connection
        let rbac_ctx2 = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                native_source: None,
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 3).into(),
                        80,
                    ),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload: Arc::new(test_default_workload()),
            },
            dest_service: None,
        };

        let mut close2 = register(&cm, &rbac_ctx2);
        // ensure drains contains exactly 2 items
        assert_eq!(cm.drains.read().unwrap().len(), 2);
        assert_eq!(cm.connections().len(), 2);
        let mut connections = cm.connections();
        // ordering cannot be guaranteed without sorting
        connections.sort_by(|a, b| a.ctx.conn.cmp(&b.ctx.conn));
        assert_eq!(connections, vec![rbac_ctx1.clone(), rbac_ctx2.clone()]);

        // spawn tasks to assert that we close in a timely manner for rbac_ctx1
        tokio::spawn(assert_close(close1.watch.take().unwrap()));
        tokio::spawn(assert_close(another_close1.watch.take().unwrap()));
        // close rbac_ctx1
        cm.close(&rbac_ctx1).await;
        // ensure drains contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(rbac_ctx2.clone()));

        // spawn a task to assert that we close in a timely manner for rbac_ctx2
        tokio::spawn(assert_close(close2.watch.take().unwrap()));
        // close rbac_ctx2
        cm.close(&rbac_ctx2).await;
        // assert that drains is empty again
        assert_eq!(cm.drains.read().unwrap().len(), 0);
        assert_eq!(cm.connections().len(), 0);
    }

    #[tokio::test]
    async fn test_connection_manager_release() {
        // setup a new ConnectionManager
        let cm = ConnectionManager::default();
        // ensure drains is empty
        assert_eq!(cm.drains.read().unwrap().len(), 0);
        assert_eq!(cm.connections().len(), 0);

        let register = |cm: &ConnectionManager, c: &InboundConnection| {
            let cm = cm.clone();
            let c = c.clone();

            let watch = cm.register(&c).unwrap();
            ConnectionGuard {
                cm,
                conn: c,
                watch: Some(watch),
                released: false,
            }
        };

        // create a new connection
        let conn1 = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                native_source: None,
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 1).into(),
                        80,
                    ),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload: Arc::new(test_default_workload()),
            },
            dest_service: None,
        };

        // create a second connection
        let conn2 = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                native_source: None,
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 3).into(),
                        80,
                    ),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload: Arc::new(test_default_workload()),
            },
            dest_service: None,
        };
        let another_conn1 = conn1.clone();

        let close1 = register(&cm, &conn1);
        let another_close1 = register(&cm, &another_conn1);

        // ensure drains contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(conn1.clone()));

        // release conn1's clone
        drop(another_close1);
        // ensure drains still contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(conn1.clone()));

        let close2 = register(&cm, &conn2);
        // ensure drains contains exactly 2 items
        assert_eq!(cm.drains.read().unwrap().len(), 2);
        assert_eq!(cm.connections().len(), 2);
        let mut connections = cm.connections();
        // ordering cannot be guaranteed without sorting
        connections.sort_by(|a, b| a.ctx.conn.cmp(&b.ctx.conn));
        assert_eq!(connections, vec![conn1.clone(), conn2.clone()]);

        // release conn1
        drop(close1);
        // ensure drains contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(conn2.clone()));

        // clone conn2 and track it
        let another_conn2 = conn2.clone();
        let another_close2 = register(&cm, &another_conn2);
        // release tracking on conn2
        drop(close2);
        // ensure drains still contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(another_conn2.clone()));

        // release tracking on conn2's clone
        drop(another_close2);
        // ensure drains contains exactly 0 items
        assert_eq!(cm.drains.read().unwrap().len(), 0);
        assert_eq!(cm.connections().len(), 0);
    }

    #[tokio::test]
    async fn test_policy_watcher_lifecycle() {
        // preamble: setup an environment
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let dstate = DemandProxyState::new(
            state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        );
        let connection_manager = ConnectionManager::default();
        let (tx, stop) = drain::new();
        let state_mutator = ProxyStateUpdateMutator::new_no_fetch();

        // clones to move into spawned task
        let ds = dstate.clone();
        let cm = connection_manager.clone();
        let pw = PolicyWatcher::new(ds, stop, cm);
        // spawn a task which watches policy and asserts that the policy watcher stop correctly
        tokio::spawn(async move {
            let res = tokio::time::timeout(Duration::from_secs(1), pw.run()).await;
            assert!(res.is_ok())
        });

        // create a test connection
        let conn1 = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                native_source: None,
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 1).into(),
                        80,
                    ),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload: Arc::new(test_default_workload()),
            },
            dest_service: None,
        };
        // watch the connection
        let close1 = connection_manager
            .register(&conn1)
            .expect("should not be None");

        // generate policy which denies everything
        let auth_name = "allow-nothing";
        let auth_namespace = "default";
        let auth = Authorization {
            name: auth_name.into(),
            action: Action::Deny as i32,
            scope: Scope::Global as i32,
            namespace: auth_namespace.into(),
            rules: vec![],
            dry_run: false,
            extensions: vec![],
        };
        let mut auth_xds_name = String::with_capacity(1 + auth_namespace.len() + auth_name.len());
        auth_xds_name.push_str(auth_namespace);
        auth_xds_name.push('/');
        auth_xds_name.push_str(auth_name);

        // spawn an assertion that our connection close is received
        tokio::spawn(assert_close(close1));

        // this block will scope our guard appropriately
        {
            // update our state
            let mut s = state
                .write()
                .expect("test fails if we're unable to get a write lock on state");
            let res =
                state_mutator.insert_authorization(&mut s, auth_xds_name.clone().into(), auth);
            // assert that the update was OK
            assert!(res.is_ok());
        } // release lock

        // send the signal which stops policy watcher
        tx.start_drain_and_wait(drain::DrainMode::Immediate).await;
    }

    #[tokio::test]
    async fn policy_watcher_drains_connections_when_xds_session_becomes_stale() {
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let session = crate::xds::XdsSessionGate::new();
        let generation = session.begin_session();
        session.mark_snapshot_ready(generation);
        let dstate = DemandProxyState::new(
            state,
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        )
        .with_require_inbound_mtls(true)
        .with_xds_session(Some(session.clone()));
        let connection = |source_port| InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                native_source: None,
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        Ipv4Addr::new(192, 168, 0, 1).into(),
                        source_port,
                    ),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload: Arc::new(test_default_workload()),
            },
            dest_service: None,
        };
        let first_manager = ConnectionManager::default();
        let second_manager = ConnectionManager::default();
        let first_conn = connection(80);
        let second_conn = connection(81);
        let third_conn = connection(82);
        let first_connection_drain = first_manager
            .register(&first_conn)
            .expect("connection must be tracked before invalidation");
        let second_connection_drain = first_manager
            .register(&second_conn)
            .expect("second connection must be tracked before invalidation");
        let third_connection_drain = second_manager
            .register(&third_conn)
            .expect("third connection must be tracked before invalidation");

        let (first_stop_tx, first_stop) = drain::new();
        let (second_stop_tx, second_stop) = drain::new();
        let first_watcher = PolicyWatcher::new(dstate.clone(), first_stop, first_manager.clone());
        let second_watcher = PolicyWatcher::new(dstate, second_stop, second_manager.clone());
        let first_task = tokio::spawn(first_watcher.run());
        let second_task = tokio::spawn(second_watcher.run());
        session.mark_stale(generation);
        let fresh_generation = session.begin_session();
        session.mark_snapshot_ready(fresh_generation);

        tokio::time::timeout(Duration::from_secs(1), async {
            while !first_manager.connections().is_empty()
                || !second_manager.connections().is_empty()
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("policy watcher must drain existing inbound streams");
        assert!(first_manager.connections().is_empty());
        assert!(second_manager.connections().is_empty());
        assert!(!session.is_open());

        // Each manager signals all its streams while the other manager is also
        // draining. The shared gate must wait for every manager's acknowledgment.
        let first_drain_ack = tokio::time::timeout(
            Duration::from_secs(1),
            first_connection_drain.clone().wait_for_drain(),
        )
        .await
        .expect("first manager's first stream must receive its drain signal");
        let second_drain_ack = tokio::time::timeout(
            Duration::from_secs(1),
            second_connection_drain.clone().wait_for_drain(),
        )
        .await
        .expect("first manager's second stream must receive its drain signal");
        let third_drain_ack = tokio::time::timeout(
            Duration::from_secs(1),
            third_connection_drain.clone().wait_for_drain(),
        )
        .await
        .expect("second manager's stream must receive its drain signal");

        // Keep stream watchers alive to prove removing connection registry
        // entries does not count as a completed drain.
        drop(first_connection_drain);
        drop(second_connection_drain);
        drop(first_drain_ack);
        drop(second_drain_ack);
        tokio::time::timeout(Duration::from_secs(1), async {
            while session.snapshot().pending_drains != 1 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("one manager acknowledgment must leave the other pending");
        assert!(
            !session.is_open(),
            "one drained manager cannot reopen the gate"
        );

        drop(third_connection_drain);
        drop(third_drain_ack);
        tokio::time::timeout(Duration::from_secs(1), async {
            while session.snapshot().drained_generation < fresh_generation
                || session.snapshot().pending_drains != 0
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("every manager must acknowledge the fresh generation drain");
        assert!(session.is_open());

        first_stop_tx
            .start_drain_and_wait(drain::DrainMode::Immediate)
            .await;
        second_stop_tx
            .start_drain_and_wait(drain::DrainMode::Immediate)
            .await;
        first_task
            .await
            .expect("first policy watcher should stop cleanly");
        second_task
            .await
            .expect("second policy watcher should stop cleanly");
    }

    #[tokio::test]
    async fn policy_watcher_closes_existing_connection_when_final_allow_is_removed() {
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        state.write().unwrap().policies.insert(
            "allow-all".into(),
            RbacAuthorization {
                action: RbacAction::Allow,
                namespace: "".into(),
                name: "allow-all".into(),
                rules: vec![vec![]],
                scope: RbacScope::Global,
                dry_run: false,
            },
        );

        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let xds_session = crate::xds::XdsSessionGate::new();
        let generation = xds_session.begin_session();
        xds_session.mark_snapshot_ready(generation);
        let dstate = DemandProxyState::new(
            state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        )
        .with_require_inbound_mtls(true)
        .with_xds_session(Some(xds_session.clone()));

        let connection = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                native_source: None,
                conn: Connection {
                    src_identity: Some(Identity::Spiffe {
                        trust_domain: "cluster.local".into(),
                        namespace: "default".into(),
                        service_account: "client".into(),
                    }),
                    src: std::net::SocketAddr::new(Ipv4Addr::new(192, 168, 0, 1).into(), 41000),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload: Arc::new(test_default_workload()),
            },
            dest_service: None,
        };
        let connection_manager = ConnectionManager::default();
        let (stop_tx, stop) = drain::new();
        // PolicyWatcher subscribes synchronously in new(), before this task can
        // race with the policy update below.
        let watcher = PolicyWatcher::new(dstate.clone(), stop, connection_manager.clone());
        let watcher_task = tokio::spawn(watcher.run());

        tokio::time::timeout(Duration::from_secs(1), async {
            while !xds_session.is_open() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("policy watcher must acknowledge the current xDS generation before admission");
        assert!(dstate.assert_rbac(&connection.ctx).await.is_ok());
        let stream_drain = connection_manager
            .register(&connection)
            .expect("authenticated connection is tracked before policy removal");

        {
            let mut state = state.write().unwrap();
            state.policies.remove("allow-all".into());
            state.policies.send();
        }

        tokio::time::timeout(Duration::from_secs(1), async {
            while !connection_manager.connections().is_empty() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("removing the final ALLOW must close an active inbound stream");
        drop(
            tokio::time::timeout(Duration::from_secs(1), stream_drain.wait_for_drain())
                .await
                .expect("active stream must receive its drain signal"),
        );
        assert_eq!(
            dstate.assert_rbac(&connection.ctx).await,
            Err(crate::proxy::AuthorizationRejectionError::NoEffectiveAllowPolicy)
        );

        stop_tx
            .start_drain_and_wait(drain::DrainMode::Immediate)
            .await;
        watcher_task
            .await
            .expect("policy watcher should stop cleanly after the test");
    }

    #[tokio::test]
    async fn xds_session_drain_cancels_protected_outbound_before_reopening() {
        let gate = crate::xds::XdsSessionGate::new();
        let first_generation = gate.begin_session();
        gate.mark_snapshot_ready(first_generation);

        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let dstate = DemandProxyState::new(
            state,
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        )
        .with_xds_session(Some(gate.clone()));
        let manager = ConnectionManager::default();
        let (stop_tx, stop) = drain::new();
        let watcher = PolicyWatcher::new(dstate, stop, manager.clone());
        let watcher_task = tokio::spawn(watcher.run());

        tokio::time::timeout(Duration::from_secs(1), async {
            while !gate.is_open() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("PolicyWatcher must drain before opening the initial snapshot");

        let flow_manager = manager.clone();
        let (flow_started_tx, flow_started_rx) = tokio::sync::oneshot::channel();
        let flow = tokio::spawn(async move {
            let mut guard = flow_manager.track_outbound(
                "10.244.0.10:41000".parse().unwrap(),
                "10.244.0.20:31337".parse().unwrap(),
                "10.244.0.20:15008".parse().unwrap(),
                crate::state::workload::OutboundProtocol::HBONE,
                true,
            );
            let watcher = guard
                .watcher()
                .expect("strict mesh outbound flow must be drainable");
            flow_started_tx
                .send(())
                .expect("test must observe the registered outbound flow");
            drop(
                tokio::time::timeout(Duration::from_secs(1), watcher.wait_for_drain())
                    .await
                    .expect("stale xDS must cancel the protected outbound flow"),
            );
            drop(guard);
        });

        flow_started_rx
            .await
            .expect("protected flow must start before xDS becomes stale");
        assert_eq!(manager.protected_outbound_connections().len(), 1);

        gate.mark_stale(first_generation);
        assert!(
            !gate.is_open(),
            "stale xDS must close admission immediately"
        );

        tokio::time::timeout(Duration::from_secs(1), flow)
            .await
            .expect("PolicyWatcher must cancel the active protected flow")
            .expect("outbound flow task should finish after its drain signal");
        assert!(manager.protected_outbound_connections().is_empty());
        assert!(
            !gate.is_open(),
            "stale session must remain closed after its old flows drain"
        );

        let replacement_generation = gate.begin_session();
        tokio::time::timeout(Duration::from_secs(1), async {
            while gate.snapshot().drained_generation < replacement_generation
                || gate.snapshot().pending_drains != 0
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("PolicyWatcher must acknowledge the replacement-generation drain");
        assert!(
            !gate.is_open(),
            "draining alone cannot reopen admission without a complete snapshot"
        );
        gate.mark_snapshot_ready(replacement_generation);
        assert!(
            gate.is_open(),
            "admission reopens only after flow drain and fresh snapshot"
        );

        stop_tx
            .start_drain_and_wait(drain::DrainMode::Immediate)
            .await;
        watcher_task
            .await
            .expect("PolicyWatcher must stop cleanly after the regression test");
    }

    // small helper to assert that the Watches are working in a timely manner
    async fn assert_close(c: DrainWatcher) {
        let result = tokio::time::timeout(Duration::from_secs(1), c.wait_for_drain()).await;
        assert!(result.is_ok())
    }
    #[test]
    fn dropping_guard_after_taking_watcher_releases_exactly_one_registry_reference() {
        let manager = ConnectionManager::default();
        let connection = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                native_source: None,
                conn: Connection {
                    src: "10.1.2.3:42000".parse().unwrap(),
                    dst: "10.1.2.4:8080".parse().unwrap(),
                    src_identity: None,
                    dst_network: "".into(),
                },
                dest_workload: Arc::new(test_default_workload()),
            },
            dest_service: None,
        };
        let first = manager.register(&connection).unwrap();
        let second = manager.register(&connection).unwrap();
        let mut guard = ConnectionGuard {
            cm: manager.clone(),
            conn: connection.clone(),
            watch: Some(first),
            released: false,
        };
        let watch = guard.watcher();
        drop(guard);
        drop(watch);
        assert_eq!(
            manager
                .drains
                .read()
                .unwrap()
                .get(&connection)
                .unwrap()
                .count,
            1
        );
        let final_guard = ConnectionGuard {
            cm: manager.clone(),
            conn: connection.clone(),
            watch: Some(second),
            released: false,
        };
        final_guard.release();
        assert!(
            manager.connections().is_empty(),
            "explicit release must not double-release another reference"
        );
    }
}
