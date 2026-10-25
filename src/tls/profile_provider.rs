// Copyright Istio Authors
// SPDX-License-Identifier: Apache-2.0
//! Native ADS trust provider. A durable receipt is not a traffic grant. Every
//! lease also requires the complete current xDS session and its drain barrier.
use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail, ensure};
use rustls::pki_types::UnixTime;
use rustls::{CommonState, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, watch};
use tokio::time::Instant;

use super::domain_anchors::{AnchorPublication, PeerRole, VerifiedPeer, verify_peer_evidence};
use super::issuer_profile_wire::{Decoded, Expected};
use super::profile_checkpoint::{
    Binding, CheckpointStore, Floors, Installation, Observation, OpenMode, ProfileCheckpoint,
};
use super::revocation::{ConnRegistration, RevocationHandle, verify_cert_chain};
use crate::identity::Identity;
use crate::proxy::metrics::Reporter;
use crate::tls::{self, WorkloadCertificate};
use crate::xds::XdsSessionGate;

#[derive(Clone)]
struct Active {
    epoch: u64,
    session: u64,
    until: SystemTime,
    monotonic_until: Instant,
    publication: Arc<AnchorPublication>,
}
struct Inner {
    record: Option<ProfileCheckpoint>,
    active: Option<Active>,
    epoch: u64,
    last_wall: SystemTime,
    next_flow: u64,
    flows: BTreeMap<u64, (u64, u64)>,
}
/// All origin/root pins are supplied by the administrator, not by ADS or the
/// checkpoint. Recovered history never becomes an active provider on its own.
pub(crate) struct ProfileProvider {
    inner: Mutex<Inner>,
    // Only commit workers take this lock. Never hold the live-state mutex
    // across a filesystem syscall; revocation and TLS I/O must remain runnable.
    store: Mutex<CheckpointStore>,
    poisoned: AtomicBool,
    installation: Installation,
    gate: XdsSessionGate,
    participant: crate::xds::DrainParticipant,
    changes: watch::Sender<u64>,
    drained: Notify,
    clock: fn() -> SystemTime,
    #[cfg(test)]
    before_disk: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    #[cfg(test)]
    before_error_fence: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}
#[derive(Clone)]
pub(crate) struct Lease {
    provider: Arc<ProfileProvider>,
    active: Active,
}
impl ProfileProvider {
    pub fn open(
        path: &Path,
        expected: &Expected,
        mode: OpenMode,
        gate: XdsSessionGate,
    ) -> Result<Arc<Self>> {
        Self::open_with_clock(path, expected, mode, gate, SystemTime::now)
    }
    pub(crate) fn open_with_clock(
        path: &Path,
        expected: &Expected,
        mode: OpenMode,
        gate: XdsSessionGate,
        clock: fn() -> SystemTime,
    ) -> Result<Arc<Self>> {
        let installation = Installation::from_expected(expected);
        let store = CheckpointStore::open(path, installation.clone(), mode)?;
        let record = store.recovered().cloned();
        // Revalidate cumulative DER history now. This does not restore a lease.
        if let Some(record) = &record {
            record.history()?;
        }
        let (changes, _) = watch::channel(0);
        let participant = gate.register_drain_participant();
        Ok(Arc::new(Self {
            store: Mutex::new(store),
            poisoned: AtomicBool::new(false),
            inner: Mutex::new(Inner {
                record,
                active: None,
                epoch: 1,
                last_wall: clock(),
                next_flow: 0,
                flows: BTreeMap::new(),
            }),
            installation,
            gate,
            participant,
            changes,
            drained: Notify::new(),
            clock,
            #[cfg(test)]
            before_disk: Mutex::new(None),
            #[cfg(test)]
            before_error_fence: Mutex::new(None),
        }))
    }
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }
    pub fn available_for_session(&self, generation: u64) -> bool {
        let inner = self.inner.lock().expect("profile state");
        inner.active.as_ref().is_some_and(|a| {
            !self.poisoned.load(Ordering::Acquire)
                && a.session == generation
                && self.gate.snapshot().generation == generation
                && !self.gate.is_revoked()
                && (self.clock)() >= inner.last_wall
                && (self.clock)() < a.until
                && Instant::now() < a.monotonic_until
        })
    }
    fn notify(&self) {
        self.changes.send_modify(|n| *n = n.wrapping_add(1));
    }
    fn reset_locked(inner: &mut Inner) {
        inner.active = None;
        // Exhaustion is a process-fatal invariant, never wrap an old epoch.
        inner.epoch = inner
            .epoch
            .checked_add(1)
            .expect("trust provider epoch exhausted");
    }
    /// Called when beginning a new ADS session. Do not revoke that new session.
    pub fn reset_session(&self) {
        Self::reset_locked(&mut self.inner.lock().expect("profile state"));
        self.notify();
    }
    pub fn fail_closed(&self) {
        self.fail_closed_for_session(self.gate.snapshot().generation);
    }
    pub fn fail_closed_for_session(&self, session: u64) {
        // Gate mutation is generation-conditional. Never look up a later
        // generation when handling an old asynchronous completion.
        self.gate.mark_stale(session);
        let mut inner = self.inner.lock().expect("profile state");
        if inner
            .active
            .as_ref()
            .is_some_and(|active| active.session == session)
        {
            Self::reset_locked(&mut inner);
        }
        drop(inner);
        self.notify();
    }
    /// Validate/commit synchronously before the RawHandler can ACK. The caller
    /// must have decoded the exact typed response under independently pinned
    /// origin configuration. Store validation enforces all later durable floors.
    #[cfg(test)]
    pub fn commit(self: &Arc<Self>, decoded: Decoded) -> Result<()> {
        let session = self.gate.snapshot().generation;
        self.commit_for_session(decoded, session)
    }
    pub fn session_generation(&self) -> u64 {
        self.gate.snapshot().generation
    }
    pub fn commit_for_session(self: &Arc<Self>, decoded: Decoded, session: u64) -> Result<()> {
        let started = Instant::now();
        let sequence = decoded.sequence;
        let logical_generation = decoded.generation;
        let result = self.commit_inner(decoded, session);
        match &result {
            Ok(()) => tracing::info!(
                component = "issuer-profile-provider",
                stage = "durable-provider-commit",
                sequence,
                logical_generation,
                session_generation = session,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "native profile durably committed before ACK; complete-session admission remains separately gated"
            ),
            Err(error) => {
                #[cfg(test)]
                if let Some((entered, resume)) = self
                    .before_error_fence
                    .lock()
                    .expect("test error barrier")
                    .take()
                {
                    entered.send(()).expect("test error observer");
                    resume
                        .recv_timeout(Duration::from_secs(2))
                        .expect("test error release");
                }
                // A cancelled old commit must not erase a newer session's
                // independently committed live state.
                self.fail_closed_for_session(session);
                tracing::warn!(component="issuer-profile-provider", stage="durable-provider-commit", sequence, logical_generation,
                    session_generation=session, elapsed_ms=started.elapsed().as_millis() as u64, error=%error,
                    "native profile rejected; admission closed and existing TLS I/O cancelled");
            }
        }
        result
    }
    fn commit_inner(&self, decoded: Decoded, session: u64) -> Result<()> {
        let mut store = self.store.lock().expect("profile commit owner");
        ensure!(
            self.gate.snapshot().generation == session && !self.gate.is_revoked(),
            "commit belongs to a stale ADS session"
        );
        let received_wall = (self.clock)();
        let received_mono = Instant::now();
        let mut inner = self.inner.lock().expect("profile state");
        ensure!(
            received_wall >= inner.last_wall,
            "wall clock moved backwards"
        );
        inner.last_wall = received_wall;
        let was_open = self.gate.is_open();
        let previous = inner.record.clone();
        let sequence = decoded.sequence;
        let generation = decoded.generation;
        let digest = decoded.publication_digest.clone();
        let approved = decoded.approval_digest.clone();
        let until = decoded.valid_until;
        let at = decoded.published_at;
        let observation: Observation = decoded.reason.into();
        let mut next = ProfileCheckpoint {
            version: 1,
            origin: self.installation.origin.clone(),
            floors: Floors {
                sequence,
                logical_generation: generation,
                approval_digest: approved.clone(),
                publication_digest: digest.clone(),
            },
            observation,
            authority_generation: 0,
            authority_approval_digest: String::new(),
            published_unix: at.duration_since(UNIX_EPOCH)?.as_secs(),
            valid_until_unix: until.duration_since(UNIX_EPOCH)?.as_secs(),
            bindings: Vec::new(),
            anchors: None,
        };
        let mut publication = None;
        let mut material_changed = true;
        if let Some(candidate) = decoded.candidate {
            next.bindings = decoded
                .bindings
                .into_iter()
                .map(|b| Binding {
                    cluster: b.cluster_id,
                    domain: b.trust_domain,
                })
                .collect();
            next.bindings.sort_by(|a, b| a.cluster.cmp(&b.cluster));
            next.authority_generation = generation;
            next.authority_approval_digest = approved;
            let history = previous
                .as_ref()
                .map(ProfileCheckpoint::history)
                .transpose()?
                .flatten();
            let built = match (previous.as_ref(), history) {
                (Some(old), Some(history)) if sequence == old.floors.sequence => {
                    // Reconnect revalidates the same complete publication and
                    // fsyncs its exact saved record. Do not rebuild/erase history.
                    ensure!(
                        digest == old.floors.publication_digest
                            && generation == old.floors.logical_generation,
                        "same-sequence substitution"
                    );
                    let proposed = AnchorPublication::initial(candidate).checkpoint()?;
                    let saved = old
                        .anchors
                        .as_ref()
                        .context("missing saved anchor history")?;
                    ensure!(
                        proposed.root_der == saved.root_der
                            && proposed.local_domain == saved.local_domain
                            && proposed.pins == saved.pins
                            && next.bindings == old.bindings
                            && next.authority_approval_digest == old.authority_approval_digest
                            && next.published_unix == old.published_unix
                            && next.valid_until_unix == old.valid_until_unix
                            && old.observation == Observation::Validated,
                        "same-publication material/lease substitution"
                    );
                    history
                }
                (Some(old), Some(history)) => {
                    ensure!(
                        generation >= old.authority_generation,
                        "material generation rollback"
                    );
                    if generation > old.authority_generation {
                        history.restore_authoritative_snapshot(candidate)?
                    } else {
                        ensure!(
                            next.authority_approval_digest == old.authority_approval_digest,
                            "same material-generation substitution"
                        );
                        history.replace(candidate)?
                    }
                }
                (_, None) => AnchorPublication::initial(candidate),
                (None, Some(_)) => unreachable!("history without a record"),
            };
            next.anchors = Some(built.checkpoint()?);
            if let Some(old) = &previous {
                material_changed = old.authority_generation != next.authority_generation
                    || old.authority_approval_digest != next.authority_approval_digest
                    || old.bindings != next.bindings
                    || old.anchors.as_ref().map(|a| {
                        (
                            &a.root_der,
                            &a.local_domain,
                            &a.pins,
                            &a.fenced_spkis,
                            &a.drain_before,
                        )
                    }) != next.anchors.as_ref().map(|a| {
                        (
                            &a.root_der,
                            &a.local_domain,
                            &a.pins,
                            &a.fenced_spkis,
                            &a.drain_before,
                        )
                    });
            }
            publication = Some(Arc::new(built));
        } else {
            // Availability does not revoke approved keys. Preserve every piece
            // of cumulative authority history and advance only observation floors.
            if let Some(old) = &previous {
                next.authority_generation = old.authority_generation;
                next.authority_approval_digest = old.authority_approval_digest.clone();
                next.bindings = old.bindings.clone();
                next.anchors = old.anchors.clone();
            }
        }
        if material_changed || publication.is_none() {
            Self::reset_locked(&mut inner);
            self.notify();
            if was_open || publication.is_none() {
                self.gate.mark_stale(session);
            }
        }
        let staged_epoch = inner.epoch;
        drop(inner);
        // The live-state mutex is free while the bounded public record is
        // fsynced by the blocking worker. Old-authority I/O is already fenced.
        #[cfg(test)]
        if let Some((entered, resume)) =
            self.before_disk.lock().expect("test commit barrier").take()
        {
            entered.send(()).expect("test commit observer");
            resume
                .recv_timeout(Duration::from_secs(2))
                .expect("test commit release");
        }
        let receipt = match store.commit(next.clone(), received_wall) {
            Ok(receipt) => receipt,
            Err(error) => {
                if store.is_poisoned() {
                    self.poisoned.store(true, Ordering::Release);
                }
                return Err(error);
            }
        };
        let mut inner = self.inner.lock().expect("profile state");
        ensure!(
            receipt.sequence() == sequence && receipt.publication_digest() == digest,
            "checkpoint receipt does not match exact ADS publication"
        );
        inner.record = Some(next);
        if material_changed && was_open {
            drop(inner);
            self.gate.mark_stale(session);
            bail!("durable material change requires complete native ADS resync and drain");
        }
        let Some(publication) = publication else {
            bail!("authenticated issuer profile is unavailable");
        };
        ensure!(
            inner.epoch == staged_epoch
                && self.gate.snapshot().generation == session
                && !self.gate.is_revoked(),
            "ADS session changed while committing profile; history retained without activation"
        );
        let after = (self.clock)();
        ensure!(
            after >= received_wall && after < until,
            "profile expired/clock regressed during durable commit"
        );
        let duration = until.duration_since(received_wall)?;
        ensure!(
            duration <= Duration::from_secs(30),
            "profile lease exceeds bound"
        );
        let monotonic_until = received_mono + duration;
        ensure!(
            Instant::now() < monotonic_until,
            "profile expired during checkpoint commit"
        );
        inner.last_wall = after;
        inner.active = Some(Active {
            epoch: inner.epoch,
            session,
            until,
            monotonic_until,
            publication,
        });
        drop(inner);
        self.notify();
        Ok(())
    }
    pub fn acquire(self: &Arc<Self>) -> Result<Lease> {
        let now = (self.clock)();
        let mut inner = self.inner.lock().expect("profile state");
        ensure!(
            !self.poisoned.load(Ordering::Acquire) && now >= inner.last_wall,
            "trust store/clock unavailable"
        );
        inner.last_wall = now;
        let active = inner
            .active
            .as_ref()
            .context("issuer profile unavailable")?;
        ensure!(
            now < active.until
                && Instant::now() < active.monotonic_until
                && self.gate.open_generation() == Some(active.session),
            "issuer profile/session lease unavailable"
        );
        Ok(Lease {
            provider: self.clone(),
            active: active.clone(),
        })
    }
    fn current(&self, lease: &Lease) -> Result<Active> {
        let now = (self.clock)();
        let mut inner = self.inner.lock().expect("profile state");
        ensure!(
            !self.poisoned.load(Ordering::Acquire) && now >= inner.last_wall,
            "trust store/clock unavailable"
        );
        inner.last_wall = now;
        let active = inner
            .active
            .as_ref()
            .context("issuer profile unavailable")?;
        ensure!(
            active.epoch == lease.active.epoch
                && active.session == lease.active.session
                && self.gate.open_generation() == Some(active.session)
                && now < active.until
                && Instant::now() < active.monotonic_until,
            "issuer profile/session changed or expired"
        );
        Ok(active.clone())
    }
    /// Owns one participant for all TLS drivers. A new session cannot open until
    /// every old registered TLS I/O owner has dropped its underlying stream.
    pub async fn supervise(self: Arc<Self>) -> Result<()> {
        let participant = self.participant;
        let mut session = self.gate.subscribe();
        let mut changes = self.subscribe();
        loop {
            let snapshot = self.gate.snapshot();
            {
                let mut inner = self.inner.lock().expect("profile state");
                if let Some(active) = &inner.active {
                    let now = (self.clock)();
                    if now < inner.last_wall
                        || now >= active.until
                        || Instant::now() >= active.monotonic_until
                    {
                        // Fence while holding the state writer lock. A late
                        // renewal cannot reopen this expired session.
                        self.gate.mark_stale(active.session);
                        Self::reset_locked(&mut inner);
                        self.notify();
                    }
                }
            }
            if self.gate.needs_drain(snapshot.generation, participant) {
                let empty = self.inner.lock().expect("profile state").flows.is_empty();
                if empty {
                    self.gate.mark_drained(snapshot.generation, participant);
                    tracing::info!(
                        component = "issuer-profile-provider",
                        stage = "tls-drain-ack",
                        session_generation = snapshot.generation,
                        "all old native TLS I/O owners released before session drain acknowledgement"
                    );
                }
            }
            // A short bounded sweep also detects an administrator clock jump;
            // per-stream timers enforce the exact monotonic lease deadline.
            tokio::select! {
                _ = session.changed() => {},
                _ = changes.changed() => {},
                _ = self.drained.notified() => {},
                _ = tokio::time::sleep(Duration::from_millis(50)) => {},
            }
        }
    }
}
impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("epoch", &self.active.epoch)
            .field("session", &self.active.session)
            .finish_non_exhaustive()
    }
}
impl Lease {
    pub fn check_current(&self) -> Result<()> {
        self.provider.current(self).map(|_| ())
    }
    #[cfg(test)]
    pub fn epoch(&self) -> u64 {
        self.active.epoch
    }
    pub fn validate_local(
        &self,
        cert: &WorkloadCertificate,
        expected: &Identity,
        role: PeerRole,
    ) -> Result<()> {
        let active = self.provider.current(self)?;
        ensure!(
            cert.identity().as_ref() == Some(expected)
                && expected.trust_domain() == *active.publication.anchors().local_domain(),
            "local workload identity/domain does not match approved local cluster"
        );
        let chain: Vec<_> = cert.chain.iter().map(|c| c.der.clone()).collect();
        let peer = verify_peer_evidence(
            &cert.cert.der,
            &chain,
            active.publication.anchors(),
            UnixTime::since_unix_epoch((self.provider.clock)().duration_since(UNIX_EPOCH)?),
            role,
        )?;
        ensure!(
            active
                .publication
                .current_unfenced_signer(
                    &expected.trust_domain(),
                    peer.signer_spki(),
                    (self.provider.clock)()
                )
                .is_some(),
            "local SPIRE signer fenced"
        );
        Ok(())
    }
    pub fn publication(&self) -> Result<Arc<AnchorPublication>> {
        Ok(self.provider.current(self)?.publication)
    }
    /// Use the current verified peer issuer as the CRL root. The local SVID's
    /// bundle is unrelated to a remote cluster and must never be used here.
    pub fn peer(
        &self,
        ssl: &CommonState,
        role: PeerRole,
        expected: &[Identity],
        crl: Option<&Arc<tls::crl::CrlManager>>,
        reporter: Reporter,
    ) -> Result<(
        VerifiedPeer,
        Option<RevocationHandle>,
        Option<Arc<super::native_crl::Coverage>>,
    )> {
        let active = self.provider.current(self)?;
        let chain = ssl.peer_certificates().context("TLS peer chain missing")?;
        let (leaf, intermediates) = chain.split_first().context("TLS peer leaf missing")?;
        let now = (self.provider.clock)();
        let time = UnixTime::since_unix_epoch(now.duration_since(UNIX_EPOCH)?);
        let peer = verify_peer_evidence(
            leaf,
            intermediates,
            active.publication.anchors(),
            time,
            role,
        )?;
        if matches!(role, PeerRole::Server) {
            ensure!(
                expected.contains(peer.identity()),
                "unexpected destination workload identity"
            );
        }
        let signer = active
            .publication
            .current_unfenced_signer(&peer.identity().trust_domain(), peer.signer_spki(), now)
            .context("peer issuer fenced")?;
        let mut roots = RootCertStore::empty();
        roots.add(signer.clone())?;
        let roots = Arc::new(roots);
        let usage = match role {
            PeerRole::Client => webpki::KeyUsage::client_auth(),
            PeerRole::Server => webpki::KeyUsage::server_auth(),
        };
        let coverage = if let Some(manager) = crl {
            Some(super::native_crl::Coverage::new(
                manager.clone(),
                leaf.clone().into_owned(),
                signer,
                role,
                self.provider.clock,
            )?)
        } else {
            // Feature disabled is explicit. Authority pins/session still apply.
            verify_cert_chain(leaf, intermediates, &roots, time, usage, &[])
                .map_err(|e| anyhow::anyhow!("current peer signature verification: {e:?}"))?;
            None
        };
        let revocation = crl.map(|c| {
            c.register(ConnRegistration::from_conn(
                ssl,
                Some(peer.identity().clone()),
                roots,
                usage,
                reporter,
            ))
        });
        // Registration and all crypto occurred while the publication could have
        // changed. Recheck current epoch/session before releasing application I/O.
        self.provider.current(self)?;
        Ok((peer, revocation, coverage))
    }
    async fn invalidated(self, peer: Option<VerifiedPeer>, local_deadline: SystemTime) {
        let mut changes = self.provider.subscribe();
        let mut session = self.provider.gate.subscribe();
        loop {
            let Ok(active) = self.provider.current(&self) else {
                return;
            };
            let now = (self.provider.clock)();
            let mut until = active.until.min(local_deadline);
            if let Some(peer) = &peer {
                if super::domain_anchors::retained_tunnel(
                    &peer.retained_tunnel(),
                    &active.publication,
                    now,
                ) == super::domain_anchors::RetainedDecision::Drain
                {
                    return;
                }
                until = until.min(peer.deadline());
            }
            let Ok(remaining) = until.duration_since(now) else {
                return;
            };
            let deadline = active.monotonic_until.min(Instant::now() + remaining);
            tokio::select! {
                _ = changes.changed() => {}, _ = session.changed() => {},
                _ = tokio::time::sleep_until(deadline) => { return; },
            }
        }
    }
}
struct Flow {
    provider: Weak<ProfileProvider>,
    id: u64,
}
impl Drop for Flow {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.upgrade() {
            provider
                .inner
                .lock()
                .expect("profile state")
                .flows
                .remove(&self.id);
            provider.drained.notify_one();
        }
    }
}
/// No background task owns the socket. The H2 driver's pending read polls this
/// cancellation future, so lease/session loss wakes even an idle pooled tunnel.
/// A cancellation drops the actual underlying TCP stream or inner H2 stream.
pub(crate) struct ProfileIo<IO> {
    io: Option<IO>,
    lease: Option<Lease>,
    local_deadline: SystemTime,
    peer: Option<VerifiedPeer>,
    invalid: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    flow: Option<Flow>,
    crl_coverage: Option<Arc<super::native_crl::Coverage>>,
}
impl<IO: Unpin> ProfileIo<IO> {
    /// Inspect TLS metadata without exposing mutable unchecked application I/O.
    pub fn get_ref(&self) -> &IO {
        self.io.as_ref().expect("live TLS metadata")
    }
    pub fn new(io: IO, lease: Option<Lease>, local_deadline: SystemTime) -> Result<Self> {
        let flow = if let Some(lease) = &lease {
            lease.provider.current(lease)?;
            let mut inner = lease.provider.inner.lock().expect("profile state");
            inner.next_flow = inner
                .next_flow
                .checked_add(1)
                .context("TLS flow ID exhausted")?;
            let id = inner.next_flow;
            inner
                .flows
                .insert(id, (lease.active.session, lease.active.epoch));
            Some(Flow {
                provider: Arc::downgrade(&lease.provider),
                id,
            })
        } else {
            None
        };
        // If a session changed between the first validation and insertion,
        // drop the newly registered owner before releasing any TLS bytes.
        if let Some(lease) = &lease {
            lease.provider.current(lease)?;
        }
        let invalid = lease.as_ref().map(|l| {
            Box::pin(l.clone().invalidated(None, local_deadline))
                as Pin<Box<dyn Future<Output = ()> + Send>>
        });
        Ok(Self {
            io: Some(io),
            lease,
            local_deadline,
            peer: None,
            invalid,
            flow,
            crl_coverage: None,
        })
    }
    fn set_peer(&mut self, peer: VerifiedPeer) {
        self.peer = Some(peer.clone());
        if let Some(lease) = &self.lease {
            self.invalid = Some(Box::pin(
                lease.clone().invalidated(Some(peer), self.local_deadline),
            ));
        }
    }
    fn set_revocation(&mut self, mut receiver: watch::Receiver<bool>) {
        let profile = self.invalid.take();
        self.invalid = Some(Box::pin(async move {
            let revoked = async move {
                loop {
                    if *receiver.borrow_and_update() {
                        return;
                    }
                    if receiver.changed().await.is_err() {
                        return;
                    }
                }
            };
            tokio::select! {
                _ = async { match profile { Some(f) => f.await, None => std::future::pending().await } } => {},
                _ = revoked => {},
            }
        }));
    }
    fn set_crl_coverage(&mut self, coverage: Arc<super::native_crl::Coverage>) {
        let clock = self
            .lease
            .as_ref()
            .expect("native CRL requires profile lease")
            .provider
            .clock;
        self.crl_coverage = Some(coverage.clone());
        let previous = self.invalid.take();
        self.invalid = Some(Box::pin(async move {
            tokio::select! {
                _=async {match previous {Some(f)=>f.await,None=>std::future::pending().await}}=>{},
                _=coverage.invalidated(clock)=>{},
            }
        }));
    }
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        // Do not rely solely on a sleeping future: wall time can jump or a VM
        // can resume while the monotonic timer has not fired. Recheck on every
        // actual read/write poll before releasing any bytes to rustls/H2.
        let invalid_now = self.lease.as_ref().is_some_and(|lease| {
            let Ok(active) = lease.provider.current(lease) else {
                return true;
            };
            let now = (lease.provider.clock)();
            now >= self.local_deadline
                || self.peer.as_ref().is_some_and(|peer| {
                    super::domain_anchors::retained_tunnel(
                        &peer.retained_tunnel(),
                        &active.publication,
                        now,
                    ) == super::domain_anchors::RetainedDecision::Drain
                })
        });
        let missing_coverage = self.crl_coverage.as_ref().is_some_and(|coverage| {
            let clock = self
                .lease
                .as_ref()
                .expect("native CRL lease")
                .provider
                .clock;
            coverage.current(clock).is_err()
        });
        if self.io.is_none()
            || invalid_now
            || missing_coverage
            || self
                .invalid
                .as_mut()
                .is_some_and(|f| f.as_mut().poll(cx).is_ready())
        {
            // Drop the socket first, then release the drain-registration owner.
            self.io.take();
            self.flow.take();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "authenticated issuer profile/session expired or changed",
            ));
        }
        Ok(())
    }
}
impl<IO: AsyncRead + Unpin> AsyncRead for ProfileIo<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(e) = self.check(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(self.io.as_mut().expect("checked live I/O")).poll_read(cx, buf)
    }
}
impl<IO: AsyncWrite + Unpin> AsyncWrite for ProfileIo<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = self.check(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(self.io.as_mut().expect("checked live I/O")).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.check(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(self.io.as_mut().expect("checked live I/O")).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.check(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(self.io.as_mut().expect("checked live I/O")).poll_shutdown(cx)
    }
}

fn io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, error.to_string())
}
/// The lower guard controls handshake/idle ciphertext I/O. The upper guard
/// controls application plaintext that rustls may already have buffered.
pub(crate) type ServerTls<IO> = ProfileIo<tokio_rustls::server::TlsStream<ProfileIo<IO>>>;
pub(crate) type ClientTls<IO> = ProfileIo<tokio_rustls::client::TlsStream<ProfileIo<IO>>>;
/// The ordinary constructor is used only when the independently configured
/// native provider is absent. A configured but unavailable provider is an error.
pub(crate) async fn accept<IO: AsyncRead + AsyncWrite + Unpin>(
    cert: Arc<WorkloadCertificate>,
    lease: Option<Lease>,
    io: IO,
    crl: Option<Arc<tls::crl::CrlManager>>,
) -> Result<(ServerTls<IO>, Option<RevocationHandle>), tls::TlsError> {
    let config = match &lease {
        Some(l) => cert.pinned_server_config(
            l.publication()
                .map_err(|e| tls::TlsError::Handshake(io_error(e)))?,
            crl.clone(),
        )?,
        None => cert.server_config(crl.clone())?,
    };
    let deadline = cert.cert.expiry.not_after;
    let wrapped = ProfileIo::new(io, lease.clone(), deadline)
        .map_err(|e| tls::TlsError::Handshake(io_error(e)))?;
    let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(config))
        .accept(wrapped)
        .await
        .map_err(tls::TlsError::Handshake)?;
    let (peer, revocation, coverage) = if let Some(lease) = &lease {
        let (peer, revocation, coverage) = lease
            .peer(
                stream.get_ref().1,
                PeerRole::Client,
                &[],
                crl.as_ref(),
                Reporter::destination,
            )
            .map_err(|e| tls::TlsError::Handshake(io_error(e)))?;
        stream.get_mut().0.set_peer(peer.clone());
        if let Some(handle) = &revocation {
            stream.get_mut().0.set_revocation(
                handle
                    .tracked_receiver()
                    .map_err(tls::TlsError::Handshake)?,
            );
        }
        if let Some(coverage) = &coverage {
            stream.get_mut().0.set_crl_coverage(coverage.clone());
        }
        (Some(peer), revocation, coverage)
    } else {
        (
            None,
            crl.as_ref().map(|manager| {
                manager.register(ConnRegistration::from_conn(
                    stream.get_ref().1,
                    tls::identity(&tls::certificate_from_connection(stream.get_ref().1)),
                    cert.root_store(),
                    webpki::KeyUsage::client_auth(),
                    Reporter::destination,
                ))
            }),
            None,
        )
    };
    let configured = lease.is_some();
    let mut application = ProfileIo::new(stream, lease, deadline)
        .map_err(|e| tls::TlsError::Handshake(io_error(e)))?;
    if let Some(peer) = peer {
        application.set_peer(peer);
    }
    if let Some(coverage) = coverage {
        application.set_crl_coverage(coverage);
    }
    if configured && let Some(handle) = &revocation {
        application.set_revocation(
            handle
                .tracked_receiver()
                .map_err(tls::TlsError::Handshake)?,
        );
    }
    Ok((application, revocation))
}
pub(crate) async fn connect<IO: AsyncRead + AsyncWrite + Unpin>(
    cert: Arc<WorkloadCertificate>,
    lease: Option<Lease>,
    io: IO,
    expected: Vec<Identity>,
    crl: Option<Arc<tls::crl::CrlManager>>,
) -> io::Result<(ClientTls<IO>, Option<RevocationHandle>)> {
    let config = match &lease {
        Some(l) => cert.pinned_client_config(
            expected.clone(),
            l.publication().map_err(io_error)?,
            crl.clone(),
        ),
        None => cert.client_config(expected.clone(), crl.clone()),
    }
    .map_err(io_error)?;
    let deadline = cert.cert.expiry.not_after;
    let wrapped = ProfileIo::new(io, lease.clone(), deadline).map_err(io_error)?;
    let name = rustls::pki_types::ServerName::IpAddress(std::net::Ipv4Addr::UNSPECIFIED.into());
    let mut stream = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, wrapped)
        .await?;
    let (peer, revocation, coverage) = if let Some(lease) = &lease {
        let (peer, revocation, coverage) = lease
            .peer(
                stream.get_ref().1,
                PeerRole::Server,
                &expected,
                crl.as_ref(),
                Reporter::source,
            )
            .map_err(io_error)?;
        stream.get_mut().0.set_peer(peer.clone());
        if let Some(handle) = &revocation {
            stream
                .get_mut()
                .0
                .set_revocation(handle.tracked_receiver()?);
        }
        if let Some(coverage) = &coverage {
            stream.get_mut().0.set_crl_coverage(coverage.clone());
        }
        (Some(peer), revocation, coverage)
    } else {
        (
            None,
            crl.as_ref().map(|manager| {
                manager.register(ConnRegistration::from_conn(
                    stream.get_ref().1,
                    tls::identity(&tls::certificate_from_connection(stream.get_ref().1)),
                    cert.root_store(),
                    webpki::KeyUsage::server_auth(),
                    Reporter::source,
                ))
            }),
            None,
        )
    };
    let configured = lease.is_some();
    let mut application = ProfileIo::new(stream, lease, deadline).map_err(io_error)?;
    if let Some(peer) = peer {
        application.set_peer(peer);
    }
    if let Some(coverage) = coverage {
        application.set_crl_coverage(coverage);
    }
    if configured && let Some(handle) = &revocation {
        application.set_revocation(handle.tracked_receiver()?);
    }
    Ok((application, revocation))
}

/// Cancellation of the owning state-manager future must revoke admission even
/// when no ADS error path gets a chance to run.
pub(crate) struct RuntimeGuard(Arc<ProfileProvider>);
impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        self.0.fail_closed();
    }
}
impl ProfileProvider {
    pub fn runtime_guard(self: &Arc<Self>) -> RuntimeGuard {
        RuntimeGuard(self.clone())
    }
    pub(crate) fn clock(&self) -> fn() -> SystemTime {
        self.clock
    }
}
impl Drop for ProfileProvider {
    fn drop(&mut self) {
        self.gate.unregister_drain_participant(self.participant);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, SanType,
    };
    use serde_json::{Value, json};
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    fn fixture_clock() -> SystemTime {
        let f: Value = serde_json::from_str(include_str!("issuer-profile-v1.json")).unwrap();
        UNIX_EPOCH + Duration::from_secs(f["nowUnix"].as_str().unwrap().parse().unwrap())
    }
    fn expected(w: &Value) -> Expected {
        Expected {
            cluster: w["cluster"].as_str().unwrap().into(),
            node: w["node"].as_str().unwrap().into(),
            source_namespace: w["sourceNamespace"].as_str().unwrap().into(),
            source_name: w["sourceName"].as_str().unwrap().into(),
            source_uid: w["sourceUID"].as_str().unwrap().into(),
            output_namespace: w["outputNamespace"].as_str().unwrap().into(),
            output_name: w["outputName"].as_str().unwrap().into(),
            output_uid: w["outputUID"].as_str().unwrap().into(),
            root_pins: vec![w["rootSHA256"].as_str().unwrap().into()],
            minimum_sequence: 10,
            minimum_generation: 7,
            approval_digest_at_minimum: Some(w["approvalDigest"].as_str().unwrap().into()),
            publication_digest_at_minimum: Some(w["publicationDigest"].as_str().unwrap().into()),
        }
    }
    fn fixture() -> (Value, Expected) {
        let f: Value = serde_json::from_str(include_str!("issuer-profile-v1.json")).unwrap();
        let w = f["wire"].clone();
        let e = expected(&w);
        (w, e)
    }
    fn decode(w: &Value, e: &Expected, clock: fn() -> SystemTime) -> Decoded {
        super::super::issuer_profile_wire::decode(&serde_json::to_vec(w).unwrap(), e, clock())
            .unwrap()
    }
    fn opened(
        d: &Path,
        e: &Expected,
        clock: fn() -> SystemTime,
    ) -> (Arc<ProfileProvider>, XdsSessionGate, u64) {
        let gate = XdsSessionGate::new();
        let provider = ProfileProvider::open_with_clock(
            d,
            e,
            OpenMode::BootstrapEmptyDirectory,
            gate.clone(),
            clock,
        )
        .unwrap();
        let generation = gate.begin_session();
        (provider, gate, generation)
    }
    fn ready(provider: &ProfileProvider, gate: &XdsSessionGate, generation: u64) {
        gate.mark_drained(generation, provider.participant);
        gate.mark_snapshot_ready(generation);
    }
    fn advance(w: &Value, seq: u64) -> Value {
        let mut next = w.clone();
        next["sequence"] = json!(seq.to_string());
        next["publicationDigest"] = json!(format!("{seq:064x}"));
        next
    }
    #[test]
    fn durable_commit_precedes_activation_and_restart_requires_fresh_session() {
        let d = dir();
        let (w, e) = fixture();
        let (p, g, s) = opened(d.path(), &e, fixture_clock);
        assert!(p.acquire().is_err());
        p.commit(decode(&w, &e, fixture_clock)).unwrap();
        assert!(d.path().join("profile-state.json").is_file());
        assert!(
            p.acquire().is_err(),
            "profile ACK is not complete xDS readiness"
        );
        ready(&p, &g, s);
        let lease = p.acquire().unwrap();
        let history = lease.publication().unwrap().checkpoint().unwrap();
        drop(lease);
        p.fail_closed();
        drop(p);
        let gate = XdsSessionGate::new();
        let p = ProfileProvider::open_with_clock(
            d.path(),
            &e,
            OpenMode::Existing,
            gate.clone(),
            fixture_clock,
        )
        .unwrap();
        let generation = gate.begin_session();
        ready(&p, &gate, generation);
        assert!(
            p.acquire().is_err(),
            "disk history must not reactivate trust"
        );
        p.commit(decode(&w, &e, fixture_clock)).unwrap();
        assert_eq!(
            p.acquire()
                .unwrap()
                .publication()
                .unwrap()
                .checkpoint()
                .unwrap(),
            history
        );
    }
    #[test]
    fn unavailable_keeps_history_and_new_floor_then_recovers_without_erasing_fences() {
        let d = dir();
        let (w, e) = fixture();
        let (p, g, s) = opened(d.path(), &e, fixture_clock);
        p.commit(decode(&w, &e, fixture_clock)).unwrap();
        ready(&p, &g, s);
        let history = p.inner.lock().unwrap().record.clone().unwrap();
        let mut tombstone = advance(&w, 11);
        tombstone["state"] = json!("withdrawn");
        tombstone["reason"] = json!("SourceUnavailable");
        tombstone["validUntilUnix"] = tombstone["publishedUnix"].clone();
        tombstone["rootDER"] = Value::Null;
        tombstone["rootSHA256"] = json!("");
        tombstone["clusters"] = json!([]);
        assert!(p.commit(decode(&tombstone, &e, fixture_clock)).is_err());
        assert!(!g.is_open());
        assert!(p.acquire().is_err());
        let saved = p.inner.lock().unwrap().record.clone().unwrap();
        assert_eq!(saved.floors.sequence, 11);
        assert_eq!(saved.anchors, history.anchors);
        assert_eq!(saved.authority_generation, history.authority_generation);
        assert!(
            p.commit(decode(&w, &e, fixture_clock)).is_err(),
            "old sequence must not restore admission"
        );
        let s = g.begin_session();
        p.reset_session();
        p.commit(decode(&advance(&w, 12), &e, fixture_clock))
            .unwrap();
        ready(&p, &g, s);
        assert!(p.acquire().is_ok());
    }
    #[test]
    fn persistence_tamper_poison_never_falls_back_to_last_good_provider() {
        let d = dir();
        let (w, e) = fixture();
        let (p, g, s) = opened(d.path(), &e, fixture_clock);
        p.commit(decode(&w, &e, fixture_clock)).unwrap();
        ready(&p, &g, s);
        std::fs::write(d.path().join("profile-state.json"), b"{}").unwrap();
        assert!(
            p.commit(decode(&advance(&w, 11), &e, fixture_clock))
                .is_err()
        );
        assert!(p.store.lock().unwrap().is_poisoned());
        assert!(!g.is_open());
        assert!(p.acquire().is_err());
    }
    #[test]
    fn same_authority_renewal_keeps_epoch_but_material_change_requires_resync() {
        let d = dir();
        let (w, e) = fixture();
        let (p, g, s) = opened(d.path(), &e, fixture_clock);
        p.commit(decode(&w, &e, fixture_clock)).unwrap();
        ready(&p, &g, s);
        let lease = p.acquire().unwrap();
        let epoch = lease.epoch();
        p.commit(decode(&advance(&w, 11), &e, fixture_clock))
            .unwrap();
        assert_eq!(p.acquire().unwrap().epoch(), epoch);
        lease.check_current().unwrap();
        let mut new = advance(&w, 12);
        new["generation"] = json!("8");
        new["approvalDigest"] = json!("f".repeat(64));
        assert!(
            p.commit(decode(&new, &e, fixture_clock)).is_err(),
            "material change is durably staged, never mixed into an open session"
        );
        assert_eq!(
            p.inner
                .lock()
                .unwrap()
                .record
                .as_ref()
                .unwrap()
                .floors
                .sequence,
            12
        );
        assert!(lease.check_current().is_err());
        assert!(!g.is_open());
        let s = g.begin_session();
        p.reset_session();
        p.commit(decode(&new, &e, fixture_clock)).unwrap();
        ready(&p, &g, s);
        assert_ne!(p.acquire().unwrap().epoch(), epoch);
    }
    #[tokio::test(start_paused = true)]
    async fn idle_pending_tcp_read_is_woken_by_monotonic_lease_expiry() {
        let d = dir();
        let (w, e) = fixture();
        let (p, g, s) = opened(d.path(), &e, fixture_clock);
        p.commit(decode(&w, &e, fixture_clock)).unwrap();
        ready(&p, &g, s);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let mut io = ProfileIo::new(
            server,
            Some(p.acquire().unwrap()),
            fixture_clock() + Duration::from_secs(300),
        )
        .unwrap();
        let read = tokio::spawn(async move {
            let mut b = [0];
            io.read(&mut b).await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(31)).await;
        let err = read.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(p.inner.lock().unwrap().flows.is_empty());
        let mut client = client;
        let mut b = [0];
        assert_eq!(client.read(&mut b).await.unwrap(), 0);
    }
    #[tokio::test]
    async fn new_session_drain_barrier_waits_for_old_socket_owner() {
        let d = dir();
        let (w, e) = fixture();
        let (p, g, s) = opened(d.path(), &e, fixture_clock);
        p.commit(decode(&w, &e, fixture_clock)).unwrap();
        ready(&p, &g, s);
        let (a, _b) = tokio::io::duplex(64);
        let io = ProfileIo::new(
            a,
            Some(p.acquire().unwrap()),
            fixture_clock() + Duration::from_secs(300),
        )
        .unwrap();
        let supervisor = tokio::spawn(p.clone().supervise());
        let new = g.begin_session();
        p.reset_session();
        p.commit(decode(&w, &e, fixture_clock)).unwrap();
        g.mark_snapshot_ready(new);
        tokio::task::yield_now().await;
        assert!(
            !g.is_open(),
            "unpolled old I/O owner must hold the barrier closed"
        );
        drop(io);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !g.is_open() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(p.acquire().is_ok());
        supervisor.abort();
    }
    #[test]
    fn cancelling_runtime_owner_revokes_even_without_an_ads_error_callback() {
        let d = dir();
        let (w, e) = fixture();
        let (p, g, s) = opened(d.path(), &e, fixture_clock);
        p.commit(decode(&w, &e, fixture_clock)).unwrap();
        ready(&p, &g, s);
        let owner = p.runtime_guard();
        drop(owner);
        assert!(!g.is_open());
        assert!(p.acquire().is_err());
    }

    type Ca = CertifiedIssuer<'static, KeyPair>;
    fn ca_params(name: &str) -> CertificateParams {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.distinguished_name.push(DnType::CommonName, name);
        p
    }
    fn ca(name: &str, parent: Option<&Ca>) -> Ca {
        let key = KeyPair::generate().unwrap();
        match parent {
            Some(parent) => CertifiedIssuer::signed_by(ca_params(name), key, parent).unwrap(),
            None => CertifiedIssuer::self_signed(ca_params(name), key).unwrap(),
        }
    }
    fn sha(data: &[u8]) -> String {
        let crypto = super::super::lib::provider();
        let hasher = crypto
            .cipher_suites
            .iter()
            .filter_map(|s| s.tls13())
            .map(|s| s.common.hash_provider)
            .find(|h| h.algorithm() == rustls::crypto::hash::HashAlgorithm::SHA256)
            .unwrap();
        hasher
            .hash(data)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    fn workload(domain: &str, signer: &Ca) -> Arc<WorkloadCertificate> {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::ExplicitNoCa;
        p.serial_number = Some(rcgen::SerialNumber::from(42u64));
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        p.subject_alt_names = vec![SanType::URI(
            format!("spiffe://{domain}/ns/orders/sa/api")
                .try_into()
                .unwrap(),
        )];
        let cert = p.signed_by(&key, &**signer).unwrap();
        Arc::new(
            WorkloadCertificate::new(
                key.serialize_pem().as_bytes(),
                cert.pem().as_bytes(),
                vec![signer.pem().as_bytes()],
            )
            .unwrap(),
        )
    }
    fn live_wire(cluster: &str, root: &Ca, a: &Ca, b: &Ca) -> Value {
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        json!({"wireVersion":1,"cluster":cluster,"node":format!("{cluster}-worker"),
        "sourceNamespace":"cmtc-system","sourceName":"issuer-approval","sourceUID":"fixture-source-uid",
        "outputNamespace":"cmtc-system","outputName":"issuer-publication","outputUID":"fixture-output-uid",
        "sequence":"10","generation":"7","approvalDigest":"a".repeat(64),"publicationDigest":"b".repeat(64),
        "state":"published","reason":"Validated","publishedUnix":at.to_string(),"validUntilUnix":(at+30).to_string(),
        "rootSHA256":sha(root.der()),"rootDER":STANDARD.encode(root.der()),"clusters":[
            {"clusterID":"cmtc-a","trustDomain":"cmtc-a.mesh.example","issuers":[{"certificateDER":STANDARD.encode(a.der()),"spkiSHA256":sha(&super::super::domain_anchors::spki_der(a.der()).unwrap())}]},
            {"clusterID":"cmtc-b","trustDomain":"cmtc-b.mesh.example","issuers":[{"certificateDER":STANDARD.encode(b.der()),"spkiSHA256":sha(&super::super::domain_anchors::spki_der(b.der()).unwrap())}]}
        ]})
    }
    #[tokio::test]
    async fn native_both_roles_tls_rejects_wrong_local_domain_and_drains_idle_live_sockets() {
        let root = ca("root", None);
        let a = ca("a", Some(&root));
        let b = ca("b", Some(&root));
        let ca = workload("cmtc-a.mesh.example", &a);
        let cb = workload("cmtc-b.mesh.example", &b);
        let wa = live_wire("cmtc-a", &root, &a, &b);
        let wb = live_wire("cmtc-b", &root, &a, &b);
        let ea = expected(&wa);
        let eb = expected(&wb);
        let da = dir();
        let db = dir();
        let (pa, ga, sa) = opened(da.path(), &ea, SystemTime::now);
        let (pb, gb, sb) = opened(db.path(), &eb, SystemTime::now);
        pa.commit(decode(&wa, &ea, SystemTime::now)).unwrap();
        pb.commit(decode(&wb, &eb, SystemTime::now)).unwrap();
        ready(&pa, &ga, sa);
        ready(&pb, &gb, sb);
        let la = pa.acquire().unwrap();
        let lb = pb.acquire().unwrap();
        la.validate_local(&ca, &ca.identity().unwrap(), PeerRole::Client)
            .unwrap();
        lb.validate_local(&cb, &cb.identity().unwrap(), PeerRole::Server)
            .unwrap();
        assert!(
            la.validate_local(&cb, &cb.identity().unwrap(), PeerRole::Client)
                .is_err()
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = async {
            let raw = TcpStream::connect(address).await.unwrap();
            connect(ca, Some(la), raw, vec![cb.identity().unwrap()], None)
                .await
                .unwrap()
                .0
        };
        let server = async {
            let (raw, _) = listener.accept().await.unwrap();
            accept(cb.clone(), Some(lb), raw, None).await.unwrap().0
        };
        let (mut client, mut server) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(client, server)
        })
        .await
        .unwrap();
        client.write_all(b"proved").await.unwrap();
        let mut buf = [0; 6];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"proved");
        // Both sides are idle. Revoke just the client session. Its pending read
        // must wake and drop the TCP owner; the peer must then observe closure.
        let waiting = tokio::spawn(async move {
            let mut b = [0];
            client.read(&mut b).await
        });
        ga.mark_stale(sa);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), waiting)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        let mut b = [0];
        let closed = tokio::time::timeout(Duration::from_secs(2), server.read(&mut b))
            .await
            .unwrap();
        assert!(closed.is_err() || matches!(closed, Ok(0)));
        assert!(pa.inner.lock().unwrap().flows.is_empty());
    }
    #[test]
    fn withdrawn_key_history_survives_restore_and_same_generation_cannot_erase_it() {
        let d = dir();
        let (w, e) = fixture();
        let (p, g, s) = opened(d.path(), &e, fixture_clock);
        p.commit(decode(&w, &e, fixture_clock)).unwrap();
        ready(&p, &g, s);
        let mut removed = advance(&w, 11);
        removed["generation"] = json!("8");
        removed["approvalDigest"] = json!("e".repeat(64));
        removed["clusters"]
            .as_array_mut()
            .unwrap()
            .retain(|c| c["clusterID"] == "cmtc-a");
        assert!(p.commit(decode(&removed, &e, fixture_clock)).is_err());
        let s = g.begin_session();
        p.reset_session();
        p.commit(decode(&removed, &e, fixture_clock)).unwrap();
        ready(&p, &g, s);
        let old = p.inner.lock().unwrap().record.clone().unwrap();
        assert!(!old.anchors.as_ref().unwrap().fenced_spkis.is_empty());
        let mut unauthorized = advance(&w, 12);
        unauthorized["generation"] = json!("8");
        unauthorized["approvalDigest"] = json!("e".repeat(64));
        assert!(p.commit(decode(&unauthorized, &e, fixture_clock)).is_err());
        assert_eq!(
            p.inner
                .lock()
                .unwrap()
                .record
                .as_ref()
                .unwrap()
                .floors
                .sequence,
            11
        );
        let mut restored = advance(&w, 13);
        restored["generation"] = json!("9");
        restored["approvalDigest"] = json!("f".repeat(64));
        let s = g.begin_session();
        p.reset_session();
        p.commit(decode(&restored, &e, fixture_clock)).unwrap();
        ready(&p, &g, s);
        let saved = p.inner.lock().unwrap().record.clone().unwrap();
        let cutoffs = &saved.anchors.as_ref().unwrap().drain_before;
        assert!(
            !cutoffs.is_empty(),
            "authoritative restore must retain old-connection cutoffs"
        );
        drop(p);
        let gate = XdsSessionGate::new();
        let p =
            ProfileProvider::open_with_clock(d.path(), &e, OpenMode::Existing, gate, fixture_clock)
                .unwrap();
        assert_eq!(
            p.inner.lock().unwrap().record.as_ref().unwrap().anchors,
            saved.anchors
        );
        assert!(p.acquire().is_err());
    }
    #[tokio::test]
    async fn native_nested_hbone_drains_actual_inner_tls_and_idle_outer_h2_driver() {
        let root = ca("root", None);
        let a = ca("a", Some(&root));
        let b = ca("b", Some(&root));
        let ca = workload("cmtc-a.mesh.example", &a);
        let cb = workload("cmtc-b.mesh.example", &b);
        let wa = live_wire("cmtc-a", &root, &a, &b);
        let wb = live_wire("cmtc-b", &root, &a, &b);
        let ea = expected(&wa);
        let eb = expected(&wb);
        let da = dir();
        let db = dir();
        let (pa, ga, sa) = opened(da.path(), &ea, SystemTime::now);
        let (pb, gb, sb) = opened(db.path(), &eb, SystemTime::now);
        pa.commit(decode(&wa, &ea, SystemTime::now)).unwrap();
        pb.commit(decode(&wb, &eb, SystemTime::now)).unwrap();
        ready(&pa, &ga, sa);
        ready(&pb, &gb, sb);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = async {
            connect(
                ca.clone(),
                Some(pa.acquire().unwrap()),
                TcpStream::connect(address).await.unwrap(),
                vec![cb.identity().unwrap()],
                None,
            )
            .await
            .unwrap()
            .0
        };
        let server = async {
            let (raw, _) = listener.accept().await.unwrap();
            accept(cb.clone(), Some(pb.acquire().unwrap()), raw, None)
                .await
                .unwrap()
                .0
        };
        let (client, server) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(client, server)
        })
        .await
        .unwrap();
        let (_drain, drain) = crate::drain::new();
        let (_force, force) = watch::channel(());
        let (req_tx, mut req_rx) = tokio::sync::mpsc::unbounded_channel();
        let cfg = Arc::new(crate::test_helpers::test_config());
        let server_task = tokio::spawn(crate::proxy::h2::server::serve_connection(
            cfg.clone(),
            server,
            drain,
            force,
            None,
            move |req| {
                let _ = req_tx.send(req);
                async {}
            },
        ));
        let (_stop, stop) = watch::channel(false);
        let key = crate::proxy::h2::client::WorkloadKey {
            src_id: ca.identity().unwrap(),
            dst_id: vec![cb.identity().unwrap()],
            src: "127.0.0.1".parse().unwrap(),
            dst: address,
        };
        let mut sender = crate::proxy::h2::client::spawn_connection(
            cfg,
            client,
            stop,
            key,
            None,
            Default::default(),
        )
        .await
        .unwrap();
        sender.bind_profile(Some(pa.acquire().unwrap()));
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("http://example.com")
            .body(())
            .unwrap();
        let opening = sender.send_request(request);
        let responding = async {
            let req = req_rx.recv().await.unwrap();
            req.send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap()
        };
        let (client_inner, server_inner) = tokio::join!(opening, responding);
        let client_inner = crate::proxy::h2::TokioH2Stream::new(client_inner.unwrap().0);
        let server_inner = crate::proxy::h2::TokioH2Stream::new(server_inner);
        let client = connect(
            ca.clone(),
            Some(pa.acquire().unwrap()),
            client_inner,
            vec![cb.identity().unwrap()],
            None,
        );
        let server = accept(cb.clone(), Some(pb.acquire().unwrap()), server_inner, None);
        let (client, server) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(client, server)
        })
        .await
        .unwrap();
        let (mut client, _) = client.unwrap();
        let (mut server, _) = server.unwrap();
        client.write_all(b"inner").await.unwrap();
        let mut data = [0; 5];
        server.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"inner");
        assert_eq!(pa.inner.lock().unwrap().flows.len(), 4);
        assert_eq!(pb.inner.lock().unwrap().flows.len(), 4);
        let client_wait = tokio::spawn(async move {
            let mut b = [0];
            client.read(&mut b).await
        });
        let server_wait = tokio::spawn(async move {
            let mut b = [0];
            server.read(&mut b).await
        });
        // Actual server lease loss invalidates BOTH nested layers, including an
        // outer driver that otherwise has no application traffic to wake it.
        pb.fail_closed();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), server_wait)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        let result = tokio::time::timeout(Duration::from_secs(2), client_wait)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_err() || matches!(result, Ok(0)));
        let _ = tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("outer H2 server must terminate")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if pa.inner.lock().unwrap().flows.is_empty()
                    && pb.inner.lock().unwrap().flows.is_empty()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    fn signed_crl(signer: &Ca, revoked: bool, number: u64) -> String {
        use rcgen::{
            CertificateRevocationListParams, KeyIdMethod, RevocationReason, RevokedCertParams,
            SerialNumber,
        };
        let now = time::OffsetDateTime::now_utc();
        CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(1),
            crl_number: SerialNumber::from(number),
            issuing_distribution_point: None,
            revoked_certs: if revoked {
                vec![RevokedCertParams {
                    serial_number: SerialNumber::from(42u64),
                    revocation_time: now,
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                }]
            } else {
                vec![]
            },
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(signer)
        .unwrap()
        .pem()
        .unwrap()
    }
    #[tokio::test]
    async fn native_peer_root_registration_enforces_live_crl_both_roles_and_signed_empty_recovery()
    {
        for inbound in [true, false] {
            let root = ca("root", None);
            let a = ca("a", Some(&root));
            let b = ca("b", Some(&root));
            let ca = workload("cmtc-a.mesh.example", &a);
            let cb = workload("cmtc-b.mesh.example", &b);
            let wa = live_wire("cmtc-a", &root, &a, &b);
            let wb = live_wire("cmtc-b", &root, &a, &b);
            let ea = expected(&wa);
            let eb = expected(&wb);
            let da = dir();
            let db = dir();
            let (pa, ga, sa) = opened(da.path(), &ea, SystemTime::now);
            let (pb, gb, sb) = opened(db.path(), &eb, SystemTime::now);
            pa.commit(decode(&wa, &ea, SystemTime::now)).unwrap();
            pb.commit(decode(&wb, &eb, SystemTime::now)).unwrap();
            ready(&pa, &ga, sa);
            ready(&pb, &gb, sb);
            let file = tempfile::NamedTempFile::new().unwrap();
            let signer = if inbound { &a } else { &b };
            std::fs::write(file.path(), signed_crl(signer, false, 1)).unwrap();
            let manager = Arc::new(
                tls::crl::CrlManager::new(
                    file.path().to_path_buf(),
                    crate::test_helpers::helpers::test_proxy_metrics(),
                )
                .unwrap(),
            );
            for revoked_phase in [true, false] {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let client = async {
                    connect(
                        ca.clone(),
                        Some(pa.acquire().unwrap()),
                        TcpStream::connect(address).await.unwrap(),
                        vec![cb.identity().unwrap()],
                        (!inbound).then(|| manager.clone()),
                    )
                    .await
                    .unwrap()
                };
                let server = async {
                    let (raw, _) = listener.accept().await.unwrap();
                    accept(
                        cb.clone(),
                        Some(pb.acquire().unwrap()),
                        raw,
                        inbound.then(|| manager.clone()),
                    )
                    .await
                    .unwrap()
                };
                let ((mut client, _client_revocation), (mut server, _server_revocation)) =
                    tokio::time::timeout(Duration::from_secs(5), async {
                        tokio::join!(client, server)
                    })
                    .await
                    .unwrap();
                client.write_all(b"proof").await.unwrap();
                let mut data = [0; 5];
                server.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"proof");
                if revoked_phase {
                    let client_wait = tokio::spawn(async move {
                        let mut b = [0];
                        client.read(&mut b).await
                    });
                    let server_wait = tokio::spawn(async move {
                        let mut b = [0];
                        server.read(&mut b).await
                    });
                    std::fs::write(file.path(), signed_crl(signer, true, 2)).unwrap();
                    manager.load_crl().unwrap();
                    let (client, server) = tokio::time::timeout(Duration::from_secs(2), async {
                        tokio::join!(client_wait, server_wait)
                    })
                    .await
                    .unwrap();
                    let checked = if inbound {
                        server.unwrap()
                    } else {
                        client.unwrap()
                    };
                    assert!(
                        checked.is_err(),
                        "verified remote signer must be the revocation root"
                    );
                    std::fs::write(file.path(), signed_crl(signer, false, 3)).unwrap();
                    manager.load_crl().unwrap();
                } // The second real handshake proves signed-empty recovery with
                // the same provider, without deleting CRLs or restarting it.
            }
        }
    }

    #[test]
    fn old_blocking_material_commit_cannot_revoke_new_ads_generation() {
        let d = dir();
        let (w, e) = fixture();
        let (p, g, s) = opened(d.path(), &e, fixture_clock);
        p.commit(decode(&w, &e, fixture_clock)).unwrap();
        ready(&p, &g, s);
        let mut changed = advance(&w, 11);
        changed["generation"] = json!("8");
        changed["approvalDigest"] = json!("f".repeat(64));
        let decoded = decode(&changed, &e, fixture_clock);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        *p.before_disk.lock().unwrap() = Some((entered_tx, resume_rx));
        let worker = p.clone();
        let thread = std::thread::spawn(move || worker.commit_for_session(decoded, s));
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let next = g.begin_session();
        p.reset_session();
        resume_tx.send(()).unwrap();
        assert!(thread.join().unwrap().is_err());
        assert_eq!(g.snapshot().generation, next);
        assert!(
            !g.is_revoked(),
            "old commit completion must address only its captured session"
        );
        assert_eq!(
            p.inner
                .lock()
                .unwrap()
                .record
                .as_ref()
                .unwrap()
                .floors
                .sequence,
            11
        );
        assert!(p.acquire().is_err());
        p.commit(decode(&changed, &e, fixture_clock)).unwrap();
        ready(&p, &g, next);
        assert!(p.acquire().is_ok());
    }

    #[test]
    fn old_error_completion_cannot_clear_new_committed_active_provider() {
        let d = dir();
        let (w, e) = fixture();
        let (p, g, s) = opened(d.path(), &e, fixture_clock);
        p.commit(decode(&w, &e, fixture_clock)).unwrap();
        ready(&p, &g, s);
        let mut changed = advance(&w, 11);
        changed["generation"] = json!("8");
        changed["approvalDigest"] = json!("f".repeat(64));
        let decoded = decode(&changed, &e, fixture_clock);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        *p.before_error_fence.lock().unwrap() = Some((entered_tx, resume_rx));
        let worker = p.clone();
        let thread = std::thread::spawn(move || worker.commit_for_session(decoded, s));
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let next = g.begin_session();
        p.reset_session();
        p.commit(decode(&changed, &e, fixture_clock)).unwrap();
        ready(&p, &g, next);
        let lease = p.acquire().unwrap();
        resume_tx.send(()).unwrap();
        assert!(thread.join().unwrap().is_err());
        assert_eq!(g.open_generation(), Some(next));
        lease.check_current().unwrap();
        assert!(p.acquire().is_ok());
    }

    /// One TLS application record contains AB. Reading A authenticates and
    /// decrypts that whole record, leaving B in rustls' plaintext buffer.
    /// No second socket read is needed to expose B, so a ciphertext-only guard
    /// cannot enforce the application admission boundary.
    #[tokio::test]
    async fn buffered_tls_plaintext_is_not_released_after_session_or_lease_loss() {
        for inbound in [true, false] {
            for expire in [false, true] {
                let root = ca("root", None);
                let a = ca("a", Some(&root));
                let b = ca("b", Some(&root));
                let ca = workload("cmtc-a.mesh.example", &a);
                let cb = workload("cmtc-b.mesh.example", &b);
                let wa = live_wire("cmtc-a", &root, &a, &b);
                let wb = live_wire("cmtc-b", &root, &a, &b);
                let ea = expected(&wa);
                let eb = expected(&wb);
                let da = dir();
                let db = dir();
                let (pa, ga, sa) = opened(da.path(), &ea, SystemTime::now);
                let (pb, gb, sb) = opened(db.path(), &eb, SystemTime::now);
                pa.commit(decode(&wa, &ea, SystemTime::now)).unwrap();
                pb.commit(decode(&wb, &eb, SystemTime::now)).unwrap();
                ready(&pa, &ga, sa);
                ready(&pb, &gb, sb);
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let client = async {
                    connect(
                        ca.clone(),
                        Some(pa.acquire().unwrap()),
                        TcpStream::connect(address).await.unwrap(),
                        vec![cb.identity().unwrap()],
                        None,
                    )
                    .await
                    .unwrap()
                    .0
                };
                let server = async {
                    let (raw, _) = listener.accept().await.unwrap();
                    accept(cb.clone(), Some(pb.acquire().unwrap()), raw, None)
                        .await
                        .unwrap()
                        .0
                };
                let (mut client, mut server) =
                    tokio::time::timeout(Duration::from_secs(5), async {
                        tokio::join!(client, server)
                    })
                    .await
                    .unwrap();
                let mut first = [0; 1];
                let mut second = [0; 1];
                if inbound {
                    client.write_all(b"AB").await.unwrap();
                    client.flush().await.unwrap();
                    server.read_exact(&mut first).await.unwrap();
                } else {
                    server.write_all(b"AB").await.unwrap();
                    server.flush().await.unwrap();
                    client.read_exact(&mut first).await.unwrap();
                }
                assert_eq!(&first, b"A");
                if expire {
                    tokio::time::pause();
                    tokio::time::advance(Duration::from_secs(31)).await;
                } else if inbound {
                    gb.mark_stale(sb);
                } else {
                    ga.mark_stale(sa);
                }
                let denied = if inbound {
                    server.read(&mut second).await
                } else {
                    client.read(&mut second).await
                };
                if expire {
                    tokio::time::resume();
                }
                assert!(
                    denied.is_err(),
                    "buffered B must not escape after loss: inbound={inbound}, expire={expire}, result={denied:?}"
                );
                let error = denied.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
                assert_eq!(
                    &second,
                    &[0],
                    "denial must not mutate the destination buffer"
                );
            }
        }
    }

    #[tokio::test]
    async fn buffered_tls_plaintext_is_not_released_after_actual_crl_revocation() {
        for inbound in [true, false] {
            let root = ca("root", None);
            let a = ca("a", Some(&root));
            let b = ca("b", Some(&root));
            let ca = workload("cmtc-a.mesh.example", &a);
            let cb = workload("cmtc-b.mesh.example", &b);
            let wa = live_wire("cmtc-a", &root, &a, &b);
            let wb = live_wire("cmtc-b", &root, &a, &b);
            let ea = expected(&wa);
            let eb = expected(&wb);
            let da = dir();
            let db = dir();
            let (pa, ga, sa) = opened(da.path(), &ea, SystemTime::now);
            let (pb, gb, sb) = opened(db.path(), &eb, SystemTime::now);
            pa.commit(decode(&wa, &ea, SystemTime::now)).unwrap();
            pb.commit(decode(&wb, &eb, SystemTime::now)).unwrap();
            ready(&pa, &ga, sa);
            ready(&pb, &gb, sb);
            let file = tempfile::NamedTempFile::new().unwrap();
            let signer = if inbound { &a } else { &b };
            std::fs::write(file.path(), signed_crl(signer, false, 1)).unwrap();
            let manager = Arc::new(
                tls::crl::CrlManager::new(
                    file.path().to_path_buf(),
                    crate::test_helpers::helpers::test_proxy_metrics(),
                )
                .unwrap(),
            );
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let client = async {
                connect(
                    ca.clone(),
                    Some(pa.acquire().unwrap()),
                    TcpStream::connect(address).await.unwrap(),
                    vec![cb.identity().unwrap()],
                    (!inbound).then(|| manager.clone()),
                )
                .await
                .unwrap()
            };
            let server = async {
                let (raw, _) = listener.accept().await.unwrap();
                accept(
                    cb.clone(),
                    Some(pb.acquire().unwrap()),
                    raw,
                    inbound.then(|| manager.clone()),
                )
                .await
                .unwrap()
            };
            let ((mut client, _client_revocation), (mut server, _server_revocation)) =
                tokio::time::timeout(Duration::from_secs(5), async {
                    tokio::join!(client, server)
                })
                .await
                .unwrap();
            let mut first = [0; 1];
            let mut second = [0; 1];
            if inbound {
                client.write_all(b"AB").await.unwrap();
                client.flush().await.unwrap();
                server.read_exact(&mut first).await.unwrap();
            } else {
                server.write_all(b"AB").await.unwrap();
                server.flush().await.unwrap();
                client.read_exact(&mut first).await.unwrap();
            }
            assert_eq!(&first, b"A");
            let handle = if inbound {
                _server_revocation.as_ref().unwrap()
            } else {
                _client_revocation.as_ref().unwrap()
            };
            let mut revoked = handle.tracked_receiver().unwrap();
            std::fs::write(file.path(), signed_crl(signer, true, 2)).unwrap();
            manager.load_crl().unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while !*revoked.borrow_and_update() {
                    revoked.changed().await.unwrap();
                }
            })
            .await
            .unwrap();
            let denied = if inbound {
                server.read(&mut second).await
            } else {
                client.read(&mut second).await
            };
            assert!(
                denied.is_err(),
                "already-buffered plaintext must be discarded on CRL revocation: inbound={inbound}, result={denied:?}"
            );
            assert_eq!(&second, &[0]);
        }
    }

    #[tokio::test]
    async fn pending_pooled_connect_response_rechecks_lease_before_admission() {
        for revoke in [false, true] {
            let d = dir();
            let (w, e) = fixture();
            let (p, g, s) = opened(d.path(), &e, fixture_clock);
            p.commit(decode(&w, &e, fixture_clock)).unwrap();
            ready(&p, &g, s);
            // Isolate the H2 sender's admission contract. This real H2 transport
            // intentionally lacks a ProfileIo underneath, so a lower-layer
            // disconnect cannot accidentally make this test pass.
            let (client, server) = tokio::io::duplex(64 * 1024);
            let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            let server_task = tokio::spawn(async move {
                let mut connection = h2::server::handshake(server).await.unwrap();
                let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
                seen_tx.send(()).unwrap();
                release_rx.await.unwrap();
                let _live_response = respond
                    .send_response(
                        http::Response::builder().status(200).body(()).unwrap(),
                        false,
                    )
                    .unwrap();
                while connection.accept().await.is_some() {}
            });
            let (stop_tx, stop_rx) = watch::channel(false);
            let key = crate::proxy::h2::client::WorkloadKey {
                src_id: Identity::default(),
                dst_id: vec![Identity::default()],
                src: "127.0.0.1".parse().unwrap(),
                dst: "127.0.0.2:15008".parse().unwrap(),
            };
            let mut sender = crate::proxy::h2::client::spawn_connection(
                Arc::new(crate::test_helpers::test_config()),
                client,
                stop_rx,
                key,
                None,
                Default::default(),
            )
            .await
            .unwrap();
            sender.bind_profile(Some(p.acquire().unwrap()));
            let pending = tokio::spawn(async move {
                sender
                    .send_request(
                        http::Request::builder()
                            .method(http::Method::CONNECT)
                            .uri("http://example.com")
                            .body(())
                            .unwrap(),
                    )
                    .await
            });
            tokio::time::timeout(Duration::from_secs(2), seen_rx)
                .await
                .unwrap()
                .unwrap();
            if revoke {
                g.mark_stale(s);
            }
            release_tx.send(()).unwrap();
            let result = tokio::time::timeout(Duration::from_secs(2), pending)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                result.is_err(),
                revoke,
                "valid control must succeed; revoked response must not become an admitted stream"
            );
            let _ = stop_tx.send(true);
            server_task.abort();
            let _ = server_task.await;
        }
    }
    fn native_crl_window(signer: &Ca, revoked: bool, number: u64, start: i64, end: i64) -> String {
        use rcgen::{
            CertificateRevocationListParams, KeyIdMethod, RevocationReason, RevokedCertParams,
            SerialNumber,
        };
        let now = time::OffsetDateTime::now_utc();
        CertificateRevocationListParams {
            this_update: now + time::Duration::seconds(start),
            next_update: now + time::Duration::seconds(end),
            crl_number: SerialNumber::from(number),
            issuing_distribution_point: None,
            revoked_certs: if revoked {
                vec![RevokedCertParams {
                    serial_number: SerialNumber::from(42u64),
                    revocation_time: now,
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                }]
            } else {
                vec![]
            },
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(signer)
        .unwrap()
        .pem()
        .unwrap()
    }

    #[test]
    fn native_strict_crl_denies_unknown_stale_wrong_key_ambiguous_and_recovers_signed_empty() {
        use super::super::native_crl::Coverage;
        let root = ca("root", None);
        let signer = ca("same-issuer-name", Some(&root));
        let wrong_key = ca("same-issuer-name", Some(&root));
        let cert = workload("cmtc-a.mesh.example", &signer);
        for case in [
            "missing",
            "empty",
            "wrong-key-same-DN",
            "expired",
            "future",
            "revoked",
            "duplicate",
            "oversized-count",
        ] {
            let directory = dir();
            let path = directory.path().join("crl.pem");
            let valid = native_crl_window(&signer, false, 1, -1, 86400);
            let data = match case {
                "missing" => None,
                "empty" => Some(String::new()),
                "wrong-key-same-DN" => Some(native_crl_window(&wrong_key, false, 1, -1, 86400)),
                "expired" => Some(native_crl_window(&signer, false, 1, -172800, -86400)),
                "future" => Some(native_crl_window(&signer, false, 1, 3600, 86400)),
                "revoked" => Some(native_crl_window(&signer, true, 1, -1, 86400)),
                "duplicate" => Some(valid.clone() + &valid),
                "oversized-count" => Some(valid.repeat(33)),
                _ => unreachable!(),
            };
            if let Some(data) = data {
                std::fs::write(&path, data).unwrap();
            }
            let manager = Arc::new(
                tls::crl::CrlManager::new(
                    path.clone(),
                    crate::test_helpers::helpers::test_proxy_metrics(),
                )
                .unwrap(),
            );
            for role in [PeerRole::Client, PeerRole::Server] {
                assert!(
                    Coverage::new(
                        manager.clone(),
                        cert.cert.der.clone(),
                        signer.der().clone(),
                        role,
                        SystemTime::now
                    )
                    .is_err(),
                    "native Some(manager) must deny {case}, role={role:?}"
                );
            }
            std::fs::write(&path, native_crl_window(&signer, false, 2, -1, 86400)).unwrap();
            manager.load_crl().unwrap();
            for role in [PeerRole::Client, PeerRole::Server] {
                let coverage = Coverage::new(
                    manager.clone(),
                    cert.cert.der.clone(),
                    signer.der().clone(),
                    role,
                    SystemTime::now,
                )
                .unwrap();
                coverage.current(SystemTime::now).unwrap();
            }
        }
    }

    #[test]
    fn native_strict_crl_retains_failure_observations_and_history_overflow_closes_old_owners() {
        use super::super::native_crl::Coverage;
        let root = ca("root", None);
        let signer = ca("same", Some(&root));
        let wrong = ca("same", Some(&root));
        let cert = workload("cmtc-a.mesh.example", &signer);
        for case in ["failed-read", "wrong-key", "overflow"] {
            let file = tempfile::NamedTempFile::new().unwrap();
            let path = file.path();
            std::fs::write(path, native_crl_window(&signer, false, 1, -1, 86400)).unwrap();
            let manager = Arc::new(
                tls::crl::CrlManager::new(
                    path.to_path_buf(),
                    crate::test_helpers::helpers::test_proxy_metrics(),
                )
                .unwrap(),
            );
            let old = Coverage::new(
                manager.clone(),
                cert.cert.der.clone(),
                signer.der().clone(),
                PeerRole::Client,
                SystemTime::now,
            )
            .unwrap();
            match case {
                "failed-read" => {
                    std::fs::write(path, b"invalid CRL DER").unwrap();
                    assert!(manager.load_crl().is_err());
                    // Native failure does not erase the existing generic legacy cache.
                    assert!(!manager.get_crls().is_empty());
                }
                "wrong-key" => {
                    std::fs::write(path, native_crl_window(&wrong, false, 2, -1, 86400)).unwrap();
                    manager.load_crl().unwrap();
                }
                "overflow" => {
                    for number in 2..36 {
                        std::fs::write(path, native_crl_window(&signer, false, number, -1, 86400))
                            .unwrap();
                        manager.load_crl().unwrap();
                    }
                }
                _ => unreachable!(),
            }
            // A fast successful recovery must NOT erase the failed interval
            // before a sleeping stream gets polled. New TLS is the recovery.
            std::fs::write(path, native_crl_window(&signer, false, 40, -1, 86400)).unwrap();
            manager.load_crl().unwrap();
            assert!(
                old.current(SystemTime::now).is_err(),
                "old owner must close after {case}"
            );
            Coverage::new(
                manager.clone(),
                cert.cert.der.clone(),
                signer.der().clone(),
                PeerRole::Client,
                SystemTime::now,
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn native_strict_crl_idle_expiry_closes_actual_tls_both_roles_then_new_signed_empty_recovers()
     {
        for inbound in [true, false] {
            let root = ca("root", None);
            let a = ca("a", Some(&root));
            let b = ca("b", Some(&root));
            let ca = workload("cmtc-a.mesh.example", &a);
            let cb = workload("cmtc-b.mesh.example", &b);
            let wa = live_wire("cmtc-a", &root, &a, &b);
            let wb = live_wire("cmtc-b", &root, &a, &b);
            let ea = expected(&wa);
            let eb = expected(&wb);
            let da = dir();
            let db = dir();
            let (pa, ga, sa) = opened(da.path(), &ea, SystemTime::now);
            let (pb, gb, sb) = opened(db.path(), &eb, SystemTime::now);
            pa.commit(decode(&wa, &ea, SystemTime::now)).unwrap();
            pb.commit(decode(&wb, &eb, SystemTime::now)).unwrap();
            ready(&pa, &ga, sa);
            ready(&pb, &gb, sb);
            let file = tempfile::NamedTempFile::new().unwrap();
            let signer = if inbound { &a } else { &b };
            std::fs::write(file.path(), native_crl_window(signer, false, 1, -1, 5)).unwrap();
            let manager = Arc::new(
                tls::crl::CrlManager::new(
                    file.path().to_path_buf(),
                    crate::test_helpers::helpers::test_proxy_metrics(),
                )
                .unwrap(),
            );
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let client = async {
                connect(
                    ca.clone(),
                    Some(pa.acquire().unwrap()),
                    TcpStream::connect(address).await.unwrap(),
                    vec![cb.identity().unwrap()],
                    (!inbound).then(|| manager.clone()),
                )
                .await
                .unwrap()
            };
            let server = async {
                let (raw, _) = listener.accept().await.unwrap();
                accept(
                    cb.clone(),
                    Some(pb.acquire().unwrap()),
                    raw,
                    inbound.then(|| manager.clone()),
                )
                .await
                .unwrap()
            };
            let ((mut client, client_handle), (mut server, server_handle)) =
                tokio::time::timeout(Duration::from_secs(5), async {
                    tokio::join!(client, server)
                })
                .await
                .unwrap();
            client.write_all(b"proof").await.unwrap();
            let mut data = [0; 5];
            server.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"proof");
            // The configured side waits without application traffic. No file
            // reload or forced invalidation drives this: signed nextUpdate does.
            if inbound {
                let waiting = tokio::spawn(async move {
                    let _handle = server_handle;
                    let mut byte = [0];
                    server.read(&mut byte).await
                });
                tokio::task::yield_now().await;
                tokio::time::pause();
                tokio::time::advance(Duration::from_secs(6)).await;
                let denied = waiting.await.unwrap();
                tokio::time::resume();
                assert!(denied.is_err());
                let mut byte = [0];
                let peer = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
                    .await
                    .unwrap();
                assert!(peer.is_err() || matches!(peer, Ok(0)));
                drop(client_handle);
            } else {
                let waiting = tokio::spawn(async move {
                    let _handle = client_handle;
                    let mut byte = [0];
                    client.read(&mut byte).await
                });
                tokio::task::yield_now().await;
                tokio::time::pause();
                tokio::time::advance(Duration::from_secs(6)).await;
                let denied = waiting.await.unwrap();
                tokio::time::resume();
                assert!(denied.is_err());
                let mut byte = [0];
                let peer = tokio::time::timeout(Duration::from_secs(2), server.read(&mut byte))
                    .await
                    .unwrap();
                assert!(peer.is_err() || matches!(peer, Ok(0)));
                drop(server_handle);
            }
            assert!(
                ga.is_open() && gb.is_open(),
                "CRL expiry must not manufacture an ADS authority change"
            );
            std::fs::write(file.path(), native_crl_window(signer, false, 2, -1, 86400)).unwrap();
            manager.load_crl().unwrap();
            // Same provider/session, fresh signed CRL, completely new TLS flow.
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let client = async {
                connect(
                    ca.clone(),
                    Some(pa.acquire().unwrap()),
                    TcpStream::connect(address).await.unwrap(),
                    vec![cb.identity().unwrap()],
                    (!inbound).then(|| manager.clone()),
                )
                .await
                .unwrap()
            };
            let server = async {
                let (raw, _) = listener.accept().await.unwrap();
                accept(
                    cb.clone(),
                    Some(pb.acquire().unwrap()),
                    raw,
                    inbound.then(|| manager.clone()),
                )
                .await
                .unwrap()
            };
            let ((mut client, _client_handle), (mut server, _server_handle)) =
                tokio::time::timeout(Duration::from_secs(5), async {
                    tokio::join!(client, server)
                })
                .await
                .unwrap();
            client.write_all(b"fresh").await.unwrap();
            let mut data = [0; 5];
            server.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"fresh");
        }
    }
    // These are real loopback TCP + native TLS + HTTP/2 tests. The fixture's
    // independently supplied ranges admit loopback only here; the native
    // Cilium publisher continues rejecting loopback workload Addresses.
    #[cfg(target_os = "linux")]
    async fn direct_source_tls_fixture() -> (
        ClientTls<TcpStream>,
        ServerTls<TcpStream>,
        crate::rbac::Connection,
        tempfile::TempDir,
        tempfile::TempDir,
        Arc<WorkloadCertificate>,
        Arc<WorkloadCertificate>,
        Arc<ProfileProvider>,
        Arc<ProfileProvider>,
    ) {
        let root = ca("root", None);
        let a = ca("a", Some(&root));
        let b = ca("b", Some(&root));
        let ca = workload("cmtc-a.mesh.example", &a);
        let cb = workload("cmtc-b.mesh.example", &b);
        let wa = live_wire("cmtc-a", &root, &a, &b);
        let wb = live_wire("cmtc-b", &root, &a, &b);
        let da = dir();
        let db = dir();
        let (pa, ga, sa) = opened(da.path(), &expected(&wa), SystemTime::now);
        let (pb, gb, sb) = opened(db.path(), &expected(&wb), SystemTime::now);
        pa.commit(decode(&wa, &expected(&wa), SystemTime::now))
            .unwrap();
        pb.commit(decode(&wb, &expected(&wb), SystemTime::now))
            .unwrap();
        ready(&pa, &ga, sa);
        ready(&pb, &gb, sb);
        let (client, server, connection) = direct_source_tls_again(&ca, &cb, &pa, &pb).await;
        (client, server, connection, da, db, ca, cb, pa, pb)
    }
    #[cfg(target_os = "linux")]
    async fn direct_source_tls_again(
        ca: &Arc<WorkloadCertificate>,
        cb: &Arc<WorkloadCertificate>,
        pa: &Arc<ProfileProvider>,
        pb: &Arc<ProfileProvider>,
    ) -> (
        ClientTls<TcpStream>,
        ServerTls<TcpStream>,
        crate::rbac::Connection,
    ) {
        let listener = TcpListener::bind("127.0.0.2:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = async {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            connect(
                ca.clone(),
                Some(pa.acquire().unwrap()),
                socket.connect(address).await.unwrap(),
                vec![cb.identity().unwrap()],
                None,
            )
            .await
            .unwrap()
            .0
        };
        let server = async {
            let (raw, peer) = listener.accept().await.unwrap();
            let destination = raw.local_addr().unwrap();
            let server = accept(cb.clone(), Some(pb.acquire().unwrap()), raw, None)
                .await
                .unwrap()
                .0;
            let (_, ssl) = server.get_ref().get_ref();
            let certificate = tls::certificate_from_connection(ssl);
            let connection = crate::rbac::Connection {
                src: peer,
                dst: destination,
                dst_network: crate::strng::EMPTY,
                src_identity: tls::identity(&certificate),
            };
            (server, connection)
        };
        let (client, (server, connection)) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(client, server)
        })
        .await
        .unwrap();
        (client, server, connection)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_kernel_peer_and_verified_uri_reject_mismatch_and_ambiguous_xds() {
        let (_client, _server, connection, _da, _db, _ca, _cb, _pa, _pb) =
            direct_source_tls_fixture().await;
        assert_eq!(
            connection.src.ip(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            connection.src_identity.as_ref().unwrap().to_string(),
            "spiffe://cmtc-a.mesh.example/ns/orders/sa/api"
        );
        let (state, ctx, _) = crate::state::source_binding::tests::fixture(connection);
        assert!(state.assert_rbac(&ctx).await.is_ok());
        let old = state
            .read()
            .workloads
            .find_uid(&"source-pod-uid".into())
            .unwrap();
        let mut wrong = (*old).clone();
        wrong.service_account = "wrong-label-owner".into();
        crate::state::source_binding::tests::insert_workload(&state, Arc::new(wrong));
        assert!(state.capture_native_source(&ctx.conn).is_err());
        crate::state::source_binding::tests::insert_workload(&state, old.clone());
        let mut duplicate = (*old).clone();
        duplicate.uid = "ambiguous-other-pod".into();
        crate::state::source_binding::tests::insert_workload(&state, Arc::new(duplicate));
        assert!(state.capture_native_source(&ctx.conn).is_err());
        assert!(state.assert_rbac(&ctx).await.is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn native_source_delta_closes_actual_idle_and_active_tls_h2_then_fresh_tls_recovers() {
        for active in [false, true] {
            for recovered in [false, true] {
                let (client, server, mut connection, _da, _db, ca, cb, pa, pb) =
                    direct_source_tls_fixture().await;
                // RBAC sees the application target port, not outer HBONE port.
                connection.dst.set_port(8080);
                let (state, ctx, _) = crate::state::source_binding::tests::fixture(connection);
                let source = state
                    .read()
                    .workloads
                    .find_uid(&"source-pod-uid".into())
                    .unwrap();
                let (_global, global) = watch::channel(());
                let (shutdown, _source_owner) =
                    state.native_source_shutdown(ctx.native_source.clone(), global);
                let (_drain_owner, drain) = crate::drain::new();
                let (entered, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
                let (dropped, mut dropped_rx) = tokio::sync::mpsc::unbounded_channel();
                struct AckDrop(tokio::sync::mpsc::UnboundedSender<()>);
                impl Drop for AckDrop {
                    fn drop(&mut self) {
                        let _ = self.0.send(());
                    }
                }
                let handler_state = state.clone();
                let handler_ctx = ctx.clone();
                let server_task = tokio::spawn(crate::proxy::h2::server::serve_connection(
                    Arc::new(crate::test_helpers::test_config()),
                    server,
                    drain,
                    shutdown,
                    None,
                    move |req| {
                        let state = handler_state.clone();
                        let ctx = handler_ctx.clone();
                        let entered = entered.clone();
                        let drop_ack = AckDrop(dropped.clone());
                        async move {
                            let _drop_ack = drop_ack;
                            // Forged telemetry never rewrites the captured kernel
                            // address or verified TLS principal in this native join.
                            assert!(req.headers().contains_key("forwarded"));
                            assert!(state.assert_rbac(&ctx).await.is_ok());
                            let stream = req
                                .send_response(
                                    http::Response::builder().status(200).body(()).unwrap(),
                                )
                                .await
                                .unwrap();
                            let mut stream = crate::proxy::h2::TokioH2Stream::new(stream);
                            entered.send(()).unwrap();
                            let mut data = [0; 5];
                            stream.read_exact(&mut data).await.unwrap();
                            assert_eq!(&data, b"proof");
                            stream.write_all(&data).await.unwrap();
                            std::future::pending::<()>().await;
                        }
                    },
                ));
                let (mut send, mut driver) = h2::client::handshake(client).await.unwrap();
                let mut ping = driver.ping_pong().unwrap();
                let driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(driver));
                tokio::time::timeout(Duration::from_secs(2), ping.ping(h2::Ping::opaque()))
                    .await
                    .unwrap()
                    .unwrap();
                let mut data = if active {
                    let request = http::Request::builder()
                        .method(http::Method::CONNECT)
                        .uri("127.0.0.2:8080")
                        .header("forwarded", "for=10.9.9.9")
                        .header(
                            "baggage",
                            "k8s.cluster.name=foreign,service.name=privileged",
                        )
                        .body(())
                        .unwrap();
                    let (response, mut stream) = send.send_request(request, false).unwrap();
                    stream
                        .send_data(bytes::Bytes::from_static(b"proof"), false)
                        .unwrap();
                    tokio::time::timeout(Duration::from_secs(2), entered_rx.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    let response = tokio::time::timeout(Duration::from_secs(2), response)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(response.status(), 200);
                    let mut body = response.into_body();
                    assert_eq!(
                        &tokio::time::timeout(Duration::from_secs(2), body.data())
                            .await
                            .unwrap()
                            .unwrap()
                            .unwrap()[..],
                        b"proof"
                    );
                    Some((body, stream))
                } else {
                    None
                };
                // Workload-only mutation; no policy event or direct close_all.
                crate::state::source_binding::tests::remove_workload(&state, &source.uid);
                if recovered {
                    crate::state::source_binding::tests::insert_workload(&state, source);
                    assert!(
                        state.assert_rbac(&ctx).await.is_err(),
                        "old TLS witness cannot rebind after ABA"
                    );
                    let mut new_ctx = ctx.clone();
                    new_ctx.native_source = state.capture_native_source(&ctx.conn).unwrap();
                    assert!(
                        state.assert_rbac(&new_ctx).await.is_ok(),
                        "a fresh qualified TLS connection can bind restored state"
                    );
                }
                let result = tokio::time::timeout(Duration::from_secs(2), server_task)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(result.is_err(), "idle outer driver must stop");
                if let Some((ref mut body, _)) = data {
                    let closed = tokio::time::timeout(Duration::from_secs(2), body.data())
                        .await
                        .unwrap();
                    assert!(closed.is_none() || closed.is_some_and(|value| value.is_err()));
                    tokio::time::timeout(Duration::from_secs(2), dropped_rx.recv())
                        .await
                        .unwrap()
                        .unwrap();
                }
                let _ = tokio::time::timeout(Duration::from_secs(2), driver)
                    .await
                    .unwrap()
                    .unwrap();
                drop(send);
                if recovered {
                    // A real NEW TCP/TLS/H2 connection uses the SAME native
                    // providers and SAME restored workload/policy state.
                    let (client, server, mut conn) =
                        direct_source_tls_again(&ca, &cb, &pa, &pb).await;
                    conn.dst.set_port(8080);
                    let mut fresh_ctx = ctx.clone();
                    fresh_ctx.conn = conn;
                    fresh_ctx.native_source = state.capture_native_source(&fresh_ctx.conn).unwrap();
                    assert!(state.assert_rbac(&ctx).await.is_err());
                    assert!(state.assert_rbac(&fresh_ctx).await.is_ok());
                    let (_global, global) = watch::channel(());
                    let (shutdown, owner) =
                        state.native_source_shutdown(fresh_ctx.native_source.clone(), global);
                    let (_drain, drain) = crate::drain::new();
                    let serving_state = state.clone();
                    let serving = tokio::spawn(crate::proxy::h2::server::serve_connection(
                        Arc::new(crate::test_helpers::test_config()),
                        server,
                        drain,
                        shutdown,
                        None,
                        move |req| {
                            let state = serving_state.clone();
                            let ctx = fresh_ctx.clone();
                            async move {
                                assert!(state.assert_rbac(&ctx).await.is_ok());
                                let _stream = req
                                    .send_response(
                                        http::Response::builder().status(200).body(()).unwrap(),
                                    )
                                    .await
                                    .unwrap();
                                std::future::pending::<()>().await;
                            }
                        },
                    ));
                    let (mut sender, driver) = h2::client::handshake(client).await.unwrap();
                    let driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(driver));
                    let request = http::Request::builder()
                        .method(http::Method::CONNECT)
                        .uri("127.0.0.2:8080")
                        .body(())
                        .unwrap();
                    let (response, _body) = sender.send_request(request, false).unwrap();
                    assert_eq!(
                        tokio::time::timeout(Duration::from_secs(2), response)
                            .await
                            .unwrap()
                            .unwrap()
                            .status(),
                        200
                    );
                    // Owner cancellation is a real cleanup event, never an allow.
                    drop(owner);
                    assert!(
                        tokio::time::timeout(Duration::from_secs(2), serving)
                            .await
                            .unwrap()
                            .unwrap()
                            .is_err()
                    );
                    let _ = tokio::time::timeout(Duration::from_secs(2), driver)
                        .await
                        .unwrap()
                        .unwrap();
                    drop(sender);
                }
            }
        }
    }
}
