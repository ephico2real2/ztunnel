// Copyright Istio Authors
// SPDX-License-Identifier: Apache-2.0
//! Strict native-profile CRL coverage. The legacy CRL policy is unchanged.
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, ensure};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, UnixTime};
use tokio::time::Instant;
use webpki::{
    EndEntityCert, ExpirationPolicy, OwnedCertRevocationList, RevocationCheckDepth,
    RevocationOptionsBuilder, UnknownStatusPolicy,
};
use x509_parser::prelude::FromDer;

use super::crl::CrlManager;
use super::domain_anchors::PeerRole;
use super::profile_provider::WallFloor;

const MAX_CRLS: usize = 32;
const MAX_CRL_BYTES: usize = 1024 * 1024;

struct Cached {
    sequence: u64,
    deadline: SystemTime,
    monotonic_deadline: Instant,
    floor: WallFloor,
}
/// Bound to one exact verified peer leaf and exact approved direct SPIRE issuer.
/// Clones share expiry state across lower ciphertext and upper plaintext guards.
pub(crate) struct Coverage {
    manager: Arc<CrlManager>,
    leaf: CertificateDer<'static>,
    signer: CertificateDer<'static>,
    role: PeerRole,
    cached: Mutex<Cached>,
    failed: AtomicBool,
    started: Instant,
}
impl Coverage {
    pub fn new(
        manager: Arc<CrlManager>,
        leaf: CertificateDer<'static>,
        signer: CertificateDer<'static>,
        role: PeerRole,
        clock: fn() -> SystemTime,
    ) -> Result<Arc<Self>> {
        let started = Instant::now();
        let now = clock();
        let result =
            Self::new_inner(manager, leaf, signer, role, now, started).and_then(|coverage| {
                coverage.current(clock)?;
                Ok(coverage)
            });
        result.inspect_err(|error| {
            tracing::warn!(component="issuer-profile-crl",stage="initial-coverage",attempt=1,
                elapsed_ms=started.elapsed().as_millis() as u64,error=%error,
                "native TLS rejected because exact peer CRL coverage is unavailable");
        })
    }
    fn new_inner(
        manager: Arc<CrlManager>,
        leaf: CertificateDer<'static>,
        signer: CertificateDer<'static>,
        role: PeerRole,
        now: SystemTime,
        received_mono: Instant,
    ) -> Result<Arc<Self>> {
        let observation = manager.native_snapshot()?;
        let ders = observation.ders.context("native CRL source unavailable")?;
        let deadline = validate(&ders, &leaf, &signer, role, now)?;
        let monotonic_deadline = received_mono + deadline.duration_since(now)?;
        Ok(Arc::new(Self {
            manager,
            leaf,
            signer,
            role,
            failed: AtomicBool::new(false),
            started: Instant::now(),
            cached: Mutex::new(Cached {
                sequence: observation.sequence,
                deadline,
                monotonic_deadline,
                floor: WallFloor::new(now),
            }),
        }))
    }
    pub fn current(&self, clock: fn() -> SystemTime) -> Result<(SystemTime, Instant)> {
        let received_mono = Instant::now();
        let (result, first_failure) = {
            let mut state = self.cached.lock().expect("native CRL lease");
            ensure!(
                !self.failed.load(Ordering::Acquire),
                "native CRL owner permanently fenced"
            );
            // Read under the lease lock through the floor (see WallFloor): a
            // bounded backward step is judged at the floor, a larger one fences.
            let result = state
                .floor
                .observe(clock())
                .context("native CRL clock moved backwards")
                .and_then(|now| self.check_current(now, received_mono, &mut state))
                .and_then(|limits| {
                    let after = state.floor.observe(clock())?;
                    ensure!(
                        after < limits.0 && Instant::now() < limits.1,
                        "native CRL expired or clock regressed during validation"
                    );
                    Ok(limits)
                });
            let failure = result.is_err();
            if failure {
                self.failed.store(true, Ordering::Release);
            }
            (result, failure)
        };
        if first_failure && let Err(error) = &result {
            tracing::warn!(component="issuer-profile-crl",stage="retained-coverage",attempt=1,
                elapsed_ms=self.started.elapsed().as_millis() as u64,error=%error,
                "native CRL coverage lost; current TLS owner must close and cannot resurrect");
        }
        result
    }
    fn check_current(
        &self,
        now: SystemTime,
        received_mono: Instant,
        state: &mut Cached,
    ) -> Result<(SystemTime, Instant)> {
        // Existing owners never resurrect after their coverage has expired,
        // even if a late valid file appears. Recovery requires a new TLS stream.
        ensure!(
            now < state.deadline && Instant::now() < state.monotonic_deadline,
            "native CRL coverage expired"
        );
        for observation in self.manager.native_since(state.sequence)? {
            let ders = observation
                .ders
                .context("native CRL source became unavailable")?;
            let deadline = validate(&ders, &self.leaf, &self.signer, self.role, now)?;
            state.monotonic_deadline = received_mono + deadline.duration_since(now)?;
            state.deadline = deadline;
            state.sequence = observation.sequence;
        }
        Ok((state.deadline, state.monotonic_deadline))
    }
    pub async fn invalidated(self: Arc<Self>, clock: fn() -> SystemTime) {
        let mut updates = self.manager.subscribe_native();
        loop {
            let Ok((_, deadline)) = self.current(clock) else {
                return;
            };
            tokio::select! {
                changed=updates.changed()=>{if changed.is_err(){return;}},
                _=tokio::time::sleep_until(deadline)=>{},
            }
        }
    }
}

/// Full direct-issuer CRL only: no delta/indirect/distribution-point ambiguity.
/// x509-parser proves the exact signer and timestamp; webpki remains the final
/// leaf usage/revocation verifier with unknown and expiry explicitly denied.
fn validate(
    ders: &[CertificateRevocationListDer<'_>],
    leaf: &CertificateDer<'_>,
    signer: &CertificateDer<'_>,
    role: PeerRole,
    now: SystemTime,
) -> Result<SystemTime> {
    ensure!(
        !ders.is_empty() && ders.len() <= MAX_CRLS,
        "missing/unbounded native CRL set"
    );
    ensure!(
        ders.iter()
            .try_fold(0usize, |n, d| n.checked_add(d.as_ref().len()))
            .is_some_and(|n| n <= MAX_CRL_BYTES),
        "native CRL bytes exceed bound"
    );
    let (tail, ca) = x509_parser::certificate::X509Certificate::from_der(signer.as_ref())
        .map_err(|e| anyhow::anyhow!("exact CRL signer parse: {e}"))?;
    ensure!(tail.is_empty(), "trailing signer certificate bytes");
    let (tail, peer) = x509_parser::certificate::X509Certificate::from_der(leaf.as_ref())
        .map_err(|e| anyhow::anyhow!("exact CRL peer parse: {e}"))?;
    ensure!(
        tail.is_empty() && peer.issuer() == ca.subject(),
        "peer is not directly signed by approved SPIRE issuer"
    );
    let seconds = now.duration_since(UNIX_EPOCH)?.as_secs();
    let now_i64 = i64::try_from(seconds).context("native CRL clock range")?;
    let usage = ca
        .key_usage()
        .map_err(|e| anyhow::anyhow!("CRL signer usage: {e}"))?
        .context("CRL signer key usage missing")?;
    ensure!(
        usage.value.crl_sign(),
        "exact SPIRE issuer cannot sign CRLs"
    );
    let mut selected = None;
    let mut until = None;
    for der in ders {
        let (tail, crl) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(der.as_ref())
                .map_err(|e| anyhow::anyhow!("native CRL DER parse: {e}"))?;
        ensure!(tail.is_empty(), "trailing native CRL DER");
        if crl.issuer() != ca.subject() || crl.verify_signature(ca.public_key()).is_err() {
            continue;
        }
        // Same DN on another cluster's key is not coverage. Exactly one full
        // CRL signed by THIS issuer is required, independent of file ordering.
        ensure!(
            selected.is_none(),
            "ambiguous duplicate CRLs for exact peer issuer"
        );
        let mut extensions = BTreeSet::new();
        for extension in crl.extensions() {
            let oid = extension.oid.to_id_string();
            ensure!(
                extensions.insert(oid.clone()),
                "duplicate native CRL extension"
            );
            ensure!(
                matches!(oid.as_str(), "2.5.29.20" | "2.5.29.35"),
                "native CRL must cover the full direct issuer without delta or distribution-point restrictions"
            );
        }
        let number = crl
            .crl_number()
            .context("native CRL requires a signed CRL number")?;
        ensure!(
            number.to_bytes_be().len() <= 20,
            "native CRL number exceeds RFC bound"
        );
        let this = crl.last_update().timestamp();
        let next = crl
            .next_update()
            .context("native CRL requires nextUpdate")?
            .timestamp();
        ensure!(
            this <= now_i64 && now_i64 < next && this < next,
            "native CRL is future-dated or expired"
        );
        let next = u64::try_from(next).context("native CRL expiry range")?;
        let issuer_until =
            u64::try_from(ca.validity().not_after.timestamp()).context("issuer expiry range")?;
        let leaf_until =
            u64::try_from(peer.validity().not_after.timestamp()).context("peer expiry range")?;
        until = Some(UNIX_EPOCH + Duration::from_secs(next.min(issuer_until).min(leaf_until)));
        selected = Some(der);
    }
    let selected = selected.context("no CRL signed by exact peer SPIRE issuer")?;
    let owned = OwnedCertRevocationList::from_der(selected.as_ref())
        .map_err(|e| anyhow::anyhow!("native full CRL verification parse: {e:?}"))?;
    let crl = webpki::CertRevocationList::from(owned);
    let refs = [&crl];
    let revocation = RevocationOptionsBuilder::new(&refs)
        .map_err(|e| anyhow::anyhow!("missing strict native CRL: {e:?}"))?
        .with_depth(RevocationCheckDepth::EndEntity)
        .with_status_policy(UnknownStatusPolicy::Deny)
        .with_expiration_policy(ExpirationPolicy::Enforce)
        .build();
    let mut roots = RootCertStore::empty();
    roots.add(signer.clone().into_owned())?;
    let usage = match role {
        PeerRole::Client => webpki::KeyUsage::client_auth(),
        PeerRole::Server => webpki::KeyUsage::server_auth(),
    };
    let ee = EndEntityCert::try_from(leaf).map_err(|e| anyhow::anyhow!("native leaf: {e:?}"))?;
    ee.verify_for_usage(
        super::lib::provider().signature_verification_algorithms.all,
        &roots.roots,
        &[],
        UnixTime::since_unix_epoch(Duration::from_secs(seconds)),
        usage,
        Some(revocation),
        None,
    )
    .map_err(|e| anyhow::anyhow!("strict direct SPIRE CRL coverage: {e:?}"))?;
    let until = until.context("native CRL deadline missing")?;
    ensure!(now < until, "native CRL/peer/issuer deadline expired");
    Ok(until)
}
