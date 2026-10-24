// Copyright Istio Authors
// SPDX-License-Identifier: Apache-2.0
// Experimental issuer-verification foundation; not wired to live TLS, policy, or pools.
// Requires x509-parser's `verify` feature in normal dependencies, not just dev-dependencies.
// Profile construction is an authenticated local-admin/CMTC authority boundary.
// Certificate signatures prove issuer lineage, not administrator approval of a domain/key mapping.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime};
use webpki::{CertRevocationList, KeyUsage};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use super::revocation::verify_cert_chain;
use crate::identity::Identity;
use crate::strng::Strng;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AnchorError {
    #[error("invalid certificate encoding or unsupported certificate fields")]
    BadEncoding,
    #[error("invalid pin or domain {0}")]
    InvalidPin(String),
    #[error("untrusted or inactive domain {0}")]
    UntrustedTrustDomain(String),
    #[error("peer certificate contained {0} SAN names; exactly one URI SAN is required")]
    PeerIdentityCount(usize),
    #[error("unsupported or malformed peer identity")]
    MalformedIdentity,
    #[error("no approved direct issuer for domain {0}")]
    UnauthorizedIssuer(String),
    #[error("a foreign domain issuer verifies peer claiming {0}")]
    AmbiguousIssuer(String),
    #[error("unexpected authenticated identity {authenticated}")]
    UnexpectedPeer { authenticated: String },
    #[error("organizational root in workload bundle for {domain}")]
    RejectedRoot { domain: String },
    #[error("noncanonical or inactive authority in bundle for {domain}")]
    UnpinnedAuthority { domain: String },
    #[error("empty bundle or no current authority for {domain}")]
    MissingCurrentPin { domain: String },
    #[error("generation {candidate} does not supersede {current}")]
    StaleGeneration { current: u64, candidate: u64 },
    #[error("cannot retire local domain {0}")]
    RetiredLocalDomain(String),
    #[error("profile changes local domain or organizational authority")]
    ChangedProfileAuthority,
    #[error("bundle contains a withdrawn issuer for {domain}")]
    WithdrawnIssuer { domain: String },
    #[error("snapshot {candidate} contains withdrawn issuer material")]
    WithdrawnSnapshot { candidate: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRole {
    Client,
    Server,
}

// Private fields prevent caller-supplied SPKI/expiry from disagreeing with DER.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainPin {
    trust_domain: Strng,
    spki_der: Vec<u8>,
    der: CertificateDer<'static>,
    not_before: SystemTime,
    not_after: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainAnchorSet {
    generation: u64,
    local_domain: Strng,
    organizational_root: CertificateDer<'static>,
    organizational_root_spki: Vec<u8>,
    root_not_before: SystemTime,
    root_not_after: SystemTime,
    by_domain: HashMap<Strng, Vec<DomainPin>>,
}

// Constructed only by successful cryptographic verification, not from xDS labels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPeer {
    identity: Identity,
    anchor_generation: u64,
    signer_spki: Vec<u8>,
    valid_until: SystemTime,
}

impl VerifiedPeer {
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn anchor_generation(&self) -> u64 {
        self.anchor_generation
    }
    pub fn deadline(&self) -> SystemTime {
        self.valid_until
    }
    pub fn retained_tunnel(&self) -> RetainedTunnel {
        RetainedTunnel(self.clone())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedTunnel(VerifiedPeer);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedDecision {
    Keep,
    Drain,
}

fn dns_name(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
fn validate_domain(domain: &Strng) -> Result<(), AnchorError> {
    if !dns_name(domain, 253) {
        return Err(AnchorError::InvalidPin(domain.to_string()));
    }
    Ok(())
}
fn parse_exact(der: &[u8]) -> Result<X509Certificate<'_>, AnchorError> {
    let (rest, cert) = X509Certificate::from_der(der).map_err(|_| AnchorError::BadEncoding)?;
    if !rest.is_empty() || cert.signature_algorithm != cert.tbs_certificate.signature {
        return Err(AnchorError::BadEncoding);
    }
    let mut oids = HashSet::new();
    for ext in cert.extensions() {
        if !oids.insert(ext.oid.to_id_string()) {
            return Err(AnchorError::BadEncoding);
        }
        match ext.parsed_extension() {
            ParsedExtension::ParseError { .. } | ParsedExtension::Unparsed => {
                return Err(AnchorError::BadEncoding);
            }
            ParsedExtension::UnsupportedExtension { .. } if ext.critical => {
                return Err(AnchorError::BadEncoding);
            }
            _ => (),
        }
    }
    Ok(cert)
}
fn at_unix(seconds: i64) -> Result<SystemTime, AnchorError> {
    let delta = Duration::from_secs(seconds.unsigned_abs());
    let result = if seconds >= 0 {
        UNIX_EPOCH.checked_add(delta)
    } else {
        UNIX_EPOCH.checked_sub(delta)
    };
    result.ok_or(AnchorError::BadEncoding)
}
fn validity(cert: &X509Certificate<'_>) -> Result<(SystemTime, SystemTime), AnchorError> {
    let before = at_unix(cert.validity().not_before.timestamp())?;
    let after = at_unix(cert.validity().not_after.timestamp())?;
    if before >= after {
        return Err(AnchorError::BadEncoding);
    }
    Ok((before, after))
}
fn ca_material(cert: &X509Certificate<'_>) -> Result<(), AnchorError> {
    let bc = cert
        .basic_constraints()
        .map_err(|_| AnchorError::BadEncoding)?
        .ok_or(AnchorError::BadEncoding)?;
    let ku = cert
        .key_usage()
        .map_err(|_| AnchorError::BadEncoding)?
        .ok_or(AnchorError::BadEncoding)?;
    if !bc.critical || !bc.value.ca || !ku.value.key_cert_sign() {
        return Err(AnchorError::BadEncoding);
    }
    // Narrow direct-issuer profile. Reject constraints we would otherwise lose
    // by converting a certificate into a trust anchor.
    for ext in cert.extensions() {
        if !matches!(
            ext.parsed_extension(),
            ParsedExtension::BasicConstraints(_)
                | ParsedExtension::KeyUsage(_)
                | ParsedExtension::SubjectKeyIdentifier(_)
                | ParsedExtension::AuthorityKeyIdentifier(_)
        ) {
            return Err(AnchorError::BadEncoding);
        }
    }
    validity(cert)?;
    Ok(())
}
pub fn spki_der(der: &[u8]) -> Result<Vec<u8>, AnchorError> {
    Ok(parse_exact(der)?.public_key().raw.to_vec())
}
pub fn pin_from_certificate(
    trust_domain: Strng,
    der: CertificateDer<'static>,
) -> Result<DomainPin, AnchorError> {
    validate_domain(&trust_domain)?;
    let cert = parse_exact(der.as_ref())?;
    ca_material(&cert)?;
    let (not_before, not_after) = validity(&cert)?;
    let spki_der = cert.public_key().raw.to_vec();
    Ok(DomainPin {
        trust_domain,
        spki_der,
        der,
        not_before,
        not_after,
    })
}
impl DomainPin {
    fn current(&self, now: SystemTime) -> bool {
        self.not_before <= now && now < self.not_after
    }
    fn validate_encoded(&self) -> Result<(), AnchorError> {
        if pin_from_certificate(self.trust_domain.clone(), self.der.clone())? != *self {
            return Err(AnchorError::InvalidPin(self.trust_domain.to_string()));
        }
        Ok(())
    }
}
impl DomainAnchorSet {
    // Trusted administration boundary, NOT a constructor for remote SPIRE bundles.
    // Root signature establishes lineage, not authority to assign a domain/key.
    pub fn try_new(
        local_domain: Strng,
        organizational_root: CertificateDer<'static>,
        generation: u64,
        pins: Vec<DomainPin>,
    ) -> Result<Self, AnchorError> {
        validate_domain(&local_domain)?;
        if generation == 0 {
            return Err(AnchorError::StaleGeneration {
                current: 0,
                candidate: 0,
            });
        }
        let root = parse_exact(organizational_root.as_ref())?;
        ca_material(&root)?;
        if root
            .basic_constraints()
            .map_err(|_| AnchorError::BadEncoding)?
            .is_some_and(|constraints| constraints.value.path_len_constraint == Some(0))
        {
            return Err(AnchorError::InvalidPin(local_domain.to_string()));
        }
        if root.subject() != root.issuer() || root.verify_signature(None).is_err() {
            return Err(AnchorError::InvalidPin(local_domain.to_string()));
        }
        let (root_not_before, root_not_after) = validity(&root)?;
        let organizational_root_spki = root.public_key().raw.to_vec();
        let mut by_domain: HashMap<Strng, Vec<DomainPin>> = HashMap::new();
        let mut seen = HashSet::new();
        for pin in pins {
            pin.validate_encoded()?;
            let cert = parse_exact(pin.der.as_ref())?;
            if pin.spki_der == organizational_root_spki
                || !seen.insert(pin.spki_der.clone())
                || cert.issuer() != root.subject()
                || cert.verify_signature(Some(root.public_key())).is_err()
            {
                return Err(AnchorError::InvalidPin(pin.trust_domain.to_string()));
            }
            by_domain
                .entry(pin.trust_domain.clone())
                .or_default()
                .push(pin);
        }
        if !by_domain.contains_key(&local_domain) {
            return Err(AnchorError::UntrustedTrustDomain(local_domain.to_string()));
        }
        Ok(Self {
            generation,
            local_domain,
            organizational_root,
            organizational_root_spki,
            root_not_before,
            root_not_after,
            by_domain,
        })
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn local_domain(&self) -> &Strng {
        &self.local_domain
    }
    pub fn permits(&self, domain: &Strng) -> bool {
        self.by_domain.contains_key(domain)
    }
    pub fn pin_spkis(&self, domain: &Strng) -> Vec<Vec<u8>> {
        self.by_domain
            .get(domain)
            .map(|pins| pins.iter().map(|p| p.spki_der.clone()).collect())
            .unwrap_or_default()
    }
    fn current_pins(&self, domain: &Strng, now: SystemTime) -> Result<&[DomainPin], AnchorError> {
        if now < self.root_not_before || now >= self.root_not_after {
            return Err(AnchorError::UntrustedTrustDomain(domain.to_string()));
        }
        let pins = self
            .by_domain
            .get(domain)
            .ok_or_else(|| AnchorError::UntrustedTrustDomain(domain.to_string()))?;
        if !pins.iter().any(|pin| pin.current(now)) {
            return Err(AnchorError::UntrustedTrustDomain(domain.to_string()));
        }
        Ok(pins)
    }
    pub fn with_generation(&self, generation: u64) -> Result<Self, AnchorError> {
        if generation <= self.generation {
            return Err(AnchorError::StaleGeneration {
                current: self.generation,
                candidate: generation,
            });
        }
        let mut next = self.clone();
        next.generation = generation;
        Ok(next)
    }
    pub fn retire_domain(&self, domain: &Strng, generation: u64) -> Result<Self, AnchorError> {
        let mut next = self.with_generation(generation)?;
        if domain == &self.local_domain {
            return Err(AnchorError::RetiredLocalDomain(domain.to_string()));
        }
        if next.by_domain.remove(domain).is_none() {
            return Err(AnchorError::UntrustedTrustDomain(domain.to_string()));
        }
        Ok(next)
    }
    pub fn restore_domain(
        &self,
        pins: Vec<DomainPin>,
        generation: u64,
    ) -> Result<Self, AnchorError> {
        let domain = pins
            .first()
            .ok_or_else(|| AnchorError::InvalidPin(String::new()))?
            .trust_domain
            .clone();
        if self.by_domain.contains_key(&domain) || pins.iter().any(|pin| pin.trust_domain != domain)
        {
            return Err(AnchorError::InvalidPin(domain.to_string()));
        }
        self.with_generation(generation)?;
        let all = self
            .by_domain
            .values()
            .flatten()
            .cloned()
            .chain(pins)
            .collect();
        Self::try_new(
            self.local_domain.clone(),
            self.organizational_root.clone(),
            generation,
            all,
        )
    }
}
fn single_identity(end: &CertificateDer<'_>) -> Result<Identity, AnchorError> {
    let cert = parse_exact(end.as_ref())?;
    let Some(san) = cert
        .subject_alternative_name()
        .map_err(|_| AnchorError::BadEncoding)?
    else {
        return Err(AnchorError::PeerIdentityCount(0));
    };
    if san.value.general_names.len() != 1 {
        return Err(AnchorError::PeerIdentityCount(
            san.value.general_names.len(),
        ));
    }
    let GeneralName::URI(uri) = &san.value.general_names[0] else {
        return Err(AnchorError::MalformedIdentity);
    };
    let identity = Identity::from_str(uri).map_err(|_| AnchorError::MalformedIdentity)?;
    let Identity::Spiffe {
        trust_domain,
        namespace,
        service_account,
    } = &identity;
    validate_domain(trust_domain).map_err(|_| AnchorError::MalformedIdentity)?;
    if !dns_name(namespace, 63)
        || namespace.contains('.')
        || !dns_name(service_account, 253)
        || identity.to_string() != *uri
    {
        return Err(AnchorError::MalformedIdentity);
    }
    Ok(identity)
}
fn path_accepts(
    end: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    pin: &DomainPin,
    now: UnixTime,
    role: PeerRole,
) -> bool {
    let Ok(leaf) = parse_exact(end.as_ref()) else {
        return false;
    };
    if intermediates
        .iter()
        .any(|cert| parse_exact(cert.as_ref()).is_err())
    {
        return false;
    }
    let Ok(issuer) = parse_exact(pin.der.as_ref()) else {
        return false;
    };
    if leaf.issuer() != issuer.subject() {
        return false;
    }
    let mut roots = RootCertStore::empty();
    if roots.add(pin.der.clone()).is_err() {
        return false;
    }
    let usage = match role {
        PeerRole::Client => KeyUsage::client_auth(),
        PeerRole::Server => KeyUsage::server_auth(),
    };
    let crls: &[CertRevocationList<'static>] = &[];
    verify_cert_chain(end, intermediates, &roots, now, usage, crls)
        .is_ok_and(|chain| chain.intermediates.is_empty())
}
pub fn verify_peer_evidence(
    end: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchors: &DomainAnchorSet,
    now: UnixTime,
    role: PeerRole,
) -> Result<VerifiedPeer, AnchorError> {
    let identity = single_identity(end)?;
    let domain = identity.trust_domain();
    let observed = UNIX_EPOCH
        .checked_add(Duration::from_secs(now.as_secs()))
        .ok_or(AnchorError::BadEncoding)?;
    let pins = anchors.current_pins(&domain, observed)?;
    let matched: Vec<_> = pins
        .iter()
        .filter(|pin| pin.current(observed) && path_accepts(end, intermediates, pin, now, role))
        .collect();
    for (other, foreign) in &anchors.by_domain {
        if other != &domain
            && foreign.iter().any(|pin| {
                pin.current(observed) && path_accepts(end, intermediates, pin, now, role)
            })
        {
            return Err(AnchorError::AmbiguousIssuer(domain.to_string()));
        }
    }
    let [pin] = matched.as_slice() else {
        return Err(AnchorError::UnauthorizedIssuer(domain.to_string()));
    };
    let (_, leaf_not_after) = validity(&parse_exact(end.as_ref())?)?;
    Ok(VerifiedPeer {
        identity,
        anchor_generation: anchors.generation,
        signer_spki: pin.spki_der.clone(),
        valid_until: leaf_not_after
            .min(pin.not_after)
            .min(anchors.root_not_after),
    })
}
pub fn verify_peer_certificate(
    end: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchors: &DomainAnchorSet,
    now: UnixTime,
    role: PeerRole,
) -> Result<Identity, AnchorError> {
    Ok(verify_peer_evidence(end, intermediates, anchors, now, role)?.identity)
}
pub fn verify_expected_identity(
    end: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchors: &DomainAnchorSet,
    expected: &[Identity],
    now: UnixTime,
    role: PeerRole,
) -> Result<Identity, AnchorError> {
    let peer = verify_peer_evidence(end, intermediates, anchors, now, role)?;
    if !expected.contains(&peer.identity) {
        return Err(AnchorError::UnexpectedPeer {
            authenticated: peer.identity.to_string(),
        });
    }
    Ok(peer.identity)
}
pub fn admit_domain_authorities(
    anchors: &DomainAnchorSet,
    domain: &Strng,
    authority_ders: &[CertificateDer<'static>],
    now: SystemTime,
) -> Result<Vec<CertificateDer<'static>>, AnchorError> {
    let pins = anchors.current_pins(domain, now)?;
    if authority_ders.is_empty() {
        return Err(AnchorError::MissingCurrentPin {
            domain: domain.to_string(),
        });
    }
    let mut seen = HashSet::new();
    let mut admitted = Vec::with_capacity(authority_ders.len());
    for der in authority_ders {
        let spki = spki_der(der.as_ref())?;
        if spki == anchors.organizational_root_spki {
            return Err(AnchorError::RejectedRoot {
                domain: domain.to_string(),
            });
        }
        let pin = pins
            .iter()
            .find(|pin| pin.current(now) && pin.der == *der)
            .ok_or_else(|| AnchorError::UnpinnedAuthority {
                domain: domain.to_string(),
            })?;
        if !seen.insert(pin.der.as_ref().to_vec()) {
            return Err(AnchorError::UnpinnedAuthority {
                domain: domain.to_string(),
            });
        }
        admitted.push(pin.der.clone());
    }
    Ok(admitted)
}
pub fn select_published(
    current: Option<&DomainAnchorSet>,
    candidate: DomainAnchorSet,
) -> Result<DomainAnchorSet, AnchorError> {
    if let Some(current) = current {
        if candidate.local_domain != current.local_domain
            || candidate.organizational_root != current.organizational_root
        {
            return Err(AnchorError::ChangedProfileAuthority);
        }
        if candidate.generation <= current.generation {
            return Err(AnchorError::StaleGeneration {
                current: current.generation,
                candidate: candidate.generation,
            });
        }
    }
    Ok(candidate)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorPublication {
    set: DomainAnchorSet,
    bundle_fenced: HashSet<Vec<u8>>,
    drain_admitted_before: HashMap<Vec<u8>, u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleFetch {
    Authorities(Vec<CertificateDer<'static>>),
    Unavailable,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleObservation {
    Consistent,
    Unavailable,
    Rejected(AnchorError),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlineSupervisor {
    deadline: SystemTime,
}

impl AnchorPublication {
    pub fn initial(set: DomainAnchorSet) -> Self {
        Self {
            set,
            bundle_fenced: HashSet::new(),
            drain_admitted_before: HashMap::new(),
        }
    }
    pub fn generation(&self) -> u64 {
        self.set.generation
    }
    pub fn anchors(&self) -> &DomainAnchorSet {
        &self.set
    }
    pub fn bundle_fenced(&self, spki: &[u8]) -> bool {
        self.bundle_fenced.contains(spki)
    }
    fn require_newer(&self, generation: u64) -> Result<(), AnchorError> {
        if generation <= self.generation() {
            return Err(AnchorError::StaleGeneration {
                current: self.generation(),
                candidate: generation,
            });
        }
        Ok(())
    }
    pub fn withdraw_pin(
        &self,
        domain: &Strng,
        spki: &[u8],
        generation: u64,
    ) -> Result<Self, AnchorError> {
        self.require_newer(generation)?;
        let pins = self
            .set
            .by_domain
            .get(domain)
            .ok_or_else(|| AnchorError::UntrustedTrustDomain(domain.to_string()))?;
        if !pins.iter().any(|pin| pin.spki_der == spki) {
            return Err(AnchorError::InvalidPin(domain.to_string()));
        }
        let mut next = self.clone();
        let pins = next
            .set
            .by_domain
            .get_mut(domain)
            .expect("validated domain");
        pins.retain(|pin| pin.spki_der != spki);
        if pins.is_empty() {
            next.set.by_domain.remove(domain);
        }
        next.bundle_fenced.insert(spki.to_vec());
        next.drain_admitted_before.insert(spki.to_vec(), generation);
        next.set.generation = generation;
        // Local domain withdrawal is allowed and fails closed; it need not wait
        // for a functioning SPIRE bundle fetch or a replacement local issuer.
        Ok(next)
    }
    pub fn restore_authoritative(
        &self,
        pins: Vec<DomainPin>,
        generation: u64,
    ) -> Result<Self, AnchorError> {
        self.require_newer(generation)?;
        let domain = pins
            .first()
            .ok_or_else(|| AnchorError::InvalidPin(String::new()))?
            .trust_domain
            .clone();
        if pins.iter().any(|pin| pin.trust_domain != domain) {
            return Err(AnchorError::InvalidPin(domain.to_string()));
        }
        // Same-domain retained pins are included so rotation overlap can restore
        // one withdrawn key while another approved key remains in that domain.
        let all = self
            .set
            .by_domain
            .values()
            .flatten()
            .cloned()
            .chain(pins.iter().cloned())
            .collect();
        let candidate = DomainAnchorSet::try_new(
            self.set.local_domain.clone(),
            self.set.organizational_root.clone(),
            generation,
            all,
        )?;
        let mut next = self.clone();
        next.set = candidate;
        for pin in pins {
            next.bundle_fenced.remove(&pin.spki_der);
            next.drain_admitted_before.insert(pin.spki_der, generation);
        }
        Ok(next)
    }
    pub fn replace(&self, candidate: DomainAnchorSet) -> Result<Self, AnchorError> {
        self.require_newer(candidate.generation)?;
        if candidate.local_domain != self.set.local_domain
            || candidate.organizational_root != self.set.organizational_root
        {
            return Err(AnchorError::ChangedProfileAuthority);
        }
        for pin in candidate.by_domain.values().flatten() {
            if self.bundle_fenced.contains(&pin.spki_der) {
                return Err(AnchorError::WithdrawnSnapshot {
                    candidate: candidate.generation,
                });
            }
            // Same key with changed DER or domain is a new explicit authority
            // decision. Require withdraw + authoritative restore, not a snapshot.
            if self
                .set
                .by_domain
                .values()
                .flatten()
                .any(|old| old.spki_der == pin.spki_der && old != pin)
            {
                return Err(AnchorError::InvalidPin(pin.trust_domain.to_string()));
            }
        }
        let mut next = self.clone();
        for old in self.set.by_domain.values().flatten() {
            if !candidate.by_domain.values().flatten().any(|pin| pin == old) {
                next.bundle_fenced.insert(old.spki_der.clone());
                next.drain_admitted_before
                    .insert(old.spki_der.clone(), candidate.generation);
            }
        }
        next.set = candidate;
        Ok(next)
    }
    pub fn observe_bundle(
        &self,
        domain: &Strng,
        fetched: BundleFetch,
        now: SystemTime,
    ) -> BundleObservation {
        let BundleFetch::Authorities(ders) = fetched else {
            return BundleObservation::Unavailable;
        };
        for der in &ders {
            match spki_der(der.as_ref()) {
                Ok(spki) if self.bundle_fenced.contains(&spki) => {
                    return BundleObservation::Rejected(AnchorError::WithdrawnIssuer {
                        domain: domain.to_string(),
                    });
                }
                Err(err) => return BundleObservation::Rejected(err),
                _ => (),
            }
        }
        match admit_domain_authorities(&self.set, domain, &ders, now) {
            Ok(_) => BundleObservation::Consistent,
            Err(error) => BundleObservation::Rejected(error),
        }
    }
}

impl DeadlineSupervisor {
    pub fn at(deadline: SystemTime) -> Self {
        Self { deadline }
    }
    pub fn decision(&self, now: SystemTime) -> RetainedDecision {
        if now >= self.deadline {
            RetainedDecision::Drain
        } else {
            RetainedDecision::Keep
        }
    }
}

pub fn retained_tunnel(
    tunnel: &RetainedTunnel,
    publication: &AnchorPublication,
    now: SystemTime,
) -> RetainedDecision {
    let evidence = &tunnel.0;
    if evidence.anchor_generation > publication.generation()
        || now >= evidence.valid_until
        || publication.bundle_fenced.contains(&evidence.signer_spki)
        || publication
            .drain_admitted_before
            .get(&evidence.signer_spki)
            .is_some_and(|generation| evidence.anchor_generation < *generation)
    {
        return RetainedDecision::Drain;
    }
    let Ok(pins) = publication
        .set
        .current_pins(&evidence.identity.trust_domain(), now)
    else {
        return RetainedDecision::Drain;
    };
    if pins
        .iter()
        .any(|pin| pin.current(now) && pin.spki_der == evidence.signer_spki)
    {
        RetainedDecision::Keep
    } else {
        RetainedDecision::Drain
    }
}

pub fn signer_deadline(anchors: &DomainAnchorSet, signer_spki: &[u8]) -> Option<SystemTime> {
    anchors
        .by_domain
        .values()
        .flatten()
        .find(|pin| pin.spki_der == signer_spki)
        .map(|pin| pin.not_after.min(anchors.root_not_after))
}

// A helper, not a running supervisor. Production still must cancel the relay
// future and both inner and outer HBONE layers and evict the affected pool key.
// SHUT_RDWR closes both halves; AsyncWriteExt::shutdown alone only sends FIN.
pub async fn apply_retention(
    stream: &mut tokio::net::TcpStream,
    decision: RetainedDecision,
) -> std::io::Result<RetainedDecision> {
    if decision == RetainedDecision::Drain {
        socket2::SockRef::from(&*stream).shutdown(std::net::Shutdown::Both)?;
    }
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::string::Ia5String;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, SanType,
    };

    const A: &str = "cmtc-a.mesh.example";
    const B: &str = "cmtc-b.mesh.example";
    const URI_A: &str = "spiffe://cmtc-a.mesh.example/ns/orders/sa/api";
    const URI_B: &str = "spiffe://cmtc-b.mesh.example/ns/orders/sa/api";

    fn ca_params(name: &str) -> CertificateParams {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        p.distinguished_name.push(DnType::CommonName, name);
        p
    }
    fn ca(name: &str) -> CertifiedIssuer<'static, KeyPair> {
        CertifiedIssuer::self_signed(ca_params(name), KeyPair::generate().unwrap()).unwrap()
    }
    fn leaf_params(sans: &[&str]) -> CertificateParams {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        p.subject_alt_names = sans
            .iter()
            .map(|s| SanType::URI(Ia5String::try_from(s.to_string()).unwrap()))
            .collect();
        p
    }
    fn leaf(sans: &[&str], issuer: &CertifiedIssuer<'_, KeyPair>) -> CertificateDer<'static> {
        leaf_params(sans)
            .signed_by(&KeyPair::generate().unwrap(), &**issuer)
            .unwrap()
            .der()
            .clone()
    }
    fn profile(
        root: &CertifiedIssuer<'_, KeyPair>,
        a: &CertifiedIssuer<'_, KeyPair>,
        b: &CertifiedIssuer<'_, KeyPair>,
    ) -> DomainAnchorSet {
        DomainAnchorSet::try_new(
            A.into(),
            root.der().clone(),
            1,
            vec![
                pin_from_certificate(A.into(), a.der().clone()).unwrap(),
                pin_from_certificate(B.into(), b.der().clone()).unwrap(),
            ],
        )
        .unwrap()
    }
    fn fixture() -> (
        CertifiedIssuer<'static, KeyPair>,
        CertifiedIssuer<'static, KeyPair>,
        CertifiedIssuer<'static, KeyPair>,
        DomainAnchorSet,
    ) {
        let root = ca("root");
        let a = CertifiedIssuer::signed_by(ca_params("a"), KeyPair::generate().unwrap(), &root)
            .unwrap();
        let b = CertifiedIssuer::signed_by(ca_params("b"), KeyPair::generate().unwrap(), &root)
            .unwrap();
        let set = profile(&root, &a, &b);
        (root, a, b, set)
    }
    #[test]
    fn positive_roles_wrong_signer_and_expected_identity() {
        let (_, a, b, set) = fixture();
        let leaf_a = leaf(&[URI_A], &a);
        for role in [PeerRole::Client, PeerRole::Server] {
            assert_eq!(
                verify_expected_identity(
                    &leaf_a,
                    &[],
                    &set,
                    &[Identity::from_str(URI_A).unwrap()],
                    UnixTime::now(),
                    role
                )
                .unwrap()
                .to_string(),
                URI_A
            );
            assert!(
                verify_peer_certificate(&leaf(&[URI_A], &b), &[], &set, UnixTime::now(), role)
                    .is_err()
            );
            assert!(
                verify_expected_identity(
                    &leaf_a,
                    &[],
                    &set,
                    &[Identity::from_str(URI_B).unwrap()],
                    UnixTime::now(),
                    role
                )
                .is_err()
            );
        }
        let evidence =
            verify_peer_evidence(&leaf_a, &[], &set, UnixTime::now(), PeerRole::Client).unwrap();
        let tunnel = evidence.retained_tunnel();
        assert_eq!(
            retained_tunnel(
                &tunnel,
                &AnchorPublication::initial(set.clone()),
                SystemTime::now()
            ),
            RetainedDecision::Keep
        );
        assert_eq!(
            retained_tunnel(
                &tunnel,
                &AnchorPublication::initial(set.with_generation(2).unwrap()),
                SystemTime::now()
            ),
            RetainedDecision::Keep
        );
        assert_eq!(
            retained_tunnel(
                &tunnel,
                &AnchorPublication::initial(set.clone()),
                evidence.valid_until
            ),
            RetainedDecision::Drain
        );
    }
    #[test]
    fn independent_metadata_cannot_hide_root_or_extend_expiry() {
        let (root, a, _, _) = fixture();
        // Child test can forge private fields; public callers cannot. Constructor
        // still detects the forged value, providing defense-in-depth.
        let legitimate = pin_from_certificate(A.into(), a.der().clone()).unwrap();
        let mut forged = pin_from_certificate(A.into(), root.der().clone()).unwrap();
        forged.spki_der = legitimate.spki_der.clone();
        assert!(DomainAnchorSet::try_new(A.into(), root.der().clone(), 1, vec![forged]).is_err());
        let mut forged = legitimate;
        forged.not_after = forged
            .not_after
            .checked_add(Duration::from_secs(1))
            .unwrap();
        assert!(DomainAnchorSet::try_new(A.into(), root.der().clone(), 1, vec![forged]).is_err());
    }
    #[test]
    fn no_leaf_or_non_keysigning_ca_as_authority() {
        let (_, a, _, _) = fixture();
        assert!(pin_from_certificate(A.into(), leaf(&[URI_A], &a)).is_err());
        let mut p = ca_params("wrong-ku");
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let cert = p.self_signed(&KeyPair::generate().unwrap()).unwrap();
        assert!(pin_from_certificate(A.into(), cert.der().clone()).is_err());
    }
    #[test]
    fn wrong_authority_signature_and_delegated_signers_fail() {
        let (root, a, _, set) = fixture();
        let other = ca("unapproved-root");
        let wrong =
            CertifiedIssuer::signed_by(ca_params("wrong"), KeyPair::generate().unwrap(), &other)
                .unwrap();
        assert!(
            DomainAnchorSet::try_new(
                A.into(),
                root.der().clone(),
                1,
                vec![pin_from_certificate(A.into(), wrong.der().clone()).unwrap()]
            )
            .is_err()
        );
        let delegated =
            CertifiedIssuer::signed_by(ca_params("delegated"), KeyPair::generate().unwrap(), &a)
                .unwrap();
        assert!(
            verify_peer_certificate(
                &leaf(&[URI_A], &delegated),
                &[delegated.der().clone()],
                &set,
                UnixTime::now(),
                PeerRole::Client
            )
            .is_err()
        );
        // Even a delegated issuer with the pinned issuer's same subject must fail.
        let same_name =
            CertifiedIssuer::signed_by(ca_params("a"), KeyPair::generate().unwrap(), &a).unwrap();
        assert!(
            verify_peer_certificate(
                &leaf(&[URI_A], &same_name),
                &[same_name.der().clone()],
                &set,
                UnixTime::now(),
                PeerRole::Client
            )
            .is_err()
        );
    }
    #[test]
    fn exact_canonical_der_rejects_same_key_altered_certificate() {
        let (root, a, _, set) = fixture();
        let changed = ca_params("replacement-subject")
            .signed_by(a.key(), &*root)
            .unwrap();
        assert_eq!(spki_der(changed.der()).unwrap(), spki_der(a.der()).unwrap());
        assert!(
            admit_domain_authorities(&set, &A.into(), &[changed.der().clone()], SystemTime::now())
                .is_err()
        );
        assert_eq!(
            admit_domain_authorities(&set, &A.into(), &[a.der().clone()], SystemTime::now())
                .unwrap(),
            vec![a.der().clone()]
        );
        assert!(
            admit_domain_authorities(&set, &A.into(), &[root.der().clone()], SystemTime::now())
                .is_err()
        );
        assert!(
            admit_domain_authorities(
                &set,
                &A.into(),
                &[a.der().clone(), a.der().clone()],
                SystemTime::now()
            )
            .is_err()
        );
    }
    #[test]
    fn trailing_der_rejected_in_all_inputs() {
        let (_, a, _, set) = fixture();
        let corrupt = |der: &CertificateDer<'_>| {
            let mut bytes = der.as_ref().to_vec();
            bytes.push(0);
            CertificateDer::from(bytes)
        };
        assert!(pin_from_certificate(A.into(), corrupt(a.der())).is_err());
        assert!(
            admit_domain_authorities(&set, &A.into(), &[corrupt(a.der())], SystemTime::now())
                .is_err()
        );
        assert!(
            verify_peer_certificate(
                &corrupt(&leaf(&[URI_A], &a)),
                &[],
                &set,
                UnixTime::now(),
                PeerRole::Client
            )
            .is_err()
        );
        assert!(
            verify_peer_certificate(
                &leaf(&[URI_A], &a),
                &[corrupt(a.der())],
                &set,
                UnixTime::now(),
                PeerRole::Client
            )
            .is_err()
        );
    }
    #[test]
    fn malformed_extra_and_unsupported_sans_fail() {
        let (_, a, _, set) = fixture();
        for sans in [
            vec![],
            vec![URI_A, URI_A],
            vec![URI_A, "https://example.org"],
            vec!["spiffe://cmtc-a.mesh.example/ns//sa/api"],
            vec!["spiffe://cmtc-a.mesh.example:443/ns/orders/sa/api"],
            vec!["spiffe://cmtc-a.mesh.example/ns/orders/sa/api?admin=true"],
        ] {
            assert!(
                verify_peer_certificate(
                    &leaf(&sans, &a),
                    &[],
                    &set,
                    UnixTime::now(),
                    PeerRole::Client
                )
                .is_err()
            );
        }
        let mut params = leaf_params(&[URI_A]);
        params.subject_alt_names.push(SanType::DnsName(
            Ia5String::try_from("example.org".to_string()).unwrap(),
        ));
        let mixed = params
            .signed_by(&KeyPair::generate().unwrap(), &*a)
            .unwrap();
        assert!(
            verify_peer_certificate(mixed.der(), &[], &set, UnixTime::now(), PeerRole::Client)
                .is_err()
        );
    }
    #[test]
    fn encoded_ca_expiry_and_not_before_cannot_be_overridden() {
        let root = ca("root");
        for future in [false, true] {
            let mut p = ca_params("timed");
            let now = time::OffsetDateTime::now_utc();
            if future {
                p.not_before = now + time::Duration::days(1);
                p.not_after = now + time::Duration::days(2);
            } else {
                p.not_before = now - time::Duration::days(2);
                p.not_after = now - time::Duration::days(1);
            }
            let timed = CertifiedIssuer::signed_by(p, KeyPair::generate().unwrap(), &root).unwrap();
            let set = DomainAnchorSet::try_new(
                A.into(),
                root.der().clone(),
                1,
                vec![pin_from_certificate(A.into(), timed.der().clone()).unwrap()],
            )
            .unwrap();
            assert!(
                verify_peer_certificate(
                    &leaf(&[URI_A], &timed),
                    &[],
                    &set,
                    UnixTime::now(),
                    PeerRole::Server
                )
                .is_err()
            );
            assert!(
                admit_domain_authorities(
                    &set,
                    &A.into(),
                    &[timed.der().clone()],
                    SystemTime::now()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn generation_removal_restore_and_authority_changes() {
        let (_, _, b, set) = fixture();
        let removed = set.retire_domain(&B.into(), 2).unwrap();
        assert!(select_published(Some(&removed), set.clone()).is_err());
        assert!(
            verify_peer_certificate(
                &leaf(&[URI_B], &b),
                &[],
                &removed,
                UnixTime::now(),
                PeerRole::Client
            )
            .is_err()
        );
        let restored = removed
            .restore_domain(
                vec![pin_from_certificate(B.into(), b.der().clone()).unwrap()],
                3,
            )
            .unwrap();
        assert!(
            verify_peer_certificate(
                &leaf(&[URI_B], &b),
                &[],
                &restored,
                UnixTime::now(),
                PeerRole::Client
            )
            .is_ok()
        );
        let mut changed = restored.with_generation(4).unwrap();
        changed.local_domain = B.into();
        assert_eq!(
            select_published(Some(&restored), changed),
            Err(AnchorError::ChangedProfileAuthority)
        );
        assert!(restored.retire_domain(&A.into(), 4).is_err());
    }
    #[test]
    fn snapshots_cannot_restore_withdrawn_issuers_or_old_connections() {
        let (_, _, b, set) = fixture();
        let peer_b = leaf(&[URI_B], &b);
        let evidence =
            verify_peer_evidence(&peer_b, &[], &set, UnixTime::now(), PeerRole::Client).unwrap();
        let tunnel = evidence.retained_tunnel();
        let publication = AnchorPublication::initial(set.clone());
        let withdrawn = publication
            .withdraw_pin(&B.into(), &evidence.signer_spki, 2)
            .unwrap();
        assert_eq!(
            retained_tunnel(&tunnel, &withdrawn, SystemTime::now()),
            RetainedDecision::Drain
        );
        assert!(withdrawn.replace(set.with_generation(3).unwrap()).is_err());
        assert!(matches!(
            withdrawn.observe_bundle(
                &B.into(),
                BundleFetch::Authorities(vec![b.der().clone()]),
                SystemTime::now()
            ),
            BundleObservation::Rejected(_)
        ));
        let restored = withdrawn
            .restore_authoritative(
                vec![pin_from_certificate(B.into(), b.der().clone()).unwrap()],
                3,
            )
            .unwrap();
        assert_eq!(
            retained_tunnel(&tunnel, &restored, SystemTime::now()),
            RetainedDecision::Drain
        );
        let fresh = verify_peer_evidence(
            &peer_b,
            &[],
            restored.anchors(),
            UnixTime::now(),
            PeerRole::Client,
        )
        .unwrap()
        .retained_tunnel();
        assert_eq!(
            retained_tunnel(&fresh, &restored, SystemTime::now()),
            RetainedDecision::Keep
        );
        // Removing a key through a full snapshot creates the same tombstone.
        let removed_set = restored.anchors().retire_domain(&B.into(), 4).unwrap();
        let removed = restored.replace(removed_set).unwrap();
        assert!(
            removed
                .replace(restored.anchors().with_generation(5).unwrap())
                .is_err()
        );
        assert_eq!(
            retained_tunnel(&fresh, &removed, SystemTime::now()),
            RetainedDecision::Drain
        );
    }
    #[tokio::test]
    async fn drain_closes_read_half_as_well_as_write_half() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        assert_eq!(
            apply_retention(&mut server, RetainedDecision::Keep)
                .await
                .unwrap(),
            RetainedDecision::Keep
        );
        apply_retention(&mut server, RetainedDecision::Drain)
            .await
            .unwrap();
        let mut byte = [0];
        let read = tokio::time::timeout(Duration::from_millis(250), server.read(&mut byte))
            .await
            .expect("SHUT_RDWR must end reads");
        assert_eq!(read.unwrap(), 0);
    }
    #[test]
    fn shared_root_chain_success_does_not_authorize_another_domain() {
        let (root, _, b, set) = fixture();
        let foreign = leaf(&[URI_A], &b);
        let mut roots = RootCertStore::empty();
        roots.add(root.der().clone()).unwrap();
        verify_cert_chain(
            &foreign,
            &[b.der().clone()],
            &roots,
            UnixTime::now(),
            KeyUsage::client_auth(),
            &[],
        )
        .expect("ordinary shared-root verification succeeds");
        assert_eq!(
            verify_peer_evidence(&foreign, &[], &set, UnixTime::now(), PeerRole::Client),
            Err(AnchorError::AmbiguousIssuer(A.to_string()))
        );
    }

    #[test]
    fn organization_root_path_length_must_allow_cluster_intermediates() {
        let mut params = ca_params("root-without-intermediates");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let root = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        let a = CertifiedIssuer::signed_by(ca_params("a"), KeyPair::generate().unwrap(), &root)
            .unwrap();
        assert!(
            DomainAnchorSet::try_new(
                A.into(),
                root.der().clone(),
                1,
                vec![pin_from_certificate(A.into(), a.der().clone()).unwrap()]
            )
            .is_err()
        );
    }

    #[test]
    fn retained_evidence_expires_with_the_leaf_before_the_authority() {
        let (_, a, _, set) = fixture();
        let now = time::OffsetDateTime::now_utc();
        let mut params = leaf_params(&[URI_A]);
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::minutes(1);
        let expected = UNIX_EPOCH + Duration::from_secs(params.not_after.unix_timestamp() as u64);
        let certificate = params
            .signed_by(&KeyPair::generate().unwrap(), &*a)
            .unwrap();
        let evidence = verify_peer_evidence(
            certificate.der(),
            &[],
            &set,
            UnixTime::now(),
            PeerRole::Client,
        )
        .unwrap();
        assert_eq!(evidence.deadline(), expected);
        let publication = AnchorPublication::initial(set);
        let tunnel = evidence.retained_tunnel();
        assert_eq!(
            retained_tunnel(&tunnel, &publication, expected - Duration::from_secs(1)),
            RetainedDecision::Keep
        );
        assert_eq!(
            retained_tunnel(&tunnel, &publication, expected),
            RetainedDecision::Drain
        );
    }
}
