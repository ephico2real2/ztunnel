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
    lineage: Vec<CertificateDer<'static>>,
    // The pin is the cluster's SPIRE intermediate, directly under the root: SPIRE
    // rotates its signing CA below it, so a peer path has exactly one CA between.
    signs_spire_ca: bool,
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
    pub fn signer_spki(&self) -> &[u8] {
        &self.signer_spki
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
    ca_material_for_domain(cert, None)
}
fn ca_material_for_domain(
    cert: &X509Certificate<'_>,
    domain: Option<&Strng>,
) -> Result<(), AnchorError> {
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
    // Retain all existing extension constraints. The only additional signer
    // field is SPIRE's exact trust-domain URI SAN. It never assigns authority.
    for ext in cert.extensions() {
        let allowed=match ext.parsed_extension(){
            ParsedExtension::BasicConstraints(_)|ParsedExtension::KeyUsage(_)|ParsedExtension::SubjectKeyIdentifier(_)|ParsedExtension::AuthorityKeyIdentifier(_)=>true,
            ParsedExtension::SubjectAlternativeName(san)=>domain.is_some_and(|domain|{
                san.general_names.len()==1 && matches!(&san.general_names[0],GeneralName::URI(uri) if *uri==format!("spiffe://{domain}"))
            }),
            _=>false,
        };
        if !allowed {
            return Err(AnchorError::BadEncoding);
        }
    }
    validity(cert)?;
    Ok(())
}
pub fn spki_der(der: &[u8]) -> Result<Vec<u8>, AnchorError> {
    Ok(parse_exact(der)?.public_key().raw.to_vec())
}
fn ca_depth_allows(cert: &X509Certificate<'_>, below: u32) -> Result<bool, AnchorError> {
    let constraints = cert
        .basic_constraints()
        .map_err(|_| AnchorError::BadEncoding)?
        .ok_or(AnchorError::BadEncoding)?;
    Ok(constraints
        .value
        .path_len_constraint
        .is_none_or(|depth| depth >= below))
}
pub fn pin_from_certificate(
    trust_domain: Strng,
    der: CertificateDer<'static>,
) -> Result<DomainPin, AnchorError> {
    pin_from_certificate_with_lineage(trust_domain, der, Vec::new())
}
// Lineage is administrator-approved public material, not a discovered bundle.
// The optional single parent is never placed in the peer workload root store.
pub fn pin_from_certificate_with_lineage(
    trust_domain: Strng,
    der: CertificateDer<'static>,
    lineage: Vec<CertificateDer<'static>>,
) -> Result<DomainPin, AnchorError> {
    pin_from_certificate_with_role(trust_domain, der, lineage, false)
}
// `signs_spire_ca` pins the cluster's SPIRE intermediate instead of SPIRE's own
// signing CA. It has no lineage (the root signs it) and path depth for one CA.
pub fn pin_from_certificate_with_role(
    trust_domain: Strng,
    der: CertificateDer<'static>,
    lineage: Vec<CertificateDer<'static>>,
    signs_spire_ca: bool,
) -> Result<DomainPin, AnchorError> {
    validate_domain(&trust_domain)?;
    if lineage.len() > 1 {
        return Err(AnchorError::InvalidPin(trust_domain.to_string()));
    }
    let cert = parse_exact(der.as_ref())?;
    ca_material_for_domain(&cert, Some(&trust_domain))?;
    if signs_spire_ca && (!lineage.is_empty() || !ca_depth_allows(&cert, 1)?) {
        return Err(AnchorError::InvalidPin(trust_domain.to_string()));
    }
    let (mut not_before, mut not_after) = validity(&cert)?;
    let spki_der = cert.public_key().raw.to_vec();
    if let Some(parent_der) = lineage.first() {
        let parent = parse_exact(parent_der.as_ref())?;
        ca_material(&parent)?;
        if spki_der.as_slice() == parent.public_key().raw
            || !ca_depth_allows(&parent, 1)?
            || cert.issuer() != parent.subject()
            || cert.verify_signature(Some(parent.public_key())).is_err()
        {
            return Err(AnchorError::InvalidPin(trust_domain.to_string()));
        }
        let (before, after) = validity(&parent)?;
        not_before = not_before.max(before);
        not_after = not_after.min(after);
    }
    if not_before >= not_after {
        return Err(AnchorError::InvalidPin(trust_domain.to_string()));
    }
    Ok(DomainPin {
        trust_domain,
        spki_der,
        der,
        lineage,
        signs_spire_ca,
        not_before,
        not_after,
    })
}
impl DomainPin {
    pub fn lineage_ders(&self) -> &[CertificateDer<'static>] {
        &self.lineage
    }
    pub fn signs_spire_ca(&self) -> bool {
        self.signs_spire_ca
    }
    fn current(&self, now: SystemTime) -> bool {
        self.not_before <= now && now < self.not_after
    }
    fn validate_encoded(&self) -> Result<(), AnchorError> {
        if pin_from_certificate_with_role(
            self.trust_domain.clone(),
            self.der.clone(),
            self.lineage.clone(),
            self.signs_spire_ca,
        )? != *self
        {
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
        Self::try_new_inner(local_domain, organizational_root, generation, pins, true)
    }
    fn try_new_inner(
        local_domain: Strng,
        organizational_root: CertificateDer<'static>,
        generation: u64,
        pins: Vec<DomainPin>,
        require_local: bool,
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
        let signer_keys: HashSet<Vec<u8>> = pins.iter().map(|pin| pin.spki_der.clone()).collect();
        let mut seen = HashSet::new();
        let mut parent_owners: HashMap<Vec<u8>, (Strng, Vec<u8>)> = HashMap::new();
        for pin in pins {
            pin.validate_encoded()?;
            let cert = parse_exact(pin.der.as_ref())?;
            if pin.spki_der == organizational_root_spki || !seen.insert(pin.spki_der.clone()) {
                return Err(AnchorError::InvalidPin(pin.trust_domain.to_string()));
            }
            if let Some(parent_der) = pin.lineage.first() {
                let parent = parse_exact(parent_der.as_ref())?;
                let key = parent.public_key().raw.to_vec();
                if key == organizational_root_spki
                    || signer_keys.contains(&key)
                    || !ca_depth_allows(&root, 2)?
                    || !ca_depth_allows(&parent, 1)?
                    || parent.issuer() != root.subject()
                    || parent.verify_signature(Some(root.public_key())).is_err()
                {
                    return Err(AnchorError::InvalidPin(pin.trust_domain.to_string()));
                }
                if parent_owners.get(&key).is_some_and(|(domain, der)| {
                    domain != &pin.trust_domain || der.as_slice() != parent_der.as_ref()
                }) {
                    return Err(AnchorError::InvalidPin(pin.trust_domain.to_string()));
                }
                parent_owners.insert(
                    key,
                    (pin.trust_domain.clone(), parent_der.as_ref().to_vec()),
                );
            } else if !ca_depth_allows(&root, if pin.signs_spire_ca { 2 } else { 1 })?
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
        if require_local && !by_domain.contains_key(&local_domain) {
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
// The peer's path to this pin, or None. Returns the path's own expiry: the pin's,
// or for a SPIRE intermediate pin the earlier of the pin and the SPIRE CA between.
fn path_accepts(
    end: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    pin: &DomainPin,
    now: UnixTime,
    role: PeerRole,
) -> Option<SystemTime> {
    let leaf = parse_exact(end.as_ref()).ok()?;
    if intermediates
        .iter()
        .any(|cert| parse_exact(cert.as_ref()).is_err())
    {
        return None;
    }
    let issuer = parse_exact(pin.der.as_ref()).ok()?;
    let mut roots = RootCertStore::empty();
    roots.add(pin.der.clone()).ok()?;
    let usage = match role {
        PeerRole::Client => KeyUsage::client_auth(),
        PeerRole::Server => KeyUsage::server_auth(),
    };
    let crls: &[CertRevocationList<'static>] = &[];
    if !pin.signs_spire_ca {
        if leaf.issuer() != issuer.subject() {
            return None;
        }
        let chain = verify_cert_chain(end, intermediates, &roots, now, usage, crls).ok()?;
        return chain.intermediates.is_empty().then_some(pin.not_after);
    }
    // pin -> exactly one SPIRE CA -> SVID. SPIRE rotates that CA, so it is not
    // pinned; it must be a CA whose only SAN is this trust domain's SPIFFE URI.
    let chain = verify_cert_chain(end, intermediates, &roots, now, usage, crls).ok()?;
    let [spire_ca] = chain.intermediates.as_slice() else {
        return None;
    };
    let ca = parse_exact(spire_ca.as_ref()).ok()?;
    ca_material_for_domain(&ca, Some(&pin.trust_domain)).ok()?;
    let has_domain_san = ca
        .subject_alternative_name()
        .ok()
        .flatten()
        .is_some_and(|san| san.value.general_names.len() == 1);
    if !has_domain_san
        || ca.public_key().raw == issuer.public_key().raw
        || ca.issuer() != issuer.subject()
        || leaf.issuer() != ca.subject()
    {
        return None;
    }
    let (_, ca_not_after) = validity(&ca).ok()?;
    Some(ca_not_after.min(pin.not_after))
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
        .filter(|pin| pin.current(observed))
        .filter_map(|pin| path_accepts(end, intermediates, pin, now, role).map(|until| (pin, until)))
        .collect();
    for (other, foreign) in &anchors.by_domain {
        if other != &domain
            && foreign.iter().any(|pin| {
                pin.current(observed) && path_accepts(end, intermediates, pin, now, role).is_some()
            })
        {
            return Err(AnchorError::AmbiguousIssuer(domain.to_string()));
        }
    }
    let [(pin, path_until)] = matched.as_slice() else {
        return Err(AnchorError::UnauthorizedIssuer(domain.to_string()));
    };
    let (_, leaf_not_after) = validity(&parse_exact(end.as_ref())?)?;
    Ok(VerifiedPeer {
        identity,
        anchor_generation: anchors.generation,
        signer_spki: pin.spki_der.clone(),
        valid_until: leaf_not_after
            .min(*path_until)
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

// Public certificate/key material only. No expiry/ACK/readiness assertion is
// trusted from disk. This format preserves revocation and connection cutoffs.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorCheckpoint {
    pub sequence: u64,
    pub local_domain: String,
    pub root_der: String,
    pub pins: Vec<CheckpointPin>,
    pub fenced_spkis: Vec<String>,
    pub drain_before: Vec<CheckpointCutoff>,
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointPin {
    pub domain: String,
    pub certificate_der: String,
    pub lineage_der: Vec<String>,
    // Absent in checkpoints written before SPIRE intermediate pins, and omitted
    // when false, so those checkpoints load and re-serialize unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub signs_spire_ca: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCutoff {
    pub spki_der: String,
    pub sequence: u64,
}
pub const MAX_CHECKPOINT_KEYS: usize = 256;
pub const MAX_CHECKPOINT_PINS: usize = 32;
fn checkpoint_b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}
fn checkpoint_der(value: &str, limit: usize) -> Result<Vec<u8>, AnchorError> {
    use base64::Engine;
    if value.is_empty() || value.len() > limit.saturating_mul(4).div_ceil(3) + 4 {
        return Err(AnchorError::BadEncoding);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| AnchorError::BadEncoding)?;
    if bytes.is_empty() || bytes.len() > limit || checkpoint_b64(&bytes) != value {
        return Err(AnchorError::BadEncoding);
    }
    Ok(bytes)
}
impl AnchorPublication {
    pub fn checkpoint(&self) -> Result<AnchorCheckpoint, AnchorError> {
        let mut pins: Vec<_> = self
            .set
            .by_domain
            .values()
            .flatten()
            .map(|p| CheckpointPin {
                domain: p.trust_domain.to_string(),
                certificate_der: checkpoint_b64(p.der.as_ref()),
                lineage_der: p
                    .lineage_ders()
                    .iter()
                    .map(|parent| checkpoint_b64(parent.as_ref()))
                    .collect(),
                signs_spire_ca: p.signs_spire_ca,
            })
            .collect();
        pins.sort_by(|a, b| (&a.domain, &a.certificate_der).cmp(&(&b.domain, &b.certificate_der)));
        let mut fenced_spkis: Vec<_> = self
            .bundle_fenced
            .iter()
            .map(|p| checkpoint_b64(p))
            .collect();
        fenced_spkis.sort();
        let mut drain_before: Vec<_> = self
            .drain_admitted_before
            .iter()
            .map(|(p, s)| CheckpointCutoff {
                spki_der: checkpoint_b64(p),
                sequence: *s,
            })
            .collect();
        drain_before.sort_by(|a, b| a.spki_der.cmp(&b.spki_der));
        let dto = AnchorCheckpoint {
            sequence: self.generation(),
            local_domain: self.set.local_domain.to_string(),
            root_der: checkpoint_b64(self.set.organizational_root.as_ref()),
            pins,
            fenced_spkis,
            drain_before,
        };
        // Apply the exact same validation to newly serialized and recovered state.
        Self::from_checkpoint(&dto)?;
        Ok(dto)
    }
    pub fn from_checkpoint(dto: &AnchorCheckpoint) -> Result<Self, AnchorError> {
        if dto.pins.len() > MAX_CHECKPOINT_PINS
            || dto.fenced_spkis.len() > MAX_CHECKPOINT_KEYS
            || dto.drain_before.len() > MAX_CHECKPOINT_KEYS
        {
            return Err(AnchorError::BadEncoding);
        }
        let mut previous_pin: Option<(&str, &str)> = None;
        let mut pins = Vec::with_capacity(dto.pins.len());
        for p in &dto.pins {
            let key = (p.domain.as_str(), p.certificate_der.as_str());
            if previous_pin.is_some_and(|old| old >= key) {
                return Err(AnchorError::BadEncoding);
            }
            previous_pin = Some(key);
            if p.lineage_der.len() > 1 {
                return Err(AnchorError::BadEncoding);
            }
            let lineage = p
                .lineage_der
                .iter()
                .map(|parent| checkpoint_der(parent, 24576).map(CertificateDer::from))
                .collect::<Result<Vec<_>, _>>()?;
            pins.push(pin_from_certificate_with_role(
                p.domain.clone().into(),
                checkpoint_der(&p.certificate_der, 32768)?.into(),
                lineage,
                p.signs_spire_ca,
            )?);
        }
        // Revalidate DER, root self-signature, direct signatures and uniqueness,
        // but permit an empty/local-withdrawn set recorded by a real withdrawal.
        let set = DomainAnchorSet::try_new_inner(
            dto.local_domain.clone().into(),
            checkpoint_der(&dto.root_der, 32768)?.into(),
            dto.sequence,
            pins,
            false,
        )?;
        if set.by_domain.len() > 16 || set.by_domain.values().any(|pins| pins.len() > 2) {
            return Err(AnchorError::BadEncoding);
        }
        let active: HashSet<_> = set
            .by_domain
            .values()
            .flatten()
            .map(|p| p.spki_der.clone())
            .collect();
        let mut bundle_fenced = HashSet::new();
        let mut previous: Option<&str> = None;
        for p in &dto.fenced_spkis {
            if previous.is_some_and(|old| old >= p.as_str()) {
                return Err(AnchorError::BadEncoding);
            }
            previous = Some(p);
            let bytes = checkpoint_der(p, 8192)?;
            if active.contains(&bytes)
                || bytes == set.organizational_root_spki
                || !bundle_fenced.insert(bytes)
            {
                return Err(AnchorError::BadEncoding);
            }
        }
        let mut drain_admitted_before = HashMap::new();
        previous = None;
        for cutoff in &dto.drain_before {
            if previous.is_some_and(|old| old >= cutoff.spki_der.as_str())
                || cutoff.sequence == 0
                || cutoff.sequence > dto.sequence
            {
                return Err(AnchorError::BadEncoding);
            }
            previous = Some(&cutoff.spki_der);
            let bytes = checkpoint_der(&cutoff.spki_der, 8192)?;
            if bytes == set.organizational_root_spki
                || drain_admitted_before
                    .insert(bytes, cutoff.sequence)
                    .is_some()
            {
                return Err(AnchorError::BadEncoding);
            }
        }
        if bundle_fenced
            .iter()
            .any(|p| !drain_admitted_before.contains_key(p))
        {
            return Err(AnchorError::BadEncoding);
        }
        let mut keys = active;
        keys.extend(bundle_fenced.iter().cloned());
        keys.extend(drain_admitted_before.keys().cloned());
        if keys.len() > MAX_CHECKPOINT_KEYS {
            return Err(AnchorError::BadEncoding);
        }
        Ok(Self {
            set,
            bundle_fenced,
            drain_admitted_before,
        })
    }
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

    /// Returns the exact current issuer certificate only for the authenticated
    /// trust domain and only when it has not been withdrawn or fenced.
    pub fn current_unfenced_signer(
        &self,
        domain: &Strng,
        spki: &[u8],
        now: SystemTime,
    ) -> Option<CertificateDer<'static>> {
        if self.bundle_fenced.contains(spki) {
            return None;
        }
        self.set
            .current_pins(domain, now)
            .ok()?
            .iter()
            .find(|pin| pin.spki_der == spki && pin.current(now))
            .map(|pin| pin.der.clone())
    }

    pub fn current_signer_ders(&self, now: SystemTime) -> Vec<CertificateDer<'static>> {
        if now < self.set.root_not_before || now >= self.set.root_not_after {
            return Vec::new();
        }
        self.set
            .by_domain
            .values()
            .flatten()
            .filter(|pin| pin.current(now) && !self.bundle_fenced.contains(&pin.spki_der))
            .map(|pin| pin.der.clone())
            .collect()
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
    /// Revoke every currently approved issuer, including the local domain, at a
    /// single authenticated publication sequence. This is an authoritative
    /// tombstone, NOT an API/ADS availability or freshness failure.
    ///
    /// Existing revocation and retained-connection history is cumulative. The
    /// organizational authority/local-domain identity is retained for a later
    /// explicitly authorized restore, but no issuer remains usable. Build the
    /// returned value first, then publish it under the runtime's single writer;
    /// this helper itself does not swap live TLS verifiers or drain sockets.
    pub fn withdraw_all(&self, sequence: u64) -> Result<Self, AnchorError> {
        self.require_newer(sequence)?;
        let mut next = self.clone();
        for pin in self.set.by_domain.values().flatten() {
            next.bundle_fenced.insert(pin.spki_der.clone());
            next.drain_admitted_before
                .insert(pin.spki_der.clone(), sequence);
        }
        next.set.by_domain.clear();
        next.set.generation = sequence;
        Ok(next)
    }

    /// Apply one complete, independently approved authority decision, including
    /// restoring multiple withdrawn domains at one publication sequence.
    ///
    /// The caller must authorize the *logical approval generation* separately
    /// from candidate.generation (the producer publication sequence). A lease
    /// renewal or same-generation replay is not restore authority. Ordinary
    /// snapshots must continue to use replace(), which rejects withdrawn keys.
    /// It never changes the local-domain identity. It may succeed the
    /// organizational root: only a strictly newer approval reaches here, and the
    /// decoder accepted its root only as an installation root pin. Every pin under
    /// the old root is then absent from the candidate, so it is fenced and drained.
    pub fn restore_authoritative_snapshot(
        &self,
        candidate: DomainAnchorSet,
    ) -> Result<Self, AnchorError> {
        self.require_newer(candidate.generation)?;
        if candidate.local_domain != self.set.local_domain {
            return Err(AnchorError::ChangedProfileAuthority);
        }
        let mut next = self.clone();
        // Removed keys remain revoked even when the same transaction restores
        // other keys. Preserve history for issuers absent from both snapshots.
        for old in self.set.by_domain.values().flatten() {
            if !candidate.by_domain.values().flatten().any(|pin| pin == old) {
                next.bundle_fenced.insert(old.spki_der.clone());
                next.drain_admitted_before
                    .insert(old.spki_der.clone(), candidate.generation);
            }
        }
        for pin in candidate.by_domain.values().flatten() {
            let was_fenced = self.bundle_fenced.contains(&pin.spki_der);
            let unchanged = self.set.by_domain.values().flatten().any(|old| old == pin);
            next.bundle_fenced.remove(&pin.spki_der);
            if was_fenced || !unchanged {
                // A restored key may authenticate a new connection, but cannot
                // resurrect a connection admitted before this decision.
                next.drain_admitted_before
                    .insert(pin.spki_der.clone(), candidate.generation);
            }
        }
        next.set = candidate;
        Ok(next)
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
    fn signer_spki_cannot_be_assigned_to_two_trust_domains() {
        let (root, a, _, _) = fixture();
        let err = DomainAnchorSet::try_new(
            A.into(),
            root.der().clone(),
            2,
            vec![
                pin_from_certificate(A.into(), a.der().clone()).unwrap(),
                pin_from_certificate(B.into(), a.der().clone()).unwrap(),
            ],
        )
        .unwrap_err();
        assert!(matches!(err, AnchorError::InvalidPin(_)));
    }

    #[test]
    fn current_signer_lookup_is_scoped_by_domain_time_and_withdrawal() {
        let (_, _, _, set) = fixture();
        let mut publication = AnchorPublication::initial(set);
        let domain_b: Strng = B.into();
        let domain_a: Strng = A.into();
        let spki = publication.anchors().pin_spkis(&domain_b).pop().unwrap();
        let now = SystemTime::now();

        assert!(
            publication
                .current_unfenced_signer(&domain_b, &spki, now)
                .is_some()
        );
        assert!(
            publication
                .current_unfenced_signer(&domain_a, &spki, now)
                .is_none()
        );
        assert!(
            publication
                .current_unfenced_signer(&domain_b, &spki, UNIX_EPOCH)
                .is_none()
        );

        publication = publication.withdraw_pin(&domain_b, &spki, 2).unwrap();
        assert!(
            publication
                .current_unfenced_signer(&domain_b, &spki, now)
                .is_none()
        );
    }

    #[test]
    fn signer_helpers_require_current_organizational_root() {
        let mut params = ca_params("short-root");
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::hours(1);
        let root = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        let a = CertifiedIssuer::signed_by(ca_params("a"), KeyPair::generate().unwrap(), &root)
            .unwrap();
        let pin = pin_from_certificate(A.into(), a.der().clone()).unwrap();
        let spki = pin.spki_der.clone();
        let set = DomainAnchorSet::try_new(A.into(), root.der().clone(), 1, vec![pin]).unwrap();
        let before = set.root_not_before - Duration::from_secs(1);
        let expired = set.root_not_after;
        let publication = AnchorPublication::initial(set);
        for time in [before, expired] {
            assert!(
                publication
                    .current_unfenced_signer(&A.into(), &spki, time)
                    .is_none()
            );
            assert!(publication.current_signer_ders(time).is_empty());
        }
        assert!(
            publication
                .current_unfenced_signer(&A.into(), &spki, SystemTime::now())
                .is_some()
        );
        assert_eq!(
            publication.current_signer_ders(SystemTime::now()),
            vec![a.der().clone()]
        );
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
    #[test]
    fn all_domain_tombstone_revokes_rotation_overlap_and_local_domain_in_one_sequence() {
        let (root, a, b, _) = fixture();
        let a2 = CertifiedIssuer::signed_by(
            ca_params("a-rotation"),
            KeyPair::generate().unwrap(),
            &root,
        )
        .unwrap();
        let c = CertifiedIssuer::signed_by(ca_params("c"), KeyPair::generate().unwrap(), &root)
            .unwrap();
        let domains = [A, A, B, "cmtc-c.mesh.example"];
        let issuers = [&a, &a2, &b, &c];
        let pins: Vec<_> = domains
            .iter()
            .zip(issuers)
            .map(|(domain, issuer)| {
                pin_from_certificate((*domain).into(), issuer.der().clone()).unwrap()
            })
            .collect();
        let set = DomainAnchorSet::try_new(A.into(), root.der().clone(), 10, pins.clone()).unwrap();
        let old = AnchorPublication::initial(set);
        let next = old.withdraw_all(11).unwrap();
        assert_eq!(old.generation(), 10);
        assert_eq!(old.current_signer_ders(SystemTime::now()).len(), 4);
        assert_eq!(next.generation(), 11);
        assert_eq!(next.anchors().local_domain(), &Strng::from(A));
        assert_eq!(next.set.organizational_root, old.set.organizational_root);
        assert!(next.current_signer_ders(SystemTime::now()).is_empty());
        assert!(next.set.by_domain.is_empty());
        for ((domain, issuer), pin) in domains.iter().zip(issuers).zip(pins) {
            let uri = format!("spiffe://{domain}/ns/orders/sa/api");
            let certificate = leaf(&[&uri], issuer);
            let retained = verify_peer_evidence(
                &certificate,
                &[],
                old.anchors(),
                UnixTime::now(),
                PeerRole::Client,
            )
            .unwrap()
            .retained_tunnel();
            assert!(next.bundle_fenced(&pin.spki_der));
            assert_eq!(next.drain_admitted_before.get(&pin.spki_der), Some(&11));
            assert!(
                next.current_unfenced_signer(&(*domain).into(), &pin.spki_der, SystemTime::now())
                    .is_none()
            );
            assert_eq!(
                retained_tunnel(&retained, &next, SystemTime::now()),
                RetainedDecision::Drain
            );
            for role in [PeerRole::Client, PeerRole::Server] {
                assert!(
                    verify_peer_evidence(&certificate, &[], next.anchors(), UnixTime::now(), role)
                        .is_err()
                );
            }
            assert!(matches!(
                next.observe_bundle(
                    &(*domain).into(),
                    BundleFetch::Authorities(vec![issuer.der().clone()]),
                    SystemTime::now()
                ),
                BundleObservation::Rejected(AnchorError::WithdrawnIssuer { .. })
            ));
        }
    }

    #[test]
    fn all_domain_tombstone_is_strictly_sequenced_and_preserves_prior_history() {
        let (_, _, _, set) = fixture();
        let b_spki = set.pin_spkis(&B.into()).pop().unwrap();
        let a_spki = set.pin_spkis(&A.into()).pop().unwrap();
        let partial = AnchorPublication::initial(set)
            .withdraw_pin(&B.into(), &b_spki, 2)
            .unwrap();
        let all = partial.withdraw_all(3).unwrap();
        assert_eq!(all.drain_admitted_before.get(&b_spki), Some(&2));
        assert_eq!(all.drain_admitted_before.get(&a_spki), Some(&3));
        for sequence in [0, 1, 2, 3] {
            let before = all.clone();
            assert_eq!(
                all.withdraw_all(sequence),
                Err(AnchorError::StaleGeneration {
                    current: 3,
                    candidate: sequence
                })
            );
            assert_eq!(all, before);
        }
        let repeated = all.withdraw_all(4).unwrap();
        assert_eq!(repeated.generation(), 4);
        assert_eq!(repeated.bundle_fenced, all.bundle_fenced);
        assert_eq!(repeated.drain_admitted_before, all.drain_admitted_before);
        assert!(repeated.set.by_domain.is_empty());
    }

    #[test]
    fn all_domain_tombstone_cannot_be_restored_by_an_ordinary_snapshot() {
        let (_, a, b, set) = fixture();
        let evidence: Vec<_> = [(&a, URI_A), (&b, URI_B)]
            .iter()
            .map(|(issuer, uri)| {
                verify_peer_evidence(
                    &leaf(&[uri], issuer),
                    &[],
                    &set,
                    UnixTime::now(),
                    PeerRole::Client,
                )
                .unwrap()
                .retained_tunnel()
            })
            .collect();
        let all = AnchorPublication::initial(set.clone())
            .withdraw_all(2)
            .unwrap();
        assert_eq!(
            all.replace(set.with_generation(3).unwrap()),
            Err(AnchorError::WithdrawnSnapshot { candidate: 3 })
        );
        let restored = all
            .restore_authoritative_snapshot(set.with_generation(3).unwrap())
            .unwrap();
        assert_eq!(restored.generation(), 3);
        assert_eq!(restored.current_signer_ders(SystemTime::now()).len(), 2);
        for (i, (issuer, uri)) in [(&a, URI_A), (&b, URI_B)].iter().enumerate() {
            assert_eq!(
                retained_tunnel(&evidence[i], &restored, SystemTime::now()),
                RetainedDecision::Drain
            );
            let fresh = verify_peer_evidence(
                &leaf(&[uri], issuer),
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
        }
        // Same-approval renewals use replace(), retain the drain floor, and do
        // not resurrect pre-revocation retained tunnels.
        let renewed = restored
            .replace(restored.anchors().with_generation(4).unwrap())
            .unwrap();
        assert_eq!(
            renewed.drain_admitted_before,
            restored.drain_admitted_before
        );
        for retained in evidence {
            assert_eq!(
                retained_tunnel(&retained, &renewed, SystemTime::now()),
                RetainedDecision::Drain
            );
        }
    }

    #[test]
    fn authoritative_snapshot_restore_preserves_unaffected_live_connections() {
        let (_, a, b, set) = fixture();
        let a_tunnel = verify_peer_evidence(
            &leaf(&[URI_A], &a),
            &[],
            &set,
            UnixTime::now(),
            PeerRole::Client,
        )
        .unwrap()
        .retained_tunnel();
        let b_tunnel = verify_peer_evidence(
            &leaf(&[URI_B], &b),
            &[],
            &set,
            UnixTime::now(),
            PeerRole::Client,
        )
        .unwrap()
        .retained_tunnel();
        let b_spki = set.pin_spkis(&B.into()).pop().unwrap();
        let partial = AnchorPublication::initial(set.clone())
            .withdraw_pin(&B.into(), &b_spki, 2)
            .unwrap();
        let restored = partial
            .restore_authoritative_snapshot(set.with_generation(3).unwrap())
            .unwrap();
        assert_eq!(
            retained_tunnel(&a_tunnel, &restored, SystemTime::now()),
            RetainedDecision::Keep
        );
        assert_eq!(
            retained_tunnel(&b_tunnel, &restored, SystemTime::now()),
            RetainedDecision::Drain
        );
        assert_eq!(restored.drain_admitted_before.get(&b_spki), Some(&3));
    }

    #[test]
    fn authoritative_snapshot_keeps_absent_issuer_history_and_revokes_simultaneous_removals() {
        let (root, a, _, set) = fixture();
        let old_a = set.pin_spkis(&A.into()).pop().unwrap();
        let old_b = set.pin_spkis(&B.into()).pop().unwrap();
        let a2 =
            CertifiedIssuer::signed_by(ca_params("new-a"), KeyPair::generate().unwrap(), &root)
                .unwrap();
        let b2 =
            CertifiedIssuer::signed_by(ca_params("new-b"), KeyPair::generate().unwrap(), &root)
                .unwrap();
        let partial = AnchorPublication::initial(set.clone())
            .withdraw_pin(&B.into(), &old_b, 2)
            .unwrap();
        let candidate = DomainAnchorSet::try_new(
            A.into(),
            root.der().clone(),
            3,
            vec![
                pin_from_certificate(A.into(), a2.der().clone()).unwrap(),
                pin_from_certificate(B.into(), b2.der().clone()).unwrap(),
            ],
        )
        .unwrap();
        let restored = partial.restore_authoritative_snapshot(candidate).unwrap();
        assert!(restored.bundle_fenced(&old_a));
        assert!(restored.bundle_fenced(&old_b));
        assert_eq!(restored.drain_admitted_before.get(&old_b), Some(&2));
        assert_eq!(restored.drain_admitted_before.get(&old_a), Some(&3));
        assert!(restored.replace(set.with_generation(4).unwrap()).is_err());
        assert!(
            verify_peer_evidence(
                &leaf(&[URI_A], &a),
                &[],
                restored.anchors(),
                UnixTime::now(),
                PeerRole::Client
            )
            .is_err()
        );
    }

    #[test]
    fn authoritative_snapshot_rejects_changed_authority_or_stale_sequence_without_mutation() {
        let (_, _, _, set) = fixture();
        let all = AnchorPublication::initial(set.clone())
            .withdraw_all(2)
            .unwrap();
        let before = all.clone();
        for sequence in [1, 2] {
            let mut stale = set.clone();
            stale.generation = sequence;
            assert_eq!(
                all.restore_authoritative_snapshot(stale),
                Err(AnchorError::StaleGeneration {
                    current: 2,
                    candidate: sequence
                })
            );
            assert_eq!(all, before);
        }
        let mut changed_local = set.with_generation(3).unwrap();
        changed_local.local_domain = B.into();
        assert_eq!(
            all.restore_authoritative_snapshot(changed_local),
            Err(AnchorError::ChangedProfileAuthority)
        );
        assert_eq!(all, before);
        assert!(
            DomainAnchorSet::try_new(A.into(), set.organizational_root.clone(), 3, vec![]).is_err()
        );
    }

    #[test]
    fn all_domain_tombstone_at_maximum_sequence_remains_closed_without_overflow() {
        let (_, _, _, set) = fixture();
        let all = AnchorPublication::initial(set)
            .withdraw_all(u64::MAX)
            .unwrap();
        assert_eq!(all.generation(), u64::MAX);
        assert!(all.current_signer_ders(SystemTime::now()).is_empty());
        assert_eq!(
            all.withdraw_all(u64::MAX),
            Err(AnchorError::StaleGeneration {
                current: u64::MAX,
                candidate: u64::MAX
            })
        );
        assert!(all.withdraw_all(1).is_err());
    }
    #[test]
    fn checkpoint_dto_retains_all_withdrawn_issuers_and_connection_cutoffs() {
        let (_, _, _, set) = fixture();
        let original = AnchorPublication::initial(set);
        let all = original.withdraw_all(2).unwrap();
        let dto = all.checkpoint().unwrap();
        assert!(dto.pins.is_empty());
        assert_eq!(dto.fenced_spkis.len(), 2);
        assert_eq!(dto.drain_before.len(), 2);
        let recovered = AnchorPublication::from_checkpoint(&dto).unwrap();
        assert_eq!(recovered, all);
        assert!(recovered.current_signer_ders(SystemTime::now()).is_empty());
        assert!(
            recovered
                .replace(original.anchors().with_generation(3).unwrap())
                .is_err()
        );
        let restored = recovered
            .restore_authoritative_snapshot(original.anchors().with_generation(3).unwrap())
            .unwrap();
        assert_eq!(
            AnchorPublication::from_checkpoint(&restored.checkpoint().unwrap()).unwrap(),
            restored
        );
    }
    #[test]
    fn checkpoint_dto_revalidates_certificates_duplicate_history_and_cutoff_bounds() {
        let (_, _, _, set) = fixture();
        let original = AnchorPublication::initial(set);
        let dto = original.withdraw_all(2).unwrap().checkpoint().unwrap();
        for variant in 0..5 {
            let mut bad = dto.clone();
            match variant {
                0 => bad.fenced_spkis.push(bad.fenced_spkis[0].clone()),
                1 => bad.drain_before.clear(),
                2 => bad.drain_before[0].sequence = 0,
                3 => bad.drain_before[0].sequence = 3,
                _ => bad.root_der.push('='),
            }
            assert!(AnchorPublication::from_checkpoint(&bad).is_err());
        }
        let mut bad = original.checkpoint().unwrap();
        bad.pins[0].certificate_der = bad.root_der.clone();
        assert!(AnchorPublication::from_checkpoint(&bad).is_err());
        let mut bad = dto;
        bad.fenced_spkis = vec!["AA==".into(); MAX_CHECKPOINT_KEYS + 1];
        assert!(AnchorPublication::from_checkpoint(&bad).is_err());
    }
    fn bounded_root(depth: u8) -> CertifiedIssuer<'static, KeyPair> {
        let mut params = ca_params("bounded organization root");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(depth));
        CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
    }
    fn bounded_child(
        name: &str,
        parent: &CertifiedIssuer<'_, KeyPair>,
        depth: u8,
    ) -> CertifiedIssuer<'static, KeyPair> {
        let mut params = ca_params(name);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(depth));
        CertifiedIssuer::signed_by(params, KeyPair::generate().unwrap(), parent).unwrap()
    }
    fn bounded_profile(
        root: &CertifiedIssuer<'_, KeyPair>,
        parent: &CertifiedIssuer<'_, KeyPair>,
        signer: &CertifiedIssuer<'_, KeyPair>,
        generation: u64,
    ) -> Result<DomainAnchorSet, AnchorError> {
        DomainAnchorSet::try_new(
            A.into(),
            root.der().clone(),
            generation,
            vec![pin_from_certificate_with_lineage(
                A.into(),
                signer.der().clone(),
                vec![parent.der().clone()],
            )?],
        )
    }
    #[test]
    fn approved_cluster_parent_does_not_become_a_workload_signer() {
        let root = bounded_root(2);
        let parent = bounded_child("cluster a CA", &root, 1);
        let signer = bounded_child("SPIRE a CA", &parent, 0);
        let set = bounded_profile(&root, &parent, &signer, 1).unwrap();
        let now = UnixTime::since_unix_epoch(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        for role in [PeerRole::Client, PeerRole::Server] {
            assert!(
                verify_peer_certificate(&leaf(&[URI_A], &signer), &[], &set, now, role).is_ok()
            );
            assert!(
                verify_peer_certificate(&leaf(&[URI_A], &parent), &[], &set, now, role).is_err()
            );
            assert!(verify_peer_certificate(&leaf(&[URI_A], &root), &[], &set, now, role).is_err());
            let delegated = bounded_child("unapproved child CA", &signer, 0);
            assert!(
                verify_peer_certificate(
                    &leaf(&[URI_A], &delegated),
                    &[delegated.der().clone()],
                    &set,
                    now,
                    role
                )
                .is_err()
            );
        }
        assert_eq!(
            set.by_domain[&Strng::from(A)][0].lineage_ders(),
            &[parent.der().clone()]
        );
    }
    #[test]
    fn bounded_lineage_rejects_missing_unused_duplicate_and_insufficient_depth() {
        let root = bounded_root(2);
        let parent = bounded_child("cluster a CA", &root, 1);
        let signer = bounded_child("SPIRE a CA", &parent, 0);
        assert!(
            DomainAnchorSet::try_new(
                A.into(),
                root.der().clone(),
                1,
                vec![pin_from_certificate(A.into(), signer.der().clone()).unwrap()]
            )
            .is_err()
        );
        assert!(
            pin_from_certificate_with_lineage(
                A.into(),
                signer.der().clone(),
                vec![parent.der().clone(), parent.der().clone()]
            )
            .is_err()
        );
        assert!(
            pin_from_certificate_with_lineage(
                A.into(),
                signer.der().clone(),
                vec![root.der().clone()]
            )
            .is_err()
        );
        let direct = bounded_child("direct root signer", &root, 0);
        assert!(
            pin_from_certificate_with_lineage(
                A.into(),
                direct.der().clone(),
                vec![parent.der().clone()]
            )
            .is_err()
        );
        let shallow_root = bounded_root(1);
        let parent = bounded_child("cluster a CA", &shallow_root, 1);
        let signer = bounded_child("SPIRE a CA", &parent, 0);
        assert!(bounded_profile(&shallow_root, &parent, &signer, 1).is_err());
        let parent = bounded_child("shallow cluster CA", &root, 0);
        let signer = bounded_child("SPIRE a CA", &parent, 0);
        assert!(bounded_profile(&root, &parent, &signer, 1).is_err());
    }
    #[test]
    fn identical_cluster_parent_can_rotate_only_within_one_domain() {
        let root = bounded_root(2);
        let parent = bounded_child("cluster a CA", &root, 1);
        let signer1 = bounded_child("SPIRE a CA1", &parent, 0);
        let signer2 = bounded_child("SPIRE a CA2", &parent, 0);
        let pin1 = pin_from_certificate_with_lineage(
            A.into(),
            signer1.der().clone(),
            vec![parent.der().clone()],
        )
        .unwrap();
        let pin2 = pin_from_certificate_with_lineage(
            A.into(),
            signer2.der().clone(),
            vec![parent.der().clone()],
        )
        .unwrap();
        assert!(
            DomainAnchorSet::try_new(A.into(), root.der().clone(), 1, vec![pin1.clone(), pin2])
                .is_ok()
        );
        let foreign = pin_from_certificate_with_lineage(
            B.into(),
            signer2.der().clone(),
            vec![parent.der().clone()],
        )
        .unwrap();
        assert!(
            DomainAnchorSet::try_new(A.into(), root.der().clone(), 1, vec![pin1, foreign]).is_err()
        );
    }
    #[test]
    fn parent_expiry_drains_and_new_approved_lineage_recovers() {
        let root = bounded_root(2);
        let instant = time::OffsetDateTime::now_utc();
        let mut params = ca_params("short cluster CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        params.not_before = instant - time::Duration::hours(1);
        params.not_after = instant + time::Duration::seconds(5);
        let parent =
            CertifiedIssuer::signed_by(params, KeyPair::generate().unwrap(), &root).unwrap();
        let signer = bounded_child("SPIRE a CA", &parent, 0);
        let old = bounded_profile(&root, &parent, &signer, 1).unwrap();
        let before = UNIX_EPOCH + Duration::from_secs(instant.unix_timestamp() as u64);
        let after = before + Duration::from_secs(6);
        let certificate = leaf(&[URI_A], &signer);
        let evidence = verify_peer_evidence(
            &certificate,
            &[],
            &old,
            UnixTime::since_unix_epoch(before.duration_since(UNIX_EPOCH).unwrap()),
            PeerRole::Client,
        )
        .unwrap();
        assert!(evidence.deadline() <= before + Duration::from_secs(5));
        assert!(
            verify_peer_certificate(
                &certificate,
                &[],
                &old,
                UnixTime::since_unix_epoch(after.duration_since(UNIX_EPOCH).unwrap()),
                PeerRole::Client
            )
            .is_err()
        );
        assert_eq!(
            retained_tunnel(
                &evidence.retained_tunnel(),
                &AnchorPublication::initial(old.clone()),
                after
            ),
            RetainedDecision::Drain
        );
        let replacement_parent = bounded_child("replacement cluster CA", &root, 1);
        let replacement_signer = bounded_child("replacement SPIRE CA", &replacement_parent, 0);
        let fresh = bounded_profile(&root, &replacement_parent, &replacement_signer, 2).unwrap();
        let fresh = select_published(Some(&old), fresh).unwrap();
        assert!(
            verify_peer_certificate(
                &leaf(&[URI_A], &replacement_signer),
                &[],
                &fresh,
                UnixTime::since_unix_epoch(after.duration_since(UNIX_EPOCH).unwrap()),
                PeerRole::Client
            )
            .is_ok()
        );
        assert!(
            verify_peer_certificate(
                &certificate,
                &[],
                &fresh,
                UnixTime::since_unix_epoch(after.duration_since(UNIX_EPOCH).unwrap()),
                PeerRole::Client
            )
            .is_err()
        );
    }

    #[test]
    fn spire_ca_hint_must_be_one_exact_approved_domain_uri() {
        let root = bounded_root(2);
        let parent = bounded_child("cluster a CA", &root, 1);
        for hint in [
            "spiffe://cmtc-a.mesh.example",
            "spiffe://cmtc-b.mesh.example",
            "spiffe://cmtc-a.mesh.example/ns/orders/sa/api",
        ] {
            let mut params = ca_params("SPIRE-shaped CA");
            params.subject_alt_names =
                vec![SanType::URI(Ia5String::try_from(hint.to_string()).unwrap())];
            let issuer =
                CertifiedIssuer::signed_by(params, KeyPair::generate().unwrap(), &parent).unwrap();
            let pin = pin_from_certificate_with_lineage(
                A.into(),
                issuer.der().clone(),
                vec![parent.der().clone()],
            );
            assert_eq!(pin.is_ok(), hint == "spiffe://cmtc-a.mesh.example");
        }
        let mut params = ca_params("duplicate CA URI");
        let uri =
            SanType::URI(Ia5String::try_from("spiffe://cmtc-a.mesh.example".to_string()).unwrap());
        params.subject_alt_names = vec![uri.clone(), uri];
        let issuer =
            CertifiedIssuer::signed_by(params, KeyPair::generate().unwrap(), &parent).unwrap();
        assert!(
            pin_from_certificate_with_lineage(
                A.into(),
                issuer.der().clone(),
                vec![parent.der().clone()]
            )
            .is_err()
        );
        let mut params = ca_params("parent with forbidden URI");
        params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from("spiffe://cmtc-a.mesh.example".to_string()).unwrap(),
        )];
        let parent =
            CertifiedIssuer::signed_by(params, KeyPair::generate().unwrap(), &root).unwrap();
        let signer = bounded_child("SPIRE CA", &parent, 0);
        assert!(
            pin_from_certificate_with_lineage(
                A.into(),
                signer.der().clone(),
                vec![parent.der().clone()]
            )
            .is_err()
        );
    }

    #[test]
    fn bounded_parent_lineage_checkpoint_is_exact_and_cannot_be_dropped_or_swapped() {
        let mut root_params = ca_params("lineage-root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(2));
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();
        let mut parent_params = ca_params("cluster-parent-a");
        parent_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        let parent_a =
            CertifiedIssuer::signed_by(parent_params, KeyPair::generate().unwrap(), &root).unwrap();
        let mut parent_params = ca_params("cluster-parent-b");
        parent_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        let parent_b =
            CertifiedIssuer::signed_by(parent_params, KeyPair::generate().unwrap(), &root).unwrap();
        let mut signer_params = ca_params("spire-a");
        signer_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let signer_a =
            CertifiedIssuer::signed_by(signer_params, KeyPair::generate().unwrap(), &parent_a)
                .unwrap();
        let mut signer_params = ca_params("spire-b");
        signer_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let signer_b =
            CertifiedIssuer::signed_by(signer_params, KeyPair::generate().unwrap(), &parent_b)
                .unwrap();
        let set = DomainAnchorSet::try_new(
            A.into(),
            root.der().clone(),
            1,
            vec![
                pin_from_certificate_with_lineage(
                    A.into(),
                    signer_a.der().clone(),
                    vec![parent_a.der().clone()],
                )
                .unwrap(),
                pin_from_certificate_with_lineage(
                    B.into(),
                    signer_b.der().clone(),
                    vec![parent_b.der().clone()],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let original = AnchorPublication::initial(set);
        let dto = original.checkpoint().unwrap();
        assert!(dto.pins.iter().all(|p| p.lineage_der.len() == 1));
        assert_eq!(AnchorPublication::from_checkpoint(&dto).unwrap(), original);
        let a = dto.pins.iter().position(|p| p.domain == A).unwrap();
        for variant in 0..4 {
            let mut bad = dto.clone();
            match variant {
                0 => bad.pins[a].lineage_der.clear(),
                1 => bad.pins[a].lineage_der = vec![checkpoint_b64(parent_b.der().as_ref())],
                2 => bad.pins[a]
                    .lineage_der
                    .push(checkpoint_b64(parent_b.der().as_ref())),
                _ => bad.pins[a].lineage_der = vec![checkpoint_b64(root.der().as_ref())],
            }
            assert!(AnchorPublication::from_checkpoint(&bad).is_err());
        }
        assert_eq!(original.current_signer_ders(SystemTime::now()).len(), 2);
        for parent in [parent_a.der(), parent_b.der()] {
            assert!(
                !original
                    .current_signer_ders(SystemTime::now())
                    .contains(parent)
            );
        }
        let all = original.withdraw_all(2).unwrap();
        assert_eq!(
            AnchorPublication::from_checkpoint(&all.checkpoint().unwrap()).unwrap(),
            all
        );
    }

    fn spire_ca(
        name: &str,
        uri: Option<&str>,
        issuer: &CertifiedIssuer<'_, KeyPair>,
    ) -> CertifiedIssuer<'static, KeyPair> {
        let mut params = ca_params(name);
        params.subject_alt_names = uri
            .map(|u| SanType::URI(Ia5String::try_from(u.to_string()).unwrap()))
            .into_iter()
            .collect();
        CertifiedIssuer::signed_by(params, KeyPair::generate().unwrap(), issuer).unwrap()
    }
    fn intermediate_set(
        root: &CertifiedIssuer<'_, KeyPair>,
        intermediate: &CertifiedIssuer<'_, KeyPair>,
        generation: u64,
    ) -> Result<DomainAnchorSet, AnchorError> {
        DomainAnchorSet::try_new(
            A.into(),
            root.der().clone(),
            generation,
            vec![pin_from_certificate_with_role(
                A.into(),
                intermediate.der().clone(),
                vec![],
                true,
            )?],
        )
    }
    #[test]
    fn spire_intermediate_pin_accepts_exactly_one_rotating_spire_ca() {
        let root = ca("mesh root");
        let intermediate = CertifiedIssuer::signed_by(
            ca_params("cmtc-a SPIRE intermediate"),
            KeyPair::generate().unwrap(),
            &root,
        )
        .unwrap();
        let set = intermediate_set(&root, &intermediate, 1).unwrap();
        let now = UnixTime::since_unix_epoch(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        let domain_uri = Some("spiffe://cmtc-a.mesh.example");
        for role in [PeerRole::Client, PeerRole::Server] {
            // SPIRE rotates its CA: each CA under the pinned intermediate is accepted.
            for name in ["SPIRE CA slot A", "SPIRE CA slot B"] {
                let ca = spire_ca(name, domain_uri, &intermediate);
                let svid = leaf(&[URI_A], &ca);
                assert!(verify_peer_certificate(&svid, &[ca.der().clone()], &set, now, role).is_ok());
                assert!(
                    verify_peer_certificate(
                        &svid,
                        &[ca.der().clone(), intermediate.der().clone()],
                        &set,
                        now,
                        role
                    )
                    .is_ok()
                );
                // The peer must present the SPIRE CA.
                assert!(verify_peer_certificate(&svid, &[], &set, now, role).is_err());
            }
            // No CA between the pin and the SVID.
            assert!(verify_peer_certificate(&leaf(&[URI_A], &intermediate), &[], &set, now, role).is_err());
            // A SPIRE CA without its domain URI, or with another domain's.
            for uri in [None, Some("spiffe://cmtc-b.mesh.example")] {
                let ca = spire_ca("not this domain's SPIRE CA", uri, &intermediate);
                assert!(
                    verify_peer_certificate(&leaf(&[URI_A], &ca), &[ca.der().clone()], &set, now, role)
                        .is_err()
                );
            }
            // Two CAs between the pin and the SVID.
            let ca = spire_ca("SPIRE CA", domain_uri, &intermediate);
            let below = spire_ca("CA below the SPIRE CA", domain_uri, &ca);
            assert!(
                verify_peer_certificate(
                    &leaf(&[URI_A], &below),
                    &[below.der().clone(), ca.der().clone()],
                    &set,
                    now,
                    role
                )
                .is_err()
            );
            // A SPIRE CA from another intermediate under the same root.
            let other = CertifiedIssuer::signed_by(
                ca_params("unpinned intermediate"),
                KeyPair::generate().unwrap(),
                &root,
            )
            .unwrap();
            let foreign = spire_ca("foreign SPIRE CA", domain_uri, &other);
            assert!(
                verify_peer_certificate(
                    &leaf(&[URI_A], &foreign),
                    &[foreign.der().clone(), other.der().clone()],
                    &set,
                    now,
                    role
                )
                .is_err()
            );
        }
    }
    #[test]
    fn spire_intermediate_pin_deadline_includes_the_spire_ca() {
        let root = ca("mesh root");
        let intermediate = CertifiedIssuer::signed_by(
            ca_params("cmtc-a SPIRE intermediate"),
            KeyPair::generate().unwrap(),
            &root,
        )
        .unwrap();
        let set = intermediate_set(&root, &intermediate, 1).unwrap();
        let mut params = ca_params("short SPIRE CA");
        params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from("spiffe://cmtc-a.mesh.example".to_string()).unwrap(),
        )];
        params.not_after = rcgen::date_time_ymd(2099, 1, 1);
        let ca = CertifiedIssuer::signed_by(params, KeyPair::generate().unwrap(), &intermediate)
            .unwrap();
        let now = UnixTime::since_unix_epoch(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        let peer = verify_peer_evidence(
            &leaf(&[URI_A], &ca),
            &[ca.der().clone()],
            &set,
            now,
            PeerRole::Server,
        )
        .unwrap();
        let (_, ca_not_after) = validity(&parse_exact(ca.der().as_ref()).unwrap()).unwrap();
        assert_eq!(peer.deadline(), ca_not_after);
    }
    #[test]
    fn spire_intermediate_pin_needs_depth_for_one_ca_and_no_lineage() {
        let root = ca("mesh root");
        let intermediate = CertifiedIssuer::signed_by(
            ca_params("cmtc-a SPIRE intermediate"),
            KeyPair::generate().unwrap(),
            &root,
        )
        .unwrap();
        assert!(
            pin_from_certificate_with_role(
                A.into(),
                intermediate.der().clone(),
                vec![root.der().clone()],
                true
            )
            .is_err()
        );
        let no_room = bounded_child("depth-zero intermediate", &root, 0);
        assert!(pin_from_certificate_with_role(A.into(), no_room.der().clone(), vec![], true).is_err());
        // The old role still pins a depth-zero CA directly under the root.
        assert!(pin_from_certificate_with_role(A.into(), no_room.der().clone(), vec![], false).is_ok());
        let shallow_root = bounded_root(1);
        let under_shallow = bounded_child("intermediate under a depth-one root", &shallow_root, 1);
        assert!(intermediate_set(&shallow_root, &under_shallow, 1).is_err());
    }
    #[test]
    fn spire_intermediate_pin_checkpoint_round_trips_and_old_checkpoints_are_unchanged() {
        let root = ca("mesh root");
        let intermediate = CertifiedIssuer::signed_by(
            ca_params("cmtc-a SPIRE intermediate"),
            KeyPair::generate().unwrap(),
            &root,
        )
        .unwrap();
        let publication = AnchorPublication::initial(intermediate_set(&root, &intermediate, 1).unwrap());
        let dto = publication.checkpoint().unwrap();
        assert!(dto.pins[0].signs_spire_ca);
        assert_eq!(AnchorPublication::from_checkpoint(&dto).unwrap(), publication);
        let (_, _, _, old_set) = fixture();
        let old = AnchorPublication::initial(old_set).checkpoint().unwrap();
        let encoded = serde_json::to_string(&old).unwrap();
        assert!(!encoded.contains("signs_spire_ca"));
        let decoded: AnchorCheckpoint = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, old);
    }
    #[test]
    fn newer_approval_may_succeed_the_root_and_fences_every_old_pin() {
        let (_, a, b, set) = fixture();
        let history = AnchorPublication::initial(set);
        let root = ca("mesh root");
        let intermediate = CertifiedIssuer::signed_by(
            ca_params("cmtc-a SPIRE intermediate"),
            KeyPair::generate().unwrap(),
            &root,
        )
        .unwrap();
        let successor = intermediate_set(&root, &intermediate, 2).unwrap();
        let next = history.restore_authoritative_snapshot(successor.clone()).unwrap();
        assert_eq!(next.set, successor);
        for old in [a.der(), b.der()] {
            let spki = spki_der(old.as_ref()).unwrap();
            assert!(next.bundle_fenced.contains(&spki));
            assert_eq!(next.drain_admitted_before.get(&spki), Some(&2));
        }
        // A replay of the same generation under the new root is still stale.
        assert!(next.restore_authoritative_snapshot(successor).is_err());
    }
}
