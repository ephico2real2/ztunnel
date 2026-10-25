// Copyright Istio Authors
// SPDX-License-Identifier: Apache-2.0
//! Pure DER-profile decoder. NOT a network handler, provider or traffic grant.
//! Authority comes from independently configured authenticated ADS origin and durable
//! floors; SHA fields provide integrity/correlation, never an admin signature.
use super::domain_anchors::{
    AnchorPublication, DomainAnchorSet, pin_from_certificate_with_lineage, spki_der,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_WIRE_BYTES: usize = 256 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Issuer {
    #[serde(rename = "certificateDER")]
    certificate_der: String,
    #[serde(rename = "spkiSHA256")]
    spki_sha256: String,
    #[serde(default, rename = "lineageDER")]
    lineage_der: Vec<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Cluster {
    #[serde(rename = "clusterID")]
    cluster_id: String,
    trust_domain: String,
    issuers: Vec<Issuer>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Wire {
    wire_version: u32,
    cluster: String,
    node: String,
    source_namespace: String,
    source_name: String,
    #[serde(rename = "sourceUID")]
    source_uid: String,
    output_namespace: String,
    output_name: String,
    #[serde(rename = "outputUID")]
    output_uid: String,
    sequence: String,
    generation: String,
    approval_digest: String,
    publication_digest: String,
    state: String,
    reason: PublicationReason,
    published_unix: String,
    valid_until_unix: String,
    #[serde(rename = "rootSHA256")]
    root_sha256: String,
    #[serde(rename = "rootDER")]
    root_der: Option<String>,
    clusters: Vec<Cluster>,
}

// All values are independent installation/checkpoint configuration, NOT taken
// from the incoming wire envelope. This type does not load/checkpoint them.
pub struct Expected {
    pub cluster: String,
    pub node: String,
    pub source_namespace: String,
    pub source_name: String,
    pub source_uid: String,
    pub output_namespace: String,
    pub output_name: String,
    pub output_uid: String,
    pub root_pins: Vec<String>,
    pub minimum_generation: u64,
    pub minimum_sequence: u64,
    pub approval_digest_at_minimum: Option<String>,
    pub publication_digest_at_minimum: Option<String>,
}
#[derive(Debug)]
pub struct ClusterBinding {
    pub cluster_id: String,
    pub trust_domain: String,
}
// The current producer reports availability failures. None of these is a
// permanent issuer-revocation command. Source deletion denies admission until
// authority is valid again; retain cumulative floors during that interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub enum PublicationReason {
    Validated,
    SourceUnavailable,
    SourceChanged,
    SourceDeleted,
    SourceUIDMismatch,
    SourceInvalid,
    SourceExpired,
    GenerationRollback,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithdrawalClass {
    Unavailable,
}
#[derive(Debug)]
pub struct Decoded {
    pub reason: PublicationReason,
    pub withdrawal: Option<WithdrawalClass>,
    pub sequence: u64,
    pub generation: u64,
    pub approval_digest: String,
    pub publication_digest: String,
    pub published_at: SystemTime,
    pub valid_until: SystemTime,
    pub bindings: Vec<ClusterBinding>,
    // None is an explicit tombstone. Some is only verified material; runtime
    // publication still requires authenticated transport and durable floors.
    pub candidate: Option<DomainAnchorSet>,
}
fn hex_pin(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn number(s: &str) -> Result<u64> {
    let v: u64 = s.parse().context("u64 decimal required")?;
    ensure!(v.to_string() == s, "noncanonical u64");
    Ok(v)
}
fn der(s: &str) -> Result<CertificateDer<'static>> {
    ensure!(
        !s.is_empty() && s.len() <= 32768,
        "bounded DER base64 required"
    );
    let bytes = STANDARD.decode(s).context("invalid base64 DER")?;
    ensure!(STANDARD.encode(&bytes) == s, "noncanonical base64 DER");
    Ok(bytes.into())
}
// Use the configured provider for hashing too. No alternate certificate/root
// verifier or platform-default crypto provider is introduced.
fn sha256(data: &[u8]) -> Result<String> {
    #[cfg(any(feature = "tls-ring", feature = "tls-aws-lc"))]
    let digest = {
        let provider = super::lib::provider();
        let hash = provider
            .cipher_suites
            .iter()
            .filter_map(|s| s.tls13())
            .map(|s| s.common.hash_provider)
            .find(|h| h.algorithm() == rustls::crypto::hash::HashAlgorithm::SHA256)
            .context("configured provider has no SHA256 implementation")?;
        hash.hash(data).as_ref().to_vec()
    };
    #[cfg(feature = "tls-boring")]
    let digest = boring::sha::sha256(data).to_vec();
    #[cfg(feature = "tls-openssl")]
    let digest = openssl::sha::sha256(data).to_vec();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}
fn cluster_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && (s.as_bytes()[0].is_ascii_lowercase() || s.as_bytes()[0].is_ascii_digit())
        && (s.as_bytes()[s.len() - 1].is_ascii_lowercase()
            || s.as_bytes()[s.len() - 1].is_ascii_digit())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn dns_subdomain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && (label.as_bytes()[0].is_ascii_lowercase()
                    || label.as_bytes()[0].is_ascii_digit())
                && (label.as_bytes()[label.len() - 1].is_ascii_lowercase()
                    || label.as_bytes()[label.len() - 1].is_ascii_digit())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

pub fn decode(data: &[u8], expected: &Expected, now: SystemTime) -> Result<Decoded> {
    ensure!(
        !data.is_empty() && data.len() <= MAX_WIRE_BYTES,
        "bounded nonempty DER profile required"
    );
    ensure!(
        cluster_id(&expected.cluster)
            && dns_subdomain(&expected.node)
            && dns_subdomain(&expected.source_namespace)
            && !expected.source_namespace.contains('.')
            && expected.source_namespace.len() <= 63
            && expected.output_namespace == expected.source_namespace
            && dns_subdomain(&expected.source_name)
            && dns_subdomain(&expected.output_name)
            && expected.output_name != expected.source_name
            && !expected.source_uid.is_empty()
            && !expected.output_uid.is_empty()
            && expected.source_uid != expected.output_uid
            && expected.minimum_generation > 0
            && expected.minimum_sequence > 0
            && !expected.root_pins.is_empty()
            && expected.root_pins.len() <= 4,
        "explicit independent origin/root/floor pins required"
    );
    ensure!(
        expected
            .approval_digest_at_minimum
            .as_ref()
            .is_none_or(|d| hex_pin(d))
            && expected
                .publication_digest_at_minimum
                .as_ref()
                .is_none_or(|d| hex_pin(d)),
        "invalid configured digest floors"
    );
    let root_pins: BTreeSet<_> = expected.root_pins.iter().collect();
    ensure!(
        root_pins.len() == expected.root_pins.len() && root_pins.iter().all(|p| hex_pin(p)),
        "invalid installation root pins"
    );
    // Derived structs reject duplicate keys and unknown fields at every level;
    // no intermediate serde_json::Value loses duplicate-key evidence.
    let w: Wire = serde_json::from_slice(data).context("strict DER profile JSON")?;
    ensure!(
        w.wire_version == 1
            && w.cluster == expected.cluster
            && w.node == expected.node
            && w.source_namespace == expected.source_namespace
            && w.source_name == expected.source_name
            && w.source_uid == expected.source_uid
            && w.output_namespace == expected.output_namespace
            && w.output_name == expected.output_name
            && w.output_uid == expected.output_uid,
        "profile origin/node mismatch"
    );
    let sequence = number(&w.sequence)?;
    let generation = number(&w.generation)?;
    ensure!(
        sequence >= expected.minimum_sequence && sequence > 0 && hex_pin(&w.publication_digest),
        "publication sequence/digest mismatch"
    );
    if sequence == expected.minimum_sequence
        && let Some(digest) = &expected.publication_digest_at_minimum
    {
        ensure!(
            &w.publication_digest == digest,
            "same-sequence substitution"
        );
    }
    ensure!(
        generation >= expected.minimum_generation,
        "logical generation rollback"
    );
    if generation == expected.minimum_generation
        && let Some(digest) = &expected.approval_digest_at_minimum
    {
        ensure!(
            &w.approval_digest == digest,
            "same-generation authority substitution"
        );
    }
    let at = UNIX_EPOCH
        .checked_add(Duration::from_secs(number(&w.published_unix)?))
        .context("published time overflow")?;
    let until = UNIX_EPOCH
        .checked_add(Duration::from_secs(number(&w.valid_until_unix)?))
        .context("lease time overflow")?;
    ensure!(now >= at, "future publication");
    if w.state == "withdrawn" {
        ensure!(
            w.reason != PublicationReason::Validated,
            "withdrawn profile has published reason"
        );
        ensure!(
            w.root_der.is_none()
                && w.root_sha256.is_empty()
                && w.clusters.is_empty()
                && until == at,
            "tombstone retained anchors/lease"
        );
        ensure!(
            w.approval_digest.is_empty() || hex_pin(&w.approval_digest),
            "invalid tombstone history"
        );
        return Ok(Decoded {
            reason: w.reason,
            withdrawal: Some(WithdrawalClass::Unavailable),
            sequence,
            generation,
            approval_digest: w.approval_digest,
            publication_digest: w.publication_digest,
            published_at: at,
            valid_until: until,
            bindings: Vec::new(),
            candidate: None,
        });
    }
    ensure!(
        w.state == "published"
            && generation >= expected.minimum_generation
            && hex_pin(&w.approval_digest)
            && until > at
            && until.duration_since(at)? <= Duration::from_secs(30)
            && now < until,
        "inactive/expired profile"
    );
    ensure!(
        !w.clusters.is_empty() && w.clusters.len() <= 16,
        "invalid domain cardinality"
    );
    let root = der(w.root_der.as_deref().context("missing root DER")?)?;
    ensure!(
        hex_pin(&w.root_sha256)
            && sha256(root.as_ref())? == w.root_sha256
            && expected.root_pins.contains(&w.root_sha256),
        "root not independently pinned"
    );
    let mut ids = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut pins = Vec::new();
    let mut bindings = Vec::new();
    let mut local = None;
    for c in w.clusters {
        ensure!(
            cluster_id(&c.cluster_id)
                && ids.insert(c.cluster_id.clone())
                && domains.insert(c.trust_domain.clone())
                && !c.issuers.is_empty()
                && c.issuers.len() <= 2,
            "duplicate/invalid cluster/domain"
        );
        if c.cluster_id == expected.cluster {
            local = Some(c.trust_domain.clone());
        }
        for issuer in c.issuers {
            let certificate = der(&issuer.certificate_der)?;
            ensure!(
                hex_pin(&issuer.spki_sha256)
                    && sha256(&spki_der(certificate.as_ref())?)? == issuer.spki_sha256,
                "issuer SPKI mismatch"
            );
            ensure!(
                issuer.lineage_der.len() <= 1,
                "only one explicit cluster CA ancestor is supported"
            );
            let lineage = issuer
                .lineage_der
                .iter()
                .map(|encoded| der(encoded))
                .collect::<Result<Vec<_>>>()?;
            pins.push(pin_from_certificate_with_lineage(
                c.trust_domain.clone().into(),
                certificate,
                lineage,
            )?);
        }
        bindings.push(ClusterBinding {
            cluster_id: c.cluster_id,
            trust_domain: c.trust_domain,
        });
    }
    let count = pins.len();
    // AnchorPublication's revision must advance on every producer publication,
    // including same-approval lease renewals. Keep logical approval generation
    // separate in Decoded for rollback checks; never collapse it with sequence.
    let set = DomainAnchorSet::try_new(
        local.context("local cluster not bound")?.into(),
        root,
        sequence,
        pins,
    )?;
    let validation = AnchorPublication::initial(set.clone());
    ensure!(
        validation.current_signer_ders(now).len() == count,
        "inactive root/issuer profile"
    );
    ensure!(
        validation
            .current_signer_ders(until - Duration::from_nanos(1))
            .len()
            == count,
        "lease exceeds root/issuer validity"
    );
    ensure!(
        w.reason == PublicationReason::Validated,
        "published profile has unavailable reason"
    );
    Ok(Decoded {
        reason: w.reason,
        withdrawal: None,
        sequence,
        generation,
        approval_digest: w.approval_digest,
        publication_digest: w.publication_digest,
        published_at: at,
        valid_until: until,
        bindings,
        candidate: Some(set),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Vec<u8>, Expected, SystemTime) {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("issuer-profile-v1.json")).unwrap();
        let body = serde_json::to_vec(&f["wire"]).unwrap();
        let expected = Expected {
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
        };
        let now = UNIX_EPOCH + Duration::from_secs(f["nowUnix"].as_str().unwrap().parse().unwrap());
        (body, expected, now)
    }
    #[test]
    fn shared_go_der_projection_decodes_without_workload_label_authority() {
        let (body, e, now) = fixture();
        let decoded = decode(&body, &e, now).unwrap();
        assert_eq!(decoded.sequence, 10);
        assert_eq!(decoded.generation, 7);
        assert_eq!(decoded.bindings.len(), 2);
        let set = decoded.candidate.unwrap();
        assert_eq!(set.generation(), 10);
        assert_eq!(set.local_domain().to_string(), "cmtc-a.mesh.example");
        assert_eq!(set.pin_spkis(&"cmtc-b.mesh.example".into()).len(), 1);
    }
    #[test]
    fn wrong_origin_floor_same_version_substitution_and_time_fail_closed() {
        let (body, e, now) = fixture();
        for (field, value) in [
            ("node", "foreign-node"),
            ("sourceUID", "replacement"),
            ("outputUID", "replacement"),
            ("sequence", "9"),
            ("sequence", "010"),
            ("generation", "6"),
            (
                "approvalDigest",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "publicationDigest",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        ] {
            let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            v[field] = value.into();
            assert!(
                decode(&serde_json::to_vec(&v).unwrap(), &e, now).is_err(),
                "accepted {field}"
            );
        }
        assert!(decode(&body, &e, now + Duration::from_secs(30)).is_err());
        assert!(decode(&body, &e, now - Duration::from_secs(2)).is_err());
    }
    #[test]
    fn unknown_duplicate_and_oversized_envelopes_rejected() {
        let (body, e, now) = fixture();
        let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        v["extra"] = true.into();
        assert!(decode(&serde_json::to_vec(&v).unwrap(), &e, now).is_err());
        let duplicate =
            String::from_utf8(body.clone())
                .unwrap()
                .replacen("{", "{\"wireVersion\":1,", 1);
        assert!(decode(duplicate.as_bytes(), &e, now).is_err());
        assert!(decode(&vec![b' '; MAX_WIRE_BYTES + 1], &e, now).is_err());
    }
    #[test]
    fn root_spki_domain_and_base64_substitution_rejected() {
        let (body, e, now) = fixture();
        for selector in 0..4 {
            let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            match selector {
                0 => {
                    v["rootSHA256"] =
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()
                }
                1 => {
                    v["clusters"][1]["issuers"][0]["spkiSHA256"] =
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()
                }
                2 => v["clusters"][1]["trustDomain"] = "cmtc-a.mesh.example".into(),
                _ => v["rootDER"] = "not-base64".into(),
            }
            assert!(decode(&serde_json::to_vec(&v).unwrap(), &e, now).is_err());
        }
    }
    #[test]
    fn explicit_tombstone_contains_no_candidate_and_cannot_retain_anchors() {
        let (body, e, now) = fixture();
        let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        v["state"] = "withdrawn".into();
        v["reason"] = "SourceUnavailable".into();
        v["sequence"] = "11".into();
        v["validUntilUnix"] = v["publishedUnix"].clone();
        assert!(decode(&serde_json::to_vec(&v).unwrap(), &e, now).is_err());
        v["rootDER"] = serde_json::Value::Null;
        v["rootSHA256"] = "".into();
        v["clusters"] = serde_json::json!([]);
        assert!(
            decode(&serde_json::to_vec(&v).unwrap(), &e, now)
                .unwrap()
                .candidate
                .is_none()
        );
    }
    #[test]
    fn withdrawal_preserves_history_and_newer_renewal_requires_checkpoint() {
        let (body, mut e, now) = fixture();
        let original: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mut withdrawn = original.clone();
        withdrawn["state"] = "withdrawn".into();
        withdrawn["reason"] = "SourceUnavailable".into();
        withdrawn["sequence"] = "11".into();
        withdrawn["publicationDigest"] =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into();
        withdrawn["rootDER"] = serde_json::Value::Null;
        withdrawn["rootSHA256"] = "".into();
        withdrawn["clusters"] = serde_json::json!([]);
        withdrawn["validUntilUnix"] = withdrawn["publishedUnix"].clone();
        for field in ["generation", "approvalDigest"] {
            let mut lost = withdrawn.clone();
            lost[field] = if field == "generation" {
                "0".into()
            } else {
                "".into()
            };
            assert!(decode(&serde_json::to_vec(&lost).unwrap(), &e, now).is_err());
        }
        let clear = decode(&serde_json::to_vec(&withdrawn).unwrap(), &e, now).unwrap();
        assert!(clear.candidate.is_none());
        assert_eq!(clear.generation, 7);
        assert_eq!(
            clear.approval_digest,
            original["approvalDigest"].as_str().unwrap()
        );
        // Simulate the caller's retained checkpoint, not a durable-store test.
        e.minimum_sequence = clear.sequence;
        e.publication_digest_at_minimum = Some(clear.publication_digest);
        assert!(decode(&body, &e, now).is_err());
        let mut renewal = original.clone();
        renewal["sequence"] = "12".into();
        renewal["publicationDigest"] =
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into();
        let renewed = decode(&serde_json::to_vec(&renewal).unwrap(), &e, now).unwrap();
        assert_eq!(renewed.generation, 7);
        assert_eq!(renewed.candidate.unwrap().generation(), 12);
        // Rejection does not mutate floors or make a later valid renewal fail.
        assert!(
            decode(
                &serde_json::to_vec(&renewal).unwrap(),
                &e,
                now + Duration::from_secs(30)
            )
            .is_err()
        );
        assert!(decode(&serde_json::to_vec(&renewal).unwrap(), &e, now).is_ok());
    }
    #[test]
    fn reasons_distinguish_unavailability_without_inventing_key_revocation() {
        let (body, e, now) = fixture();
        for reason in ["Unknown", "SourceUnavailable", "SourceChanged"] {
            let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            v["reason"] = reason.into();
            assert!(decode(&serde_json::to_vec(&v).unwrap(), &e, now).is_err());
        }
        for reason in [
            "SourceUnavailable",
            "SourceChanged",
            "SourceDeleted",
            "SourceUIDMismatch",
            "SourceInvalid",
            "SourceExpired",
            "GenerationRollback",
        ] {
            let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            v["state"] = "withdrawn".into();
            v["reason"] = reason.into();
            v["sequence"] = "11".into();
            v["validUntilUnix"] = v["publishedUnix"].clone();
            v["rootDER"] = serde_json::Value::Null;
            v["rootSHA256"] = "".into();
            v["clusters"] = serde_json::json!([]);
            let unavailable = decode(&serde_json::to_vec(&v).unwrap(), &e, now).unwrap();
            assert_eq!(unavailable.withdrawal, Some(WithdrawalClass::Unavailable));
            assert!(unavailable.candidate.is_none());
            assert_eq!(unavailable.generation, e.minimum_generation);
            for bad in ["Validated", "Unknown", "AuthoritativeWithdrawal"] {
                v["reason"] = bad.into();
                assert!(decode(&serde_json::to_vec(&v).unwrap(), &e, now).is_err());
            }
        }
    }
    fn approved_lineage_fixture() -> (Vec<u8>, Expected, SystemTime, serde_json::Value) {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("issuer-profile-lineage-v1.json")).unwrap();
        let expected = Expected {
            cluster: "cmtc-a".into(),
            node: "cmtc-a-worker".into(),
            source_namespace: "cmtc-system".into(),
            source_name: "issuer-approval".into(),
            source_uid: "fixture-source-uid".into(),
            output_namespace: "cmtc-system".into(),
            output_name: "issuer-publication".into(),
            output_uid: "fixture-source-output-uid".into(),
            root_pins: vec![
                "1211aab8606cf0845c3a3078289fe39126b35aba067aa85e81096d6993afb3e5".into(),
            ],
            minimum_generation: 7,
            minimum_sequence: 10,
            approval_digest_at_minimum: Some(
                "9b222564c540e40d2ca08305fdfc072031c08fae89c85f7ade2a1b67a4921093".into(),
            ),
            publication_digest_at_minimum: Some(
                "94a6322abcf648dbe9906d477e2a7399aa4d7c5992ef09ec18d36dc2e2261c87".into(),
            ),
        };
        let now = UNIX_EPOCH + Duration::from_secs(f["nowUnix"].as_str().unwrap().parse().unwrap());
        (serde_json::to_vec(&f["wire"]).unwrap(), expected, now, f)
    }
    #[test]
    fn actual_spire_shaped_lineage_decodes_but_only_direct_svid_signers_authenticate() {
        use super::super::domain_anchors::{PeerRole, verify_peer_certificate};
        use rustls::pki_types::UnixTime;
        let (body, e, now, f) = approved_lineage_fixture();
        let decoded = decode(&body, &e, now).unwrap();
        assert_eq!(decoded.bindings.len(), 2);
        let set = decoded.candidate.unwrap();
        let unix = UnixTime::since_unix_epoch(now.duration_since(UNIX_EPOCH).unwrap());
        for name in ["svid-a", "svid-b"] {
            let leaf = der(f["certificates"][name]["der"].as_str().unwrap()).unwrap();
            for role in [PeerRole::Client, PeerRole::Server] {
                assert!(verify_peer_certificate(&leaf, &[], &set, unix, role).is_ok());
            }
        }
        for name in ["svid-parent", "svid-root", "svid-delegated"] {
            let leaf = der(f["certificates"][name]["der"].as_str().unwrap()).unwrap();
            let delegated = der(f["certificates"]["delegated"]["der"].as_str().unwrap()).unwrap();
            for role in [PeerRole::Client, PeerRole::Server] {
                assert!(
                    verify_peer_certificate(
                        &leaf,
                        std::slice::from_ref(&delegated),
                        &set,
                        unix,
                        role
                    )
                    .is_err(),
                    "unapproved signer {name}"
                );
            }
        }
        let parent = der(f["certificates"]["parent-a"]["der"].as_str().unwrap()).unwrap();
        assert!(
            !set.pin_spkis(&"cmtc-a.mesh.example".into())
                .contains(&spki_der(parent.as_ref()).unwrap())
        );
        assert!(
            !AnchorPublication::initial(set)
                .current_signer_ders(now)
                .contains(&parent)
        );
    }
    #[test]
    fn explicit_lineage_cannot_be_missing_reordered_expanded_or_reassigned() {
        let (body, e, now, _) = approved_lineage_fixture();
        for case in [
            "missing",
            "wrong-parent",
            "root-as-parent",
            "two-parents",
            "wrong-domain",
            "null-parent",
        ] {
            let mut wire: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let parent = wire["clusters"][0]["issuers"][0]["lineageDER"][0].clone();
            match case {
                "missing" => {
                    let _ = wire["clusters"][0]["issuers"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("lineageDER");
                }
                "wrong-parent" => {
                    wire["clusters"][0]["issuers"][0]["lineageDER"][0] =
                        wire["clusters"][1]["issuers"][0]["lineageDER"][0].clone();
                }
                "root-as-parent" => {
                    wire["clusters"][0]["issuers"][0]["lineageDER"][0] = wire["rootDER"].clone();
                }
                "two-parents" => {
                    wire["clusters"][0]["issuers"][0]["lineageDER"] =
                        serde_json::json!([parent, wire["rootDER"].clone()]);
                }
                "wrong-domain" => {
                    wire["clusters"][0]["trustDomain"] = "another.mesh.example".into();
                }
                _ => {
                    wire["clusters"][0]["issuers"][0]["lineageDER"] = serde_json::Value::Null;
                }
            };
            assert!(
                decode(&serde_json::to_vec(&wire).unwrap(), &e, now).is_err(),
                "accepted {case}"
            );
        }
        assert!(
            decode(&body, &e, now).is_ok(),
            "rejected input must not poison a later validated candidate"
        );
    }
}
