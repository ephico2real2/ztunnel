// Copyright Istio Authors
// SPDX-License-Identifier: Apache-2.0
//! Linux public profile checkpoint. Persistence is NOT an activation/ACK grant.
//! The runtime must keep admission closed on recovery until a fresh authenticated
//! session has passed its independent provider/drain/peer-root commit barrier.
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::domain_anchors::{AnchorCheckpoint, AnchorPublication};
use super::issuer_profile_wire::{ApprovalSource, Expected, PublicationReason};
use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// Version 2 binds the installation (cluster, node, namespaces, output object,
/// roots), not the approval object: a successor approval with a strictly
/// greater generation continues the same checkpoint. Version 1 bound the
/// approval object's name and UID as immutable scope; it is read once as a
/// migration and never written again.
pub(crate) const VERSION: u32 = 2;
const V1: u32 = 1;
pub const MAX_CHECKPOINT_BYTES: usize = 2 * 1024 * 1024;
const STATE: &str = "profile-state.json";
const PENDING: &str = ".profile-state.pending";
const MARKER: &str = ".profile-state.initialized";
const LOCK: &str = ".profile-state.lock";
const MARKER_BYTES: &[u8] = b"CMTC issuer profile checkpoint v1\n";

/// Immutable installation scope of a checkpoint. The approval object is not
/// part of it: approvals are immutable ConfigMaps, so each new approval
/// generation is a new object, and binding its name/UID here forced a
/// checkpoint reset at every issuer rotation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub cluster: String,
    pub node: String,
    pub source_namespace: String,
    pub output_namespace: String,
    pub output_name: String,
    pub output_uid: String,
    pub root_pins: Vec<String>,
}
impl Origin {
    pub fn from_expected(e: &Expected) -> Self {
        let mut root_pins = e.root_pins.clone();
        root_pins.sort();
        Self {
            cluster: e.cluster.clone(),
            node: e.node.clone(),
            source_namespace: e.source_namespace.clone(),
            output_namespace: e.output_namespace.clone(),
            output_name: e.output_name.clone(),
            output_uid: e.output_uid.clone(),
            root_pins,
        }
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            dns(&self.cluster, 32) && !self.cluster.contains('.') && dns(&self.node, 253),
            "invalid independent cluster/node"
        );
        ensure!(
            dns(&self.source_namespace, 63)
                && !self.source_namespace.contains('.')
                && self.output_namespace == self.source_namespace,
            "invalid independent namespace"
        );
        ensure!(
            dns(&self.output_name, 253) && uid(&self.output_uid),
            "invalid independent output object"
        );
        ensure!(
            !self.root_pins.is_empty()
                && self.root_pins.len() <= 4
                && self.root_pins.iter().all(|p| pin(p))
                && self.root_pins.windows(2).all(|p| p[0] < p[1]),
            "sorted unique independent roots required"
        );
        Ok(())
    }
    /// An approval object must be distinct from the pinned output object.
    fn valid_source(&self, source: &ApprovalSource) -> bool {
        dns(&source.name, 253)
            && source.name != self.output_name
            && uid(&source.uid)
            && source.uid != self.output_uid
    }
}
/// Audit record of the last source succession: the approval object whose
/// material the current authority source replaced. It is history only and
/// never authorizes anything.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Predecessor {
    pub source: ApprovalSource,
    pub generation: u64,
    pub approval_digest: String,
}
fn dns(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.as_bytes()[0].is_ascii_alphanumeric()
                && l.as_bytes()[l.len() - 1].is_ascii_alphanumeric()
                && l.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}
fn uid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn pin(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Installation {
    pub origin: Origin,
    // These come from independent configuration/secure external recovery, NOT
    // the incoming ADS envelope or a floor read only from the same file.
    pub minimum_sequence: u64,
    pub minimum_generation: u64,
    pub approval_digest_at_minimum: Option<String>,
    pub publication_digest_at_minimum: Option<String>,
    // The approval object accepted at `minimum_generation`, like the digest
    // floor above: it binds that generation only, never a successor.
    pub source_at_minimum: ApprovalSource,
}
impl Installation {
    pub fn from_expected(e: &Expected) -> Self {
        Self {
            origin: Origin::from_expected(e),
            minimum_sequence: e.minimum_sequence,
            minimum_generation: e.minimum_generation,
            approval_digest_at_minimum: e.approval_digest_at_minimum.clone(),
            publication_digest_at_minimum: e.publication_digest_at_minimum.clone(),
            source_at_minimum: ApprovalSource {
                name: e.source_name.clone(),
                uid: e.source_uid.clone(),
            },
        }
    }
    fn validate(&self) -> Result<()> {
        self.origin.validate()?;
        ensure!(
            self.origin.valid_source(&self.source_at_minimum),
            "invalid independent approval source at the floor"
        );
        ensure!(
            self.minimum_sequence > 0 && self.minimum_generation > 0,
            "positive independent floors required"
        );
        ensure!(
            self.approval_digest_at_minimum
                .as_ref()
                .is_none_or(|p| pin(p))
                && self
                    .publication_digest_at_minimum
                    .as_ref()
                    .is_none_or(|p| pin(p)),
            "invalid independent digest floor"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Floors {
    pub sequence: u64,
    pub logical_generation: u64,
    pub approval_digest: String,
    pub publication_digest: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub cluster: String,
    pub domain: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Observation {
    Validated,
    AuthorityRevoked,
    SourceUnavailable,
    SourceChanged,
    SourceDeleted,
    SourceUIDMismatch,
    SourceInvalid,
    SourceExpired,
    GenerationRollback,
}
impl From<PublicationReason> for Observation {
    fn from(reason: PublicationReason) -> Self {
        match reason {
            PublicationReason::Validated => Self::Validated,
            PublicationReason::SourceUnavailable => Self::SourceUnavailable,
            PublicationReason::SourceChanged => Self::SourceChanged,
            PublicationReason::SourceDeleted => Self::SourceDeleted,
            PublicationReason::SourceUIDMismatch => Self::SourceUIDMismatch,
            PublicationReason::SourceInvalid => Self::SourceInvalid,
            PublicationReason::SourceExpired => Self::SourceExpired,
            PublicationReason::GenerationRollback => Self::GenerationRollback,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCheckpoint {
    pub version: u32,
    pub origin: Origin,
    pub floors: Floors,
    pub observation: Observation,
    pub authority_generation: u64,
    pub authority_approval_digest: String,
    // The approval object that supplied the `authority_generation` material.
    // Present exactly when anchor history is present.
    pub authority_source: Option<ApprovalSource>,
    pub predecessor: Option<Predecessor>,
    pub published_unix: u64,
    pub valid_until_unix: u64,
    // Last approved bindings/history survive availability withdrawals. This
    // is history, not an independently current or active TLS provider.
    pub bindings: Vec<Binding>,
    pub anchors: Option<AnchorCheckpoint>,
}
impl ProfileCheckpoint {
    pub fn history(&self) -> Result<Option<AnchorPublication>> {
        self.anchors
            .as_ref()
            .map(AnchorPublication::from_checkpoint)
            .transpose()
            .map_err(Into::into)
    }
    fn validate(&self, installation: &Installation) -> Result<()> {
        ensure!(
            self.version == VERSION && self.origin == installation.origin,
            "checkpoint independent origin/root scope differs"
        );
        if let Some(source) = &self.authority_source {
            ensure!(
                self.origin.valid_source(source),
                "invalid checkpoint authority source"
            );
            ensure!(
                self.authority_generation != installation.minimum_generation
                    || *source == installation.source_at_minimum,
                "checkpoint authority source at the independent floor differs"
            );
        }
        if let Some(previous) = &self.predecessor {
            ensure!(
                self.origin.valid_source(&previous.source)
                    && self.authority_source.as_ref() != Some(&previous.source)
                    && previous.generation > 0
                    && previous.generation < self.authority_generation
                    && pin(&previous.approval_digest),
                "invalid source succession record"
            );
        }
        let f = &self.floors;
        ensure!(
            f.sequence >= installation.minimum_sequence
                && f.logical_generation >= installation.minimum_generation
                && pin(&f.approval_digest)
                && pin(&f.publication_digest),
            "checkpoint below independent floors"
        );
        if f.sequence == installation.minimum_sequence
            && let Some(expected) = &installation.publication_digest_at_minimum
        {
            ensure!(
                &f.publication_digest == expected,
                "checkpoint sequence digest differs"
            );
        }
        if f.logical_generation == installation.minimum_generation
            && let Some(expected) = &installation.approval_digest_at_minimum
        {
            ensure!(
                &f.approval_digest == expected,
                "checkpoint authority digest differs"
            );
        }
        ensure!(
            self.published_unix <= i64::MAX as u64 && self.valid_until_unix <= i64::MAX as u64,
            "checkpoint timestamp overflow"
        );
        if self.observation == Observation::Validated {
            ensure!(
                self.valid_until_unix > self.published_unix
                    && self.valid_until_unix - self.published_unix <= 30
                    && self.anchors.is_some(),
                "published checkpoint lease/history missing"
            );
        } else {
            ensure!(
                self.valid_until_unix == self.published_unix,
                "unavailable checkpoint retained a lease"
            );
        }
        ensure!(
            self.bindings.len() <= 16
                && self
                    .bindings
                    .windows(2)
                    .all(|p| p[0].cluster < p[1].cluster),
            "bounded sorted unique bindings required"
        );
        let mut domains = BTreeSet::new();
        for b in &self.bindings {
            ensure!(
                dns(&b.cluster, 32)
                    && !b.cluster.contains('.')
                    && dns(&b.domain, 253)
                    && domains.insert(b.domain.clone()),
                "duplicate/invalid binding"
            );
        }
        match &self.anchors {
            Some(dto) => {
                let history = AnchorPublication::from_checkpoint(dto)?;
                ensure!(
                    self.authority_generation > 0
                        && self.authority_generation <= f.logical_generation
                        && pin(&self.authority_approval_digest)
                        && self.authority_source.is_some(),
                    "last material authority floor missing"
                );
                if self.authority_generation == f.logical_generation {
                    ensure!(
                        self.authority_approval_digest == f.approval_digest,
                        "last material/floor approval digest differs"
                    );
                }
                ensure!(
                    dto.sequence <= f.sequence,
                    "anchor sequence exceeds accepted floor"
                );
                let root = base64::engine::general_purpose::STANDARD.decode(&dto.root_der)?;
                ensure!(
                    installation.origin.root_pins.contains(&hash(&root)?),
                    "checkpoint root not independently pinned"
                );
                ensure!(
                    self.bindings
                        .iter()
                        .any(|b| b.cluster == self.origin.cluster && b.domain == dto.local_domain),
                    "checkpoint local cluster/domain not bound"
                );
                ensure!(
                    dto.pins.iter().all(|p| domains.contains(&p.domain)),
                    "active issuer missing approved domain binding"
                );
                if self.observation == Observation::Validated {
                    ensure!(
                        dto.sequence == f.sequence
                            && self.authority_generation == f.logical_generation
                            && self.authority_approval_digest == f.approval_digest
                            && dto.pins.iter().any(|p| p.domain == dto.local_domain),
                        "published anchor/authority floor/local issuer not current"
                    );
                    let at = UNIX_EPOCH
                        .checked_add(std::time::Duration::from_secs(self.published_unix))
                        .context("checkpoint publication clock overflow")?;
                    let last = UNIX_EPOCH
                        .checked_add(std::time::Duration::from_secs(self.valid_until_unix - 1))
                        .context("checkpoint lease clock overflow")?;
                    ensure!(
                        history.current_signer_ders(at).len() == dto.pins.len()
                            && history.current_signer_ders(last).len() == dto.pins.len(),
                        "checkpoint published lease exceeds approved root/signer/parent validity"
                    );
                }
            }
            None => ensure!(
                self.bindings.is_empty()
                    && self.observation != Observation::Validated
                    && self.observation != Observation::AuthorityRevoked
                    && self.authority_generation == 0
                    && self.authority_approval_digest.is_empty()
                    && self.authority_source.is_none()
                    && self.predecessor.is_none(),
                "no-anchor checkpoint cannot grant bindings/authority"
            ),
        }
        Ok(())
    }
    fn supersedes(&self, old: &Self) -> Result<()> {
        ensure!(
            self.floors.sequence > old.floors.sequence,
            "checkpoint sequence did not advance"
        );
        ensure!(
            self.floors.logical_generation >= old.floors.logical_generation,
            "logical authority rollback"
        );
        if self.floors.logical_generation == old.floors.logical_generation {
            ensure!(
                self.floors.approval_digest == old.floors.approval_digest,
                "same-generation approval floor substitution"
            );
        }
        ensure!(
            self.authority_generation >= old.authority_generation,
            "material authority generation rollback"
        );
        if self.authority_generation == old.authority_generation {
            ensure!(
                self.authority_approval_digest == old.authority_approval_digest
                    && self.bindings == old.bindings
                    && self.authority_source == old.authority_source
                    && self.predecessor == old.predecessor,
                "same material-generation authority substitution"
            );
        } else if self.authority_source != old.authority_source
            && let Some(previous) = &old.authority_source
        {
            // A source succession is a new material generation from another
            // approval object. Its record names exactly the replaced object.
            ensure!(
                self.predecessor
                    == Some(Predecessor {
                        source: previous.clone(),
                        generation: old.authority_generation,
                        approval_digest: old.authority_approval_digest.clone(),
                    }),
                "source succession must record its exact predecessor"
            );
        } else {
            ensure!(
                self.predecessor == old.predecessor,
                "succession history changed without a source succession"
            );
        }
        if self.observation != Observation::Validated
            && self.observation != Observation::AuthorityRevoked
        {
            ensure!(
                self.anchors == old.anchors
                    && self.bindings == old.bindings
                    && self.authority_generation == old.authority_generation
                    && self.authority_approval_digest == old.authority_approval_digest
                    && self.authority_source == old.authority_source
                    && self.predecessor == old.predecessor,
                "availability failure mutated authority history"
            );
        }
        if let Some(previous) = &old.anchors {
            let next = self
                .anchors
                .as_ref()
                .context("cannot erase persisted anchor history")?;
            ensure!(
                previous.local_domain == next.local_domain && previous.root_der == next.root_der,
                "checkpoint changed installed authority"
            );
            ensure!(
                next.sequence >= previous.sequence,
                "anchor history rollback"
            );
            if self.authority_generation == old.authority_generation
                && self.observation == Observation::Validated
            {
                ensure!(
                    next.pins == previous.pins,
                    "same material generation changed issuer certificate/lineage"
                );
            }
            if self.observation == Observation::AuthorityRevoked {
                ensure!(
                    self.authority_generation == old.authority_generation
                        && self.authority_approval_digest == old.authority_approval_digest
                        && self.bindings == old.bindings
                        && next.pins.iter().all(|p| previous.pins.contains(p)),
                    "revocation cannot add/rebind authority"
                );
            }
            let before: BTreeMap<_, _> = previous
                .drain_before
                .iter()
                .map(|c| (c.spki_der.as_str(), c.sequence))
                .collect();
            let after: BTreeMap<_, _> = next
                .drain_before
                .iter()
                .map(|c| (c.spki_der.as_str(), c.sequence))
                .collect();
            for (key, cutoff) in before {
                ensure!(
                    after.get(key).is_some_and(|s| *s >= cutoff),
                    "retained-connection cutoff erased/rolled back"
                );
            }
            let active: BTreeSet<_> = next
                .pins
                .iter()
                .map(|p| {
                    let bytes =
                        base64::engine::general_purpose::STANDARD.decode(&p.certificate_der)?;
                    let spki = super::domain_anchors::spki_der(&bytes)?;
                    Ok(base64::engine::general_purpose::STANDARD.encode(spki))
                })
                .collect::<Result<_>>()?;
            let fenced: BTreeSet<_> = next.fenced_spkis.iter().cloned().collect();
            for key in &previous.fenced_spkis {
                ensure!(
                    fenced.contains(key)
                        || (self.authority_generation > old.authority_generation
                            && active.contains(key)
                            && after.get(key.as_str()).is_some_and(|s| *s == next.sequence)),
                    "revoked key restored without new approved authority/cutoff"
                );
            }
            let old_active: Vec<_> = previous
                .pins
                .iter()
                .map(|p| {
                    let bytes =
                        base64::engine::general_purpose::STANDARD.decode(&p.certificate_der)?;
                    Ok(base64::engine::general_purpose::STANDARD
                        .encode(super::domain_anchors::spki_der(&bytes)?))
                })
                .collect::<Result<_>>()?;
            for key in old_active {
                if !active.contains(&key) {
                    ensure!(
                        fenced.contains(&key)
                            && after.get(key.as_str()).is_some_and(|s| *s == next.sequence),
                        "removed issuer lacks cumulative revocation"
                    );
                }
            }
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    state: ProfileCheckpoint,
    checksum: String,
}
/// Reads only `state.version` to select the strict layout below.
#[derive(Deserialize)]
struct VersionProbe {
    state: VersionField,
}
#[derive(Deserialize)]
struct VersionField {
    version: u32,
}
// The exact v1 layout written by ztunnel f221f29 and earlier. Field order is
// the checksum input and must not change. Read for migration only.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginV1 {
    cluster: String,
    node: String,
    source_namespace: String,
    source_name: String,
    source_uid: String,
    output_namespace: String,
    output_name: String,
    output_uid: String,
    root_pins: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileCheckpointV1 {
    version: u32,
    origin: OriginV1,
    floors: Floors,
    observation: Observation,
    authority_generation: u64,
    authority_approval_digest: String,
    published_unix: u64,
    valid_until_unix: u64,
    bindings: Vec<Binding>,
    anchors: Option<AnchorCheckpoint>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeV1 {
    state: ProfileCheckpointV1,
    checksum: String,
}
impl ProfileCheckpointV1 {
    /// A v1 checkpoint could only hold material from its origin's approval
    /// object, so that object is the authority source. Floors, observation,
    /// bindings and anchor history (fences, cutoffs) carry over unchanged.
    fn migrate(self) -> Result<ProfileCheckpoint> {
        ensure!(self.version == V1, "v1 checkpoint layout/version differs");
        let o = self.origin;
        let source = ApprovalSource {
            name: o.source_name,
            uid: o.source_uid,
        };
        Ok(ProfileCheckpoint {
            version: VERSION,
            origin: Origin {
                cluster: o.cluster,
                node: o.node,
                source_namespace: o.source_namespace,
                output_namespace: o.output_namespace,
                output_name: o.output_name,
                output_uid: o.output_uid,
                root_pins: o.root_pins,
            },
            floors: self.floors,
            observation: self.observation,
            authority_generation: self.authority_generation,
            authority_approval_digest: self.authority_approval_digest,
            authority_source: self.anchors.is_some().then_some(source),
            predecessor: None,
            published_unix: self.published_unix,
            valid_until_unix: self.valid_until_unix,
            bindings: self.bindings,
            anchors: self.anchors,
        })
    }
}
fn hash(data: &[u8]) -> Result<String> {
    #[cfg(any(feature = "tls-ring", feature = "tls-aws-lc"))]
    let bytes = {
        let p = super::lib::provider();
        let h = p
            .cipher_suites
            .iter()
            .filter_map(|s| s.tls13())
            .map(|s| s.common.hash_provider)
            .find(|h| h.algorithm() == rustls::crypto::hash::HashAlgorithm::SHA256)
            .context("configured crypto provider lacks SHA256")?;
        h.hash(data).as_ref().to_vec()
    };
    #[cfg(feature = "tls-boring")]
    let bytes = boring::sha::sha256(data).to_vec();
    #[cfg(feature = "tls-openssl")]
    let bytes = openssl::sha::sha256(data).to_vec();
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn encode(state: &ProfileCheckpoint) -> Result<Vec<u8>> {
    let checksum = hash(&serde_json::to_vec(state)?)?;
    let bytes = serde_json::to_vec(&Envelope {
        state: state.clone(),
        checksum,
    })?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_CHECKPOINT_BYTES,
        "checkpoint capacity exceeded; history cannot be pruned"
    );
    Ok(bytes)
}
fn decode(bytes: &[u8], installation: &Installation) -> Result<ProfileCheckpoint> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_CHECKPOINT_BYTES,
        "bounded checkpoint required"
    );
    let probe: VersionProbe = serde_json::from_slice(bytes).context("strict checkpoint JSON")?;
    let state = match probe.state.version {
        VERSION => {
            let env: Envelope = serde_json::from_slice(bytes).context("strict checkpoint JSON")?;
            ensure!(
                pin(&env.checksum) && hash(&serde_json::to_vec(&env.state)?)? == env.checksum,
                "checkpoint integrity mismatch"
            );
            env.state
        }
        V1 => {
            // Integrity is checked on the exact v1 bytes before migration. The
            // file stays v1 on disk until the next distinct durable commit.
            let env: EnvelopeV1 =
                serde_json::from_slice(bytes).context("strict v1 checkpoint JSON")?;
            ensure!(
                pin(&env.checksum) && hash(&serde_json::to_vec(&env.state)?)? == env.checksum,
                "checkpoint integrity mismatch"
            );
            env.state.migrate()?
        }
        version => bail!("unsupported checkpoint version {version}"),
    };
    state.validate(installation)?;
    Ok(state)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenMode {
    Existing,
    BootstrapEmptyDirectory,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableCommit {
    sequence: u64,
    publication_digest: String,
}
impl DurableCommit {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn publication_digest(&self) -> &str {
        &self.publication_digest
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Inode {
    dev: u64,
    ino: u64,
}
fn inode(file: &File) -> Result<Inode> {
    let m = file.metadata()?;
    Ok(Inode {
        dev: m.dev(),
        ino: m.ino(),
    })
}
fn cstring(s: &OsStr) -> Result<CString> {
    Ok(CString::new(s.as_bytes())?)
}
fn open_at(dir: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
    let name = CString::new(name)?;
    // openat returns an owned FD on success. O_NOFOLLOW is mandatory for every
    // store entry; no procfs/path re-resolution is used for file operations.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            mode as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("checkpoint openat");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn open_directory(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute() && path.as_os_str().len() <= 4096,
        "bounded absolute checkpoint directory required"
    );
    let root = CString::new("/")?;
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("checkpoint root open");
    }
    let mut current = unsafe { File::from_raw_fd(fd) };
    let mut count = 0;
    for part in path.components() {
        match part {
            Component::RootDir => (),
            Component::Normal(name) => {
                let name = cstring(name)?;
                let fd = unsafe {
                    libc::openat(
                        current.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("checkpoint directory component");
                }
                current = unsafe { File::from_raw_fd(fd) };
                count += 1;
            }
            _ => bail!("noncanonical checkpoint directory"),
        }
    }
    ensure!(count > 0, "checkpoint cannot use root directory");
    private_directory(&current)?;
    Ok(current)
}
fn private_directory(file: &File) -> Result<()> {
    let m = file.metadata()?;
    let uid = unsafe { libc::geteuid() };
    ensure!(
        m.is_dir() && m.uid() == uid && m.mode() & 0o7777 == 0o700,
        "checkpoint directory must be owned by effective UID, mode0700"
    );
    Ok(())
}
fn private_file(file: &File) -> Result<()> {
    let m = file.metadata()?;
    let uid = unsafe { libc::geteuid() };
    ensure!(
        m.is_file() && m.uid() == uid && m.mode() & 0o7777 == 0o600 && m.nlink() == 1,
        "checkpoint entry must be single-link regular0600 owned by effective UID"
    );
    Ok(())
}
fn absent_at(dir: &File, name: &str) -> Result<bool> {
    let name = CString::new(name)?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let r = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r == 0 {
        return Ok(false);
    }
    let e = std::io::Error::last_os_error();
    if e.kind() == std::io::ErrorKind::NotFound {
        Ok(true)
    } else {
        Err(e.into())
    }
}
fn directory_entries(dir: &File) -> Result<Vec<String>> {
    let copy = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if copy < 0 {
        return Err(std::io::Error::last_os_error()).context("checkpoint directory dup");
    }
    let stream = unsafe { libc::fdopendir(copy) };
    if stream.is_null() {
        unsafe { libc::close(copy) };
        return Err(std::io::Error::last_os_error()).context("checkpoint fdopendir");
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = Stream(stream);
    let mut names = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error).context("checkpoint readdir");
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_str()?
            .to_owned();
        if name != "." && name != ".." {
            names.push(name);
            ensure!(names.len() <= 16, "too many checkpoint directory entries");
        }
    }
    Ok(names)
}
fn bounded_read(mut file: &File, max: usize) -> Result<Vec<u8>> {
    private_file(file)?;
    ensure!(
        file.metadata()?.len() <= max as u64,
        "oversized checkpoint file"
    );
    let mut bytes = Vec::new();
    (&mut file).take((max + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "oversized checkpoint read");
    Ok(bytes)
}

pub struct CheckpointStore {
    path: PathBuf,
    directory: File,
    directory_inode: Inode,
    lock: File,
    lock_inode: Inode,
    installation: Installation,
    marker_inode: Option<Inode>,
    recovered: Option<ProfileCheckpoint>,
    state_inode: Option<Inode>,
    state_bytes: Option<Vec<u8>>,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<TestFault>,
}
impl CheckpointStore {
    pub fn open(path: &Path, installation: Installation, mode: OpenMode) -> Result<Self> {
        installation.validate()?;
        let directory = open_directory(path)?;
        let directory_inode = inode(&directory)?;
        let lock = open_at(&directory, LOCK, libc::O_RDWR | libc::O_CREAT, 0o600)?;
        private_file(&lock)?;
        let rc = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("checkpoint writer lock held");
        }
        let lock_inode = inode(&lock)?;
        let mut store = Self {
            path: path.to_owned(),
            directory,
            directory_inode,
            lock,
            lock_inode,
            installation,
            marker_inode: None,
            recovered: None,
            state_inode: None,
            state_bytes: None,
            poisoned: false,
            #[cfg(test)]
            fault: None,
        };
        store.verify_namespace()?;
        match mode {
            OpenMode::BootstrapEmptyDirectory => {
                ensure!(
                    absent_at(&store.directory, MARKER)?
                        && absent_at(&store.directory, STATE)?
                        && absent_at(&store.directory, PENDING)?,
                    "bootstrap requires new uninitialized store; never reset history"
                );
                ensure!(
                    directory_entries(&store.directory)?
                        .into_iter()
                        .all(|entry| entry == LOCK),
                    "bootstrap requires otherwise empty private directory"
                );
                // Explicit one-shot bootstrap creates a durable initialization
                // marker BEFORE first state write. A crash in that interval is
                // not permission to bootstrap again or accept a missing state.
                let mut marker = open_at(
                    &store.directory,
                    MARKER,
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                    0o600,
                )?;
                private_file(&marker)?;
                marker.write_all(MARKER_BYTES)?;
                marker.sync_all()?;
                store.directory.sync_all()?;
                store.marker_inode = Some(inode(&marker)?);
            }
            OpenMode::Existing => {
                let marker = open_at(&store.directory, MARKER, libc::O_RDONLY, 0)?;
                ensure!(
                    bounded_read(&marker, 128)? == MARKER_BYTES,
                    "checkpoint initialization marker corrupt"
                );
                store.marker_inode = Some(inode(&marker)?);
                let file = open_at(&store.directory, STATE, libc::O_RDONLY, 0)
                    .context("initialized checkpoint missing; explicit recovery required")?;
                let bytes = bounded_read(&file, MAX_CHECKPOINT_BYTES)?;
                store.recovered = Some(decode(&bytes, &store.installation)?);
                store.state_inode = Some(inode(&file)?);
                store.state_bytes = Some(bytes);
            }
        }
        store.verify_namespace()?;
        Ok(store)
    }
    pub fn recovered(&self) -> Option<&ProfileCheckpoint> {
        self.recovered.as_ref()
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    fn verify_namespace(&self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "checkpoint store poisoned; close admission and reopen/recover"
        );
        private_directory(&self.directory)?;
        ensure!(
            inode(&open_directory(&self.path)?)? == self.directory_inode,
            "checkpoint directory path replaced"
        );
        private_file(&self.lock)?;
        let current = open_at(&self.directory, LOCK, libc::O_RDONLY, 0)?;
        private_file(&current)?;
        ensure!(
            inode(&current)? == self.lock_inode,
            "checkpoint writer lock path replaced"
        );
        if let Some(expected) = self.marker_inode {
            let marker = open_at(&self.directory, MARKER, libc::O_RDONLY, 0)?;
            ensure!(
                inode(&marker)? == expected && bounded_read(&marker, 128)? == MARKER_BYTES,
                "checkpoint initialization marker replaced/modified"
            );
        }
        Ok(())
    }
    fn verify_current_state(&self) -> Result<()> {
        match (&self.state_inode, &self.state_bytes) {
            (Some(expected), Some(bytes)) => {
                let file = open_at(&self.directory, STATE, libc::O_RDONLY, 0)?;
                ensure!(
                    inode(&file)? == *expected
                        && bounded_read(&file, MAX_CHECKPOINT_BYTES)? == *bytes,
                    "checkpoint state replaced/modified outside owner"
                );
            }
            (None, None) => ensure!(
                absent_at(&self.directory, STATE)?,
                "unexpected checkpoint state during bootstrap"
            ),
            _ => bail!("checkpoint owner state inconsistent"),
        }
        Ok(())
    }
    pub fn commit(&mut self, next: ProfileCheckpoint, now: SystemTime) -> Result<DurableCommit> {
        if let Err(error) = self
            .verify_namespace()
            .and_then(|()| self.verify_current_state())
        {
            self.poisoned = true;
            return Err(error).context("checkpoint namespace/state changed; no ACK or activation");
        }
        next.validate(&self.installation)?;
        let now = now.duration_since(UNIX_EPOCH)?.as_secs();
        ensure!(now >= next.published_unix, "future checkpoint observation");
        if next.observation == Observation::Validated {
            ensure!(
                now < next.valid_until_unix,
                "cannot commit an expired active publication"
            );
        }
        if let Some(previous) = &self.recovered {
            if previous == &next {
                if let Err(error) = self.requalify_current_durability() {
                    self.poisoned = true;
                    return Err(error).context(
                        "recovered checkpoint durability not confirmed; no ACK or activation",
                    );
                }
                return Ok(DurableCommit {
                    sequence: next.floors.sequence,
                    publication_digest: next.floors.publication_digest.clone(),
                });
            }
            next.supersedes(previous)?;
        }
        let bytes = encode(&next)?;
        ensure!(
            absent_at(&self.directory, PENDING)?,
            "uncommitted pending file retained; explicit pending recovery required"
        );
        let result = self.write_transaction(&bytes);
        let state_inode = match result {
            Ok(value) => value,
            Err(error) => {
                self.poisoned = true;
                return Err(error)
                    .context("checkpoint write ambiguous/failed; no ACK or activation");
            }
        };
        self.state_inode = Some(state_inode);
        self.state_bytes = Some(bytes);
        self.recovered = Some(next.clone());
        Ok(DurableCommit {
            sequence: next.floors.sequence,
            publication_digest: next.floors.publication_digest,
        })
    }
    // A reopened state may be the visible result of a rename whose writer
    // died before directory fsync. Reading valid bytes is not a durability ACK.
    fn requalify_current_durability(&mut self) -> Result<()> {
        self.verify_namespace()?;
        self.verify_current_state()?;
        let file = open_at(&self.directory, STATE, libc::O_RDONLY, 0)?;
        private_file(&file)?;
        ensure!(
            Some(inode(&file)?) == self.state_inode,
            "recovered checkpoint inode replaced"
        );
        self.test_boundary(TestBoundary::BeforeFileSync)?;
        file.sync_all().context("recovered checkpoint file fsync")?;
        self.test_boundary(TestBoundary::AfterFileSync)?;
        self.directory
            .sync_all()
            .context("recovered checkpoint directory fsync")?;
        self.test_boundary(TestBoundary::AfterDirectorySync)?;
        self.verify_namespace()?;
        self.verify_current_state()?;
        Ok(())
    }
    fn write_transaction(&mut self, bytes: &[u8]) -> Result<Inode> {
        let mut file = open_at(
            &self.directory,
            PENDING,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        private_file(&file)?;
        file.write_all(bytes).context("checkpoint write")?;
        self.test_boundary(TestBoundary::BeforeFileSync)?;
        file.sync_all().context("checkpoint file fsync")?;
        self.test_boundary(TestBoundary::AfterFileSync)?;
        self.verify_namespace()?;
        self.verify_current_state()?;
        // Prove the pending path still names our held FD before rename.
        let pending = open_at(&self.directory, PENDING, libc::O_RDONLY, 0)?;
        private_file(&pending)?;
        ensure!(
            inode(&pending)? == inode(&file)?,
            "checkpoint pending path replaced"
        );
        let from = CString::new(PENDING)?;
        let to = CString::new(STATE)?;
        let rc = unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                from.as_ptr(),
                self.directory.as_raw_fd(),
                to.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("checkpoint atomic rename");
        }
        self.test_boundary(TestBoundary::AfterRename)?;
        self.directory
            .sync_all()
            .context("checkpoint directory fsync")?;
        self.test_boundary(TestBoundary::AfterDirectorySync)?;
        self.verify_namespace()?;
        let current = open_at(&self.directory, STATE, libc::O_RDONLY, 0)?;
        ensure!(
            inode(&current)? == inode(&file)?
                && bounded_read(&current, MAX_CHECKPOINT_BYTES)? == bytes,
            "checkpoint postcommit identity differs"
        );
        inode(&file)
    }
    /// Explicit operator-approved removal of an unacknowledged pending file.
    /// Requires a validated EXISTING state and an exclusive current lock. It
    /// cannot repair missing/corrupt state, change floors, or discard history.
    pub fn remove_pending_for_recovery(&mut self) -> Result<()> {
        self.verify_namespace()?;
        ensure!(
            self.recovered.is_some(),
            "pending recovery requires validated committed state"
        );
        self.verify_current_state()?;
        if absent_at(&self.directory, PENDING)? {
            return Ok(());
        }
        let result = (|| {
            let pending = open_at(&self.directory, PENDING, libc::O_RDONLY, 0)?;
            private_file(&pending)?;
            let before = inode(&pending)?;
            let current = open_at(&self.directory, PENDING, libc::O_RDONLY, 0)?;
            ensure!(inode(&current)? == before, "pending recovery path replaced");
            self.verify_namespace()?;
            let name = CString::new(PENDING)?;
            let rc = unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error()).context("pending recovery unlink");
            }
            self.directory.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn test_boundary(&self, boundary: TestBoundary) -> Result<()> {
        #[cfg(not(test))]
        let _ = boundary;
        #[cfg(test)]
        if let Some(f) = &self.fault
            && f.boundary == boundary
        {
            match f.action {
                TestAction::Error => bail!("injected checkpoint fault {boundary:?}"),
                TestAction::Kill => {
                    unsafe { libc::raise(libc::SIGKILL) };
                    std::process::abort();
                }
            }
        }
        Ok(())
    }
}
// Kept private: production cannot inject faults or skip durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestBoundary {
    BeforeFileSync,
    AfterFileSync,
    AfterRename,
    AfterDirectorySync,
}
#[cfg(test)]
#[derive(Clone, Copy)]
enum TestAction {
    Error,
    Kill,
}
#[cfg(test)]
struct TestFault {
    boundary: TestBoundary,
    action: TestAction,
}
#[cfg(test)]
mod tests {
    use super::super::issuer_profile_wire::decode as decode_wire;
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    use std::time::Duration;

    fn fixture() -> (Installation, ProfileCheckpoint, SystemTime) {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("issuer-profile-v1.json")).unwrap();
        let w = &f["wire"];
        let e = Expected {
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
        };
        let now = UNIX_EPOCH + Duration::from_secs(f["nowUnix"].as_str().unwrap().parse().unwrap());
        let d = decode_wire(&serde_json::to_vec(w).unwrap(), &e, now).unwrap();
        let anchors = AnchorPublication::initial(d.candidate.unwrap())
            .checkpoint()
            .unwrap();
        let state = ProfileCheckpoint {
            version: VERSION,
            origin: Origin::from_expected(&e),
            floors: Floors {
                sequence: d.sequence,
                logical_generation: d.generation,
                approval_digest: d.approval_digest.clone(),
                publication_digest: d.publication_digest,
            },
            observation: Observation::Validated,
            authority_generation: d.generation,
            authority_approval_digest: d.approval_digest,
            authority_source: Some(d.source),
            predecessor: None,
            published_unix: w["publishedUnix"].as_str().unwrap().parse().unwrap(),
            valid_until_unix: w["validUntilUnix"].as_str().unwrap().parse().unwrap(),
            bindings: d
                .bindings
                .into_iter()
                .map(|b| Binding {
                    cluster: b.cluster_id,
                    domain: b.trust_domain,
                })
                .collect(),
            anchors: Some(anchors),
        };
        (Installation::from_expected(&e), state, now)
    }
    /// Opens a checkpoint store, waiting out a writer lock that only a forked
    /// copy of a dropped handle still holds. cargo test runs tests as threads of
    /// one process, and a child that any test spawns holds a copy of every open
    /// descriptor until it execs, O_CLOEXEC or not; while it does, the flock of
    /// a handle this test already dropped is still taken. ztunnel itself never
    /// spawns a process, so CheckpointStore::open stays non-blocking, and a
    /// handle that is still open keeps the lock past the bound and still fails.
    fn open_store(
        path: &Path,
        installation: Installation,
        mode: OpenMode,
    ) -> Result<CheckpointStore> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match CheckpointStore::open(path, installation.clone(), mode) {
                Err(e) if writer_lock_held(&e) && std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                result => return result,
            }
        }
    }
    fn writer_lock_held(e: &anyhow::Error) -> bool {
        e.to_string() == "checkpoint writer lock held"
            && e.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::raw_os_error)
                    == Some(libc::EWOULDBLOCK)
            })
    }
    fn dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    fn advanced(old: &ProfileCheckpoint) -> ProfileCheckpoint {
        let mut next = old.clone();
        next.floors.sequence += 1;
        next.floors.publication_digest = "a".repeat(64);
        let history = old.history().unwrap().unwrap();
        next.anchors = Some(
            history
                .replace(
                    history
                        .anchors()
                        .with_generation(next.floors.sequence)
                        .unwrap(),
                )
                .unwrap()
                .checkpoint()
                .unwrap(),
        );
        next
    }
    fn committed(d: &Path) -> (Installation, ProfileCheckpoint, SystemTime) {
        let (i, s, now) = fixture();
        let mut store = open_store(d, i.clone(), OpenMode::BootstrapEmptyDirectory).unwrap();
        let receipt = store.commit(s.clone(), now).unwrap();
        assert_eq!(receipt.sequence, s.floors.sequence);
        (i, s, now)
    }
    #[test]
    fn existing_store_never_auto_initializes_and_bootstrap_is_one_shot() {
        let d = dir();
        let (i, s, now) = fixture();
        assert!(open_store(d.path(), i.clone(), OpenMode::Existing).is_err());
        let interrupted = dir();
        let empty = open_store(
            interrupted.path(),
            i.clone(),
            OpenMode::BootstrapEmptyDirectory,
        )
        .unwrap();
        drop(empty);
        assert!(open_store(interrupted.path(), i.clone(), OpenMode::Existing).is_err());
        assert!(
            open_store(
                interrupted.path(),
                i.clone(),
                OpenMode::BootstrapEmptyDirectory
            )
            .is_err()
        );
        // Existing open creates only a private cooperative lock, not a state.
        let mut first = open_store(d.path(), i.clone(), OpenMode::BootstrapEmptyDirectory).unwrap();
        first.commit(s, now).unwrap();
        drop(first);
        assert!(open_store(d.path(), i.clone(), OpenMode::BootstrapEmptyDirectory).is_err());
        std::fs::remove_file(d.path().join(STATE)).unwrap();
        assert!(open_store(d.path(), i, OpenMode::Existing).is_err());
    }
    #[test]
    fn held_writer_lock_refuses_concurrent_owner_and_detects_replacement() {
        let d = dir();
        let (i, s, now) = committed(d.path());
        let mut first = open_store(d.path(), i.clone(), OpenMode::Existing).unwrap();
        // A live owner is refused at once: the store's open never waits.
        assert!(CheckpointStore::open(d.path(), i, OpenMode::Existing).is_err());
        std::fs::remove_file(d.path().join(LOCK)).unwrap();
        std::fs::write(d.path().join(LOCK), b"").unwrap();
        std::fs::set_permissions(d.path().join(LOCK), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(first.commit(advanced(&s), now).is_err());
        assert!(first.is_poisoned());
    }
    #[test]
    fn rejects_symlink_directory_files_wrong_modes_hardlinks_and_foreign_bootstrap_contents() {
        let parent = dir();
        let target = dir();
        let link = parent.path().join("symlink");
        symlink(target.path(), &link).unwrap();
        let (i, _, _) = fixture();
        assert!(open_store(&link, i.clone(), OpenMode::Existing).is_err());
        let d = dir();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(open_store(d.path(), i.clone(), OpenMode::BootstrapEmptyDirectory).is_err());
        let d = dir();
        std::fs::write(d.path().join("foreign"), b"preserve").unwrap();
        assert!(open_store(d.path(), i.clone(), OpenMode::BootstrapEmptyDirectory).is_err());
        assert_eq!(
            std::fs::read(d.path().join("foreign")).unwrap(),
            b"preserve"
        );
        let d = dir();
        let (i, _, _) = committed(d.path());
        let state = d.path().join(STATE);
        std::fs::hard_link(&state, d.path().join("foreign-link")).unwrap();
        assert!(open_store(d.path(), i, OpenMode::Existing).is_err());
        let d = dir();
        let (i, _, _) = committed(d.path());
        std::fs::remove_file(d.path().join(STATE)).unwrap();
        symlink(parent.path().join("foreign"), d.path().join(STATE)).unwrap();
        assert!(open_store(d.path(), i, OpenMode::Existing).is_err());
    }
    #[test]
    fn detects_held_directory_path_substitution_without_writing_new_directory() {
        let parent = dir();
        let path = parent.path().join("owned");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (i, s, now) = committed(&path);
        let mut store = open_store(&path, i, OpenMode::Existing).unwrap();
        std::fs::rename(&path, parent.path().join("old")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(store.commit(advanced(&s), now).is_err());
        assert!(store.is_poisoned());
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
    }
    #[test]
    fn strict_bounded_corrupt_and_origin_or_independent_floor_mismatches_fail_closed() {
        let (i, s, _) = fixture();
        let bytes = encode(&s).unwrap();
        assert_eq!(decode(&bytes, &i).unwrap(), s);
        let mut bad = bytes.clone();
        let p = bad.iter().position(|b| *b == b'7').unwrap();
        bad[p] = b'8';
        assert!(decode(&bad, &i).is_err());
        assert!(decode(&vec![b' '; MAX_CHECKPOINT_BYTES + 1], &i).is_err());
        assert!(decode(b"{\"state\":{},\"state\":{}}", &i).is_err());
        for variant in 0..6 {
            let mut changed = i.clone();
            match variant {
                0 => changed.origin.node = "other-node".into(),
                // The pinned floor source still binds the floor generation.
                1 => changed.source_at_minimum.uid = "other-source".into(),
                2 => changed.origin.output_uid = "other-output".into(),
                3 => changed.origin.root_pins = vec!["f".repeat(64)],
                4 => changed.minimum_sequence += 1,
                _ => changed.minimum_generation += 1,
            };
            assert!(decode(&bytes, &changed).is_err());
        }
        let mut changed = i.clone();
        changed.publication_digest_at_minimum = Some("f".repeat(64));
        assert!(decode(&bytes, &changed).is_err());
    }
    #[test]
    fn commit_sequence_generation_and_digest_floors_never_roll_back() {
        let d = dir();
        let (i, s, now) = committed(d.path());
        let mut store = open_store(d.path(), i, OpenMode::Existing).unwrap();
        let inode = store.state_inode;
        store.commit(s.clone(), now).unwrap();
        assert_eq!(store.state_inode, inode);
        let mut next = advanced(&s);
        next.floors.sequence = s.floors.sequence;
        assert!(store.commit(next, now).is_err());
        let mut next = advanced(&s);
        next.floors.logical_generation -= 1;
        assert!(store.commit(next, now).is_err());
        let mut next = advanced(&s);
        next.floors.approval_digest = "f".repeat(64);
        assert!(store.commit(next, now).is_err());
        assert!(!store.is_poisoned());
        store.commit(advanced(&s), now).unwrap();
    }
    #[test]
    fn unavailable_observation_preserves_authority_and_recovered_lease_is_not_a_grant() {
        let d = dir();
        let (i, s, now) = committed(d.path());
        let mut store = open_store(d.path(), i.clone(), OpenMode::Existing).unwrap();
        let mut unavailable = s.clone();
        unavailable.floors.sequence += 1;
        unavailable.floors.publication_digest = "a".repeat(64);
        unavailable.observation = Observation::SourceUnavailable;
        unavailable.valid_until_unix = unavailable.published_unix;
        store.commit(unavailable.clone(), now).unwrap();
        assert_eq!(store.recovered().unwrap().anchors, s.anchors);
        drop(store);
        let loaded = open_store(d.path(), i, OpenMode::Existing).unwrap();
        assert_eq!(loaded.recovered().unwrap(), &unavailable);
        // No ready/session/ACK data is returned, and opening is independent of
        // wall clock; certificate history may be needed long after lease expiry.
        assert!(loaded.recovered().unwrap().history().unwrap().is_some());
        let mut expired = advanced(&s);
        expired.floors.sequence += 2;
        expired.anchors.as_mut().unwrap().sequence = expired.floors.sequence;
        drop(loaded);
        let mut store = open_store(d.path(), fixture().0, OpenMode::Existing).unwrap();
        assert!(
            store
                .commit(expired, now + Duration::from_secs(60))
                .is_err()
        );
    }
    #[test]
    fn cumulative_withdrawal_and_connection_history_round_trip_and_cannot_be_erased() {
        let (i, s, now) = fixture();
        let original = s.history().unwrap().unwrap();
        let domain: crate::strng::Strng = "cmtc-b.mesh.example".into();
        let key = original.anchors().pin_spkis(&domain).pop().unwrap();
        let revoked = original.withdraw_pin(&domain, &key, 11).unwrap();
        let mut next = s.clone();
        next.floors.sequence = 11;
        next.floors.publication_digest = "a".repeat(64);
        next.anchors = Some(revoked.checkpoint().unwrap());
        // Direct authority maintenance is not an Unavailable observation.
        // The test uses a validated, newer logical authority decision.
        next.floors.logical_generation = 8;
        next.floors.approval_digest = "b".repeat(64);
        next.authority_generation = 8;
        next.authority_approval_digest = "b".repeat(64);
        let d = dir();
        let mut store = open_store(d.path(), i.clone(), OpenMode::BootstrapEmptyDirectory).unwrap();
        store.commit(s.clone(), now).unwrap();
        store.commit(next.clone(), now).unwrap();
        drop(store);
        let mut reopened = open_store(d.path(), i, OpenMode::Existing).unwrap();
        let history = reopened.recovered().unwrap().history().unwrap().unwrap();
        assert_eq!(history, revoked);
        assert!(history.bundle_fenced(&key));
        let mut erased = next.clone();
        erased.floors.sequence = 12;
        erased.floors.publication_digest = "c".repeat(64);
        erased.anchors = Some(
            original
                .anchors()
                .with_generation(12)
                .map(AnchorPublication::initial)
                .unwrap()
                .checkpoint()
                .unwrap(),
        );
        assert!(reopened.commit(erased, now).is_err());
        let restored = revoked
            .restore_authoritative_snapshot(original.anchors().with_generation(12).unwrap())
            .unwrap();
        let mut approved = next.clone();
        approved.floors.sequence = 12;
        approved.floors.publication_digest = "c".repeat(64);
        approved.floors.logical_generation = 9;
        approved.floors.approval_digest = "d".repeat(64);
        approved.authority_generation = 9;
        approved.authority_approval_digest = "d".repeat(64);
        approved.anchors = Some(restored.checkpoint().unwrap());
        reopened.commit(approved, now).unwrap();
    }
    /// The exact bytes the v1 writer (ztunnel f221f29) committed for the
    /// fixture: origin bound to the approval object `issuer-approval`.
    const V1_STATE: &[u8] = include_bytes!("profile-state-v1-f221f29.json");
    fn v1_store() -> tempfile::TempDir {
        let d = dir();
        let (i, _, _) = fixture();
        drop(open_store(d.path(), i, OpenMode::BootstrapEmptyDirectory).unwrap());
        let path = d.path().join(STATE);
        std::fs::write(&path, V1_STATE).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        d
    }
    /// A successor approval object supplies generation 8 at sequence 11.
    fn successor(old: &ProfileCheckpoint, name: &str) -> ProfileCheckpoint {
        let mut next = advanced(old);
        next.floors.logical_generation = 8;
        next.floors.approval_digest = "8".repeat(64);
        next.authority_generation = 8;
        next.authority_approval_digest = "8".repeat(64);
        let previous = old.authority_source.clone().unwrap();
        next.authority_source = Some(ApprovalSource {
            name: name.into(),
            uid: format!("{name}-uid"),
        });
        next.predecessor = Some(Predecessor {
            source: previous,
            generation: old.authority_generation,
            approval_digest: old.authority_approval_digest.clone(),
        });
        next
    }
    #[test]
    fn v1_checkpoint_on_disk_is_migrated_in_place_without_reset_or_rewrite() {
        let d = v1_store();
        let (i, s, now) = fixture();
        let mut store = open_store(d.path(), i.clone(), OpenMode::Existing).unwrap();
        // The v1 origin's approval object becomes the recorded authority source.
        assert_eq!(store.recovered().unwrap(), &s);
        assert_eq!(
            store
                .recovered()
                .unwrap()
                .authority_source
                .as_ref()
                .unwrap(),
            &i.source_at_minimum
        );
        // Revalidating the same publication fsyncs the v1 file; it never rewrites it.
        store.commit(s.clone(), now).unwrap();
        assert_eq!(std::fs::read(d.path().join(STATE)).unwrap(), V1_STATE);
        // Bootstrap still refuses the initialized directory.
        drop(store);
        assert!(open_store(d.path(), i.clone(), OpenMode::BootstrapEmptyDirectory).is_err());
        // The first new commit writes v2 with every floor and history entry carried.
        let mut store = open_store(d.path(), i.clone(), OpenMode::Existing).unwrap();
        let next = successor(&s, "issuer-approval-g8");
        store.commit(next.clone(), now).unwrap();
        drop(store);
        let reopened = open_store(d.path(), i, OpenMode::Existing).unwrap();
        assert_eq!(reopened.recovered().unwrap(), &next);
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(d.path().join(STATE)).unwrap()).unwrap();
        assert_eq!(raw["state"]["version"], 2);
        assert!(raw["state"]["origin"].get("source_uid").is_none());
    }
    #[test]
    fn v1_checkpoint_keeps_integrity_and_installation_scope() {
        let (i, _, _) = fixture();
        assert!(decode(V1_STATE, &i).is_ok());
        let mut tampered = V1_STATE.to_vec();
        let at = tampered
            .windows(b"\"sequence\":10".len())
            .position(|w| w == b"\"sequence\":10")
            .unwrap();
        tampered[at + b"\"sequence\":1".len()] = b'1';
        assert!(decode(&tampered, &i).is_err(), "v1 checksum not enforced");
        for variant in 0..5 {
            let mut changed = i.clone();
            match variant {
                0 => changed.origin.node = "other-node".into(),
                1 => changed.origin.output_uid = "other-output".into(),
                2 => changed.origin.root_pins = vec!["f".repeat(64)],
                3 => changed.minimum_generation += 1,
                // At the floor generation the v1 approval object is still bound.
                _ => changed.source_at_minimum.uid = "other-source".into(),
            }
            assert!(decode(V1_STATE, &changed).is_err(), "variant {variant}");
        }
        let mut future = V1_STATE.to_vec();
        let at = future
            .windows(b"\"version\":1".len())
            .position(|w| w == b"\"version\":1")
            .unwrap();
        future[at + b"\"version\":".len()] = b'3';
        assert!(decode(&future, &i).is_err());
    }
    #[test]
    fn source_succession_carries_floors_and_records_its_exact_predecessor() {
        let d = dir();
        let (i, s, now) = committed(d.path());
        let mut store = open_store(d.path(), i.clone(), OpenMode::Existing).unwrap();
        let next = successor(&s, "issuer-approval-g8");
        let mut unrecorded = next.clone();
        unrecorded.predecessor = None;
        assert!(store.commit(unrecorded, now).is_err());
        let mut misrecorded = next.clone();
        misrecorded.predecessor.as_mut().unwrap().generation = 6;
        assert!(store.commit(misrecorded, now).is_err());
        let mut same_generation = next.clone();
        same_generation.floors.logical_generation = 7;
        same_generation.floors.approval_digest = s.floors.approval_digest.clone();
        same_generation.authority_generation = 7;
        same_generation.authority_approval_digest = s.authority_approval_digest.clone();
        same_generation.predecessor = None;
        assert!(
            store.commit(same_generation, now).is_err(),
            "another object cannot supply the accepted generation"
        );
        assert!(!store.is_poisoned());
        store.commit(next.clone(), now).unwrap();
        // The successor is now the floor: its renewal keeps the record.
        let renewal = advanced(&next);
        assert_eq!(renewal.floors.sequence, 12);
        store.commit(renewal.clone(), now).unwrap();
        // A third object at the accepted generation is a substitution.
        let mut third = advanced(&renewal);
        third.authority_source = Some(ApprovalSource {
            name: "issuer-approval-other".into(),
            uid: "issuer-approval-other-uid".into(),
        });
        assert!(store.commit(third, now).is_err());
        // Rolling back to the predecessor's generation is refused at any sequence.
        let mut rollback = advanced(&renewal);
        rollback.floors.logical_generation = 7;
        rollback.floors.approval_digest = s.floors.approval_digest.clone();
        rollback.authority_generation = 7;
        rollback.authority_approval_digest = s.authority_approval_digest.clone();
        rollback.authority_source = s.authority_source.clone();
        rollback.predecessor = None;
        assert!(store.commit(rollback, now).is_err());
        // Erasing or rewriting the audit record is refused.
        let mut erased = advanced(&renewal);
        erased.predecessor = None;
        assert!(store.commit(erased, now).is_err());
        assert!(!store.is_poisoned());
        drop(store);
        // A restart with the unchanged installation pins (predecessor at floor 7) recovers.
        let reopened = open_store(d.path(), i, OpenMode::Existing).unwrap();
        assert_eq!(reopened.recovered().unwrap(), &renewal);
    }
    #[test]
    fn crash_child_succession() {
        let Ok(path) = std::env::var("CMTC_CHECKPOINT_SUCCESSION_CRASH_PATH") else {
            return;
        };
        let (i, s, now) = fixture();
        let mut store = open_store(Path::new(&path), i, OpenMode::Existing).unwrap();
        store.fault = Some(TestFault {
            boundary: TestBoundary::AfterRename,
            action: TestAction::Kill,
        });
        let _ = store.commit(successor(&s, "issuer-approval-g8"), now);
        panic!("child must be SIGKILLed after the succession rename");
    }
    #[test]
    fn sigkill_after_succession_rename_recovers_the_successor_from_a_v1_store() {
        let d = v1_store();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tls::profile_checkpoint::tests::crash_child_succession",
                "--nocapture",
            ])
            .env("CMTC_CHECKPOINT_SUCCESSION_CRASH_PATH", d.path())
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let (i, s, now) = fixture();
        let mut recovered = open_store(d.path(), i, OpenMode::Existing).unwrap();
        let next = successor(&s, "issuer-approval-g8");
        assert_eq!(recovered.recovered().unwrap(), &next);
        // The visible rename is re-synced before it is acknowledged again.
        assert_eq!(recovered.commit(next, now).unwrap().sequence(), 11);
    }
    #[test]
    fn injected_io_failure_poisons_handle_and_reopen_preserves_old_or_committed_state() {
        for boundary in [
            TestBoundary::BeforeFileSync,
            TestBoundary::AfterFileSync,
            TestBoundary::AfterRename,
            TestBoundary::AfterDirectorySync,
        ] {
            let d = dir();
            let (i, s, now) = committed(d.path());
            let mut store = open_store(d.path(), i.clone(), OpenMode::Existing).unwrap();
            let next = advanced(&s);
            store.fault = Some(TestFault {
                boundary,
                action: TestAction::Error,
            });
            assert!(store.commit(next.clone(), now).is_err());
            assert!(store.is_poisoned());
            assert!(store.commit(next.clone(), now).is_err());
            drop(store);
            let mut reopened = open_store(d.path(), i, OpenMode::Existing).unwrap();
            let expected = if matches!(
                boundary,
                TestBoundary::AfterRename | TestBoundary::AfterDirectorySync
            ) {
                &next
            } else {
                &s
            };
            assert_eq!(reopened.recovered().unwrap(), expected);
            if matches!(
                boundary,
                TestBoundary::BeforeFileSync | TestBoundary::AfterFileSync
            ) {
                assert!(reopened.commit(next.clone(), now).is_err());
                reopened.remove_pending_for_recovery().unwrap();
                reopened.commit(next, now).unwrap();
            }
        }
    }
    #[test]
    fn crash_child() {
        let Ok(path) = std::env::var("CMTC_CHECKPOINT_CRASH_PATH") else {
            return;
        };
        let boundary = match std::env::var("CMTC_CHECKPOINT_CRASH_STAGE")
            .unwrap()
            .as_str()
        {
            "synced" => TestBoundary::AfterFileSync,
            "renamed" => TestBoundary::AfterRename,
            "durable" => TestBoundary::AfterDirectorySync,
            _ => panic!("unknown boundary"),
        };
        let (i, s, now) = fixture();
        let mut store = open_store(Path::new(&path), i, OpenMode::Existing).unwrap();
        store.fault = Some(TestFault {
            boundary,
            action: TestAction::Kill,
        });
        let _ = store.commit(advanced(&s), now);
        panic!("child must be SIGKILLed at selected boundary");
    }
    #[test]
    fn actual_sigkill_before_rename_after_rename_and_after_directory_sync_recovery() {
        for stage in ["synced", "renamed", "durable"] {
            let d = dir();
            let (i, s, _) = committed(d.path());
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tls::profile_checkpoint::tests::crash_child",
                    "--nocapture",
                ])
                .env("CMTC_CHECKPOINT_CRASH_PATH", d.path())
                .env("CMTC_CHECKPOINT_CRASH_STAGE", stage)
                .status()
                .unwrap();
            assert_eq!(status.signal(), Some(libc::SIGKILL));
            let recovered = open_store(d.path(), i, OpenMode::Existing).unwrap();
            assert_eq!(
                recovered.recovered().unwrap().floors.sequence,
                if stage == "synced" {
                    s.floors.sequence
                } else {
                    s.floors.sequence + 1
                }
            );
        }
    }
    #[test]
    fn corrupt_missing_or_marker_replaced_state_never_uses_bootstrap_as_repair() {
        let d = dir();
        let (i, _, _) = committed(d.path());
        std::fs::write(d.path().join(STATE), b"{corrupt").unwrap();
        assert!(open_store(d.path(), i.clone(), OpenMode::Existing).is_err());
        assert!(open_store(d.path(), i, OpenMode::BootstrapEmptyDirectory).is_err());
        let d = dir();
        let (i, s, now) = committed(d.path());
        let mut store = open_store(d.path(), i, OpenMode::Existing).unwrap();
        std::fs::remove_file(d.path().join(MARKER)).unwrap();
        assert!(store.commit(advanced(&s), now).is_err());
        assert!(store.is_poisoned());
    }
    #[test]
    fn explicit_all_issuer_revocation_is_durable_and_requires_new_material_authority_to_restore() {
        let d = dir();
        let (i, s, now) = committed(d.path());
        let mut store = open_store(d.path(), i.clone(), OpenMode::Existing).unwrap();
        let original = s.history().unwrap().unwrap();
        let withdrawn = original.withdraw_all(11).unwrap();
        let mut revoked = s.clone();
        revoked.floors.sequence = 11;
        revoked.floors.publication_digest = "a".repeat(64);
        revoked.observation = Observation::AuthorityRevoked;
        revoked.valid_until_unix = revoked.published_unix;
        revoked.anchors = Some(withdrawn.checkpoint().unwrap());
        store.commit(revoked.clone(), now).unwrap();
        drop(store);
        let mut store = open_store(d.path(), i, OpenMode::Existing).unwrap();
        assert_eq!(
            store.recovered().unwrap().history().unwrap().unwrap(),
            withdrawn
        );
        let restored = withdrawn
            .restore_authoritative_snapshot(original.anchors().with_generation(12).unwrap())
            .unwrap();
        let mut next = s.clone();
        next.floors.sequence = 12;
        next.floors.publication_digest = "b".repeat(64);
        next.anchors = Some(restored.checkpoint().unwrap());
        assert!(store.commit(next.clone(), now).is_err());
        next.floors.logical_generation = 8;
        next.floors.approval_digest = "c".repeat(64);
        next.authority_generation = 8;
        next.authority_approval_digest = "c".repeat(64);
        store.commit(next, now).unwrap();
    }
    #[test]
    fn unavailable_new_producer_floor_does_not_erase_last_material_generation() {
        let d = dir();
        let (i, s, now) = committed(d.path());
        let mut store = open_store(d.path(), i, OpenMode::Existing).unwrap();
        let mut unavailable = s.clone();
        unavailable.floors.sequence = 11;
        unavailable.floors.logical_generation = 8;
        unavailable.floors.approval_digest = "a".repeat(64);
        unavailable.floors.publication_digest = "b".repeat(64);
        unavailable.observation = Observation::SourceChanged;
        unavailable.valid_until_unix = unavailable.published_unix;
        store.commit(unavailable, now).unwrap();
        assert_eq!(store.recovered().unwrap().authority_generation, 7);
        let mut published = advanced(&s);
        published.floors.sequence = 12;
        published.floors.logical_generation = 8;
        published.floors.approval_digest = "a".repeat(64);
        published.floors.publication_digest = "c".repeat(64);
        published.authority_generation = 8;
        published.authority_approval_digest = "a".repeat(64);
        published.anchors = Some(
            s.history()
                .unwrap()
                .unwrap()
                .replace(
                    s.history()
                        .unwrap()
                        .unwrap()
                        .anchors()
                        .with_generation(12)
                        .unwrap(),
                )
                .unwrap()
                .checkpoint()
                .unwrap(),
        );
        store.commit(published, now).unwrap();
    }
    #[test]
    fn external_state_mutation_and_file_modes_fail_closed_and_independent_floor_catches_old_valid_copy()
     {
        let d = dir();
        let (i, s, now) = committed(d.path());
        let mut store = open_store(d.path(), i.clone(), OpenMode::Existing).unwrap();
        std::fs::write(d.path().join(STATE), b"{}").unwrap();
        assert!(store.commit(advanced(&s), now).is_err());
        assert!(store.is_poisoned());
        drop(store);
        let d = dir();
        let (i, s, now) = committed(d.path());
        let old = std::fs::read(d.path().join(STATE)).unwrap();
        let mut store = open_store(d.path(), i.clone(), OpenMode::Existing).unwrap();
        store.commit(advanced(&s), now).unwrap();
        drop(store);
        std::fs::write(d.path().join(STATE), old).unwrap();
        let mut floor = i;
        floor.minimum_sequence = 11;
        floor.publication_digest_at_minimum = Some("a".repeat(64));
        assert!(open_store(d.path(), floor, OpenMode::Existing).is_err());
        let d = dir();
        let (i, _, _) = committed(d.path());
        std::fs::set_permissions(d.path().join(STATE), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(open_store(d.path(), i, OpenMode::Existing).is_err());
    }

    #[test]
    fn visible_recovered_rename_must_be_resynced_before_idempotent_receipt() {
        for boundary in [
            TestBoundary::BeforeFileSync,
            TestBoundary::AfterFileSync,
            TestBoundary::AfterDirectorySync,
        ] {
            let d = dir();
            let (i, s, now) = committed(d.path());
            let next = advanced(&s);
            let mut interrupted = open_store(d.path(), i.clone(), OpenMode::Existing).unwrap();
            interrupted.fault = Some(TestFault {
                boundary: TestBoundary::AfterRename,
                action: TestAction::Error,
            });
            assert!(interrupted.commit(next.clone(), now).is_err());
            drop(interrupted);
            let mut reopened = open_store(d.path(), i.clone(), OpenMode::Existing).unwrap();
            assert_eq!(reopened.recovered().unwrap(), &next);
            reopened.fault = Some(TestFault {
                boundary,
                action: TestAction::Error,
            });
            assert!(reopened.commit(next.clone(), now).is_err());
            assert!(reopened.is_poisoned());
            drop(reopened);
            let mut final_owner = open_store(d.path(), i, OpenMode::Existing).unwrap();
            let inode = final_owner.state_inode;
            assert_eq!(
                final_owner.commit(next.clone(), now).unwrap().sequence(),
                next.floors.sequence
            );
            assert_eq!(final_owner.state_inode, inode);
        }
    }
    #[test]
    fn fifo_child() {
        let Ok(path) = std::env::var("CMTC_CHECKPOINT_FIFO_PATH") else {
            return;
        };
        let entry = std::env::var("CMTC_CHECKPOINT_FIFO_ENTRY").unwrap();
        let (i, _, _) = fixture();
        if entry == PENDING {
            let mut store = open_store(Path::new(&path), i, OpenMode::Existing).unwrap();
            assert!(store.remove_pending_for_recovery().is_err());
        } else {
            assert!(open_store(Path::new(&path), i, OpenMode::Existing).is_err());
        }
    }
    #[test]
    fn every_reserved_fifo_is_rejected_in_bounded_real_child_without_thread_leaks() {
        for entry in [STATE, MARKER, LOCK, PENDING] {
            let d = dir();
            let _ = committed(d.path());
            let path = d.path().join(entry);
            if path.exists() {
                std::fs::remove_file(&path).unwrap();
            }
            let name = cstring(path.as_os_str()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tls::profile_checkpoint::tests::fifo_child",
                    "--nocapture",
                ])
                .env("CMTC_CHECKPOINT_FIFO_PATH", d.path())
                .env("CMTC_CHECKPOINT_FIFO_ENTRY", entry)
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("reserved FIFO {entry} blocked real open/recovery");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert!(
                status.success(),
                "child rejected FIFO {entry} incorrectly: {status:?}"
            );
        }
    }
}
