// Copyright Istio Authors
// SPDX-License-Identifier: Apache-2.0
//! Native typed ADS issuer profile. Pins alone select a NACK-only probe.
//! A separately configured native provider must durably commit before ACK.
use super::{RawHandler, RejectedConfig, State};
use crate::config::{Config, RootCert};
use crate::strng::{self, Strng};
use crate::tls::issuer_profile_wire::{self, Expected, MAX_WIRE_BYTES};
use crate::xds::ISSUER_PROFILE_TYPE;
use crate::xds::cilium::ztunnel::v1::IssuerProfile;
use crate::xds::service::discovery::v3::DeltaDiscoveryResponse;
use anyhow::{Context, Result, ensure};
use prost::Message;
use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::SystemTime;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Pins {
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
    root_pins: Vec<String>,
    minimum_generation: String,
    minimum_sequence: String,
    approval_digest_at_minimum: String,
    publication_digest_at_minimum: String,
}
fn positive(s: &str) -> Result<u64> {
    let n: u64 = s.parse()?;
    ensure!(
        n > 0 && n.to_string() == s,
        "positive canonical checkpoint required"
    );
    Ok(n)
}
fn decode_pins(data: &[u8]) -> Result<Expected> {
    ensure!(
        !data.is_empty() && data.len() <= 16 * 1024,
        "bounded probe pins required"
    );
    let p: Pins = serde_json::from_slice(data).context("strict issuer-profile probe pins")?;
    Ok(Expected {
        cluster: p.cluster,
        node: p.node,
        source_namespace: p.source_namespace,
        source_name: p.source_name,
        source_uid: p.source_uid,
        output_namespace: p.output_namespace,
        output_name: p.output_name,
        output_uid: p.output_uid,
        root_pins: p.root_pins,
        minimum_generation: positive(&p.minimum_generation)?,
        minimum_sequence: positive(&p.minimum_sequence)?,
        approval_digest_at_minimum: (!p.approval_digest_at_minimum.is_empty())
            .then_some(p.approval_digest_at_minimum),
        publication_digest_at_minimum: (!p.publication_digest_at_minimum.is_empty())
            .then_some(p.publication_digest_at_minimum),
    })
}
pub(super) fn load_config(config: &Config) -> Result<Option<Expected>> {
    let Some(path) = &config.issuer_profile_probe_pins else {
        return Ok(None);
    };
    ensure!(
        config.require_inbound_mtls
            && config.require_mesh_hbone
            && !config.xds_on_demand
            && config.local_xds_config.is_none(),
        "issuer-profile transport probe requires strict inbound/mesh egress and complete remote ADS"
    );
    ensure!(
        config.alt_xds_hostname.is_none() && !matches!(&config.xds_root_cert, RootCert::Default),
        "issuer-profile probe requires explicit ADS roots and one expected server name"
    );
    let uri: http::Uri = config
        .xds_address
        .as_ref()
        .context("missing profile ADS address")?
        .parse()?;
    ensure!(
        uri.scheme_str() == Some("https")
            && matches!(uri.host(), Some("localhost" | "127.0.0.1" | "[::1]")),
        "issuer-profile probe requires authenticated loopback HTTPS ADS"
    );
    ensure!(
        path.is_absolute(),
        "absolute issuer-profile probe pins path required"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let stat = file.metadata()?;
    ensure!(
        stat.is_file() && stat.uid() == 0 && stat.mode() & 0o022 == 0 && stat.len() <= 16 * 1024,
        "probe pins must be bounded root-owned regular non-writable-by-others file"
    );
    let mut data = Vec::new();
    file.by_ref().take(16 * 1024 + 1).read_to_end(&mut data)?;
    let expected = decode_pins(&data)?;
    ensure!(
        expected.cluster == config.cluster_id
            && config.local_node.as_deref() == Some(expected.node.as_str()),
        "issuer-profile pins differ from configured local cluster/node"
    );
    Ok(Some(expected))
}

pub(super) struct ProbeHandler {
    expected: Expected,
    clock: fn() -> SystemTime,
}
impl ProbeHandler {
    pub(super) fn new(expected: Expected, clock: fn() -> SystemTime) -> Self {
        Self { expected, clock }
    }
    fn decode(&self, res: &DeltaDiscoveryResponse) -> Result<issuer_profile_wire::Decoded> {
        self.decode_at(res, (self.clock)())
    }
    /// Decode at an explicit verifier time: the native provider passes its
    /// wall floor so a bounded backward step cannot NACK a current profile.
    fn decode_at(
        &self,
        res: &DeltaDiscoveryResponse,
        now: SystemTime,
    ) -> Result<issuer_profile_wire::Decoded> {
        ensure!(
            res.type_url == ISSUER_PROFILE_TYPE.to_string()
                && !res.nonce.is_empty()
                && res.nonce.len() <= 128,
            "issuer-profile outer type/nonce mismatch"
        );
        ensure!(
            res.resources.len() == 1 && res.removed_resources.is_empty(),
            "exactly one issuer-profile snapshot required"
        );
        let raw = &res.resources[0];
        ensure!(
            raw.name == format!("cilium/issuer-profile/{}", self.expected.node)
                && raw.aliases.is_empty()
                && raw.ttl.is_none()
                && raw.cache_control.is_none(),
            "issuer-profile resource name or delta metadata mismatch"
        );
        let any = raw
            .resource
            .as_ref()
            .context("missing issuer-profile Any")?;
        ensure!(
            any.type_url == ISSUER_PROFILE_TYPE.to_string()
                && any.value.len() <= MAX_WIRE_BYTES + 64,
            "issuer-profile inner type/size mismatch"
        );
        let profile = IssuerProfile::decode(any.value.as_slice())?;
        ensure!(
            profile.transport_version == 1,
            "unsupported issuer-profile transport version"
        );
        let decoded =
            issuer_profile_wire::decode(&profile.strict_der_profile_json, &self.expected, now)?;
        let version = format!("{}/{}", decoded.sequence, decoded.publication_digest);
        ensure!(
            raw.version == version && res.system_version_info == version,
            "issuer-profile resource version mismatch"
        );
        Ok(decoded)
    }
    fn validate_and_refuse_activation(&self, res: &DeltaDiscoveryResponse) -> Result<()> {
        self.decode(res)?;
        // This is intentionally not a commit callback. A fresh publication,
        // an unavailability tombstone and a lease renewal all leave the live
        // trust/provider checkpoint untouched. The native session stays closed.
        anyhow::bail!(
            "issuer profile validated; durable provider commit unavailable; admission remains fenced"
        )
    }
}
impl RawHandler for ProbeHandler {
    fn handle(
        &self,
        _state: &mut State,
        res: DeltaDiscoveryResponse,
    ) -> Result<(), Vec<RejectedConfig>> {
        let name = res
            .resources
            .first()
            .map(|r| strng::new(&r.name))
            .unwrap_or(ISSUER_PROFILE_TYPE);
        let err = match self.validate_and_refuse_activation(&res) {
            Err(err) => err,
            Ok(()) => anyhow::anyhow!("issuer-profile activation is unavailable"),
        };
        Err(vec![RejectedConfig::new(name, err)])
    }
    fn clear(&self, state: &mut State, type_url: &Strng) -> Result<(), Vec<RejectedConfig>> {
        // No provider is installed. Remove only the transport bookkeeping.
        state.known_resources.remove(type_url);
        Ok(())
    }
}

pub(super) struct ProviderHandler {
    decoder: ProbeHandler,
    provider: std::sync::Arc<crate::tls::profile_provider::ProfileProvider>,
}
impl ProviderHandler {
    pub(super) fn new(
        expected: Expected,
        provider: std::sync::Arc<crate::tls::profile_provider::ProfileProvider>,
    ) -> Self {
        Self {
            decoder: ProbeHandler::new(expected, provider.clock()),
            provider,
        }
    }
}
#[async_trait::async_trait]
impl RawHandler for ProviderHandler {
    fn handle(
        &self,
        _state: &mut State,
        _res: DeltaDiscoveryResponse,
    ) -> Result<(), Vec<RejectedConfig>> {
        Err(vec![RejectedConfig::new(
            ISSUER_PROFILE_TYPE,
            anyhow::anyhow!("native durable handler requires its asynchronous commit path"),
        )])
    }
    async fn handle_async(
        &self,
        state: &mut State,
        res: DeltaDiscoveryResponse,
    ) -> Result<(), Vec<RejectedConfig>> {
        let name = res
            .resources
            .first()
            .map(|r| strng::new(&r.name))
            .unwrap_or(ISSUER_PROFILE_TYPE);
        let version = res
            .resources
            .first()
            .map(|r| strng::new(&r.version))
            .unwrap_or_default();
        let session = self.provider.session_generation();
        let decoded = self
            .provider
            .verifier_now()
            .and_then(|now| self.decoder.decode_at(&res, now));
        let result = match decoded {
            Err(error) => Err(error),
            Ok(decoded) => {
                let provider = self.provider.clone();
                match tokio::task::spawn_blocking(move || {
                    provider.commit_for_session(decoded, session)
                })
                .await
                {
                    Ok(result) => result,
                    Err(error) => Err(anyhow::anyhow!(
                        "native profile commit worker failed: {error}"
                    )),
                }
            }
        };
        match result {
            Ok(()) => {
                state.add_resource(ISSUER_PROFILE_TYPE, name, version);
                Ok(())
            }
            Err(error) => {
                self.provider.fail_closed_for_session(session);
                Err(vec![RejectedConfig::new(name, error)])
            }
        }
    }
    fn clear(&self, state: &mut State, type_url: &Strng) -> Result<(), Vec<RejectedConfig>> {
        self.provider.reset_session();
        state.known_resources.remove(type_url);
        Ok(())
    }
}
pub(crate) fn configured_expected(config: &Config) -> Result<Option<Expected>> {
    load_config(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pin_json_rejects_aliases_duplicates_and_noncanonical_floors() {
        for body in [
            br#"{"cluster":"a","cluster":"b"}"#.as_slice(),
            br#"{"Cluster":"a"}"#.as_slice(),
            br#"{} {}"#.as_slice(),
        ] {
            assert!(decode_pins(body).is_err());
        }
        assert!(positive("01").is_err());
        assert!(positive("0").is_err());
        assert!(positive("-1").is_err());
        assert_eq!(positive("18446744073709551615").unwrap(), u64::MAX);
    }
    #[test]
    fn configured_probe_rejects_plaintext_system_roots_and_unfenced_modes() {
        for case in [
            "http",
            "unix",
            "system-roots",
            "alt-name",
            "inbound-open",
            "egress-open",
            "local-config",
        ] {
            let mut config = crate::test_helpers::test_config();
            config.issuer_profile_probe_pins = Some("/unopened-probe-pins.json".into());
            config.require_inbound_mtls = true;
            config.require_mesh_hbone = true;
            config.xds_on_demand = false;
            config.local_xds_config = None;
            config.xds_address = Some("https://localhost:15012".into());
            config.xds_root_cert = RootCert::File("/unopened-explicit-root.pem".into());
            config.alt_xds_hostname = None;
            match case {
                "http" => config.xds_address = Some("http://localhost:15012".into()),
                "unix" => config.xds_address = Some("unix:///run/unverified.sock".into()),
                "system-roots" => config.xds_root_cert = RootCert::Default,
                "alt-name" => config.alt_xds_hostname = Some("another-server".into()),
                "inbound-open" => config.require_inbound_mtls = false,
                "egress-open" => config.require_mesh_hbone = false,
                _ => {
                    config.local_xds_config =
                        Some(crate::config::ConfigSource::Static(bytes::Bytes::new()))
                }
            }
            let error = load_config(&config)
                .err()
                .expect("unsafe transport mode must fail");
            assert!(
                !error.to_string().contains("No such file"),
                "must reject {case} before reading pins: {error}"
            );
        }
    }

    #[test]
    fn pins_fifo_is_rejected_without_waiting_for_a_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins-fifo");
        let raw = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
        let reader_path = path.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut config = crate::test_helpers::test_config();
            config.issuer_profile_probe_pins = Some(reader_path);
            config.require_inbound_mtls = true;
            config.require_mesh_hbone = true;
            config.xds_on_demand = false;
            config.local_xds_config = None;
            config.xds_address = Some("https://localhost:15012".into());
            config.xds_root_cert = RootCert::File("/unopened-explicit-root.pem".into());
            config.alt_xds_hostname = None;
            tx.send(load_config(&config).err().map(|e| e.to_string()))
                .unwrap();
        });
        match rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(Some(error)) => {
                worker.join().unwrap();
                assert!(
                    error.contains("regular"),
                    "unexpected pins refusal: {error}"
                );
            }
            Ok(None) => {
                worker.join().unwrap();
                panic!("FIFO was accepted as a pins file");
            }
            Err(error) => {
                // Release a legacy blocking reader before failing the test.
                let writer = OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&path)
                    .unwrap();
                rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap();
                drop(writer);
                worker.join().unwrap();
                panic!("pins read waited for a FIFO writer: {error}");
            }
        }
    }
}
