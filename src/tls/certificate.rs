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

use crate::identity::Identity;
use crate::tls::{Error, IdentityVerifier, OutboundConnector};
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use itertools::Itertools;
use std::{cmp, iter};
use x509_parser::asn1_rs::FromDer;

use rustls::client::Resumption;
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, CommonState, RootCertStore, ServerConfig};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::tls;
use x509_parser::certificate::X509Certificate;
use x509_parser::error::X509Result;

#[derive(Clone, Debug)]
pub struct Certificate {
    pub expiry: Expiration,
    pub der: CertificateDer<'static>,
}

#[derive(Clone, Debug)]
pub struct Expiration {
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

#[derive(Debug)]
pub struct WorkloadCertificate {
    /// cert is the leaf certificate
    pub cert: Certificate,
    /// chain is the entire trust chain, excluding the leaf and root
    pub chain: Vec<Certificate>,
    pub private_key: PrivateKeyDer<'static>,

    /// precomputed roots. This is used for verification
    root_store: Arc<RootCertStore>,
    /// original roots, used for debugging
    pub roots: Vec<Certificate>,
}

// Explicitly disable stateless resumption for both TLS1.2 and TLS1.3. Do not
// inherit a future rustls/provider ticket default in this security boundary.
#[derive(Debug)]
struct NoPinnedSessionTickets;

impl rustls::server::ProducesTickets for NoPinnedSessionTickets {
    fn enabled(&self) -> bool {
        false
    }
    fn lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

pub fn certificate_from_connection(conn: &CommonState) -> X509Result<'_, X509Certificate<'_>> {
    use x509_parser::prelude::*;
    conn.peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or(X509Error::InvalidCertificate.into())
        .and_then(|cert| {
            X509Certificate::from_der(cert).inspect_err(|e| warn!("invalid certificate: {e}"))
        })
}

pub fn identity(result: &X509Result<X509Certificate>) -> Option<Identity> {
    result
        .as_ref()
        .map_or(None, |(_, cert)| match identities(cert) {
            Ok(ids) => ids.into_iter().next(),
            Err(e) => {
                warn!("failed to extract identity: {}", e);
                None
            }
        })
}

pub fn identities(cert: &X509Certificate) -> Result<Vec<Identity>, Error> {
    use x509_parser::prelude::*;
    let names = cert
        .subject_alternative_name()?
        .map(|x| &x.value.general_names);

    if let Some(names) = names {
        return Ok(names
            .iter()
            .filter_map(|n| {
                let id = match n {
                    GeneralName::URI(uri) => Identity::from_str(uri),
                    _ => return None,
                };

                match id {
                    Ok(id) => Some(id),
                    Err(err) => {
                        warn!("SAN {n} could not be parsed: {err}");
                        None
                    }
                }
            })
            .collect());
    }
    Ok(Vec::default())
}

impl Certificate {
    // TODO: I would love to parse this once, but ran into lifetime issues.
    fn parsed(&self) -> X509Certificate<'_> {
        x509_parser::parse_x509_certificate(&self.der)
            .expect("certificate was already parsed successfully before")
            .1
    }

    pub fn as_pem(&self) -> String {
        der_to_pem(&self.der, CERTIFICATE)
    }

    pub fn identity(&self) -> Option<Identity> {
        self.parsed()
            .subject_alternative_name()
            .ok()
            .flatten()
            .and_then(|ext| {
                ext.value
                    .general_names
                    .iter()
                    .filter_map(|n| match n {
                        x509_parser::extensions::GeneralName::URI(uri) => Some(uri),
                        _ => None,
                    })
                    .next()
            })
            .and_then(|san| Identity::from_str(san).ok())
    }

    #[cfg(test)]
    pub fn names(&self) -> Vec<String> {
        let reg = oid_registry::OidRegistry::default().with_x509();

        self.parsed()
            .subject
            .iter()
            .flat_map(|dn| {
                dn.iter().map(|x| {
                    reg.get(x.attr_type()).unwrap().sn().to_string() + "/" + x.as_str().unwrap()
                })
            })
            .chain(
                self.parsed()
                    .subject_alternative_name()
                    .ok()
                    .flatten()
                    .iter()
                    .flat_map(|ext| ext.value.general_names.iter().map(|n| n.to_string())),
            )
            .collect()
    }

    pub fn serial(&self) -> String {
        self.parsed().serial.to_string()
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn serial_bytes(&self) -> Vec<u8> {
        self.parsed().tbs_certificate.raw_serial().to_vec()
    }

    pub fn expiration(&self) -> Expiration {
        self.expiry.clone()
    }
}

fn expiration(cert: X509Certificate) -> Expiration {
    Expiration {
        not_before: UNIX_EPOCH
            + Duration::from_secs(
                cert.validity
                    .not_before
                    .timestamp()
                    .try_into()
                    .unwrap_or_default(),
            ),
        not_after: UNIX_EPOCH
            + Duration::from_secs(
                cert.validity
                    .not_after
                    .timestamp()
                    .try_into()
                    .unwrap_or_default(),
            ),
    }
}

pub fn parse_cert(cert: Vec<u8>) -> Result<Certificate, Error> {
    let der = CertificateDer::from_pem_slice(&cert)
        .map_err(|e| Error::CertificateParseError(format!("no certificate: {e}")))?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der)?;
    let expiry = expiration(parsed);
    Ok(Certificate { der, expiry })
}

fn parse_cert_multi(cert: &[u8]) -> Result<Vec<Certificate>, Error> {
    // Iterate over all recognised sections (not just certificates) so that unexpected content,
    // such as a private key in a root bundle, is rejected rather than silently skipped.
    <(SectionKind, Vec<u8>)>::pem_slice_iter(cert)
        .map(|p| {
            let (kind, der) =
                p.map_err(|e| Error::CertificateParseError(format!("invalid certificate: {e}")))?;
            if kind != SectionKind::Certificate {
                return Err(Error::CertificateParseError(format!(
                    "unexpected PEM section in certificate bundle: {kind:?}"
                )));
            }
            let der = CertificateDer::from(der);
            let (_, parsed) = x509_parser::parse_x509_certificate(&der)?;
            let expiry = expiration(parsed);
            Ok(Certificate { der, expiry })
        })
        .collect()
}

fn parse_key(key: &[u8]) -> Result<PrivateKeyDer<'static>, Error> {
    PrivatePkcs8KeyDer::from_pem_slice(key)
        .map(PrivateKeyDer::Pkcs8)
        .map_err(|e| Error::CertificateParseError(format!("no PKCS#8 private key: {e}")))
}

impl WorkloadCertificate {
    pub fn new(key: &[u8], cert: &[u8], chain: Vec<&[u8]>) -> Result<WorkloadCertificate, Error> {
        let cert = parse_cert(cert.to_vec())?;

        // The Istio API does something pretty unhelpful, by providing a single chain of certs.
        // The last one is the root. However, there may be multiple roots concatenated in that last cert,
        // so we will need to split them.
        let Some(raw_root) = chain.last() else {
            return Err(Error::InvalidRootCert(
                "no root certificate present".to_string(),
            ));
        };
        let roots = parse_cert_multi(raw_root)?;
        let chain = chain[..cmp::max(0, chain.len() - 1)]
            .iter()
            .map(|x| x.to_vec())
            .map(parse_cert)
            .collect::<Result<Vec<_>, _>>()?;
        let key: PrivateKeyDer = parse_key(key)?;

        let mut roots_store = RootCertStore::empty();
        let (_valid, invalid) =
            roots_store.add_parsable_certificates(roots.iter().map(|c| c.der.clone()));
        if invalid > 0 {
            tracing::warn!("warning: found {invalid} invalid root certs");
        }
        Ok(WorkloadCertificate {
            cert,
            chain,
            private_key: key,
            roots,
            root_store: Arc::new(roots_store),
        })
    }

    pub fn new_svid(
        svid: &spiffe::X509Svid,
        bundle: &[spiffe::cert::Certificate],
    ) -> Result<WorkloadCertificate, Error> {
        let leaf = svid.leaf();
        let chain = svid
            .cert_chain()
            .iter()
            .map(|c| {
                let (_, cert) = x509_parser::parse_x509_certificate(c.content()).unwrap();
                Certificate {
                    der: c.content().to_vec().into(),
                    expiry: expiration(cert),
                }
            })
            .collect::<Vec<_>>();

        let cert = X509Certificate::from_der(leaf.content()).unwrap();
        let cert = Certificate {
            der: leaf.content().to_vec().into(),
            expiry: expiration(cert.1),
        };

        let private_key = PrivateKeyDer::Pkcs8(svid.private_key().content().to_vec().into());

        let roots = bundle
            .iter()
            .map(|c| {
                let (_, cert) = x509_parser::parse_x509_certificate(c.content()).unwrap();
                Certificate {
                    der: c.content().to_vec().into(),
                    expiry: expiration(cert),
                }
            })
            .collect::<Vec<_>>();

        let mut roots_store = RootCertStore::empty();

        let (_valid, invalid) = roots_store
            .add_parsable_certificates(bundle.iter().map(|c| c.content().to_vec().into()));
        if invalid > 0 {
            tracing::warn!("warning: found {invalid} invalid root certs");
        }

        Ok(WorkloadCertificate {
            cert,
            private_key,
            roots,
            root_store: Arc::new(roots_store),
            chain,
        })
    }

    pub fn identity(&self) -> Option<Identity> {
        self.cert.identity()
    }

    /// The trust anchors this certificate chains to. Used to re-run the shared webpki
    /// chain-validation path ([`crate::tls::revocation::verify_cert_chain`]) against a peer chain
    /// captured at handshake time, e.g. to re-check CRL revocation on an existing connection.
    pub fn root_store(&self) -> Arc<RootCertStore> {
        self.root_store.clone()
    }

    // TODO: can we precompute some or all of this?

    pub(in crate::tls) fn cert_and_intermediates_der(&self) -> Vec<CertificateDer<'static>> {
        std::iter::once(self.cert.der.clone())
            .chain(self.chain.iter().map(|x| x.der.clone()))
            .collect()
    }

    pub fn cert_and_intermediates(&self) -> Vec<Certificate> {
        std::iter::once(self.cert.clone())
            .chain(self.chain.clone())
            .collect()
    }

    pub fn full_chain_and_roots(&self) -> Vec<String> {
        self.cert_and_intermediates()
            .into_iter()
            .map(|c| c.as_pem())
            .chain(iter::once(self.roots.iter().map(|c| c.as_pem()).join("\n")))
            .collect()
    }

    pub fn server_config(
        &self,
        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    ) -> Result<ServerConfig, Error> {
        let td = self.cert.identity().map(|i| match i {
            Identity::Spiffe { trust_domain, .. } => trust_domain,
        });

        // build the base client cert verifier with optional CRL support
        let mut builder = WebPkiClientVerifier::builder_with_provider(
            self.root_store.clone(),
            crate::tls::lib::provider(),
        );

        // add CRLs if available
        if let Some(ref mgr) = crl_manager {
            let crls = mgr.get_crl_ders();
            if !crls.is_empty() {
                builder = builder
                    .with_crls(crls.iter().cloned())
                    .allow_unknown_revocation_status(); // fail-open for unknown status
            }
        }

        // TODO: check if our own certificate is revoked in the CRL and log warning
        let raw_client_cert_verifier = builder.build()?;

        let client_cert_verifier =
            crate::tls::workload::TrustDomainVerifier::new(raw_client_cert_verifier, td);
        let mut sc = ServerConfig::builder_with_provider(crate::tls::lib::provider())
            .with_protocol_versions(tls::tls_versions())
            .expect("server config must be valid")
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(
                self.cert_and_intermediates_der(),
                self.private_key.clone_key(),
            )?;
        sc.alpn_protocols = vec![b"h2".into()];
        Ok(sc)
    }

    pub fn client_config(
        &self,
        identity: Vec<Identity>,
        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    ) -> Result<ClientConfig, rustls::Error> {
        let roots = self.root_store.clone();
        let verifier = IdentityVerifier {
            roots,
            identity,
            crl_manager,
        };
        let mut cc = ClientConfig::builder_with_provider(crate::tls::lib::provider())
            .with_protocol_versions(tls::tls_versions())
            .expect("client config must be valid")
            .dangerous() // Customer verifier is requires "dangerous" opt-in
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(
                self.cert_and_intermediates_der(),
                self.private_key.clone_key(),
            )?;
        cc.alpn_protocols = vec![b"h2".into()];
        cc.resumption = Resumption::disabled();
        cc.enable_sni = false;
        Ok(cc)
    }

    pub fn outbound_connector(
        &self,
        identity: Vec<Identity>,
        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    ) -> Result<OutboundConnector, Error> {
        let cc = self.client_config(identity, crl_manager)?;
        Ok(OutboundConnector {
            client_config: Arc::new(cc),
        })
    }

    /// Builds an inbound mTLS config against the explicitly published
    /// trust-domain issuer pins. The local SPIRE roots are not used to verify peers.
    pub fn pinned_server_config(
        &self,
        publication: Arc<crate::tls::domain_anchors::AnchorPublication>,
        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    ) -> Result<ServerConfig, Error> {
        let client_verifier = crate::tls::PinnedTrustDomainVerifier::new(publication, crl_manager);
        let mut config = ServerConfig::builder_with_provider(crate::tls::lib::provider())
            .with_protocol_versions(tls::tls_versions())
            .expect("server config protocol versions must be valid")
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                self.cert_and_intermediates_der(),
                self.private_key.clone_key(),
            )?;
        config.alpn_protocols = vec![b"h2".into()];
        // Every inbound connection must execute the current pin, time, client
        // certificate and CRL verification. An independent client may resume
        // even though our outbound helper disables its own session cache.
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.ticketer = Arc::new(NoPinnedSessionTickets);
        config.send_tls13_tickets = 0;
        config.max_tls13_tickets = 0;
        config.max_early_data_size = 0;
        Ok(config)
    }

    /// Builds an outbound mTLS config against explicit peer issuer pins and
    /// exact expected SPIFFE identities. The local SPIRE roots are not a fallback.
    pub fn pinned_client_config(
        &self,
        identities: Vec<Identity>,
        publication: Arc<crate::tls::domain_anchors::AnchorPublication>,
        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    ) -> Result<ClientConfig, rustls::Error> {
        let verifier =
            crate::tls::PinnedIdentityVerifier::new(publication, identities, crl_manager);
        let mut config = ClientConfig::builder_with_provider(crate::tls::lib::provider())
            .with_protocol_versions(tls::tls_versions())
            .expect("client config protocol versions must be valid")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(
                self.cert_and_intermediates_der(),
                self.private_key.clone_key(),
            )?;
        config.alpn_protocols = vec![b"h2".into()];
        config.resumption = Resumption::disabled();
        config.enable_sni = false;
        Ok(config)
    }

    pub fn dump_chain(&self) -> Bytes {
        self.chain.iter().map(|c| c.as_pem()).join("\n").into()
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.cert.expiry.not_after
    }

    pub fn refresh_at(&self) -> SystemTime {
        let expiry = &self.cert.expiry;
        match expiry.not_after.duration_since(expiry.not_before) {
            Ok(valid_for) => expiry.not_before + valid_for / 2,
            Err(_) => expiry.not_after,
        }
    }

    pub fn get_duration_until_refresh(&self) -> Duration {
        let expiry = &self.cert.expiry;
        let halflife = expiry
            .not_after
            .duration_since(expiry.not_before)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            / 2;
        // If now() is earlier than not_before, we need to refresh ASAP, so return 0.
        let elapsed = SystemTime::now()
            .duration_since(expiry.not_before)
            .unwrap_or(halflife);
        halflife
            .checked_sub(elapsed)
            .unwrap_or_else(|| Duration::from_secs(0))
    }
}

const CERTIFICATE: &str = "CERTIFICATE";

/// Converts DER encoded data to PEM.
fn der_to_pem(der: &[u8], label: &str) -> String {
    use base64::Engine;
    let mut ans = String::from("-----BEGIN ");
    ans.push_str(label);
    ans.push_str("-----\n");
    let b64 = STANDARD.encode(der);
    let line_length = 60;
    for chunk in b64.chars().collect::<Vec<_>>().chunks(line_length) {
        ans.extend(chunk);
        ans.push('\n');
    }
    ans.push_str("-----END ");
    ans.push_str(label);
    ans.push_str("-----\n");
    ans
}

#[cfg(test)]
mod test {
    use crate::identity::Identity;
    use crate::test_helpers::helpers;
    use crate::tls::domain_anchors::AnchorError;
    use crate::tls::mock::{
        TEST_ROOT, TEST_ROOT_KEY, TEST_ROOT2, TEST_ROOT2_KEY, TestIdentity, crl_pem_revoking_cert,
        generate_intermediate_ca,
    };
    use crate::tls::{WorkloadCertificate, io_error_is_cert_revoked};

    use std::io::Write;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::SystemTime;
    use tempfile::NamedTempFile;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsAcceptor;

    use super::{parse_cert, parse_cert_multi, parse_key};

    fn parse_err(r: Result<impl std::fmt::Debug, crate::tls::Error>) -> String {
        match r.unwrap_err() {
            crate::tls::Error::CertificateParseError(s) => s,
            e => panic!("unexpected error variant: {e:?}"),
        }
    }

    #[test]
    fn parse_cert_empty() {
        let e = parse_err(parse_cert(vec![]));
        assert!(
            e.starts_with("no certificate:") && e.contains("no items found"),
            "{e}"
        );
    }

    #[test]
    fn parse_cert_key_only() {
        let (key, _) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(Identity::from_str("spiffe://td/ns/n/sa/a").unwrap()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(60),
            None,
            TEST_ROOT_KEY,
        );
        let e = parse_err(parse_cert(key.into_bytes()));
        assert!(e.contains("no items found"), "{e}");
    }

    #[test]
    fn parse_cert_truncated() {
        let truncated = &TEST_ROOT[..TEST_ROOT.len() / 2];
        let e = parse_err(parse_cert(truncated.to_vec()));
        assert!(e.starts_with("no certificate:"), "{e}");
    }

    #[test]
    fn parse_cert_multi_empty_and_truncated() {
        assert!(parse_cert_multi(b"").unwrap().is_empty());
        let e = parse_err(parse_cert_multi(&TEST_ROOT[..TEST_ROOT.len() / 2]));
        assert!(e.starts_with("invalid certificate:"), "{e}");
    }

    #[test]
    fn parse_cert_multi_rejects_non_cert_sections() {
        let (key, _) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(Identity::from_str("spiffe://td/ns/n/sa/a").unwrap()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(60),
            None,
            TEST_ROOT_KEY,
        );
        let mut bundle = TEST_ROOT.to_vec();
        bundle.push(b'\n');
        bundle.extend(key.as_bytes());
        let e = parse_err(parse_cert_multi(&bundle));
        assert!(e.contains("unexpected PEM section"), "{e}");
        // Multiple certificates are still fine.
        let mut ok = TEST_ROOT.to_vec();
        ok.push(b'\n');
        ok.extend(TEST_ROOT2);
        assert_eq!(parse_cert_multi(&ok).unwrap().len(), 2);
    }

    #[test]
    fn parse_key_errors() {
        let e = parse_err(parse_key(b""));
        assert!(
            e.starts_with("no PKCS#8 private key:") && e.contains("no items found"),
            "{e}"
        );
        // A certificate is not a key.
        let e = parse_err(parse_key(TEST_ROOT));
        assert!(e.contains("no items found"), "{e}");
        // RSA (non-PKCS#8) keys are not accepted.
        let rsa = b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        let e = parse_err(parse_key(rsa));
        assert!(e.contains("no items found"), "{e}");
    }

    #[test]
    fn parse_key_ok() {
        let (key, _) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(Identity::from_str("spiffe://td/ns/n/sa/a").unwrap()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(60),
            None,
            TEST_ROOT_KEY,
        );
        assert!(parse_key(key.as_bytes()).is_ok());
    }

    #[tokio::test]
    async fn multi_root() {
        helpers::initialize_telemetry();
        let id = Identity::from_str("spiffe://td/ns/n/sa/a").unwrap();
        // Joined root
        let mut joined = TEST_ROOT.to_vec();
        joined.push(b'\n');
        joined.extend(TEST_ROOT2);

        // Generate key+cert signed by root1
        let (key, cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(60),
            None,
            TEST_ROOT_KEY,
        );
        let cert1 =
            WorkloadCertificate::new(key.as_bytes(), cert.as_bytes(), vec![&joined]).unwrap();

        // Generate key+cert signed by root2
        let (key, cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(60),
            None,
            TEST_ROOT2_KEY,
        );
        let cert2 =
            WorkloadCertificate::new(key.as_bytes(), cert.as_bytes(), vec![&joined]).unwrap();

        // Do a simple handshake between them; we should be able to accept the trusted root
        let server = cert1.server_config(None).unwrap();
        let tls = TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::task::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = tls.accept(stream).await.unwrap();
            let _ = tls.write(b"serv").await.unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let client = cert2.outbound_connector(vec![id], None).unwrap();
        let mut tls = client.connect(stream).await.unwrap();

        let _ = tls.write(b"hi").await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"serv");
    }

    /// Outbound client must abort TLS when the peer's leaf cert appears in the loaded CRL (i.e. is revoked).
    #[tokio::test]
    async fn outbound_rejects_revoked_server_cert() {
        helpers::initialize_telemetry();

        let id = Identity::from_str("spiffe://td/ns/n/sa/a").unwrap();

        // Generate server key+cert signed by root
        let (server_key, server_cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(3600),
            None,
            TEST_ROOT_KEY,
        );
        let server_wl = WorkloadCertificate::new(
            server_key.as_bytes(),
            server_cert.as_bytes(),
            vec![TEST_ROOT],
        )
        .unwrap();

        // Generate client key+cert signed by root
        let (client_key, client_cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(3600),
            None,
            TEST_ROOT_KEY,
        );
        let client_wl = WorkloadCertificate::new(
            client_key.as_bytes(),
            client_cert.as_bytes(),
            vec![TEST_ROOT],
        )
        .unwrap();

        // Generate CRL that revokes the server cert
        let crl_pem = crl_pem_revoking_cert(&server_wl.cert.serial_bytes());

        let mut crl_file = NamedTempFile::new().unwrap();
        crl_file.write_all(crl_pem.as_bytes()).unwrap();
        crl_file.flush().unwrap();

        // Create CRL manager to load the CRL from file path
        let crl_mgr = Arc::new(
            crate::tls::crl::CrlManager::new(
                crl_file.path().to_path_buf(),
                crate::test_helpers::helpers::test_proxy_metrics(),
            )
            .unwrap(),
        );

        // Create TLS server to listen for incoming connections
        let server_tls = TlsAcceptor::from(Arc::new(server_wl.server_config(None).unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::task::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = server_tls.accept(stream).await;
        });

        // Create outbound connector to connect to the TLS server
        // we expect the connection to fail because the CRL is enforced and the server cert is revoked
        let stream = TcpStream::connect(addr).await.unwrap();
        let connector = client_wl
            .outbound_connector(vec![id.clone()], Some(crl_mgr))
            .unwrap();
        let err = connector
            .connect(stream)
            .await
            .expect_err("connection should fail: server cert is revoked");
        assert!(io_error_is_cert_revoked(&err));
    }

    /// Outbound client must abort TLS when the peer's IA cert appears in the loaded CRL (i.e. is revoked).
    /// Validates that full cert chain is checked, not just the EE cert.
    #[tokio::test]
    async fn outbound_rejects_revoked_intermediate_cert() {
        helpers::initialize_telemetry();

        let id = Identity::from_str("spiffe://td/ns/n/sa/a").unwrap();

        // Generate IA signed by TEST_ROOT and a leaf signed by the IA
        let (ia_key, ia_cert, ia_serial_bytes) = generate_intermediate_ca(TEST_ROOT_KEY);
        let (server_key, server_cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(3600),
            None,
            ia_key.as_bytes(),
        );
        // Generate server workload certificate with the full chain: leaf cert signed by IA, IA cert, TEST_ROOT as trust anchor
        let server_wl = WorkloadCertificate::new(
            server_key.as_bytes(),
            server_cert.as_bytes(),
            vec![ia_cert.as_bytes(), TEST_ROOT],
        )
        .unwrap();

        // Client uses a direct root-signed cert — not revoked by the CRL
        let (client_key, client_cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(3600),
            None,
            TEST_ROOT_KEY,
        );
        let client_wl = WorkloadCertificate::new(
            client_key.as_bytes(),
            client_cert.as_bytes(),
            vec![TEST_ROOT],
        )
        .unwrap();

        // CRL signed by TEST_ROOT that revokes the IA — not the leaf cert
        let crl_pem = crl_pem_revoking_cert(&ia_serial_bytes);

        let mut crl_file = NamedTempFile::new().unwrap();
        crl_file.write_all(crl_pem.as_bytes()).unwrap();
        crl_file.flush().unwrap();

        let crl_mgr = Arc::new(
            crate::tls::crl::CrlManager::new(
                crl_file.path().to_path_buf(),
                crate::test_helpers::helpers::test_proxy_metrics(),
            )
            .unwrap(),
        );

        let server_tls = TlsAcceptor::from(Arc::new(server_wl.server_config(None).unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::task::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = server_tls.accept(stream).await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let connector = client_wl
            .outbound_connector(vec![id.clone()], Some(crl_mgr))
            .unwrap();
        let err = connector
            .connect(stream)
            .await
            .expect_err("connection should fail: intermediate cert is revoked");
        assert!(io_error_is_cert_revoked(&err));
    }

    type TestIssuer = rcgen::CertifiedIssuer<'static, rcgen::KeyPair>;

    const URI_A: &str = "spiffe://cmtc-a.mesh.example/ns/orders/sa/api";
    const URI_B: &str = "spiffe://cmtc-b.mesh.example/ns/orders/sa/api";
    const URI_C: &str = "spiffe://cmtc-c.mesh.example/ns/orders/sa/api";
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

    fn ca_params(name: &str) -> rcgen::CertificateParams {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyUsagePurpose};

        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        params
    }

    fn issuer(name: &str) -> TestIssuer {
        rcgen::CertifiedIssuer::self_signed(ca_params(name), rcgen::KeyPair::generate().unwrap())
            .unwrap()
    }

    fn issued(name: &str, parent: &TestIssuer) -> TestIssuer {
        rcgen::CertifiedIssuer::signed_by(
            ca_params(name),
            rcgen::KeyPair::generate().unwrap(),
            parent,
        )
        .unwrap()
    }

    fn leaf_with(
        uris: &[&str],
        signer: &TestIssuer,
        serial: u64,
        usages: &[rcgen::ExtendedKeyUsagePurpose],
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) -> (rcgen::KeyPair, rcgen::Certificate) {
        use rcgen::{CertificateParams, IsCa, KeyPair, KeyUsagePurpose, SanType, SerialNumber};

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = usages.to_vec();
        params.serial_number = Some(SerialNumber::from(serial));
        params.not_before = not_before;
        params.not_after = not_after;
        params.subject_alt_names = uris
            .iter()
            .map(|uri| SanType::URI(rcgen::string::Ia5String::try_from(uri.to_string()).unwrap()))
            .collect();
        let cert = params.signed_by(&key, &**signer).unwrap();
        (key, cert)
    }

    fn leaf(
        uris: &[&str],
        signer: &TestIssuer,
        serial: u64,
        usages: &[rcgen::ExtendedKeyUsagePurpose],
    ) -> (rcgen::KeyPair, rcgen::Certificate) {
        let now = time::OffsetDateTime::now_utc();
        leaf_with(
            uris,
            signer,
            serial,
            usages,
            now - time::Duration::days(1),
            now + time::Duration::days(30),
        )
    }

    fn workload(
        key: &rcgen::KeyPair,
        cert: &rcgen::Certificate,
        unused_root: &TestIssuer,
    ) -> WorkloadCertificate {
        let root_pem = unused_root.pem();
        WorkloadCertificate::new(
            key.serialize_pem().as_bytes(),
            cert.pem().as_bytes(),
            vec![root_pem.as_bytes()],
        )
        .unwrap()
    }

    fn publication_of(
        root: &TestIssuer,
        a: &TestIssuer,
        b: &TestIssuer,
    ) -> Arc<crate::tls::domain_anchors::AnchorPublication> {
        use crate::tls::domain_anchors::{
            AnchorPublication, DomainAnchorSet, pin_from_certificate,
        };

        let set = DomainAnchorSet::try_new(
            "cmtc-a.mesh.example".into(),
            root.der().clone(),
            1,
            vec![
                pin_from_certificate("cmtc-a.mesh.example".into(), a.der().clone()).unwrap(),
                pin_from_certificate("cmtc-b.mesh.example".into(), b.der().clone()).unwrap(),
            ],
        )
        .unwrap();
        Arc::new(AnchorPublication::initial(set))
    }

    fn error_text(error: &std::io::Error) -> String {
        let mut text = format!("{error} {error:?}");
        let mut source = std::error::Error::source(error);
        while let Some(item) = source {
            text.push_str(&format!(" {item} {item:?}"));
            source = std::error::Error::source(item);
        }
        text
    }

    fn anchor_error(error: &std::io::Error) -> &AnchorError {
        let tls = error
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<rustls::Error>())
            .expect("I/O error must retain the actual rustls verifier error");
        let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
            cause,
        ))) = tls
        else {
            panic!("expected a typed issuer/identity verifier error, got {tls:?}");
        };
        cause
            .downcast_ref::<AnchorError>()
            .expect("typed anchor error")
    }

    fn server_name() -> rustls::pki_types::ServerName<'static> {
        rustls::pki_types::ServerName::IpAddress(std::net::Ipv4Addr::new(0, 0, 0, 0).into())
    }

    fn no_client_auth_config(
        publication: Arc<crate::tls::domain_anchors::AnchorPublication>,
        expected_server: Identity,
    ) -> rustls::ClientConfig {
        let verifier =
            crate::tls::PinnedIdentityVerifier::new(publication, vec![expected_server], None);
        let mut config = rustls::ClientConfig::builder_with_provider(crate::tls::lib::provider())
            .with_protocol_versions(crate::tls::tls_versions())
            .expect("client config protocol versions must be valid")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".into()];
        config
    }

    async fn exchange(
        server: WorkloadCertificate,
        client: WorkloadCertificate,
        publication: Arc<crate::tls::domain_anchors::AnchorPublication>,
        expected_server: Identity,
        server_crl: Option<Arc<crate::tls::crl::CrlManager>>,
        client_crl: Option<Arc<crate::tls::crl::CrlManager>>,
    ) -> (Identity, Identity) {
        helpers::initialize_telemetry();
        let server_config = server
            .pinned_server_config(publication.clone(), server_crl)
            .unwrap();
        let client_config = client
            .pinned_client_config(vec![expected_server], publication, client_crl)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server_task = async move {
            let (stream, _) = listener.accept().await?;
            let mut tls = acceptor.accept(stream).await?;
            let (_, state) = tls.get_ref();
            let client_identity =
                crate::tls::identity(&crate::tls::certificate_from_connection(state))
                    .ok_or_else(|| std::io::Error::other("missing client identity"))?;
            let mut request = [0; 2];
            tls.read_exact(&mut request).await?;
            if &request != b"hi" {
                return Err(std::io::Error::other("client payload mismatch"));
            }
            tls.write_all(b"serv").await?;
            Ok::<Identity, std::io::Error>(client_identity)
        };

        let client_task = async move {
            let stream = TcpStream::connect(address).await?;
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client_config))
                .connect(server_name(), stream)
                .await?;
            tls.write_all(b"hi").await?;
            let mut response = [0; 4];
            tls.read_exact(&mut response).await?;
            if &response != b"serv" {
                return Err(std::io::Error::other("server payload mismatch"));
            }
            let (_, state) = tls.get_ref();
            crate::tls::identity(&crate::tls::certificate_from_connection(state))
                .ok_or_else(|| std::io::Error::other("missing server identity"))
        };

        let (server_result, client_result) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            tokio::join!(server_task, client_task)
        })
        .await
        .expect("both TLS handshake tasks must finish");
        let client_identity = client_result.unwrap();
        let server_identity = server_result.unwrap();
        (server_identity, client_identity)
    }

    async fn client_rejection(
        server: WorkloadCertificate,
        client: WorkloadCertificate,
        publication: Arc<crate::tls::domain_anchors::AnchorPublication>,
        expected_server: Identity,
        server_crl: Option<Arc<crate::tls::crl::CrlManager>>,
        client_crl: Option<Arc<crate::tls::crl::CrlManager>>,
    ) -> std::io::Error {
        helpers::initialize_telemetry();
        let server_config = server
            .pinned_server_config(publication.clone(), server_crl)
            .unwrap();
        let client_config = client
            .pinned_client_config(vec![expected_server], publication, client_crl)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server_task = async move {
            let (stream, _) = listener.accept().await?;
            match acceptor.accept(stream).await {
                Ok(mut tls) => {
                    let mut request = [0; 2];
                    let _ = tls.read_exact(&mut request).await;
                    let _ = tls.write_all(b"serv").await;
                    Ok::<(), std::io::Error>(())
                }
                Err(error) => Err(error),
            }
        };
        let client_task = async move {
            let stream = TcpStream::connect(address).await?;
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client_config))
                .connect(server_name(), stream)
                .await?;
            tls.write_all(b"hi").await?;
            let mut response = [0; 4];
            tls.read_exact(&mut response).await?;
            Ok::<(), std::io::Error>(())
        };

        let (server_result, client_result) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            tokio::join!(server_task, client_task)
        })
        .await
        .expect("both TLS handshake tasks must finish");
        let _server_result = server_result;
        client_result.expect_err("the outbound verifier must reject this peer")
    }

    async fn server_rejection(
        server: WorkloadCertificate,
        client_config: rustls::ClientConfig,
        publication: Arc<crate::tls::domain_anchors::AnchorPublication>,
        server_crl: Option<Arc<crate::tls::crl::CrlManager>>,
    ) -> std::io::Error {
        helpers::initialize_telemetry();
        let server_config = server
            .pinned_server_config(publication, server_crl)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server_task = async move {
            let (stream, _) = listener.accept().await?;
            let mut tls = acceptor.accept(stream).await?;
            let mut request = [0; 2];
            tls.read_exact(&mut request).await?;
            if &request != b"hi" {
                return Err(std::io::Error::other("client payload mismatch"));
            }
            Ok::<(), std::io::Error>(())
        };
        let client_task = async move {
            let stream = TcpStream::connect(address).await?;
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client_config))
                .connect(server_name(), stream)
                .await?;
            tls.write_all(b"hi").await?;
            Ok::<(), std::io::Error>(())
        };

        let (server_result, client_result) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            tokio::join!(server_task, client_task)
        })
        .await
        .expect("both TLS handshake tasks must finish");
        let _client_result = client_result;
        server_result.expect_err("the inbound verifier must reject this peer")
    }

    fn crl_pem(issuer: &TestIssuer, serials: &[u64]) -> String {
        crl_pem_number(issuer, serials, 1)
    }

    fn crl_pem_number(issuer: &TestIssuer, serials: &[u64], number: u64) -> String {
        use rcgen::{
            CertificateRevocationListParams, KeyIdMethod, RevocationReason, RevokedCertParams,
            SerialNumber,
        };

        let now = time::OffsetDateTime::now_utc();
        CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(30),
            crl_number: SerialNumber::from(number),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|serial| RevokedCertParams {
                    serial_number: SerialNumber::from(*serial),
                    revocation_time: now,
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(issuer)
        .unwrap()
        .pem()
        .unwrap()
    }

    fn write_crl(file: &mut NamedTempFile, pem: &str) {
        use std::io::{Seek, SeekFrom};

        file.as_file_mut().set_len(0).unwrap();
        file.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
        file.write_all(pem.as_bytes()).unwrap();
        file.flush().unwrap();
    }

    fn crl_manager(file: &NamedTempFile) -> Arc<crate::tls::crl::CrlManager> {
        Arc::new(
            crate::tls::crl::CrlManager::new(
                file.path().to_path_buf(),
                helpers::test_proxy_metrics(),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn pinned_loopback_accepts_remote_domain_and_both_application_directions() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
        let (server_key, server_cert) = leaf(&[URI_B], &b, 22, &[ClientAuth, ServerAuth]);

        let (client_identity, server_identity) = exchange(
            workload(&server_key, &server_cert, &b),
            workload(&client_key, &client_cert, &a),
            publication,
            Identity::from_str(URI_B).unwrap(),
            None,
            None,
        )
        .await;
        assert_eq!(client_identity, Identity::from_str(URI_A).unwrap());
        assert_eq!(server_identity, Identity::from_str(URI_B).unwrap());
    }

    #[tokio::test]
    async fn pinned_loopback_rejects_same_root_wrong_server_issuer() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
        let (server_key, server_cert) = leaf(&[URI_A], &b, 44, &[ClientAuth, ServerAuth]);

        let err = client_rejection(
            workload(&server_key, &server_cert, &b),
            workload(&client_key, &client_cert, &a),
            publication,
            Identity::from_str(URI_A).unwrap(),
            None,
            None,
        )
        .await;
        assert_eq!(
            anchor_error(&err),
            &AnchorError::AmbiguousIssuer("cmtc-a.mesh.example".into())
        );
    }

    #[tokio::test]
    async fn pinned_loopback_inbound_rejects_same_root_wrong_client_issuer() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &b, 11, &[ClientAuth, ServerAuth]);
        let (server_key, server_cert) = leaf(&[URI_B], &b, 22, &[ClientAuth, ServerAuth]);
        let client = workload(&client_key, &client_cert, &b);
        let client_config = client
            .pinned_client_config(
                vec![Identity::from_str(URI_B).unwrap()],
                publication.clone(),
                None,
            )
            .unwrap();

        let err = server_rejection(
            workload(&server_key, &server_cert, &b),
            client_config,
            publication,
            None,
        )
        .await;
        assert_eq!(
            anchor_error(&err),
            &AnchorError::AmbiguousIssuer("cmtc-a.mesh.example".into())
        );
    }

    #[tokio::test]
    async fn pinned_loopback_inbound_rejects_client_without_certificate() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (server_key, server_cert) = leaf(&[URI_B], &b, 22, &[ClientAuth, ServerAuth]);

        let err = server_rejection(
            workload(&server_key, &server_cert, &b),
            no_client_auth_config(publication.clone(), Identity::from_str(URI_B).unwrap()),
            publication,
            None,
        )
        .await;
        assert!(matches!(
            err.get_ref()
                .and_then(|cause| cause.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::NoCertificatesPresented)
        ));
    }

    #[tokio::test]
    async fn pinned_loopback_rejects_malformed_server_san() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
        let (server_key, server_cert) = leaf(
            &["spiffe://cmtc-b.mesh.example/not-an-identity"],
            &b,
            22,
            &[ClientAuth, ServerAuth],
        );

        let err = client_rejection(
            workload(&server_key, &server_cert, &b),
            workload(&client_key, &client_cert, &a),
            publication,
            Identity::from_str(URI_B).unwrap(),
            None,
            None,
        )
        .await;
        assert_eq!(anchor_error(&err), &AnchorError::MalformedIdentity);
    }

    #[tokio::test]
    async fn pinned_loopback_rejects_duplicate_server_san() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
        let (server_key, server_cert) = leaf(&[URI_B, URI_A], &b, 22, &[ClientAuth, ServerAuth]);

        let err = client_rejection(
            workload(&server_key, &server_cert, &b),
            workload(&client_key, &client_cert, &a),
            publication,
            Identity::from_str(URI_B).unwrap(),
            None,
            None,
        )
        .await;
        assert_eq!(anchor_error(&err), &AnchorError::PeerIdentityCount(2));
    }

    #[tokio::test]
    async fn pinned_loopback_rejects_unpublished_server_domain() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
        let (server_key, server_cert) = leaf(&[URI_C], &b, 22, &[ClientAuth, ServerAuth]);

        let err = client_rejection(
            workload(&server_key, &server_cert, &b),
            workload(&client_key, &client_cert, &a),
            publication,
            Identity::from_str(URI_C).unwrap(),
            None,
            None,
        )
        .await;
        assert_eq!(
            anchor_error(&err),
            &AnchorError::UntrustedTrustDomain("cmtc-c.mesh.example".into())
        );
    }

    #[tokio::test]
    async fn pinned_loopback_empty_expected_identity_rejects_every_server() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
        let (server_key, server_cert) = leaf(&[URI_B], &b, 22, &[ClientAuth, ServerAuth]);
        let server = workload(&server_key, &server_cert, &b);
        let client = workload(&client_key, &client_cert, &a);
        let server_config = Arc::new(
            server
                .pinned_server_config(publication.clone(), None)
                .unwrap(),
        );
        let client_config = Arc::new(
            client
                .pinned_client_config(Vec::new(), publication, None)
                .unwrap(),
        );
        let (_server_result, client_result) =
            exchange_pinned_configs(server_config, client_config).await;
        let err =
            client_result.expect_err("missing expected identity cannot mean any trusted server");
        assert_eq!(
            anchor_error(&err),
            &AnchorError::UnexpectedPeer {
                authenticated: URI_B.into()
            }
        );
    }

    #[tokio::test]
    async fn pinned_loopback_rejects_wrong_expected_server_identity() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
        let (server_key, server_cert) = leaf(&[URI_B], &b, 22, &[ClientAuth, ServerAuth]);

        let err = client_rejection(
            workload(&server_key, &server_cert, &b),
            workload(&client_key, &client_cert, &a),
            publication,
            Identity::from_str(URI_A).unwrap(),
            None,
            None,
        )
        .await;
        assert_eq!(
            anchor_error(&err),
            &AnchorError::UnexpectedPeer {
                authenticated: URI_B.into()
            }
        );
    }

    #[tokio::test]
    async fn pinned_loopback_rejects_expired_issuer_pin() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let now = time::OffsetDateTime::now_utc();
        let mut params = ca_params("issuer-b-expired");
        params.not_before = now - time::Duration::hours(2);
        params.not_after = now - time::Duration::minutes(1);
        let b =
            rcgen::CertifiedIssuer::signed_by(params, rcgen::KeyPair::generate().unwrap(), &root)
                .unwrap();
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
        let (server_key, server_cert) = leaf(&[URI_B], &b, 22, &[ClientAuth, ServerAuth]);

        let err = client_rejection(
            workload(&server_key, &server_cert, &b),
            workload(&client_key, &client_cert, &a),
            publication,
            Identity::from_str(URI_B).unwrap(),
            None,
            None,
        )
        .await;
        assert_eq!(
            anchor_error(&err),
            &AnchorError::UntrustedTrustDomain("cmtc-b.mesh.example".into())
        );
    }

    #[tokio::test]
    async fn pinned_loopback_rejects_expired_leaf() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
        let now = time::OffsetDateTime::now_utc();
        let (server_key, server_cert) = leaf_with(
            &[URI_B],
            &b,
            22,
            &[ClientAuth, ServerAuth],
            now - time::Duration::hours(2),
            now - time::Duration::minutes(1),
        );

        let err = client_rejection(
            workload(&server_key, &server_cert, &b),
            workload(&client_key, &client_cert, &a),
            publication,
            Identity::from_str(URI_B).unwrap(),
            None,
            None,
        )
        .await;
        assert_eq!(
            anchor_error(&err),
            &AnchorError::UnauthorizedIssuer("cmtc-b.mesh.example".into())
        );
    }

    #[tokio::test]
    async fn pinned_loopback_rejects_server_with_client_only_eku() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
        let (server_key, server_cert) = leaf(&[URI_B], &b, 22, &[ClientAuth]);

        let err = client_rejection(
            workload(&server_key, &server_cert, &b),
            workload(&client_key, &client_cert, &a),
            publication,
            Identity::from_str(URI_B).unwrap(),
            None,
            None,
        )
        .await;
        assert_eq!(
            anchor_error(&err),
            &AnchorError::UnauthorizedIssuer("cmtc-b.mesh.example".into())
        );
    }

    #[tokio::test]
    async fn pinned_loopback_inbound_rejects_client_with_server_only_eku() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ServerAuth]);
        let (server_key, server_cert) = leaf(&[URI_B], &b, 22, &[ClientAuth, ServerAuth]);
        let client = workload(&client_key, &client_cert, &a);
        let client_config = client
            .pinned_client_config(
                vec![Identity::from_str(URI_B).unwrap()],
                publication.clone(),
                None,
            )
            .unwrap();

        let err = server_rejection(
            workload(&server_key, &server_cert, &b),
            client_config,
            publication,
            None,
        )
        .await;
        assert_eq!(
            anchor_error(&err),
            &AnchorError::UnauthorizedIssuer("cmtc-a.mesh.example".into())
        );
    }

    #[tokio::test]
    async fn pinned_loopback_new_config_rejects_withdrawn_pin() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
        let (server_key, server_cert) = leaf(&[URI_B], &b, 22, &[ClientAuth, ServerAuth]);

        exchange(
            workload(&server_key, &server_cert, &b),
            workload(&client_key, &client_cert, &a),
            publication.clone(),
            Identity::from_str(URI_B).unwrap(),
            None,
            None,
        )
        .await;

        let domain_b: crate::strng::Strng = "cmtc-b.mesh.example".into();
        let spki = publication.anchors().pin_spkis(&domain_b).pop().unwrap();
        let withdrawn = publication.withdraw_pin(&domain_b, &spki, 2).unwrap();
        assert!(withdrawn.bundle_fenced(&spki));

        let err = client_rejection(
            workload(&server_key, &server_cert, &b),
            workload(&client_key, &client_cert, &a),
            Arc::new(withdrawn),
            Identity::from_str(URI_B).unwrap(),
            None,
            None,
        )
        .await;
        assert_eq!(
            anchor_error(&err),
            &AnchorError::UntrustedTrustDomain("cmtc-b.mesh.example".into())
        );
    }

    #[tokio::test]
    async fn pinned_loopback_outbound_crl_rejects_then_recovers() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
        let (server_key, server_cert) = leaf(&[URI_B], &b, 22, &[ClientAuth, ServerAuth]);
        let server = workload(&server_key, &server_cert, &b);
        let client = workload(&client_key, &client_cert, &a);

        let mut crl_file = NamedTempFile::new().unwrap();
        write_crl(&mut crl_file, &crl_pem(&b, &[22]));
        let crl = crl_manager(&crl_file);
        let err = client_rejection(
            server,
            workload(&client_key, &client_cert, &a),
            publication.clone(),
            Identity::from_str(URI_B).unwrap(),
            None,
            Some(crl.clone()),
        )
        .await;
        assert!(io_error_is_cert_revoked(&err), "{:?}", error_text(&err));

        write_crl(&mut crl_file, "");
        crl.load_crl().unwrap();
        let (seen_client, seen_server) = exchange(
            workload(&server_key, &server_cert, &b),
            client,
            publication,
            Identity::from_str(URI_B).unwrap(),
            None,
            Some(crl),
        )
        .await;
        assert_eq!(seen_client, Identity::from_str(URI_A).unwrap());
        assert_eq!(seen_server, Identity::from_str(URI_B).unwrap());
    }

    #[tokio::test]
    async fn pinned_loopback_inbound_crl_rejects_then_recovers() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let root = issuer("organization-root");
        let a = issued("issuer-a", &root);
        let b = issued("issuer-b", &root);
        let publication = publication_of(&root, &a, &b);
        let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
        let (server_key, server_cert) = leaf(&[URI_B], &b, 22, &[ClientAuth, ServerAuth]);
        let server = workload(&server_key, &server_cert, &b);
        let client = workload(&client_key, &client_cert, &a);
        let client_config = client
            .pinned_client_config(
                vec![Identity::from_str(URI_B).unwrap()],
                publication.clone(),
                None,
            )
            .unwrap();

        let mut crl_file = NamedTempFile::new().unwrap();
        write_crl(&mut crl_file, &crl_pem(&a, &[11]));
        let crl = crl_manager(&crl_file);
        let err = server_rejection(
            server,
            client_config,
            publication.clone(),
            Some(crl.clone()),
        )
        .await;
        assert!(io_error_is_cert_revoked(&err), "{:?}", error_text(&err));

        write_crl(&mut crl_file, "");
        crl.load_crl().unwrap();
        let (seen_client, seen_server) = exchange(
            workload(&server_key, &server_cert, &b),
            client,
            publication,
            Identity::from_str(URI_B).unwrap(),
            Some(crl),
            None,
        )
        .await;
        assert_eq!(seen_client, Identity::from_str(URI_A).unwrap());
        assert_eq!(seen_server, Identity::from_str(URI_B).unwrap());
    }

    // Reuse the exact configs across connections: rebuilding would conceal a
    // verifier that froze CRLs or a server that resumed cached client identity.
    // Directly joined futures are cancelled on timeout (no detached tasks).
    async fn exchange_pinned_configs(
        server_config: Arc<rustls::ServerConfig>,
        client_config: Arc<rustls::ClientConfig>,
    ) -> (
        Result<rustls::HandshakeKind, std::io::Error>,
        Result<rustls::HandshakeKind, std::io::Error>,
    ) {
        exchange_pinned_configs_at_version(server_config, client_config, None).await
    }

    async fn exchange_pinned_configs_at_version(
        server_config: Arc<rustls::ServerConfig>,
        client_config: Arc<rustls::ClientConfig>,
        expected_version: Option<rustls::ProtocolVersion>,
    ) -> (
        Result<rustls::HandshakeKind, std::io::Error>,
        Result<rustls::HandshakeKind, std::io::Error>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = async move {
            let (stream, _) = listener.accept().await?;
            let mut tls = TlsAcceptor::from(server_config).accept(stream).await?;
            if let Some(expected) = expected_version {
                assert_eq!(
                    tls.get_ref().1.protocol_version(),
                    Some(expected),
                    "server negotiated wrong TLS version"
                );
                eprintln!(
                    "pinned config-reuse server negotiated {:?}",
                    tls.get_ref().1.protocol_version()
                );
            }
            let kind = tls
                .get_ref()
                .1
                .handshake_kind()
                .expect("completed handshake kind");
            let mut request = [0; 2];
            tls.read_exact(&mut request).await?;
            if &request != b"hi" {
                return Err(std::io::Error::other("client payload mismatch"));
            }
            // Pending post-handshake tickets, if any, are processed before the
            // client can finish this read. That client then reuses the same cache.
            tls.write_all(b"serv").await?;
            tls.shutdown().await?;
            Ok(kind)
        };
        let client = async move {
            let stream = TcpStream::connect(address).await?;
            let mut tls = tokio_rustls::TlsConnector::from(client_config)
                .connect(server_name(), stream)
                .await?;
            if let Some(expected) = expected_version {
                assert_eq!(
                    tls.get_ref().1.protocol_version(),
                    Some(expected),
                    "client negotiated wrong TLS version"
                );
                eprintln!(
                    "pinned config-reuse client negotiated {:?}",
                    tls.get_ref().1.protocol_version()
                );
            }
            tls.write_all(b"hi").await?;
            let mut response = [0; 4];
            tls.read_exact(&mut response).await?;
            if &response != b"serv" {
                return Err(std::io::Error::other("server payload mismatch"));
            }
            Ok(tls
                .get_ref()
                .1
                .handshake_kind()
                .expect("completed handshake kind"))
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async { tokio::join!(server, client) })
            .await
            .expect("both config-reuse handshake futures must finish")
    }

    fn assert_full_exchange(
        result: (
            Result<rustls::HandshakeKind, std::io::Error>,
            Result<rustls::HandshakeKind, std::io::Error>,
        ),
    ) {
        for side in [result.0, result.1] {
            assert!(
                matches!(
                    side.unwrap(),
                    rustls::HandshakeKind::Full | rustls::HandshakeKind::FullWithHelloRetryRequest
                ),
                "pinned mTLS must perform current certificate verification on every connection"
            );
        }
    }

    // Independent TLS1.2-only peers force negotiation without altering the
    // pinned constructor under test or mutating a process-global environment.
    // Run this profile in a separate TLS12_ENABLED=true process so the selected
    // provider exposes the repository-approved TLS1.2 cipher suites.
    fn independent_tls12_client(
        client: &WorkloadCertificate,
        publication: Arc<crate::tls::domain_anchors::AnchorPublication>,
    ) -> rustls::ClientConfig {
        let verifier = crate::tls::PinnedIdentityVerifier::new(
            publication,
            vec![Identity::from_str(URI_B).unwrap()],
            None,
        );
        let mut config = rustls::ClientConfig::builder_with_provider(crate::tls::lib::provider())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS12_ENABLED=true must expose TLS1.2 provider suites")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(
                client.cert_and_intermediates_der(),
                client.private_key.clone_key(),
            )
            .unwrap();
        config.alpn_protocols = vec![b"h2".into()];
        config.enable_sni = false;
        // Independent client permits both stateful and RFC5077 ticket reuse.
        config.resumption = rustls::client::Resumption::in_memory_sessions(128);
        config
    }

    fn independent_tls12_server(
        server: &WorkloadCertificate,
        publication: Arc<crate::tls::domain_anchors::AnchorPublication>,
    ) -> rustls::ServerConfig {
        let mut config = rustls::ServerConfig::builder_with_provider(crate::tls::lib::provider())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS12_ENABLED=true must expose TLS1.2 provider suites")
            .with_client_cert_verifier(crate::tls::PinnedTrustDomainVerifier::new(
                publication,
                None,
            ))
            .with_single_cert(
                server.cert_and_intermediates_der(),
                server.private_key.clone_key(),
            )
            .unwrap();
        config.alpn_protocols = vec![b"h2".into()];
        config
    }

    #[tokio::test]
    async fn pinned_configs_recheck_live_crls_with_signed_empty_and_optional_blank_recovery() {
        use rcgen::ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};

        let force_tls12 = *crate::TLS12_ENABLED;
        let expected_version = Some(if force_tls12 {
            rustls::ProtocolVersion::TLSv1_2
        } else {
            rustls::ProtocolVersion::TLSv1_3
        });
        for inbound in [true, false] {
            let root = issuer("organization-root");
            let a = issued("issuer-a", &root);
            let b = issued("issuer-b", &root);
            let publication = publication_of(&root, &a, &b);
            let (client_key, client_cert) = leaf(&[URI_A], &a, 11, &[ClientAuth, ServerAuth]);
            let (server_key, server_cert) = leaf(&[URI_B], &b, 22, &[ClientAuth, ServerAuth]);
            let server = workload(&server_key, &server_cert, &b);
            let client = workload(&client_key, &client_cert, &a);
            let mut file = NamedTempFile::new().unwrap();
            write_crl(&mut file, "");
            let manager = crl_manager(&file);
            let server_config = server
                .pinned_server_config(publication.clone(), inbound.then(|| manager.clone()))
                .unwrap();
            assert!(!server_config.session_storage.can_cache());
            assert!(!server_config.ticketer.enabled());
            assert_eq!(server_config.ticketer.lifetime(), 0);
            assert!(server_config.ticketer.encrypt(b"test").is_none());
            assert!(
                server_config
                    .ticketer
                    .decrypt(b"attacker-controlled")
                    .is_none()
            );
            assert_eq!(server_config.send_tls13_tickets, 0);
            assert_eq!(server_config.max_tls13_tickets, 0);
            assert_eq!(server_config.max_early_data_size, 0);
            let client_config = client
                .pinned_client_config(
                    vec![Identity::from_str(URI_B).unwrap()],
                    publication.clone(),
                    (!inbound).then(|| manager.clone()),
                )
                .unwrap();
            // The constructor UNDER TEST stays untouched: for inbound use
            // actual pinned_server_config plus a TLS1.2-only independent client;
            // for outbound use actual pinned_client_config plus a TLS1.2-only
            // independent server. Enabling TLS1.2 alone does not force it.
            let server_config = if force_tls12 && !inbound {
                independent_tls12_server(&server, publication.clone())
            } else {
                server_config
            };
            let mut client_config = if force_tls12 && inbound {
                independent_tls12_client(&client, publication)
            } else {
                client_config
            };
            if inbound {
                // An independent client can enable resumption. Server security
                // cannot depend on our outbound constructor disabling it.
                client_config.resumption = rustls::client::Resumption::in_memory_sessions(128);
            }
            let server_config = Arc::new(server_config);
            let client_config = Arc::new(client_config);
            assert_full_exchange(
                exchange_pinned_configs_at_version(
                    server_config.clone(),
                    client_config.clone(),
                    expected_version,
                )
                .await,
            );
            assert_full_exchange(
                exchange_pinned_configs_at_version(
                    server_config.clone(),
                    client_config.clone(),
                    expected_version,
                )
                .await,
            );

            let revoking = if inbound {
                crl_pem(&a, &[11])
            } else {
                crl_pem(&b, &[22])
            };
            write_crl(&mut file, &revoking);
            manager.load_crl().unwrap();
            let (server_result, client_result) = exchange_pinned_configs_at_version(
                server_config.clone(),
                client_config.clone(),
                expected_version,
            )
            .await;
            let error = if inbound {
                server_result.expect_err("current inbound verifier must reject revoked client")
            } else {
                client_result.expect_err("current outbound verifier must reject revoked server")
            };
            assert!(io_error_is_cert_revoked(&error), "{:?}", error_text(&error));

            // Cryptographically valid, issuer-signed empty CRL with a newer
            // number, using the SAME verifier/config/manager in both directions.
            let empty_signed = crl_pem_number(if inbound { &a } else { &b }, &[], 2);
            write_crl(&mut file, &empty_signed);
            manager.load_crl().unwrap();
            assert_eq!(manager.get_crls().len(), 1);
            assert_full_exchange(
                exchange_pinned_configs_at_version(
                    server_config.clone(),
                    client_config.clone(),
                    expected_version,
                )
                .await,
            );

            // Separate optional-CRL blank-file semantics; this is not signed
            // empty-CRL recovery and is not evidence of authenticated CRL feed.
            write_crl(&mut file, "");
            manager.load_crl().unwrap();
            assert!(manager.get_crls().is_empty());
            assert_full_exchange(
                exchange_pinned_configs_at_version(server_config, client_config, expected_version)
                    .await,
            );
        }
    }
}
