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

use super::process_binding::{KernelProcessBinder, ProcessBinder};
use crate::{
    config::Config,
    container_runtime::ContainerRuntimeManager,
    identity::{CacheKey, Error, Identity, SecretManager},
    inpod::WorkloadUid,
    tls,
};
use spiffe::{TrustDomain, X509Svid};
use spire_api::{DelegateAttestationRequest, DelegatedIdentityClient};
use std::{str::FromStr, sync::Arc};
use tokio_stream::{Stream, StreamExt};
use tonic::async_trait;

/// Trait abstraction over the SPIRE DelegatedIdentityClient
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DelegatedIdentityApi: Send + Sync {
    async fn get_x509_bundles(
        &self,
    ) -> Result<spiffe::X509BundleSet, spiffe::error::GrpcClientError>;
    async fn get_x509_svids(
        &self,
        attest_type: DelegateAttestationRequest,
    ) -> Result<
        Box<
            dyn Stream<Item = Result<spiffe::X509Svid, spiffe::error::GrpcClientError>>
                + Send
                + Unpin,
        >,
        spiffe::error::GrpcClientError,
    >;
}

#[async_trait]
impl DelegatedIdentityApi for DelegatedIdentityClient {
    async fn get_x509_bundles(
        &self,
    ) -> Result<spiffe::X509BundleSet, spiffe::error::GrpcClientError> {
        self.clone().fetch_x509_bundles().await
    }

    async fn get_x509_svids(
        &self,
        attest_type: DelegateAttestationRequest,
    ) -> Result<
        Box<
            dyn Stream<Item = Result<spiffe::X509Svid, spiffe::error::GrpcClientError>>
                + Send
                + Unpin,
        >,
        spiffe::error::GrpcClientError,
    > {
        let stream = self.clone().stream_x509_svids(attest_type).await?;
        Ok(Box::new(stream))
    }
}

#[derive(
    Eq, PartialEq, Hash, Debug, Clone, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct WorkloadPid {
    pub(crate) pid: i32,
    pub(crate) sandbox_id: Option<String>,
    pub(crate) container_id: Option<String>,
}
impl WorkloadPid {
    /// An unbound PID is useful to explicit test doubles. The production
    /// KernelProcessBinder rejects it; it can never authorize a credential.
    pub fn new(pid: i32) -> Self {
        Self {
            pid,
            sandbox_id: None,
            container_id: None,
        }
    }
    pub(crate) fn from_cri(pid: i32, sandbox: String, container: String) -> Self {
        Self {
            pid,
            sandbox_id: Some(sandbox),
            container_id: Some(container),
        }
    }
    pub fn into_i32(&self) -> i32 {
        self.pid
    }
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait PidClientTrait: Send + Sync {
    async fn fetch_pid(&self, uid: &WorkloadUid) -> Result<WorkloadPid, std::io::Error>;
}

/// SPIRE delegated PID attestation bound to an exact CRI sandbox/container,
/// held Linux process incarnation and kernel Pod UID. No selector fallback.
pub struct SpireClient<C: DelegatedIdentityApi> {
    /// gRPC client for communicating with the SPIRE Delegated Identity API
    client: C,
    /// SPIFFE trust domain (e.g., "cluster.local") used for certificate validation
    trust_domain: String,
    /// Optional PID client for workload PID verification
    pid: Box<dyn PidClientTrait>,
    process_binder: Arc<dyn ProcessBinder>,
    /// Shared configuration for SPIRE client behavior
    cfg: Arc<Config>,
}

impl<C: DelegatedIdentityApi> SpireClient<C> {
    /// Creates a new SPIRE client with the provided gRPC client and trust domain.
    ///
    /// # Arguments
    /// * `client` - Configured DelegatedIdentityClient for SPIRE communication
    /// * `trust_domain` - SPIFFE trust domain string for this cluster
    /// * `pid` - Optional PID client for workload PID verification
    /// * `cfg` - Shared configuration for SPIRE client behavior
    pub fn new(
        client: C,
        trust_domain: String,
        pid: Box<dyn PidClientTrait>,
        cfg: Arc<Config>,
    ) -> Self {
        SpireClient {
            client,
            trust_domain,
            pid,
            process_binder: Arc::new(KernelProcessBinder),
            cfg,
        }
    }

    #[cfg(test)]
    fn new_with_test_binder(
        client: C,
        trust_domain: String,
        pid: Box<dyn PidClientTrait>,
        cfg: Arc<Config>,
    ) -> Self {
        Self {
            client,
            trust_domain,
            pid,
            process_binder: Arc::new(spire_tests::LiveTestBinder),
            cfg,
        }
    }

    /// Fetches a workload certificate using container pid.
    /// This method implements a streaming approach to handle SPIRE's async certificate delivery.
    ///
    /// # Arguments
    /// * `pid` - The container process ID for the workload
    /// * `wl_uid` - The unique identifier for the workload
    ///
    /// # Returns
    /// A WorkloadCertificate containing the X.509 certificate and private key
    ///
    /// # Errors
    /// Returns error if stream setup fails, no certificates are received within timeout,
    /// or certificate construction fails.
    async fn get_cert_by_pid(
        &self,
        process: WorkloadPid,
        id: &Identity,
        uid: &WorkloadUid,
    ) -> Result<tls::WorkloadCertificate, Error> {
        let binding_error = |error: std::io::Error| {
            Error::UnableToDeterminePidForWorkload(format!(
                "workload process incarnation rejected: {error}"
            ))
        };
        let held = self
            .process_binder
            .bind(&process, uid)
            .map_err(binding_error)?;
        held.validate().map_err(binding_error)?;
        // Rejoin CRI after pinning the process, before delegating its integer.
        let current = self.pid.fetch_pid(uid).await.map_err(binding_error)?;
        if current != process {
            return Err(Error::UnableToDeterminePidForWorkload(
                "CRI sandbox/container/PID changed before attestation".into(),
            ));
        }
        held.validate().map_err(binding_error)?;
        let certs = self
            .get_cert_from_spire(DelegateAttestationRequest::Pid(process.pid), id)
            .await?;
        // The pidfd remains held through stream establishment, first SVID,
        // bundle retrieval and the final CRI join. An exited process never
        // becomes valid merely because the same PID integer is reused.
        held.validate().map_err(binding_error)?;
        let current = self.pid.fetch_pid(uid).await.map_err(binding_error)?;
        if current != process {
            return Err(Error::UnableToDeterminePidForWorkload(
                "CRI sandbox/container/PID changed after attestation".into(),
            ));
        }
        held.validate().map_err(binding_error)?;
        Ok(certs)
    }

    /// Fetches a workload certificate using workload UID to determine PID.
    /// This method implements a streaming approach to handle SPIRE's async certificate delivery.
    /// # Arguments
    /// * `wl_uid` - The unique identifier for the workload
    ///
    /// # Returns
    /// A WorkloadCertificate containing the X.509 certificate and private key
    ///
    /// # Errors
    /// Returns error if PID client is not configured, stream setup fails,
    /// no certificates are received within timeout, or certificate construction fails.
    async fn get_cert_by_workload_uid(
        &self,
        id: &Identity,
        uid: &WorkloadUid,
    ) -> Result<tls::WorkloadCertificate, Error> {
        tracing::info!(
            "Fetching PID for workload UID: {}",
            uid.clone().into_string()
        );
        let pid = self.pid.fetch_pid(uid).await;
        match pid {
            Ok(pid) => self.get_cert_by_pid(pid, id, uid).await,
            Err(e) => Err(Error::UnableToDeterminePidForWorkload(format!(
                "Failed to fetch PID for workload UID {}: {}",
                uid.clone().into_string(),
                e
            ))),
        }
    }

    /// Subscribes to the SPIRE server for workload certificates using the provided attestation request.
    ///
    /// # Arguments
    /// * `value` - The attestation request specifying how to identify the workload
    ///
    /// # Returns
    /// The first X509Svid received from the SPIRE server
    ///
    /// # Errors
    /// Returns error if stream setup fails, no certificates are received within timeout,
    /// or certificate construction fails.
    async fn subscribe_and_wait_for_workload_cert(
        &self,
        value: DelegateAttestationRequest,
    ) -> Result<X509Svid, Error> {
        let time_out = self.cfg.spire_timeout;

        // Wrap both stream establishment AND reading in a single timeout.
        // The gRPC stream_x509_svids call can hang indefinitely if the SPIRE
        // agent's socket accepts the connection but never responds (e.g., during
        // a prolonged restart). Without this, a hung connection blocks the
        // identity manager's fetch slot and prevents cert rotation.
        let sf = tokio::time::timeout(time_out, async {
            let stream = self.client.get_x509_svids(value).await.map_err(|e| {
                Error::FailedToFetchCertificate(format!("Failed to stream X.509 SVIDs: {e}"))
            })?;

            // SPIRE may deliver multiple responses, but we only need the first successful one
            tokio::pin!(stream);
            while let Some(svid_response) = stream.next().await {
                match svid_response {
                    Ok(response) => {
                        return Ok(response);
                    }
                    Err(e) => {
                        tracing::warn!("Error receiving SVID response: {}", e);
                    }
                }
            }
            Err(Error::FailedToFetchCertificate(
                "No SVIDs received in stream".to_string(),
            ))
        })
        .await;

        match sf {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                tracing::error!(
                    "Timeout while waiting for SPIRE SVID (stream establishment or reading took longer than {:?})",
                    time_out
                );
                Err(Error::FailedToFetchCertificate(
                    "Timeout while waiting for SVID stream".to_string(),
                ))
            }
        }
    }

    /// Fetches a workload certificate from SPIRE using the provided attestation request.
    ///
    /// # Arguments
    /// * `value` - The attestation request specifying how to identify the workload
    ///
    /// # Returns
    /// A WorkloadCertificate containing the X.509 certificate and private key
    ///
    /// # Errors
    /// Returns error if stream setup fails, no certificates are received within timeout,
    /// or certificate construction fails.
    async fn get_cert_from_spire(
        &self,
        value: DelegateAttestationRequest,
        id: &Identity,
    ) -> Result<tls::WorkloadCertificate, Error> {
        // Handle nested Result types from timeout + stream operations
        let svid_response = self.subscribe_and_wait_for_workload_cert(value).await?;

        // Fetch the trust bundle containing CA certificates for validation
        let bundle = self.get_bundle().await?;

        // Construct the final WorkloadCertificate combining SVID and trust bundle
        let certs = tls::WorkloadCertificate::new_svid(&svid_response, &bundle)?;

        let id_strg = format!(
            "spiffe://{}{}",
            svid_response.spiffe_id().trust_domain(),
            svid_response.spiffe_id().path()
        );

        // Validate that the returned identity matches the requested one
        if id.to_string() != Identity::from_str(&id_strg)?.to_string() {
            return Err(Error::Spiffe(format!(
                "Mismatched identity: expected {}, got {}",
                id, id_strg
            )));
        }

        Ok(certs)
    }

    /// Fetches the X.509 trust bundle from SPIRE containing CA certificates
    /// for validating certificates within this trust domain.
    ///
    /// # Returns
    /// Vector of CA certificates that can verify certificates in this trust domain
    ///
    /// # Errors
    /// Returns error if bundle fetch fails, trust domain is invalid, or no bundle
    /// exists for the configured trust domain.
    async fn get_bundle(&self) -> Result<Vec<spiffe::cert::Certificate>, Error> {
        // Fetch all available trust bundles from SPIRE server
        let bundle_req = self.client.get_x509_bundles().await.map_err(|e| {
            Error::FailedToFetchBundle(format!("Failed to fetch X.509 bundles: {}", e))
        })?;

        // Parse and validate the trust domain string
        let td = TrustDomain::new(&self.trust_domain).map_err(|e| {
            Error::InvalidTrustDomain(format!("Invalid trust domain {}: {}", self.trust_domain, e))
        })?;
        tracing::debug!("Fetched bundle for trust domain: {}", td);

        // Extract CA certificates for our specific trust domain
        let bundles = match bundle_req.get_bundle(&td) {
            Some(b) => b.authorities(), // Get the CA certificates
            None => {
                // No trust bundle available for this domain - configuration error
                return Err(Error::InvalidTrustDomain(format!(
                    "No bundle found for trust domain: {}",
                    td
                )));
            }
        };

        // Clone the certificates to return owned values
        // This allows the bundle request to be dropped while keeping the certificates
        Ok(bundles.clone())
    }
}

/// Implementation of the CaClientTrait that integrates SPIRE with ztunnel's
/// certificate management system. This allows the SPIRE client to be used
/// interchangeably with other certificate authority implementations.
#[async_trait]
impl<C: DelegatedIdentityApi> crate::identity::CaClientTrait for SpireClient<C> {
    /// Fetches a certificate for one workload. This is the main integration
    /// point with ztunnel's certificate manager.
    ///
    /// SPIRE attests the pod by PID, so the fetch must carry the pod UID. An
    /// identity-keyed fetch fails closed.
    async fn fetch_certificate(&self, key: &CacheKey) -> Result<tls::WorkloadCertificate, Error> {
        let start = std::time::Instant::now();
        let result = match key {
            CacheKey::Workload { id, uid, .. } => {
                tokio::time::timeout(self.cfg.spire_timeout,
                    self.get_cert_by_workload_uid(id, &WorkloadUid::new(uid.to_string())))
                    .await.unwrap_or_else(|_| Err(Error::FailedToFetchCertificate(
                        "SPIRE credential deadline exceeded across CRI, process binding, SVID and bundle".into())))
            }
            CacheKey::Identity(_) => Err(Error::InvalidConfiguration(
                "expected Workload key for SPIRE attestation".to_string(),
            )),
        };
        if let Err(error) = &result {
            tracing::warn!(component="spire-client", stage="workload-credential", attempt=1u64,
                elapsed_ms=start.elapsed().as_millis() as u64,
                deadline_ms=self.cfg.spire_timeout.as_millis() as u64, backoff_ms=0u64,
                error=%error, "native workload credential rejected");
        }
        result
    }
}

impl SecretManager {
    pub async fn new_with_spire_client<C: 'static + DelegatedIdentityApi>(
        cfg: Arc<Config>,
        dc: C,
    ) -> Result<Self, spiffe::error::GrpcClientError> {
        let pid_client = ContainerRuntimeManager::new(&cfg).await.map_err(|error| {
            spiffe::error::GrpcClientError::Grpc(tonic::Status::unavailable(format!(
                "node CRI initialization failed: {error}"
            )))
        })?;

        let client = SpireClient::new(dc, cfg.cluster_domain.clone(), Box::new(pid_client), cfg);

        Ok(Self::new_with_client(client))
    }

    pub async fn new_with_spire_client_pid<C: 'static + DelegatedIdentityApi>(
        cfg: Arc<Config>,
        dc: C,
        pid_client: Box<dyn PidClientTrait>,
    ) -> Result<Self, spiffe::error::GrpcClientError> {
        let client = SpireClient::new(dc, cfg.cluster_domain.clone(), pid_client, cfg);

        Ok(Self::new_with_client(client))
    }
}

#[cfg(test)]
pub mod spire_tests {
    pub(super) struct LiveTestBinder;
    struct LiveTestProcess;
    impl super::super::process_binding::BoundProcess for LiveTestProcess {
        fn validate(&self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl ProcessBinder for LiveTestBinder {
        fn bind(
            &self,
            _: &WorkloadPid,
            _: &WorkloadUid,
        ) -> std::io::Result<Box<dyn super::super::process_binding::BoundProcess>> {
            Ok(Box::new(LiveTestProcess))
        }
    }

    use crate::config;
    use crate::identity::CaClientTrait;
    use crate::state::WorkloadInfo;

    use super::*;
    use futures::SinkExt;
    use futures::channel::mpsc;
    use mockall::predicate::*;
    use rcgen::BasicConstraints;
    use rcgen::Certificate;
    use rcgen::CertificateParams;
    use rcgen::CertifiedIssuer;
    use rcgen::DnType;
    use rcgen::IsCa;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;
    use rcgen::SanType;
    use rcgen::string::Ia5String;
    use spiffe::error::GrpcClientError;
    use spiffe::*;

    use rcgen::ExtendedKeyUsagePurpose as EKU;

    #[tokio::test]
    async fn test_get_bundle_success() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let pid_client = MockPidClientTrait::new();

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let spire_client = SpireClient::new_with_test_binder(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::new(cfg),
        );

        let result = spire_client.get_bundle().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_bundle_trust_domain_not_found() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let pid_client = MockPidClientTrait::new();

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let spire_client = SpireClient::new_with_test_binder(
            mock_client,
            "wrong.trust_domain".to_string(),
            Box::new(pid_client),
            Arc::new(cfg),
        );

        let result = spire_client.get_bundle().await;
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("No bundle found for trust domain"));
    }

    #[tokio::test]
    async fn test_get_cert_by_pid_success() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_response(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client
            .expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let cfg = Arc::new(cfg);

        let spire_client = SpireClient::new_with_test_binder(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::clone(&cfg),
        );

        let identity =
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into());
        let uid = WorkloadUid::new("uid-123456".to_string());
        let result = spire_client
            .get_cert_by_pid(WorkloadPid::new(10), &identity, &uid)
            .await;

        assert!(result.is_ok());

        let workload_cert = result.unwrap();

        let id = workload_cert.identity();

        assert!(id.unwrap().to_string() == "spiffe://example.org/ns/default/sa/test-sa");

        assert!(identity.to_string() == "spiffe://example.org/ns/default/sa/test-sa");

        let fetch_result = spire_client
            .fetch_certificate(&workload_key(&identity, "uid-123456"))
            .await;

        assert!(fetch_result.is_ok());
    }

    #[tokio::test]
    async fn test_get_cert_by_pid_changed() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_response(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client
            .expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let cfg = Arc::new(cfg);

        let spire_client = SpireClient::new_with_test_binder(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::clone(&cfg),
        );

        let identity =
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into());
        let uid = WorkloadUid::new("uid-123456".to_string());
        let result = spire_client
            .get_cert_by_pid(WorkloadPid::new(1337), &identity, &uid)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_cert_by_pid_not_found() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_response(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client.expect_fetch_pid().returning(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No PID found for pod",
            ))
        });

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let spire_client = SpireClient::new_with_test_binder(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::new(cfg),
        );

        let identity =
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into());
        let uid = WorkloadUid::new("uid-123456".to_string());
        let result = spire_client
            .get_cert_by_pid(WorkloadPid::new(10), &identity, &uid)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_cert_by_secret_manager_with_pid_success() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_response(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client
            .expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let cfg = Arc::new(cfg);

        let spire_client = SpireClient::new_with_test_binder(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::clone(&cfg),
        );

        let identity =
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into());
        let sm = SecretManager::new_with_client(spire_client);
        let certs = sm
            .fetch_certificate_by_workload(&identity, test_workload_info(), "uid-123456".into())
            .await
            .unwrap();
        assert!(
            certs.identity().unwrap().to_string() == "spiffe://example.org/ns/default/sa/test-sa"
        );
        assert!(sm.cache_len().await == 1);
        let certs = sm
            .fetch_certificate_by_workload(&identity, test_workload_info(), "uid-123456".into())
            .await
            .unwrap();
        assert!(
            certs.identity().unwrap().to_string() == "spiffe://example.org/ns/default/sa/test-sa"
        );
        assert!(sm.cache_len().await == 1);
        let certs = sm
            .fetch_certificate_by_workload(&identity, test_workload_info(), "uid-654321".into())
            .await
            .unwrap();
        assert!(
            certs.identity().unwrap().to_string() == "spiffe://example.org/ns/default/sa/test-sa"
        );
        assert!(sm.cache_len().await == 2);
    }

    #[tokio::test]
    async fn test_get_cert_by_secret_manager_with_pid_not_found() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_response(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client.expect_fetch_pid().returning(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No PID found for pod",
            ))
        });

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let cfg = Arc::new(cfg);

        let spire_client = SpireClient::new_with_test_binder(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::clone(&cfg),
        );

        let identity =
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into());
        let sm = SecretManager::new_with_client(spire_client);
        let certs = sm
            .fetch_certificate_by_workload(&identity, test_workload_info(), "uid-123456".into())
            .await;
        assert!(certs.is_err());
        assert!(sm.cache_len().await == 1);
        let err = certs.err().unwrap().to_string();
        assert!(err.contains("No PID found for pod"));
    }

    #[tokio::test]
    async fn test_get_cert_by_pid_success_delay_response() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_delay_response(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client
            .expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let cfg = Arc::new(cfg);

        let spire_client = SpireClient::new_with_test_binder(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::clone(&cfg),
        );

        let identity =
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into());
        let uid = WorkloadUid::new("uid-123456".to_string());
        let result = spire_client
            .get_cert_by_pid(WorkloadPid::new(10), &identity, &uid)
            .await;

        assert!(result.is_ok());

        let workload_cert = result.unwrap();

        let id = workload_cert.identity();

        assert!(id.unwrap().to_string() == "spiffe://example.org/ns/default/sa/test-sa");

        assert!(identity.to_string() == "spiffe://example.org/ns/default/sa/test-sa");

        let fetch_result = spire_client
            .fetch_certificate(&workload_key(&identity, "uid-123456"))
            .await;

        assert!(fetch_result.is_ok());
    }

    #[tokio::test]
    async fn test_get_cert_by_pid_delay_response_timeout() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_delay_response_timeout(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client
            .expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;
        cfg.spire_timeout = std::time::Duration::from_secs(5);

        let cfg = Arc::new(cfg);

        let spire_client = SpireClient::new_with_test_binder(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::clone(&cfg),
        );

        let identity =
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into());
        let uid = WorkloadUid::new("uid-123456".to_string());
        let result = spire_client
            .get_cert_by_pid(WorkloadPid::new(10), &identity, &uid)
            .await;

        assert!(result.is_err());

        let err = result.err().unwrap().to_string();
        assert!(err.contains("No SVIDs received in stream"));
    }

    #[tokio::test]
    async fn test_get_cert_by_pid_delay_response_timeout_empty() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_delay_response_timeout_empty(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client
            .expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let cfg = Arc::new(cfg);

        let spire_client = SpireClient::new_with_test_binder(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::clone(&cfg),
        );

        let identity =
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into());
        let uid = WorkloadUid::new("uid-123456".to_string());
        let result = spire_client
            .get_cert_by_pid(WorkloadPid::new(10), &identity, &uid)
            .await;

        assert!(result.is_err());

        let err = result.err().unwrap().to_string();
        assert!(err.contains("Timeout while waiting for SVID stream"));
    }

    fn test_workload_info() -> Arc<WorkloadInfo> {
        Arc::new(WorkloadInfo::new(
            "test-pod".to_string(),
            "default".to_string(),
            "test-sa".to_string(),
        ))
    }

    fn workload_key(id: &Identity, uid: &str) -> CacheKey {
        CacheKey::Workload {
            id: id.clone(),
            uid: uid.into(),
            workload: test_workload_info(),
        }
    }

    fn mock_bundle_response() -> spiffe::X509BundleSet {
        let ca_key = KeyPair::generate().unwrap();
        let ca_params = ca_params("example.org").unwrap();

        // CertifiedIssuer gives you both the issuer + its self-signed cert
        let ca_issuer = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let td = TrustDomain::new("example.org").unwrap();
        let mut bundle = X509Bundle::new(td.clone());

        let ca_der_slice: &[u8] = ca_issuer.der();
        bundle.add_authority(ca_der_slice).unwrap();

        let mut set = spiffe::X509BundleSet::new();
        set.add_bundle(bundle);

        set
    }

    fn mock_stream_svid_success_response(
        spiffe_id: String,
    ) -> Box<dyn Stream<Item = Result<X509Svid, GrpcClientError>> + Send + Unpin> {
        let (mut tx, rx) = mpsc::channel(10);
        tokio::spawn(async move {
            let svid = generate_svid(&spiffe_id, "example.org");
            tx.send(Ok(svid)).await.unwrap();
        });
        Box::new(rx)
    }

    fn mock_stream_svid_success_delay_response(
        spiffe_id: String,
    ) -> Box<dyn Stream<Item = Result<X509Svid, GrpcClientError>> + Send + Unpin> {
        let (mut tx, rx) = mpsc::channel(10);
        tokio::spawn(async move {
            tx.send(Err(GrpcClientError::EmptyResponse)).await.unwrap();

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            let svid = generate_svid(&spiffe_id, "example.org");
            tx.send(Ok(svid)).await.unwrap();
        });
        Box::new(rx)
    }

    fn mock_stream_svid_success_delay_response_timeout(
        _: String,
    ) -> Box<dyn Stream<Item = Result<X509Svid, GrpcClientError>> + Send + Unpin> {
        let (_, rx) = mpsc::channel(10);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        });
        Box::new(rx)
    }

    fn mock_stream_svid_success_delay_response_timeout_empty(
        _: String,
    ) -> Box<dyn Stream<Item = Result<X509Svid, GrpcClientError>> + Send + Unpin> {
        let (mut tx, rx) = mpsc::channel(10);
        tokio::spawn(async move {
            tx.send(Err(GrpcClientError::EmptyResponse)).await.unwrap();

            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        });
        Box::new(rx)
    }

    #[tokio::test]
    async fn test_get_cert_by_pid_mismatched_identity() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let pid_client = MockPidClientTrait::new();

        // SPIRE returns a certificate for a DIFFERENT identity than requested
        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_response(
                "spiffe://example.org/ns/other-namespace/sa/other-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let spire_client = SpireClient::new_with_test_binder(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::new(cfg),
        );

        // Request certificate for ns/default/sa/test-sa but SPIRE returns ns/other-namespace/sa/other-sa
        let identity =
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into());
        let result = spire_client
            .get_cert_from_spire(DelegateAttestationRequest::Pid(10), &identity)
            .await;

        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(
            err.contains("Mismatched identity"),
            "Expected error to contain 'Mismatched identity', got: {}",
            err
        );
    }

    struct FlagBinder {
        alive: Arc<std::sync::atomic::AtomicBool>,
        leases: Arc<std::sync::atomic::AtomicUsize>,
    }
    struct FlagProcess {
        alive: Arc<std::sync::atomic::AtomicBool>,
        leases: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Drop for FlagProcess {
        fn drop(&mut self) {
            self.leases
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl super::super::process_binding::BoundProcess for FlagProcess {
        fn validate(&self) -> std::io::Result<()> {
            if self.alive.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "test held incarnation exited",
                ))
            }
        }
    }
    impl ProcessBinder for FlagBinder {
        fn bind(
            &self,
            _: &WorkloadPid,
            _: &WorkloadUid,
        ) -> std::io::Result<Box<dyn super::super::process_binding::BoundProcess>> {
            if !self.alive.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(std::io::Error::other("test pidfd unavailable"));
            }
            self.leases
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Box::new(FlagProcess {
                alive: self.alive.clone(),
                leases: self.leases.clone(),
            }))
        }
    }
    fn test_key() -> CacheKey {
        workload_key(
            &Identity::from_parts("example.org".into(), "default".into(), "test-sa".into()),
            "11111111-2222-3333-4444-555555555555",
        )
    }
    fn guarded_client<C: DelegatedIdentityApi>(
        client: C,
        pid: Box<dyn PidClientTrait>,
        alive: Arc<std::sync::atomic::AtomicBool>,
        leases: Arc<std::sync::atomic::AtomicUsize>,
    ) -> SpireClient<C> {
        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;
        cfg.spire_timeout = std::time::Duration::from_secs(2);
        let mut client = SpireClient::new(client, "example.org".into(), pid, Arc::new(cfg));
        client.process_binder = Arc::new(FlagBinder { alive, leases });
        client
    }
    #[tokio::test]
    async fn same_integer_pid_cannot_revive_dead_binding_after_bundle() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let alive = Arc::new(AtomicBool::new(true));
        let leases = Arc::new(AtomicUsize::new(0));
        let mut api = MockDelegatedIdentityApi::new();
        api.expect_get_x509_svids().returning(|_| {
            Ok(mock_stream_svid_success_response(
                "spiffe://example.org/ns/default/sa/test-sa".into(),
            ))
        });
        let flag = alive.clone();
        api.expect_get_x509_bundles().returning(move || {
            flag.store(false, Ordering::SeqCst);
            Ok(mock_bundle_response())
        });
        let mut pid = MockPidClientTrait::new();
        pid.expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));
        let client = guarded_client(api, Box::new(pid), alive, leases.clone());
        let error = client.fetch_certificate(&test_key()).await.unwrap_err();
        assert!(error.to_string().contains("incarnation exited"));
        assert_eq!(leases.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn unavailable_pidfd_prevents_any_spire_request() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let alive = Arc::new(AtomicBool::new(false));
        let leases = Arc::new(AtomicUsize::new(0));
        let mut api = MockDelegatedIdentityApi::new();
        api.expect_get_x509_svids().times(0);
        api.expect_get_x509_bundles().times(0);
        let mut pid = MockPidClientTrait::new();
        pid.expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));
        let client = guarded_client(api, Box::new(pid), alive, leases.clone());
        assert!(client.fetch_certificate(&test_key()).await.is_err());
        assert_eq!(leases.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn same_pid_new_sandbox_cannot_complete_old_fetch() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let alive = Arc::new(AtomicBool::new(true));
        let leases = Arc::new(AtomicUsize::new(0));
        let changed = Arc::new(AtomicBool::new(false));
        let mut api = MockDelegatedIdentityApi::new();
        api.expect_get_x509_svids().returning(|_| {
            Ok(mock_stream_svid_success_response(
                "spiffe://example.org/ns/default/sa/test-sa".into(),
            ))
        });
        let flag = changed.clone();
        api.expect_get_x509_bundles().returning(move || {
            flag.store(true, Ordering::SeqCst);
            Ok(mock_bundle_response())
        });
        let mut pid = MockPidClientTrait::new();
        pid.expect_fetch_pid().returning(move |_| {
            Ok(WorkloadPid::from_cri(
                10,
                if changed.load(Ordering::SeqCst) {
                    "new"
                } else {
                    "old"
                }
                .into(),
                "a".repeat(64),
            ))
        });
        let client = guarded_client(api, Box::new(pid), alive, leases.clone());
        let error = client.fetch_certificate(&test_key()).await.unwrap_err();
        assert!(error.to_string().contains("changed after attestation"));
        assert_eq!(leases.load(Ordering::SeqCst), 0);
    }
    struct HangingBundle;
    #[async_trait]
    impl DelegatedIdentityApi for HangingBundle {
        async fn get_x509_bundles(&self) -> Result<spiffe::X509BundleSet, GrpcClientError> {
            std::future::pending().await
        }
        async fn get_x509_svids(
            &self,
            _: DelegateAttestationRequest,
        ) -> Result<
            Box<dyn Stream<Item = Result<X509Svid, GrpcClientError>> + Send + Unpin>,
            GrpcClientError,
        > {
            Ok(mock_stream_svid_success_response(
                "spiffe://example.org/ns/default/sa/test-sa".into(),
            ))
        }
    }
    #[tokio::test]
    async fn bundle_deadline_cancels_and_drops_process_binding() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let alive = Arc::new(AtomicBool::new(true));
        let leases = Arc::new(AtomicUsize::new(0));
        let mut pid = MockPidClientTrait::new();
        pid.expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));
        let mut client = guarded_client(HangingBundle, Box::new(pid), alive, leases.clone());
        Arc::get_mut(&mut client.cfg).unwrap().spire_timeout = std::time::Duration::from_millis(30);
        let start = std::time::Instant::now();
        let error = client.fetch_certificate(&test_key()).await.unwrap_err();
        assert!(error.to_string().contains("deadline exceeded across CRI"));
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(leases.load(Ordering::SeqCst), 0);
    }
    struct HangingPid;
    #[async_trait]
    impl PidClientTrait for HangingPid {
        async fn fetch_pid(&self, _: &WorkloadUid) -> Result<WorkloadPid, std::io::Error> {
            std::future::pending().await
        }
    }
    #[tokio::test]
    async fn initial_cri_deadline_prevents_any_spire_request() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let alive = Arc::new(AtomicBool::new(true));
        let leases = Arc::new(AtomicUsize::new(0));
        let mut api = MockDelegatedIdentityApi::new();
        api.expect_get_x509_svids().times(0);
        let mut client = guarded_client(api, Box::new(HangingPid), alive, leases.clone());
        Arc::get_mut(&mut client.cfg).unwrap().spire_timeout = std::time::Duration::from_millis(30);
        let error = client.fetch_certificate(&test_key()).await.unwrap_err();
        assert!(error.to_string().contains("deadline exceeded across CRI"));
        assert_eq!(leases.load(Ordering::SeqCst), 0);
    }

    fn ca_params(cn: &str) -> Result<CertificateParams, rcgen::Error> {
        // Empty Vec<String> => no DNS SANs; we'll just use DN for the CA
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.distinguished_name.push(DnType::CommonName, cn);
        params.use_authority_key_identifier_extension = true;
        Ok(params)
    }

    fn spiffe_leaf_params(spiffe_id: &str) -> Result<CertificateParams, rcgen::Error> {
        // Again, no default DNS SANs
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
            KeyUsagePurpose::ContentCommitment,
        ];
        params.extended_key_usages = vec![EKU::ClientAuth, EKU::ServerAuth];

        // Optional subject DN
        params
            .distinguished_name
            .push(DnType::CommonName, "spiffe-workload");

        // SPIFFE ID as URI SAN: URI(Ia5String)
        let uri = Ia5String::try_from(spiffe_id)?;
        params.subject_alt_names.push(SanType::URI(uri));

        Ok(params)
    }

    #[test]
    fn native_spire_certificate_chain_contains_leaf_once() {
        let svid = generate_svid(
            "spiffe://cmtc-a.mesh.example/ns/demo/sa/client",
            "exact-direct-signer",
        );
        assert_eq!(svid.cert_chain().len(), 2);
        let issuer = svid.cert_chain().last().unwrap();
        let cert = tls::WorkloadCertificate::new_svid(&svid, std::slice::from_ref(issuer))
            .expect("actual parsed X509Svid fixture must convert");
        let emitted = cert.cert_and_intermediates();
        assert_eq!(
            emitted.len(),
            2,
            "leaf must not be duplicated as an intermediate"
        );
        assert_eq!(emitted[0].der.as_ref(), svid.leaf().content());
        assert_eq!(emitted[1].der.as_ref(), issuer.content());
        assert_eq!(cert.chain.len(), 1);
        assert_eq!(cert.chain[0].der.as_ref(), issuer.content());
    }

    fn generate_svid(spiffe_id: &str, cn: &str) -> X509Svid {
        let ca_key = KeyPair::generate().unwrap();
        let ca_params = ca_params(cn).unwrap();

        // CertifiedIssuer gives you both the issuer + its self-signed cert
        let ca_issuer = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        // ----- Leaf cert with SPIFFE SAN -----
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = spiffe_leaf_params(spiffe_id).unwrap();

        // Sign leaf with CA
        let leaf_cert: Certificate = leaf_params.signed_by(&leaf_key, &*ca_issuer).unwrap();

        let leaf_cert_der: Vec<u8> = leaf_cert.der().to_vec();
        let leaf_key_der: Vec<u8> = leaf_key.serialize_der();
        let ca_cert_der: Vec<u8> = ca_issuer.der().to_vec();

        // Combine leaf cert and CA cert chain
        let mut cert_chain = leaf_cert_der.clone();
        cert_chain.extend_from_slice(&ca_cert_der);

        X509Svid::parse_from_der(&cert_chain, &leaf_key_der)
            .map_err(|e| {
                tracing::error!("Failed to parse SVID: {}", e);
                e
            })
            .unwrap()
    }
}
