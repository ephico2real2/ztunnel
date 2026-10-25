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

//! Observation of one workload TLS handshake at its accept/connect owner.
//!
//! An observation starts when TLS bytes can flow and ends when the verified
//! peer is bound, or when the handshake fails. Local credential or profile
//! preparation before that point is not a handshake. A dropped (cancelled)
//! observation records nothing.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate::proxy::metrics::{Metrics, Reporter, TlsConnectionLabels, TlsHandshakeResult};

/// The verification authority (issuer profile, xDS session or local
/// credential deadline) ended while a TLS stream depended on it.
#[derive(Debug, thiserror::Error)]
#[error("authenticated issuer profile/session expired or changed")]
pub(crate) struct AuthorityInvalidated;

/// The handshake deadline elapsed before the peer was bound.
#[derive(Debug, thiserror::Error)]
#[error("TLS handshake did not complete within {0:?}")]
pub(crate) struct HandshakeTimedOut(Duration);

/// Shared, cheap handle used by every workload TLS accept/connect owner.
#[derive(Clone, Debug)]
pub(crate) struct HandshakeObserver {
    metrics: Arc<Metrics>,
    timeout: Duration,
}

impl HandshakeObserver {
    pub(crate) fn new(metrics: Arc<Metrics>, timeout: Duration) -> Self {
        Self { metrics, timeout }
    }

    #[cfg(test)]
    pub(crate) fn with_timeout(&self, timeout: Duration) -> Self {
        Self {
            metrics: self.metrics.clone(),
            timeout,
        }
    }

    /// Count one live verified session. The application stream owner holds
    /// the guard and drops it together with the decrypted TLS stream.
    pub(crate) fn active(&self, reporter: Reporter) -> ActiveSession {
        self.metrics
            .tls_connections_active
            .get_or_create(&TlsConnectionLabels { reporter })
            .inc();
        ActiveSession {
            metrics: self.metrics.clone(),
            reporter,
        }
    }

    /// Start one observation. Call this immediately before the TLS
    /// acceptor/connector receives the transport.
    pub(crate) fn start(&self, reporter: Reporter) -> HandshakeAttempt {
        HandshakeAttempt {
            observer: self.clone(),
            reporter,
            started: Instant::now(),
        }
    }
}

/// Owner of one in-flight handshake. Dropping it records nothing.
#[must_use = "an attempt records only when it completes"]
pub(crate) struct HandshakeAttempt {
    observer: HandshakeObserver,
    reporter: Reporter,
    started: Instant,
}

impl HandshakeAttempt {
    /// Drive the TLS handshake future under the configured deadline.
    /// A failure is recorded here; success moves to the peer binding stage.
    pub(crate) async fn drive<T>(
        self,
        handshake: impl Future<Output = io::Result<T>>,
    ) -> io::Result<(PeerBinding, T)> {
        let deadline = self.observer.timeout;
        match tokio::time::timeout(deadline, handshake).await {
            Ok(Ok(stream)) => Ok((PeerBinding { attempt: self }, stream)),
            Ok(Err(error)) => {
                self.record(classify(&error));
                Err(error)
            }
            Err(_elapsed) => {
                self.record(TlsHandshakeResult::timeout);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    HandshakeTimedOut(deadline),
                ))
            }
        }
    }

    fn record(self, result: TlsHandshakeResult) {
        self.observer
            .metrics
            .record_tls_handshake(self.reporter, result, self.started.elapsed());
    }
}

/// One live verified workload TLS session. Dropping it ends the session count.
pub(crate) struct ActiveSession {
    metrics: Arc<Metrics>,
    reporter: Reporter,
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.metrics
            .tls_connections_active
            .get_or_create(&TlsConnectionLabels {
                reporter: self.reporter,
            })
            .dec();
    }
}

/// The TLS protocol completed. The reporter must still bind the verified peer
/// to its current issuer profile, CRL and session before it is a success.
#[must_use = "a completed TLS protocol records only after the peer binding"]
pub(crate) struct PeerBinding {
    attempt: HandshakeAttempt,
}

impl PeerBinding {
    /// Record `success` or `peer_verification_failed` and return the result.
    pub(crate) fn complete<T, E>(self, bound: Result<T, E>) -> Result<T, E> {
        self.attempt.record(if bound.is_ok() {
            TlsHandshakeResult::success
        } else {
            TlsHandshakeResult::peer_verification_failed
        });
        bound
    }
}

/// Classify a failed TLS handshake I/O result. Only this reporter's rejection
/// of the peer credential is `peer_verification_failed`.
pub(crate) fn classify(error: &io::Error) -> TlsHandshakeResult {
    if let Some(inner) = error.get_ref() {
        if let Some(tls) = inner.downcast_ref::<rustls::Error>() {
            return match tls {
                rustls::Error::InvalidCertificate(_)
                | rustls::Error::NoCertificatesPresented
                | rustls::Error::InvalidCertRevocationList(_) => {
                    TlsHandshakeResult::peer_verification_failed
                }
                _ => TlsHandshakeResult::protocol_error,
            };
        }
        if inner.is::<AuthorityInvalidated>() {
            return TlsHandshakeResult::peer_verification_failed;
        }
        if inner.is::<HandshakeTimedOut>() {
            return TlsHandshakeResult::timeout;
        }
    }
    match error.kind() {
        io::ErrorKind::TimedOut => TlsHandshakeResult::timeout,
        _ => TlsHandshakeResult::protocol_error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::metrics::TlsHandshakeLabels;
    use rustls::{AlertDescription, CertificateError};

    fn tls(error: rustls::Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }

    #[test]
    fn tls_handshake_classification_is_closed_and_local() {
        let cases = [
            (
                tls(rustls::Error::InvalidCertificate(
                    CertificateError::UnknownIssuer,
                )),
                TlsHandshakeResult::peer_verification_failed,
            ),
            (
                tls(rustls::Error::InvalidCertificate(CertificateError::Revoked)),
                TlsHandshakeResult::peer_verification_failed,
            ),
            (
                tls(rustls::Error::NoCertificatesPresented),
                TlsHandshakeResult::peer_verification_failed,
            ),
            (
                io::Error::new(io::ErrorKind::PermissionDenied, AuthorityInvalidated),
                TlsHandshakeResult::peer_verification_failed,
            ),
            // A remote rejection of this reporter's credential is an alert.
            (
                tls(rustls::Error::AlertReceived(
                    AlertDescription::BadCertificate,
                )),
                TlsHandshakeResult::protocol_error,
            ),
            (
                tls(rustls::Error::InvalidMessage(
                    rustls::InvalidMessage::InvalidContentType,
                )),
                TlsHandshakeResult::protocol_error,
            ),
            (
                io::Error::from(io::ErrorKind::UnexpectedEof),
                TlsHandshakeResult::protocol_error,
            ),
            (
                io::Error::from(io::ErrorKind::ConnectionReset),
                TlsHandshakeResult::protocol_error,
            ),
            // An unrelated EPERM is not a verification decision.
            (
                io::Error::from(io::ErrorKind::PermissionDenied),
                TlsHandshakeResult::protocol_error,
            ),
            (
                io::Error::from(io::ErrorKind::TimedOut),
                TlsHandshakeResult::timeout,
            ),
            (
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    HandshakeTimedOut(Duration::from_secs(1)),
                ),
                TlsHandshakeResult::timeout,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(classify(&error), expected, "{error:?}");
        }
    }

    fn count(metrics: &Metrics, reporter: Reporter, result: TlsHandshakeResult) -> u64 {
        metrics
            .tls_handshakes
            .get_or_create(&TlsHandshakeLabels { reporter, result })
            .get()
    }

    #[tokio::test(start_paused = true)]
    async fn tls_handshake_attempt_records_timeout_and_ignores_cancellation() {
        let metrics = crate::test_helpers::helpers::test_proxy_metrics();
        let observer = HandshakeObserver::new(metrics.clone(), Duration::from_secs(3));

        // Deadline: the pending handshake is dropped and recorded as timeout.
        let error = observer
            .start(Reporter::destination)
            .drive(std::future::pending::<io::Result<()>>())
            .await
            .err()
            .expect("deadline must end the handshake");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            count(&metrics, Reporter::destination, TlsHandshakeResult::timeout),
            1
        );

        // Cancellation: the caller drops the attempt before completion.
        let cancelled = observer
            .start(Reporter::source)
            .drive(std::future::pending::<io::Result<()>>());
        assert!(
            tokio::time::timeout(Duration::from_secs(1), cancelled)
                .await
                .is_err()
        );
        for result in TlsHandshakeResult::ALL {
            assert_eq!(count(&metrics, Reporter::source, result), 0, "{result:?}");
        }

        // A completed TLS protocol is not a success until the peer is bound.
        let (binding, ()) = observer
            .start(Reporter::source)
            .drive(async { Ok(()) })
            .await
            .unwrap();
        binding
            .complete::<(), _>(Err("peer issuer fenced"))
            .unwrap_err();
        assert_eq!(
            count(
                &metrics,
                Reporter::source,
                TlsHandshakeResult::peer_verification_failed
            ),
            1
        );
        assert_eq!(
            count(&metrics, Reporter::source, TlsHandshakeResult::success),
            0
        );
    }
}
