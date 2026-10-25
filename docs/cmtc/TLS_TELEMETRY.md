# Workload TLS telemetry at the native accept/connect owner

Status: source-tested, not deployed. These families do not establish that a
workload is Protected. A live scrape from the exact image is a separate gate.

## Owner boundary

`src/tls/profile_provider.rs` `accept` and `connect` are the only production
workload TLS constructors:

| Caller | Reporter | Transport |
| --- | --- | --- |
| `proxy/inbound.rs` `accept_profile_tls` | `destination` | inbound HBONE TCP |
| `proxy/pool.rs` `ConnSpawner::new_pool_conn` | `source` | pooled outbound HBONE TCP |
| `proxy/outbound.rs` `proxy_to_double_hbone` | `source` | inner TLS over the outer HBONE stream |

Control-plane TLS (xDS, CA, SPIRE) is not counted.

## Families

All series are exposed at zero from process start. A scraped zero means the
reporter observed no such event. A missing series means a missing scrape target.
Cluster and node come from the scrape target. No principal, UID, namespace or
address label is emitted.

| Family | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `istio_tls_handshakes_total` | counter | `reporter`, `result` | One completed workload TLS handshake. |
| `istio_tls_handshake_duration_seconds` | histogram | `reporter` | Duration of successful handshakes only, including the native peer binding. Buckets 1 ms to 10 s. |
| `istio_tls_connections_active` | gauge | `reporter` | Live verified TLS sessions owned by this process. |

`result` is closed: `success`, `peer_verification_failed`, `protocol_error`,
`timeout`.

## Semantics

1. The observation starts when the transport reaches the rustls acceptor or
   connector. Local preparation before that point (certificate fetch, issuer
   profile lease, TLS configuration) is not a handshake.
2. `success` is recorded only after the verified peer is bound to the current
   issuer-profile lease, approved unfenced signer, CRL coverage and tracked
   revocation receiver.
3. `peer_verification_failed` counts only this reporter's rejection of the peer
   credential: unknown or unapproved issuer, unexpected SAN, fenced signer,
   revocation, missing certificate, or loss of the verification authority
   during the handshake (`AuthorityInvalidated`).
4. A remote peer that rejects this reporter's credential sends an alert. This
   reporter counts `protocol_error`. Malformed TLS, version or cipher mismatch,
   EOF and reset are also `protocol_error`.
5. `timeout` counts the `TLS_HANDSHAKE_TIMEOUT` deadline (default 10 s; zero is
   refused) and transport `ETIMEDOUT`.
6. A cancelled handshake (the owner future is dropped) records nothing.
7. TLS 1.3 completes the client handshake before the server verifies the client
   certificate. A server rejection of a client is recorded at
   `reporter="destination"` only. The client records `success` and then fails
   its first read. Use `destination` for client-identity rejection questions.
8. A pooled HBONE connection performs one handshake. Requests reusing it are
   not handshakes.
9. The active gauge increments when the application TLS owner is created after
   `success`. It decrements when that owner releases the decrypted stream: on
   drop, or immediately when the lease, session, local deadline, CRL coverage or
   revocation receiver invalidates it. A peer EOF does not decrement it until
   the owner drops the stream.

## Queries

- Handshake rate by result: `sum by (cluster, result) (rate(istio_tls_handshakes_total{reporter="destination"}[5m]))`.
- Identity rejections at servers: `sum by (cluster) (rate(istio_tls_handshakes_total{reporter="destination",result="peer_verification_failed"}[5m]))`.
- p95 successful handshake: `histogram_quantile(0.95, sum by (cluster, le) (rate(istio_tls_handshake_duration_seconds_bucket{reporter="destination"}[5m])))`.
- Live sessions counted once: `sum by (cluster) (istio_tls_connections_active{reporter="destination"})`. Do not add `source` and `destination`; that counts each session twice.

Handshakes are distinct from TCP opens (`istio_tcp_connections_opened_total`)
and from HBONE requests. A TCP connection to an uncaptured server has no
handshake.

## Tests

- `tls::handshake::tests`: closed classification; paused-clock deadline;
  cancellation records nothing; completed TLS with a failed binding is
  `peer_verification_failed`.
- `tls::profile_provider::tests::native_tls_handshake_metrics_count_actual_results_at_both_reporters`:
  real sockets and two-cluster issuer profiles; success, unexpected server
  identity, unapproved issuer under the same root, unenrolled client, non-TLS
  bytes, deadline and cancellation at both reporters; assertions read the text
  exposition.
- `tls::profile_provider::tests::native_tls_active_session_gauge_follows_exact_stream_owner`.
- `proxy::pool::test::pooled_reuse_records_one_actual_tls_handshake_per_connection`.
- `tests/namespaced.rs`: captured to captured records one handshake per
  reporter; captured to uncaptured records none while one TCP connection opens;
  `trust_domain_mismatch_rejected` records destination
  `peer_verification_failed` and source `success`.
