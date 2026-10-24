# Cluster-bound issuer verification foundation

Local source qualification, October 24, 2026. This increment adds an experimental `tls::domain_anchors` helper. It is not wired to the active TLS verifiers, SPIRE bundle consumption, authorization evaluator or HBONE pools. The ClusterMesh compatibility guard remains unchanged. No live mTLS or Protected claim follows.

The guided Cursor Grok 4.7 Extra High proposals supplied the design and complete code/test candidates. Primary and independent review rejected unsafe policy replacement, independently supplied pin metadata, same-key certificate substitutions, write-half-only shutdown and incomplete withdrawal semantics. The implemented smaller module incorporates the corrected reviewer candidate and primary tests rather than accepting the proposed integration wholesale.

## Implemented scope

- Private certificate-derived SPKI and validity, strict full DER consumption, duplicate/unsupported extension checks, CA and signing-key-usage checks.
- An explicitly configured organizational root approves directly signed cluster intermediates; root signature alone does not authorize assignment of a domain. That entire profile still requires authenticated administrative/CMTC provenance.
- Separate domains select separate approved intermediates. Tests show ordinary shared-root verification succeeds for a foreign signer while the issuer screen rejects it.
- Canonical approved certificate bytes, exact single supported URI SAN and direct issuer only; reject substituted certificates, extra/malformed SANs and delegated CA paths.
- Verified peer evidence binds actual signer, generation and minimum leaf/authority/root expiry. Full-snapshot removals create withdrawal tombstones. Explicit restore cannot revive old retained evidence.
- Socket helper uses full-duplex shutdown; it is not a running relay/pool supervisor.

## Local qualification

Pinned ARM64 Rust 1.90, AWS-LC default feature profile, host Podman connection `cmtc-ubuntu-build`:

- 370 library tests, 20 direct tests, 30 namespace tests: **420 passed, zero failed/ignored**. The 14 new issuer tests actually ran.
- `cargo fmt --all -- --check` passes.
- `cargo clippy --locked --benches --tests --bins -- -D warnings` passes.

The first broad run used the compile-only builder without `ip`/`iptables` and failed 19 namespace-dependent cases, with one ignored case. The original failure log is retained. A reusable tool-complete test builder was then built, namespace creation and iptables were preflighted, and the complete suite reran with `--include-ignored`. Its image configuration ID is `def7f2e8dac02fbe34556331944cd766aa7f2ea9b90784f083634d52b59edb0f`.

Exact commands, exit status and raw logs remain under `/private/tmp/cmtc-rebuild-20261024/`: `qualify-domain-anchors.sh`, `domain-anchors-first.log`, `domain-anchors-full.log` (failed diagnostic), `domain-anchors-qualified.log`, `domain-anchors-qualified.exit`, and `ztunnel-netns-builder.{json,log}`. The reusable test Containerfile is `/private/tmp/cmtc-ztunnel-netns-builder/Containerfile`.

## Required integration gates

Preserve existing CRL validation when wiring the issuer helper; its current wrappers screen issuer paths with no CRLs. Peer-only evidence does not cover the connection's own credential withdrawal/expiry. Recheck current publication atomically after the handshake; a stale cloned profile must not admit a new flow. Add authenticated profile freshness and anti-rollback persistence, active relay cancellation, both HBONE layers and pool eviction. Effective policy must retain every native predicate and DENY precedence. Complete native remote discovery, kernel admission/restore fencing and exact-image positive/negative/recovery traffic before enabling ClusterMesh. No image or runtime acceptance is established by this source test report.
