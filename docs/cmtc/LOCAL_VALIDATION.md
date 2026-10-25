# CMTC ztunnel development branch

Status: source-tested development work, October 24, 2026. This branch is not an
end-to-end ClusterMesh mTLS release.

Repository: <https://github.com/ephico2real2/ztunnel>

Upstream: <https://github.com/cilium/ztunnel>

Branch: `feat/persistent-inbound-mtls-upstream`

The original source snapshot used Cilium proxy base
`5bb9cf256b10a209ae9bc0624ddfbf27dbc439de` and ended at
`0c244126ab2141474b41191bf24720e82c961482`. This replacement branch starts directly
from upstream `master` at `9a17cb0ff35c20977100de3582c1e4435360f618`, with our
enhancements ported onto that source. The original branch remains available as
`feat/persistent-inbound-mtls`; its older development history was not rewritten.

## Strict authorization rejection qualification

The current local increment rejects malformed CIDRs, overflowing/zero TCP ports,
missing string match types, unsupported extensions and malformed service accounts.
It retains a rejected strict ADS session for at most one second so the queued
NACK reaches the actual TLS peer. The traffic gate stays closed. Corrections on
that stream cannot update state or receive an ACK. Recovery requires a new,
complete session. A workload-specific wildcard DENY overrides a global ALLOW.

The complete ARM64 Podman run passes 515 tests: 465 library, 20 direct and 30
namespace tests, with zero failed, ignored or filtered tests. Formatting and
strict Clippy pass after two test-only initializer corrections. The actual TLS
ADS tests verify NACK delivery, active-flow cancellation, rejected same-stream
correction and fresh recovery. Native quarantine tests verify all application
ports and old or recreated policy references.

The earlier ADS test reproduced a dropped NACK before this fix. Its failure log,
the full passing suite and lint diagnostics are retained in the CMTC repository's
`docs/evidence/native-issuer-profile/live-provider/` ledger. This source increment
has not been deployed. It does not qualify cross-cluster membership, effective
positive authorization, persistent CRL antirollback history or workload mTLS.

## Changes

- Require verified inbound workload peers independently of whether an
  authorization policy has arrived.
- Track xDS session/snapshot generations and hold protected traffic when the
  required configuration is stale or incomplete.
- Bind protected outbound forwarding to its admitted generation and cancel
  tracked flows when the policy watcher invalidates that generation.
- Add failure, reconnect and recovery regressions, including exercising the
  actual policy-watcher transition rather than directly calling `close_all()`.
- Keep large async futures boxed only at task boundaries so cancellation
  remains polled; repair the test service-resource key collision.

## Original snapshot checks

Checks ran on the MacBook's explicit `cmtc-ubuntu-build` Podman connection in a
Linux ARM64 builder using Rust 1.90. The disposable test container needed
`iproute2` and `iptables` for the privileged network-namespace tests. The first
environment failure was retained before installing those prerequisites and
rerunning the full suite.

```sh
cargo test --locked --lib --tests --bins -- --test-threads=1
cargo fmt --all -- --check
cargo clippy --locked --benches --tests --bins -- -D warnings
```

Results:

```text
library:    254 passed; 0 failed; 0 ignored
direct:      20 passed; 0 failed; 0 ignored
namespaced:  26 passed; 0 failed; 0 ignored
total:      300 passed; 0 failed; 0 ignored
format:     passed
Clippy:     passed, warnings denied
git diff --check: passed before commit
```

The binary harness defines no tests; its zero-test result is not included in
the 300-test count. These checks preceded publication, and source files were
not changed between the final successful run and the publication commit.

Original local log SHA-256 digests:

| Log | SHA-256 |
| --- | --- |
| `full-final3.log` | `854443477ec8300f6229366798a40e250390d2380f301265131a35abc26be293` |
| `clippy-final.log` | `f0ea29c44f5440fc122dc4ab9c944a33d8ee04c6a674de56f4bd999c7e20d3f2` |

The original logs remain in `/private/tmp/cmtc-ztunnel-logs/` on the development
host. They are source-test evidence, not deployed-image evidence.

## Fresh port onto current upstream

The new base includes 109 upstream commits beyond the original base, including namespace-aware and
CIDR service lookup, endpoint batching, workload-keyed SPIRE certificates,
resource-version replay, protocol extensions, CRL teardown and new dependency
versions. The port adapts `src/proxy/outbound.rs`, `src/xds.rs` and
`src/xds/client.rs` while keeping the strict session admission and atomic
Address/Authorization rejection behavior.

Merge-specific checks cover:

- Namespace-aware destination lookup without allowing raw TCP passthrough for
  protected exact-IP or CIDR service destinations.
- IPv4/IPv6 prefix rejection before narrowing the protobuf `u32` value; `/256`
  must not wrap to a catch-all `/0`.
- Consistent ordering of workload updates/removals in the batched endpoint
  accumulator and the retained-version cache; deletion must not resurrect an
  endpoint or advertise its old version after reconnect.
- Rejection of a typed-invalid Address response without changing proxy state,
  retained versions or pending waiters; a corrected retry updates them together.
- Per-UID certificate cleanup for SPIRE workloads sharing a principal, while
  preserving the default CA's shared-certificate and same-identity update behavior.

The first local compile found seven test-fixture uses of superseded protobuf
fields and address-lookup arguments. These were repaired, and the subsequent
Linux ARM64 compilation completed. The first diagnostic log is retained as
`upstream-sync-compile-first.log` on the development host.

The first full attempt exposed a non-strict xDS reconnect regression: returning
immediately after queueing a NACK could close the stream before the client saw
it. Ordinary clients now retain the accepted state and await a corrected
response on the same stream; a NACK does not satisfy initial readiness. Strict
clients still revoke their snapshot and reconnect on rejection. The failed run
is retained in `upstream-sync-full.log`. After this repair, all 406 tests passed,
including upstream's normally ignored logging test; Clippy then caught a
duplicated allocator feature attribute, which was removed before the final
verification run. That diagnostic is retained in `upstream-port-first.log`.

Final verification used the MacBook Podman connection `cmtc-ubuntu-build`,
Linux ARM64, Rust 1.90, and builder image ID
`52a5259e139b807a9bcfd42109e269a6eedbfdbe69e52c6fdd42c0010a0768c7`.
The disposable container was privileged for network-namespace tests, limited to
4 CPUs/6 GiB, and installed `iproute2`/`iptables` inside the container.

```sh
cargo fmt --all -- --check
cargo test --locked --lib --tests --bins -- --include-ignored --test-threads=1
cargo clippy --locked --benches --tests --bins -- -D warnings
git diff --check
```

```text
library:    356 passed; 0 failed; 0 ignored; 0 filtered out
direct:      20 passed; 0 failed; 0 ignored; 0 filtered out
namespaced:  30 passed; 0 failed; 0 ignored; 0 filtered out
total:      406 passed; 0 failed; 0 ignored
format:     passed
Clippy:     passed, warnings denied
git diff --check: passed before commit
container command exit status: 0
```

The binary harness has zero tests and is excluded from the count. The full final
log is `/private/tmp/cmtc-ztunnel-logs/upstream-port-full.log`, SHA-256
`9e4aea0c8ddef847e5420f57b20b80d05c44e43c56d4450758caaad3e08462e9`.
This fresh result qualifies the port's source tests; it does not qualify a
deployed image or cross-cluster workload mTLS.

## Remaining qualification

No image from the newest session/draining changes has been deployed or
qualified on the retained `cmtc-a`/`cmtc-b` clusters. Remaining gates include:

- Authenticated remote workload discovery and cryptographic cluster identity
  binding supplied by the Cilium fork.
- Effective Cilium policy compilation and complete, challenge-bound
  Address/Authorization snapshot confirmation.
- Protected unknown-destination behavior, workload-incarnation flow tracking,
  and retirement of pooled HBONE transports.
- Exact-image cross-cluster positive, plaintext-negative, policy loss,
  restart/reconnect and recovery traffic tests.
- Independent WireGuard and IPsec composition, packet evidence and platform
  safety qualification.

Keep Cilium's ClusterMesh/ztunnel compatibility guard closed until its supported
profile passes the corresponding security matrix. A namespace label, SVID,
ACK, passing unit suite or encrypted packet alone cannot establish `Protected`.

Tracking: [CMTC issue #23](https://github.com/ephico2real2/clustermesh-trust-controller/issues/23).
