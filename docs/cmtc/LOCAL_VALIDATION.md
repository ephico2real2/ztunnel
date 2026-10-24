# CMTC ztunnel development branch

Status: source-tested development work, October 24, 2026. This branch is not an
end-to-end ClusterMesh mTLS release.

Repository: <https://github.com/ephico2real2/ztunnel>

Upstream: <https://github.com/cilium/ztunnel>

Branch: `feat/persistent-inbound-mtls`

The branch preserves the tested Cilium proxy base
`5bb9cf256b10a209ae9bc0624ddfbf27dbc439de`. The fork's `master` was created from
current upstream independently; this development branch has not been rebased
onto that newer source.

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

## Local checks

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
