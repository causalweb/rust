# Causal Web for Rust

Experimental protocol implementation components for [Causal Web](https://github.com/causalweb/spec): signed evidence, dependency evaluation, and HTTP constrained-observation helpers. Rust is an implementation language, not the definition of the protocol.

This repository is not a backend framework, database, or production-ready service. There is no crates.io release yet. The exact specification source is pinned in [SPEC_REVISION](SPEC_REVISION); fixtures use revision `0.1.2`. The protocol remains `0.1.1-experimental`.

## Run the checks

Install Rust 1.95 or newer, Git, and Node.js 24 for the cross-cryptography check. Then:

```sh
git clone https://github.com/causalweb/rust.git
cd rust
cargo test --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
```

Run a synthetic wire exchange:

```sh
cargo run --locked --example wire_fixture
```

It generates a fresh test key, signs synthetic evidence, rejects a stale state with 412, and confirms a covered state with 200. It prints public test evidence, not the private key. This is an in-process protocol test, **not** a durable source or a real multi-service demonstration. Never configure a deployment to trust these test identities.

To verify fixture provenance and Rust signatures with Node.js, check out the `spec` commit named in `SPEC_REVISION`, then run:

```sh
node scripts/check-wire.mjs ../spec
```

The command reads the exact pinned Git commit, even if that checkout's branch has advanced, and rejects modified vendored fixtures. It checks cryptographic compatibility, not a second complete implementation.

## Components

| Module | Behavior | Integration responsibility |
| --- | --- | --- |
| `evidence::Issuer` | Emits ES256 JWS with validated common claims and prefix positions | Commit a stable fact and its propagation recovery information first; allocate stable positions and globally unique evidence IDs. |
| `evidence::Verifier` | Enforces canonical encoding, unique JSON names at every depth, ES256, exact issuer/domain authority, audience, subject, version, and time policy | Supply trusted keys, domains, current authenticated subject, clock, lifetime, skew, and finite limits. |
| `prefix` | Distinguishes six outcomes against every relevant component of a selected state | Construct `Snapshot` from the exact representation and crash-safe lineage; authorize contract/schema-specific exclusions. |
| `http` | Parses RFC 9651 fields, checks requirements before reading, rechecks authorization/expiry, emits fail-closed responses and capabilities | Supply a designated finite observation, authenticated transport, current access checks, and a state reader. |

The library does not fetch keys, follow redirects, perform network I/O, or wait for progress. It advertises `max_wait_seconds: 0`; `Prefer: wait` is ignored. A client can retry a 412 under its own bounded policy. No dependency is silently discarded, compacted across domains, or rewritten.

## Safe integration sequence

1. Commit the source operation and recovery/outbox fact under a documented storage fault model. Only then call `Issuer::issue_committed`. Signing does not prove commitment.
2. Preserve the returned evidence bytes. Use `http::request_headers` for a constrained observation; it adds `no-cache, no-store`.
3. Authorize the target through the application's existing authentication system. Evidence is not access authorization.
4. Call `http::observe` with a callback that reads representation and lineage from one immutable state cut or transaction. A global checkpoint must not approve an older cache entry.
5. The observer returns every indexed outcome when any requirement is not satisfied. An application payload is returned only when all requirements are satisfied.
6. Check `http::accept_confirmation` before exposing a response body. A legacy 200 without confirmation is rejected. Confirmed 404 and 410 retain their application absence semantics.

`Snapshot::new` is a trusted-adapter boundary. Its constructor cannot prove that a database transaction occurred or that an exclusion contract is truthful. Do not build lineage from client fields, wall-clock timestamps, or the largest event merely received.

## Status and participation

See [CONFORMANCE.md](CONFORMANCE.md) for tested behavior and unclaimed classes, [SECURITY.md](SECURITY.md) for deployment risks and private reporting, and [RELEASING.md](RELEASING.md) for release gates. Design discussion belongs in [organization Discussions](https://github.com/orgs/causalweb/discussions); normative corrections belong in the [specification proposal process](https://github.com/causalweb/spec/tree/main/proposals).

Code and tooling: `Apache-2.0 OR MIT`. Documentation: `CC-BY-4.0`. See [LICENSE.md](LICENSE.md).
