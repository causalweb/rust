# Causal Web for Rust

Experimental protocol implementation components for [Causal Web](https://github.com/causalweb/spec): signed evidence, dependency evaluation, and HTTP constrained-observation helpers. Rust is an implementation language, not the definition of the protocol.

This repository is not a backend framework, database, or production-ready service. There is no crates.io release yet. The exact specification source is pinned in [SPEC_REVISION](https://github.com/causalweb/rust/blob/main/SPEC_REVISION); fixtures use revision `0.1.4`. The protocol remains `0.1.1-experimental`.

## Run the checks

Install Rust 1.95 or newer, Git, and Node.js 24 for the cross-cryptography check. Then:

```sh
git clone https://github.com/causalweb/rust.git
cd rust
cargo test --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
node scripts/check-package.mjs
```

The last command requires a clean checkout. It builds and verifies the actual `.crate`, then compiles and runs a separate application against Cargo's extracted package, not this checkout's `src` directory. It uses the pinned dependency lockfile and cached dependencies in offline mode. The [consumer application](https://github.com/causalweb/rust/blob/main/tests/consumer/src/main.rs) exercises typed issuance, stale rejection, confirmation, and access denial. It is synthetic and makes no durability claim.

Run a synthetic wire exchange:

```sh
cargo run --locked --example wire_fixture
```

It generates a fresh test key, signs synthetic evidence, rejects a stale state with 412, and confirms a covered state with 200. It prints public test evidence, not the private key. This is an in-process protocol test, **not** a durable source or a real multi-service demonstration. Never configure a deployment to trust these test identities.

The `persistent_source` example is a narrower, POSIX-only development fixture for the TypeScript peer check. It persists a fixed-identity source fact/outbox document before issuing a token, can intentionally stop at that boundary, and can later recover blank entries. Its `--listen` mode exposes only three bounded loopback-test routes (`POST /orders/{order}`, `POST /recover`, and `POST /shutdown`) so the peer can exercise a Rust source HTTP response against a TypeScript observer. The complementary `persistent_observer` fixture verifies TypeScript-issued evidence, persists its response data and frontier in one replaced document, and exposes bounded `POST /deliver`, `POST /terminal`, `POST /unknown`, `GET /orders`, and shutdown routes. `POST /deliver` requires an operator-supplied `CAUSALWEB_DEMO_DELIVERY_CREDENTIAL` bearer credential (at least 32 non-control bytes) and an ES256 JWS created by the test source over the delivered event; the peer proves that missing credentials and an altered payload cannot advance the projection. `POST /terminal` uses the same authenticated test envelope to persist an explicit source position that cannot become observable; a corresponding requirement reports `failed` while already applied positions remain covered. `POST /unknown` simulates loss of the observer's lineage information: all constrained requirements for that source become `unknown` through restart. Separately, the `sqlite_projection` integration test uses two local SQLite files to prove a source fact/outbox transaction and a projection response-bytes/frontier transaction through close/reopen, rollback, duplicate delivery, stale rejection, and confirmation. It is a test experiment, not a packaged database adapter or a power-loss model. The JWS envelope and test routes are application-test mechanisms, not Causal Web protocol fields or recommended event formats. The credential and proof are not persisted and do not provide TLS, authorization, key lifecycle, confidentiality, or a general replay-defense policy. The file fixtures lack `fsync`, durable key storage, TLS, application authorization, a general HTTP parser, concurrency control, and Windows persistent-peer support. They are evidence for narrow test paths, not reusable adapters or production durability claims.

To verify fixture provenance and Rust signatures with Node.js, check out the `spec` commit named in `SPEC_REVISION`, then run:

```sh
node scripts/check-wire.mjs ../spec
```

The command reads the exact pinned Git commit, even if that checkout's branch has advanced, and rejects modified vendored fixtures. It checks cryptographic compatibility, not a second complete implementation.

The development-only `conformance_adapter` example accepts one JSON Lines request from the separate [`causalweb/conformance`](https://github.com/causalweb/conformance) runner and returns its coarse evidence-verification outcome. It is invoked by that runner in CI against the exact profile/vector pins. It is neither a network service nor a complete conformance claim.

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
4. Call `http::observe` with `ObservationOptions`, fallible authorization, a clock, and a callback that reads representation and lineage from one immutable state cut or transaction. A global checkpoint must not approve an older cache entry.
5. The observer returns every indexed outcome when any requirement is not satisfied. An application payload is returned only when all requirements are satisfied.
6. Check `http::accept_confirmation` before exposing a response body. A legacy 200 without confirmation is rejected. Confirmed 404 and 410 retain their application absence semantics.

`Snapshot::new` is a trusted-adapter boundary. Its constructor cannot prove that a database transaction occurred or that an exclusion contract is truthful. Do not build lineage from client fields, wall-clock timestamps, or the largest event merely received.

## Typed source facts

The issuer constructs the protocol claims. Application code supplies a `CommittedEvidence` value rather than JSON:

```rust
use causalweb::evidence::{CommittedEvidence, Issuer};

fn issue_after_commit(issuer: &Issuer, stable_position: u64, evidence_id: &str,
    now: u64, expires_at: u64) -> Result<String, causalweb::Error> {
    issuer.issue_committed(&CommittedEvidence {
        subject: "tenant-42",
        audiences: &["orders-view"],
        domain: "https://source.example/domains/orders/epoch-1",
        position: stable_position,
        issued_at: now,
        expires_at,
        evidence_id,
    }, now)
}
```

Call this only after the storage adapter establishes commitment and recovery. `evidence_id` must be globally unique; an order number or per-domain position is not sufficient on its own. Positions use `u64`, including zero and its maximum value. Dates use integral UTC seconds within `MAX_DATE`. The issuer validates dates, audiences, domain authority, and bounds, but cannot establish database truth.

`Limits::default()` supplies finite local limits: 16 requirements, 16,384 combined field bytes, 8,192 token bytes, 8,192 decoded bytes, and JSON depth 32. Lifetime, clock skew, trust, subject, and authorization remain explicit. Use `cargo doc --open --no-deps` for the API reference.

Source API migration: `issue_committed` previously took `&serde_json::Value`. Replace it with `&CommittedEvidence`; do not supply `iss`, `alg`, `commit`, `profile`, or version markers. This is a breaking change to the unreleased source preview, not a new wire revision. See [CHANGELOG.md](https://github.com/causalweb/rust/blob/main/CHANGELOG.md). No registry package has been released.

## Observer errors belong to the application

`observe` now takes four arguments. `ObservationOptions` names the request, target, verifier, authenticated subject, and endpoint designation. Authorization returns `Result<bool, A>`: `Ok(false)` is denied access, while `Err` means that authorization could not be checked. The state reader returns its own `Result<Snapshot<_>, R>` without converting errors to `()`.

```rust
use causalweb::{http::{observe, ObservationOptions}, prefix::Snapshot};
use http::Response;
use std::io;

fn handle(
    options: ObservationOptions<'_>,
    authorize: impl FnMut() -> Result<bool, io::Error>,
    clock: impl FnMut() -> u64,
    read: impl FnOnce() -> Result<Snapshot<Response<Vec<u8>>>, io::Error>,
) -> Response<Vec<u8>> {
    match observe(options, authorize, clock, read) {
        Ok(response) => response,
        Err(error) => {
            // The application chooses its logger. Only the safe category is logged here.
            eprintln!("observer adapter failure: {}", error.code());
            error.into_response()
        }
    }
}
```

`Ok` is an HTTP response, not a successful observation: it can contain 403, 400/431, or indexed 412/503 causal outcomes. `Err(ObservationError)` is a local adapter or snapshot-contract failure. The original authorization/read error type is preserved for explicit matching or `std::error::Error::source` when those types implement that trait. Authorization errors identify the before-read or before-response check. `Debug`/`Display` omit causes; cause-chain logging can still expose secrets and must use the application's redaction policy.

`into_response()` deliberately discards local diagnostics and produces an empty `no-store` 503, or 500 for an invalid representation, without `Causal-Result` or application bytes. It does not serialize the cause or label a local backend outage as a causal `failed` outcome. Adapter timeouts, cancellation, and unexpected panics belong to the host; this synchronous helper cannot preempt blocked storage I/O. The [migration guide](https://github.com/causalweb/rust/blob/main/MIGRATION.md) covers the earlier eight-argument source API.

## Status and participation

See [CONFORMANCE.md](https://github.com/causalweb/rust/blob/main/CONFORMANCE.md) for tested behavior and unclaimed classes, [SECURITY.md](https://github.com/causalweb/rust/blob/main/SECURITY.md) for deployment risks and private reporting, and [RELEASING.md](https://github.com/causalweb/rust/blob/main/RELEASING.md) for release gates. Design discussion belongs in [organization Discussions](https://github.com/orgs/causalweb/discussions); normative corrections belong in the [specification proposal process](https://github.com/causalweb/spec/tree/main/proposals).

Code and tooling: `Apache-2.0 OR MIT`. Documentation: `CC-BY-4.0`. See [LICENSE.md](https://github.com/causalweb/rust/blob/main/LICENSE.md).
