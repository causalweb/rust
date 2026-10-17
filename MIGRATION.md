# Unreleased source API migrations

These changes affect the experimental Rust API, not the protocol wire format, specification pin, or vector revision. No crates.io package or version tag preceded them. Applications using earlier Git revisions must migrate explicitly; a source preview is not a stability commitment.

## Evidence issuance

Replace `issue_committed(&serde_json::Value, now)` with `issue_committed(&CommittedEvidence { ... }, now)`. Use `u64` positions, integral UTC seconds within `MAX_DATE`, an authenticated application subject, explicit audiences/domain, and a globally unique evidence identifier. The issuer constructs the envelope. Do not set `iss`, `alg`, profile, version, or commitment markers yourself.

This does not move commitment into the SDK. A source adapter must establish the durable fact and its recovery information before issuance.

## Observation calls

Replace the first five positional arguments with one `http::ObservationOptions` value:

| Earlier argument | Named field |
| --- | --- |
| request | `request` |
| target | `target` |
| designated observation | `designated_observation` |
| verifier | `verifier` |
| authenticated subject | `authenticated_subject` |

Keep authorization, clock, and state reader as the remaining three arguments. Reuse an options value only while its request, subject, target, and trusted verifier policy remain valid for the exchange. Constructing it performs no authentication.

The authorization callback changes from `bool` to `Result<bool, A>`. Preserve the application's real backend error type instead of converting an outage into denied access. An in-memory/infallible test can use `Ok::<_, std::convert::Infallible>(true)`; production code should call its actual current authorization check.

The reader's error type is no longer restricted to `()`. Remove `.map_err(|_| ())`; preserve the database/adapter error. The SDK imposes no common error type, logging framework, `Send`, or global-lifetime requirement. Its `std::error::Error` implementation is available when both retained error types implement that trait with a static type lifetime.

## Handle local failures before writing HTTP

`observe` returns `Result<Response<Vec<u8>>, ObservationError<A, R>>`:

- `Ok(response)` means the SDK constructed a protocol/ordinary HTTP response. Inspect it; 400, 403, 412, 431, and 503 do not become application success.
- `Err(ObservationError::Authorization { check, source })` retains the original error and whether the check failed before reading or before responding.
- `Err(ObservationError::Read(source))` retains the original reader error.
- Snapshot-target mismatch and invalid representation are local contract defects without a backend cause.

Match/report the error under the application's own redaction policy, then call `into_response()`. It maps authorization/read/target failures to ordinary 503 and invalid representations to ordinary 500. Bodies are empty, cache control is `no-store`, and causal markers/application bytes are absent. A protocol-level causal `failed` outcome is different: it is an indexed result about a verified dependency, not an exception from the reader.

Using `?` is appropriate only when the outer host already handles the resulting error safely. Do not let a framework serialize a raw error or its cause. The [README](README.md) has a compiled handler example; the [archive consumer](tests/consumer/src/main.rs) exercises the actual public types and conversion. This API does not add a network server, cancel synchronous I/O, catch panics, or supply durable storage.
