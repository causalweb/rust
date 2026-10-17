# Implementation and conformance report

Status: Experimental, source preview; no complete deployment conformance claim

Specification: `0.1.1-experimental`, exact commit in [SPEC_REVISION](SPEC_REVISION). Vector revision: `0.1.2`. The independent runner revision is pinned in [CONFORMANCE_REVISION](CONFORMANCE_REVISION). A passing fixture is evidence for that scenario, not certification of an entire class.

The `conformance_adapter` example implements the separate [`causalweb/conformance`](https://github.com/causalweb/conformance) runner's experimental JSON Lines profiles. It runs the 32-case evidence-verification profile through this library's verifier, the 17-case prefix-evaluation profile through its verifier, exact position parser, and `Snapshot` lineage evaluator, and the 11-case HTTP client-confirmation profile through the public HTTP parsing and confirmation APIs. The prefix profile explicitly excludes its three context-reduction cases because this library does not expose a Core Carrier reducer. The HTTP profile explicitly excludes cross-origin redirect forwarding because that requires an HTTP agent. The adapter does not expose local validation diagnostics, receive network trust, or establish full protocol conformance.

## Implemented and tested

| Area | Evidence | Boundary |
| --- | --- | --- |
| JWS evidence | All six baseline and 26 security fixtures; fresh Rust issuance verified by Node.js crypto | Fixed ES256 policy and locally configured keys only. Unknown protected header parameters are rejected by local policy. |
| Claims | Exact URI-string trust matching, per-issuer domain authority, audience and subject binding, exact integral NumericDates, expiry boundary, lifetime/skew, duplicate names at every depth | Subject binding is exact equality to an already authenticated application partition. No permissive default or remote key discovery. |
| Prefix evaluation | All twenty repository fixtures; 17 selected cases also pass through the shared independent runner, including bottom versus zero, uint64 boundaries, stale cuts, composite minimum, exclusions, failures, and expiry precedence | The three context-reduction fixtures are explicitly outside the shared evaluator profile. Representation and lineage are supplied by a trusted adapter. No durable projection adapter is included yet. |
| Carrier | Evidence bytes and duplicate input indices preserved; context reduction is not performed | Retaining all input is allowed by the profile. Limits report errors rather than silently dropping input. |
| HTTP | Twelve response fixtures, request parsing/limits, invalid-input-before-read, indexed outcomes, current authorization and expiry rechecks, confirmation/cache fields; 11 selected client-confirmation cases pass through the shared runner | The profile excludes cross-origin redirect forwarding because these helpers are not an HTTP agent. Network, TLS, CORS, CSRF, trailers, routing, cancellation, and ordinary preconditions belong to the integration. |

The SDK tests also exercise typed issuance at zero and the maximum uint64 position, invalid source facts, retained authorization/read error types, both authorization checkpoints, local snapshot-contract failures, redacted error formatting, and explicit safe HTTP conversion. Twenty-three integration-test functions and three compiled documentation examples pass locally. A separate application consumes the verified `.crate` archive and exercises the public error API. These checks concern SDK usability and packaging, not a complete deployment class. The committed CI workflow tests Linux and Windows using Rust 1.95; refer to the run on the exact reviewed commit for results.

The [TypeScript implementation](https://github.com/causalweb/typescript) now implements the wire rules independently. Its development peer check verifies actual signed evidence and HTTP field strings in both directions against an exact Rust commit. The current peer pin and result belong to that repository; do not infer them from the latest Rust branch. On Linux, the peer checks Rust local source-outbox interruption/recovery before TypeScript validates recovered evidence, then exchanges a Rust source `POST /orders/{order}` with a TypeScript observer that moves from a stale result to confirmation. In the reverse direction it starts a TypeScript source and this fixture's Rust observer as separate loopback processes with separate persisted documents; it checks stale rejection, propagation, source and observer restart, out-of-order and duplicate delivery, forged evidence rejection, and source outbox recovery before confirmation. The [exact peer CI run](https://github.com/causalweb/typescript/actions/runs/39050399189) is green. This is bounded file-backed test evidence, not a persistent HTTP-service deployment or independent external review.

## Deliberately not claimed

- **Prefix Issuer:** no reusable durable source log/outbox adapter or storage fault-model report exists. The POSIX test fixture covers one local file and injected pre-issuance interruption only. The signer requires a caller-established commitment point and caller-managed globally unique `jti` values. It cannot prove their truth or uniqueness.
- **Prefix Verifier:** no reusable durable projection/frontier transaction or process-crash recovery test exists. The file-backed fixture exercises logical restart only. A false snapshot supplied by an adapter can cause false satisfaction.
- **Complete HTTP Server or Client:** no network adapter, streaming/cancellation integration, browser CORS verification, full conditional-request integration, or default redirect policy for an actual HTTP agent yet. The helpers themselves do not perform redirects or network requests.
- **Durable independent-service interoperability:** the peer has file-backed loopback evidence in both directions, but no transactional, authenticated, deployable source-to-projection service or process/power-loss recovery demonstration exists. Node.js crypto alone would only be a signature cross-check.
- **Production readiness or security audit:** no external audit, external pilot, comprehensive fuzz campaign, load characterization, or stability commitment.

## Operational policy

Every verifier configures positive byte/count/depth limits and a positive maximum evidence lifetime. There are no implicit trusted issuers, domains, audiences, or subjects. Clock skew is explicit; tests use zero unless stated. UTC seconds determine expiry only, never causal coverage. Waiting is disabled and discovery reports zero maximum wait.

Trust is immutable during an exchange. Construct a verifier from the current trusted policy for each request or ensure an equivalent policy snapshot remains authorized through response commitment. Do not reuse `VerifiedEvidence` across policy changes. Key retirement, emergency revocation, durable history epochs, frontier repair, and log redaction remain deployment obligations.

This repository cannot declare a universal storage fault model. A future adapter report must state its storage guarantees, commitment point, propagation recovery, target/schema/contract binding, and tests around both sides of the projection commit boundary before claiming a deployment class.
