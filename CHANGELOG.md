# Changelog

## Unreleased

- Replace eight positional observation arguments with `ObservationOptions` plus authorization/clock/read callbacks. Return `Result<Response<_>, ObservationError<A, R>>`, retaining typed adapter causes and authorization checkpoints. This breaks the unreleased observer source API; see `MIGRATION.md`. Safe error conversion preserves ordinary 500/503 responses without causal markers or private bodies.
- Replace the raw-JSON `Issuer::issue_committed` input with `CommittedEvidence`. The issuer owns envelope construction; adapters supply typed stable facts. This breaks the earlier unreleased source API, not the wire format. Callers must migrate as described in the README.
- Add finite `Limits::default()`, full-range typed-position tests, a compiled documentation example, and an external consumer of the verified `.crate` archive on Linux/Windows CI.
- Implement ES256 evidence issuance and strict, bounded verification with explicit trust, subject, and time policy.
- Evaluate prefix dependencies against selected-state component lineage with six outcomes.
- Add HTTP Structured Fields, fail-closed confirmation, ordered problem outcomes, and single-attempt observation helpers.
- Pin and test specification fixtures, including independently signed adversarial evidence.
- Add a synthetic wire example and Node.js signature/provenance check. These are not a real-service durability demonstration.
- Document adapter obligations, unclaimed conformance classes, security, licensing, and release gates.
