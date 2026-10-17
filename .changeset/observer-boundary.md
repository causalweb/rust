---
"@causalweb/rust-release": minor
---

Replace raw JSON issuance with `CommittedEvidence` and the eight-argument observer call with named `ObservationOptions` plus authorization, clock, and state-reader callbacks. These break the earlier unreleased Git API; see `MIGRATION.md`.

Return local observer failures as `ObservationError<A, R>`, preserving native authorization/read causes and authorization checkpoints. Provide explicit safe ordinary HTTP conversion without private bodies or causal markers. Test the typed API and migration through documentation and an actual packaged-crate consumer. The protocol wire revision remains unchanged and the implementation remains experimental.
