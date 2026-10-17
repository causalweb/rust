# Release gates

No registry package or GitHub release has been published yet. `publish = false` intentionally prevents accidental crates.io publication.

A source preview or package release needs:

1. An exact specification commit, vector revision, and compatibility report; never infer compatibility from `0.1` alone.
2. Passing formatting, lint, tests, documentation, fixture-provenance, cross-cryptography, and `node scripts/check-package.mjs` checks on the release commit. The last check must compile/run a separate consumer of the extracted `.crate`; `cargo package` alone is insufficient SDK evidence.
3. A dependency advisory/license review with tool/database versions and unresolved findings recorded. An unavailable or stale advisory source is not a clean audit.
4. Updated changelog, limitations, security channel, and installation instructions that match what is actually distributed.
5. An explicit review of the declared classes. Do not call the source preview a complete Prefix Issuer/Verifier or HTTP agent while adapters and crash tests are missing.
6. Maintainer approval of version, immutable source tag, package contents, name availability, registry ownership, and credentials. Never place tokens in the repository or logs.

Prefer a signed annotated tag when a maintainer signing identity is configured. Record when signing is unavailable rather than inventing a signature. Build packages from the reviewed commit and retain checksums and CI provenance where supported. Do not reserve a registry name with a placeholder package.

Package stability does not promote the protocol. Stable specification status additionally requires the [organization release-readiness evidence](https://github.com/causalweb/spec/blob/main/ROADMAP.md), including independent interoperability, external review, an external pilot, and a recorded maintainer decision.
