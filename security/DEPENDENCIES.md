# Dependency review snapshot

Reviewed: 2026-10-18

Scope: the `Cargo.lock` at source-preview commit `a27bd0668ac6d6ef3081e5b143cf5f901bc3cd2a`, SHA-256 `ad803f9a5bb6e2be603922493c4c69f4c0333878a5016eef9743c201444703f2`.

`cargo-audit` 0.22.2 checked 98 lockfile dependencies against RustSec database commit `999ec89d5d3f10f20be14750ec8c2d8b44e0ac9b` (1,338 advisories; database timestamp `2026-10-17T17:23:59+02:00`). It reported zero known vulnerabilities and no informational warnings. The [machine-readable result](rustsec-2026-10-18.json) records the check. New lockfile contents require a new review.

Cargo metadata listed 87 packages, including the root package; every listed package declares license metadata. The dependency set contains MIT/Apache alternatives, BSD-3-Clause, Unlicense alternatives, and a Unicode-3.0 notice conjunction; one package offers MIT/Apache alternatives alongside LGPL-2.1-or-later. This is a metadata review, not a legal compliance certification or an audit of dependency source code. Distributors must retain the notices required by their selected licenses.

The implementation reuses RustCrypto for ECDSA and the `sfv` parser for Structured Fields. Lockfile pins and reviewed action commit SHAs reduce unexpected changes but do not establish that dependencies are free of defects. Registry checksums do not authenticate every upstream maintainer or prevent a malicious future release.

This automated advisory check and founding-author review are **not** an independent security audit. Repeat `cargo audit --json` against a current database before a release; an unavailable database must not be reported as a clean result.

## Development and release tooling

The optional Node.js development project uses `@changesets/cli` 3.0.3 (MIT) and `@biomejs/biome` 2.5.15 (MIT OR Apache-2.0), pinned in `package-lock.json`, SHA-256 `10feea8b220f0db975fcb257d2c396230d6fbfec6c6ae90e914af9cba24aab2c`. Its 49 dependency records, including optional platform binaries, declare 37 MIT, three ISC, and nine MIT OR Apache-2.0 licenses, with none missing license metadata. `npm audit --audit-level=high` on 2026-10-17 reported zero known registry advisories. The dependency count excludes the private root project.

This is development/release tooling, not a Cargo dependency or npm-distributed implementation. Its dependencies and configuration are excluded from the crate archive. Biome checks JavaScript/owned JSON only; rustfmt and Clippy check Rust. The npm registry check is not RustSec coverage, an independent audit, or a legal certification. Repeat it against the reviewed release lockfile and retain applicable notices.
