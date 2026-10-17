# Dependency review snapshot

Reviewed: 2026-10-17

Scope: the `Cargo.lock` at source-preview commit `4708d1565447da76e9716e0aa65465d26bd0a35d`, SHA-256 `2e491f39051ee78b0c7b45a27284cb74b179748a5918ecec4ad5a571c871f6bb`.

`cargo-audit` 0.22.2 checked 65 lockfile dependencies against RustSec database commit `64f92cdc64401fab47baa10e2e11fe382aa57155` (1,334 advisories; database timestamp `2026-10-17T01:27:42+02:00`). It reported zero known vulnerabilities and no informational warnings. The [machine-readable result](rustsec-2026-10-17.json) records the check. New lockfile contents require a new review.

Cargo package metadata was also inspected for all 65 resolved packages. Every package declares license metadata. The dependency set contains MIT/Apache alternatives, BSD-3-Clause, Unlicense alternatives, and a Unicode-3.0 notice conjunction; `r-efi` offers MIT/Apache alternatives alongside LGPL. This is a metadata review, not a legal compliance certification or an audit of dependency source code. Distributors must retain the notices required by their selected licenses.

The implementation reuses RustCrypto for ECDSA and the `sfv` parser for Structured Fields. Lockfile pins and reviewed action commit SHAs reduce unexpected changes but do not establish that dependencies are free of defects. Registry checksums do not authenticate every upstream maintainer or prevent a malicious future release.

This automated advisory check and founding-author review are **not** an independent security audit. Repeat `cargo audit --json` against a current database before a release; an unavailable database must not be reported as a clean result.
