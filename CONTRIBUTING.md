# Contributing

Read the [specification](https://github.com/causalweb/spec) and [conformance report](CONFORMANCE.md) before changing behavior. Add regression cases for trust boundaries, invalid input, expiry, stale state, and failures, not just success.

Normative corrections belong in a public specification proposal; do not silently redefine semantics in Rust. Vendored fixtures must remain byte-for-byte identical to the commit in `SPEC_REVISION`. Update the pin and CI checkout together after a reviewed specification change.

Run `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`, and the Node.js wire/provenance check before requesting review. Explain any storage or transport assumption a new adapter needs and provide failure-injection evidence before claiming its conformance class.

Install development tooling with `npm ci --ignore-scripts`. Run `npm run check` for the pinned Biome formatter/linter and import-order checks on JavaScript and owned JSON. Warnings fail the check. `npm run format` applies formatting only; review lint fixes separately. Rust uses rustfmt and Clippy, not Biome. Also run `rustfmt --edition 2024 --check tests/consumer/src/main.rs`, since the isolated consumer is outside the root Cargo package. CI runs these checks on Linux and Windows. Vendored vectors, advisory snapshots, generated lockfiles/build output, and nested checkouts are not reformatted; provenance checks remain mandatory.

Use the [Changesets workflow](.changeset/README.md) for release notes. Each PR includes a new changeset, or an explained empty note when no SDK release is needed. Install release tooling with `npm ci --ignore-scripts`, then run `npm run changeset`, `npm run release:check`, and `npm run test:release`. The npm manifest is a private Cargo-version mirror, not a runtime dependency or an npm implementation. Do not manually add new release entries to `CHANGELOG.md`.

Use [organization Discussions](https://github.com/orgs/causalweb/discussions) for design and experiments. Report concrete implementation defects in this repository's issues. Security issues follow [SECURITY.md](SECURITY.md). The [community conduct policy](https://github.com/causalweb/.github/blob/main/CODE_OF_CONDUCT.md) applies.

Submit only contributions you have the right to provide under the [applicable licenses](LICENSE.md), retain attribution, and do not add production credentials or private test keys. No copyright assignment is requested.
