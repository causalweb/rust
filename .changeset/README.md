# Rust release notes with Changesets

Changesets 3.0.3 tracks crate changes and generates version/changelog updates. The private npm project `@causalweb/rust-release` is only release metadata, not a Rust implementation distributed through npm. Rust consumers still use Cargo; Node.js and Changesets are contributor/release tools, not protocol or crate dependencies.

For every pull request, add a note:

```sh
npm ci --ignore-scripts
npm run changeset
npm run changeset:status
npm run release:check
```

Select `@causalweb/rust-release`. Describe observable changes, compatibility/migration, and limitations. Use patch for compatible fixes and minor for breaking experimental `0.x` APIs or new capabilities; major does not mean protocol maturity. Changesets prerelease arithmetic determines the final number. For documentation/tooling-only changes, use `npm run changeset -- --empty -m "Explain why no crate release is needed"`. Commit the generated note. CI requires a new changeset or an explained empty note relative to the PR base.

Maintainers run `npm run version:prepare` on a review branch. It checks that Cargo, the private version mirror, and npm lock metadata agree and that both publishing switches remain disabled. Changesets calculates the next experimental version and writes the changelog. A small bridge updates only this crate's version in `Cargo.toml` and `Cargo.lock`, refreshes npm lock metadata offline, then rechecks agreement through Cargo. Dependency versions are not updated. Preparation adds an empty note for its own non-feature PR; consumed prerelease notes remain under `.changeset/pre`.

Review the complete diff and run the normal crate/package checks before accepting prepared metadata. `npm run test:release` exercises preparation in an isolated temporary Git repository, verifies the exact crate-only lockfile edit, rejects stable-exit intent and missing notes, and checks that no tag was created. It does not publish a crate or npm package.

Do not use raw `changeset version` as the Rust release procedure: it does not understand Cargo. Do not run `changeset pre exit`, `changeset publish`, or `changeset git-tag` as routine contribution work. The npm metadata always stays private; crate publication, signing, and maturity decisions follow [RELEASING.md](../RELEASING.md). No automatic publication/tagging workflow is configured.

References: [Changesets for non-npm packages](https://changesets.dev/guide/beyond-npm), [configuration](https://changesets.dev/guide/config), [prereleases](https://changesets.dev/guide/prereleases).
