import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cargo = process.platform === "win32" ? "cargo.exe" : "cargo";
const json = path => JSON.parse(readFileSync(join(root, path), "utf8"));
function check() {
  const pkg = json("package.json"), config = json(".changeset/config.json"), pre = json(".changeset/pre.json");
  assert.equal(pkg.private, true, "this is release metadata, never an npm implementation");
  assert.match(pkg.version, /^\d+\.\d+\.\d+-experimental(?:\.\d+)?$/, "only experimental SDK versions are currently approved");
  assert.equal(pre.mode, "pre"); assert.equal(pre.tag, "experimental", "stable promotion requires a separate reviewed decision");
  assert.equal(config.commit, false);
  assert.deepEqual(config.privatePackages, { version: true, tag: false });
  const metadata = JSON.parse(execFileSync(cargo, ["metadata", "--locked", "--offline", "--no-deps", "--format-version", "1"], { cwd: root, encoding: "utf8" }));
  const crate = metadata.packages.find(entry => entry.name === "causalweb");
  assert.ok(crate); assert.deepEqual(crate.publish, [], "crate publishing remains disabled pending maintainer approval");
  assert.equal(crate.version, pkg.version, "Cargo and Changesets versions have drifted");
  const lock = json("package-lock.json");
  assert.equal(lock.version, pkg.version); assert.equal(lock.packages[""].version, pkg.version);
  return crate.version;
}

const command = process.argv[2];
assert.ok(command === "check" || command === "prepare", "usage: npm run release:check or npm run version:prepare");
const before = check();
if (command === "check" && process.env.CAUSALWEB_CHANGESET_BASE) {
  assert.match(process.env.CAUSALWEB_CHANGESET_BASE, /^[a-f0-9]{40}$/);
  execFileSync(process.execPath, [join(root, "node_modules/@changesets/cli/bin.js"), "status", "--since", process.env.CAUSALWEB_CHANGESET_BASE],
    { cwd: root, stdio: "inherit" });
}
if (command === "prepare") {
  assert.ok(process.env.npm_execpath?.endsWith("npm-cli.js"), "use npm run version:prepare");
  execFileSync(process.execPath, [join(root, "node_modules/@changesets/cli/bin.js"), "version"], { cwd: root, stdio: "inherit" });
  const version = json("package.json").version;
  assert.match(version, /^\d+\.\d+\.\d+-experimental(?:\.\d+)?$/);
  // Cargo owns crate metadata. Change exactly this package's version, not dependencies.
  const manifestPath = join(root, "Cargo.toml"), lockPath = join(root, "Cargo.lock");
  const manifest = readFileSync(manifestPath, "utf8"), lock = readFileSync(lockPath, "utf8");
  let manifestCount = 0, lockCount = 0;
  const updatedManifest = manifest.replace(/(^\[package\][\s\S]*?^version\s*=\s*")([^"]+)(")/m, (_, prefix, old, suffix) => {
    assert.equal(old, before); manifestCount++; return `${prefix}${version}${suffix}`;
  });
  const updatedLock = lock.replace(/(^\[\[package\]\]\r?\nname = "causalweb"\r?\nversion = ")([^"]+)(")/m, (_, prefix, old, suffix) => {
    assert.equal(old, before); lockCount++; return `${prefix}${version}${suffix}`;
  });
  assert.equal(manifestCount, 1); assert.equal(lockCount, 1);
  writeFileSync(manifestPath, updatedManifest); writeFileSync(lockPath, updatedLock);
  execFileSync(process.execPath, [process.env.npm_execpath, "install", "--package-lock-only", "--ignore-scripts", "--offline", "--no-audit", "--no-fund"],
    { cwd: root, stdio: "inherit" });
  check();
  execFileSync(process.execPath, [join(root, "node_modules/@changesets/cli/bin.js"), "add", "--empty", "--message", "Release preparation only; prior changesets supply the release notes."],
    { cwd: root, stdio: "inherit" });
}
console.log("Experimental Cargo/Changesets versions agree; nothing published or tagged");
