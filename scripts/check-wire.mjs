import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const spec = process.argv[2];
assert.ok(spec, "usage: node scripts/check-wire.mjs PATH_TO_SPEC_CHECKOUT");
const revision = readFileSync("SPEC_REVISION", "utf8").trim();
assert.match(revision, /^[0-9a-f]{40}$/);
for (const name of [
  "jws-evidence.json",
  "prefix-evaluation.json",
  "http-outcomes.json",
  "evidence-validation.json",
]) {
  const pinned = execFileSync("git", ["-C", spec, "show", `${revision}:test-vectors/${name}`]);
  assert.deepEqual(
    readFileSync(resolve("tests/vectors", name)),
    pinned,
    `${name} differs from pinned specification`,
  );
}

const cargo = process.platform === "win32" ? "cargo.exe" : "cargo";
const fixture = JSON.parse(
  execFileSync(cargo, ["run", "--locked", "--quiet", "--example", "wire_fixture"], {
    encoding: "utf8",
  }),
);
assert.equal(fixture.synthetic_test_fixture, true);
const [header, payload, signature] = fixture.compact.split(".");
const key = createPublicKey({ key: fixture.public_jwk, format: "jwk" });
assert.equal(
  verify(
    "sha256",
    Buffer.from(`${header}.${payload}`),
    { key, dsaEncoding: "ieee-p1363" },
    Buffer.from(signature, "base64url"),
  ),
  true,
);
assert.equal(fixture.stale_status, 412);
assert.equal(fixture.fresh_status, 200);
assert.equal(fixture.confirmed, true);
console.log(
  "four fixture files match the specification pin; Node.js verifies Rust ES256 output; synthetic observer rejects stale state and confirms covered state",
);
