import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cargo = process.platform === "win32" ? "cargo.exe" : "cargo";
const scratch = mkdtempSync(join(tmpdir(), "causalweb-crate-consumer-"));
try {
  execFileSync(cargo, ["package", "--locked"], { cwd: root, stdio: "inherit" });
  const manifest = JSON.parse(
    execFileSync(cargo, ["metadata", "--no-deps", "--format-version", "1"], {
      cwd: root,
      encoding: "utf8",
    }),
  );
  const entry = manifest.packages.find((p) => p.name === "causalweb");
  const packaged = join(manifest.target_directory, "package", `${entry.name}-${entry.version}`);
  assert.ok(readFileSync(join(packaged, "src", "lib.rs"), "utf8").includes("pub mod evidence;"));
  cpSync(join(root, "tests", "consumer"), scratch, { recursive: true });
  const template = readFileSync(join(scratch, "Cargo.toml"), "utf8");
  writeFileSync(
    join(scratch, "Cargo.toml"),
    template.replace('"__PACKAGED_CRATE__"', JSON.stringify(packaged)),
  );
  cpSync(join(root, "Cargo.lock"), join(scratch, "Cargo.lock"));
  execFileSync(cargo, ["run", "--offline"], { cwd: scratch, stdio: "inherit" });
} finally {
  assert.equal(dirname(scratch), resolve(tmpdir()));
  assert.ok(scratch.startsWith(join(resolve(tmpdir()), "causalweb-crate-consumer-")));
  rmSync(scratch, { recursive: true, force: true });
}
