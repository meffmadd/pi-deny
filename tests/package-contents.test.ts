import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const repositoryRoot = new URL("..", import.meta.url);

describe("npm package contents", () => {
  it("ships the CLI without repository-only content", () => {
    const packed = spawnSync("npm", ["pack", "--dry-run", "--json"], {
      cwd: repositoryRoot,
      encoding: "utf8",
    });
    assert.equal(packed.status, 0, packed.stderr || packed.error?.message);

    const manifests = JSON.parse(packed.stdout) as Array<{
      name: string;
      files: Array<{ path: string; mode: number }>;
    }>;
    assert.equal(manifests.length, 1);
    assert.equal(manifests[0]!.name, "@meffmadd/bash-deny");

    const files = manifests[0]!.files;
    const paths = files.map((file) => file.path);
    for (const required of [
      "LICENSE",
      "README.md",
      "dist/bash-deny.js",
      "package.json",
    ]) {
      assert.ok(paths.includes(required), `missing ${required}\n${paths.join("\n")}`);
    }

    const executable = files.find((file) => file.path === "dist/bash-deny.js");
    assert.ok(executable);
    assert.notEqual(executable.mode & 0o111, 0, "CLI must be executable");

    const builtCli = readFileSync(new URL("../dist/bash-deny.js", import.meta.url), "utf8");
    assert.match(builtCli, /^#!\/usr\/bin\/env node\n(?!#!)/);

    for (const excluded of ["bash-deny", "docs", "scripts", "tests"]) {
      assert.equal(
        paths.some(
          (path) => path === excluded || path.startsWith(`${excluded}/`),
        ),
        false,
        paths.join("\n"),
      );
    }
  });
});
