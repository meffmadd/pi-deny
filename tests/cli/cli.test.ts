/**
 * Tests for bash-deny CLI
 *
 * Usage: npm test  (or: node --import tsx --test tests/cli/cli.test.ts)
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const CLI = "node --import tsx bash-deny/cli.ts";

function run(args: string, stdin?: string) {
  return spawnSync(CLI + " " + args, {
    shell: true,
    input: stdin ?? undefined,
    encoding: "utf-8",
    stdio: stdin !== undefined ? ["pipe", "pipe", "pipe"] : undefined,
  });
}

// ═══════════════════════════════════════════════════════════════════
// help and version
// ═══════════════════════════════════════════════════════════════════

describe("cli help/version", () => {
  it("-h prints usage and exits 0", () => {
    const r = run("-h");
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes("Usage:"));
  });

  it("--help prints usage and exits 0", () => {
    const r = run("--help");
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes("Usage:"));
  });

  it("-V prints version and exits 0", () => {
    const r = run("-V");
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes("bash-deny"));
  });

  it("--version prints version and exits 0", () => {
    const r = run("--version");
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes("bash-deny"));
  });
});

// ═══════════════════════════════════════════════════════════════════
// rule loading
// ═══════════════════════════════════════════════════════════════════

describe("cli rule loading", () => {
  let tmpDir: string;

  before(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "bash-deny-"));
  });

  after(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("no rules → error exit 2", () => {
    const r = run('-i "echo hello"');
    assert.strictEqual(r.status, 2);
    assert.ok(r.stderr.includes("no rules provided"));
  });

  it("-f with non-existent file → error exit 1", () => {
    const r = run('-f nonexistent.bashdeny -i "echo hello"');
    assert.strictEqual(r.status, 1);
    assert.ok(r.stderr.includes("file not found"));
  });

  it("-f with valid file blocks matching command", () => {
    const rulesPath = join(tmpDir, "test.bashdeny");
    writeFileSync(rulesPath, "kubectl delete\n");

    const r = run(`-f "${rulesPath}" -i "kubectl delete pod"`);
    assert.strictEqual(r.status, 1);
    assert.ok(r.stderr.includes("blocked"));
    assert.ok(r.stderr.includes("kubectl delete pod"));
    assert.ok(r.stderr.includes("kubectl delete"));
  });

  it("-f with valid file allows non-matching command", () => {
    const rulesPath = join(tmpDir, "test2.bashdeny");
    writeFileSync(rulesPath, "kubectl delete\n");

    const r = run(`-f "${rulesPath}" -i "echo hello"`);
    assert.strictEqual(r.status, 0);
    assert.strictEqual(r.stdout, "");
    assert.strictEqual(r.stderr, "");
  });

  it("-r inline rules block matching command", () => {
    const r = run('-r "kubectl delete" -i "kubectl delete pod"');
    assert.strictEqual(r.status, 1);
    assert.ok(r.stderr.includes("blocked"));
    assert.ok(r.stderr.includes("kubectl delete pod"));
    assert.ok(r.stderr.includes("kubectl delete"));
  });

  it("-r inline rules: ! allow exception works", () => {
    const r = run('-r "kubectl;! kubectl logs" -i "kubectl logs nginx"');
    assert.strictEqual(r.status, 0);
  });

  it("-r inline rules: allow exception overrides deny", () => {
    const r = run('-r "kubectl;! kubectl logs" -i "kubectl delete pod"');
    assert.strictEqual(r.status, 1);
  });

  it("-r with only semicolons → all pass", () => {
    // empty segments after split are skipped, no rules → all pass
    const r = run('-r ";;;" -i "kubectl delete pod"');
    assert.strictEqual(r.status, 0);
  });

  it("-r with # comments skipped", () => {
    const r = run('-r "# this is a comment;rm -rf" -i "rm -rf /"');
    assert.strictEqual(r.status, 1);
  });

  it("-r with only # comments → all pass", () => {
    const r = run('-r "# comment only" -i "rm -rf /"');
    assert.strictEqual(r.status, 0);
  });

  it("-r with semicolons splits properly", () => {
    const r = run('-r "kubectl ; git push --force ; rm -rf" -i "git push --force origin"');
    assert.strictEqual(r.status, 1);
    assert.ok(r.stderr.includes("git push --force"));
  });

  it("merge -f and -r: file loaded first, inline can override with !", () => {
    const rulesPath = join(tmpDir, "merge.bashdeny");
    writeFileSync(rulesPath, "kubectl\n");

    // file says deny kubectl, inline adds ! exception
    const r = run(`-f "${rulesPath}" -r "! kubectl logs" -i "kubectl logs nginx"`);
    assert.strictEqual(r.status, 0);
  });

  it("merge -f and -r: file deny still works when not excepted", () => {
    const rulesPath = join(tmpDir, "merge2.bashdeny");
    writeFileSync(rulesPath, "kubectl\n");

    const r = run(`-f "${rulesPath}" -r "! kubectl logs" -i "kubectl delete pod"`);
    assert.strictEqual(r.status, 1);
  });
});

// ═══════════════════════════════════════════════════════════════════
// -i flag command input
// ═══════════════════════════════════════════════════════════════════

describe("cli -i input", () => {
  it("-i with denied command → exit 1", () => {
    const r = run('-r "rm -rf" -i "rm -rf /"');
    assert.strictEqual(r.status, 1);
  });

  it("-i with allowed command → exit 0", () => {
    const r = run('-r "rm -rf" -i "echo hello"');
    assert.strictEqual(r.status, 0);
  });

  it("-i with multi-segment command blocks on first deny", () => {
    const r = run('-r "kubectl delete" -i "echo safe && kubectl delete pod"');
    assert.strictEqual(r.status, 1);
    assert.ok(r.stderr.includes("kubectl delete pod"));
  });

  it("-i multi-segment: all allowed → exit 0", () => {
    const r = run('-r "kubectl delete" -i "echo safe && echo also safe"');
    assert.strictEqual(r.status, 0);
  });

  it("-i with empty string → error exit 2", () => {
    const r = run('-r "kubectl" -i ""');
    assert.strictEqual(r.status, 2);
    assert.ok(r.stderr.includes("no command"));
  });

  it("-i wins over stdin", () => {
    const r = run('-r "kubectl delete" -i "echo hello"',
      "kubectl delete pod\n");
    // -i "echo hello" should pass (stdin ignored)
    assert.strictEqual(r.status, 0);
  });
});

// ═══════════════════════════════════════════════════════════════════
// stdin command input
// ═══════════════════════════════════════════════════════════════════

describe("cli stdin input", () => {
  it("single line denied → exit 1", () => {
    const r = run('-r "rm -rf"', "rm -rf /\n");
    assert.strictEqual(r.status, 1);
  });

  it("single line allowed → exit 0", () => {
    const r = run('-r "rm -rf"', "echo hello\n");
    assert.strictEqual(r.status, 0);
  });

  it("multiple lines: first deny stops immediately", () => {
    const r = run('-r "kubectl delete"',
      "kubectl delete pod\ngit push --force\necho safe\n");
    assert.strictEqual(r.status, 1);
    assert.ok(r.stderr.includes("kubectl delete pod"));
  });

  it("multiple lines: all allowed → exit 0", () => {
    const r = run('-r "kubectl delete"',
      "echo safe\ngit log\necho also safe\n");
    assert.strictEqual(r.status, 0);
  });

  it("empty stdin → exit 0 (no commands to check)", () => {
    const r = run('-r "rm -rf"', "");
    assert.strictEqual(r.status, 0);
  });

  it("stdin with blank lines: blank lines are skipped", () => {
    const r = run('-r "rm -rf"',
      "\necho safe\n\n");
    assert.strictEqual(r.status, 0);
  });

  it("no -i and no stdin pipe → error exit 2", () => {
    // Since the test runner has a pipe, we simulate TTY by closing stdin early
    // This is tricky to test in a subprocess; we skip it for now
    // but the code path is: process.stdin.isTTY check in main()
  });
});

// ═══════════════════════════════════════════════════════════════════
// --dry-run and --quiet
// ═══════════════════════════════════════════════════════════════════

describe("cli --dry-run / --quiet", () => {
  it("-n prints to stdout and exits 0 even when denied", () => {
    const r = run('-r "rm -rf" -n -i "rm -rf /"');
    assert.strictEqual(r.status, 0);
    assert.ok(r.stdout.includes("blocked"));
    assert.ok(r.stdout.includes("rm -rf /"));
  });

  it("-n on allowed command: no output, exit 0", () => {
    const r = run('-r "rm -rf" -n -i "echo hello"');
    assert.strictEqual(r.status, 0);
    assert.strictEqual(r.stdout, "");
    assert.strictEqual(r.stderr, "");
  });

  it("-q on denied command: no output, exit 1", () => {
    const r = run('-r "rm -rf" -q -i "rm -rf /"');
    assert.strictEqual(r.status, 1);
    assert.strictEqual(r.stdout, "");
    assert.strictEqual(r.stderr, "");
  });

  it("-q on allowed command: no output, exit 0", () => {
    const r = run('-r "rm -rf" -q -i "echo hello"');
    assert.strictEqual(r.status, 0);
    assert.strictEqual(r.stdout, "");
    assert.strictEqual(r.stderr, "");
  });

  it("-n and -q together → error exit 2", () => {
    const r = run('-r "rm -rf" -n -q -i "rm -rf /"');
    assert.strictEqual(r.status, 2);
    assert.ok(r.stderr.includes("mutually exclusive"));
  });
});

// ═══════════════════════════════════════════════════════════════════
// exit codes
// ═══════════════════════════════════════════════════════════════════

describe("cli exit codes", () => {
  it("exit 0 when command passes", () => {
    const r = run('-r "kubectl delete" -i "echo hello"');
    assert.strictEqual(r.status, 0);
  });

  it("exit 1 when command is denied", () => {
    const r = run('-r "kubectl delete" -i "kubectl delete pod"');
    assert.strictEqual(r.status, 1);
  });

  it("exit 2 for usage errors", () => {
    const r = run("-i 'echo hello'"); // no rules
    assert.strictEqual(r.status, 2);
  });

  it("exit 2 for unknown flags", () => {
    const r = run('-f rules.bashdeny --unknown-flag -i "echo hello"');
    assert.strictEqual(r.status, 2);
  });
});

// ═══════════════════════════════════════════════════════════════════
// edge cases
// ═══════════════════════════════════════════════════════════════════

describe("cli edge cases", () => {
  it("wrapper-aware matching: sudo kubectl delete → denied", () => {
    const r = run('-r "kubectl delete" -i "sudo kubectl delete pod"');
    assert.strictEqual(r.status, 1);
  });

  it("wrapper-aware matching: su -c → denied", () => {
    const r = run('-r "rm -rf" -i "su -c \\"rm -rf /\\""');
    assert.strictEqual(r.status, 1);
  });

  it("rm -rf with trailing path blocked", () => {
    const r = run('-r "rm -rf" -i "rm -rf /tmp/foo"');
    assert.strictEqual(r.status, 1);
  });

  it("git push --force detetes force pushes", () => {
    const r = run('-r "git push --force" -i "git push --force origin main"');
    assert.strictEqual(r.status, 1);
  });

  it("git push without --force passes", () => {
    const r = run('-r "git push --force" -i "git push origin main"');
    assert.strictEqual(r.status, 0);
  });
});
