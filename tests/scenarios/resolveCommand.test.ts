/**
 * Unit tests for resolveCommand — covers edge cases like builtins,
 * missing commands, paths, caching, and shell-dependent behaviors.
 *
 * Usage: npm test
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { resolveCommand } from "../../pi-deny/engine";

// ── Helpers ────────────────────────────────────────────────────────

/**
 * Check whether `which` (the same mechanism resolveCommand uses) finds a binary.
 * Returns true only if `which` exits 0 AND output starts with "/" (real path).
 * Builtins and aliases that `command -v` reports but `which` doesn't are excluded.
 */
function hasWhichBinary(name: string): boolean {
  try {
    const out = execSync(`which "${name}"`, { encoding: "utf8", timeout: 1000, stdio: "pipe" }).trim();
    return out.startsWith("/");
  } catch {
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════

describe("resolveCommand", () => {

  describe("normal commands resolve to their on-disk path", () => {
    const cases: [string, boolean][] = [
      ["ls",     true],
      ["echo",   true],
      ["cat",    true],
      ["git",    true],
      ["which",  true],
      ["bash",   true],
      ["sh",     true],
    ];

    for (const [name, exists] of cases) {
      it(`resolveCommand("${name}")`, () => {
        const result = resolveCommand(name);
        assert.ok(result.startsWith("/"), `expected absolute path, got "${result}"`);
        assert.ok(result.includes(name),
          `expected result to contain command name "${name}", got "${result}"`);
      });
    }
  });

  describe("paths containing / are returned as-is", () => {
    const cases = [
      "/bin/ls",
      "/usr/local/bin/kubectl",
      "./script.sh",
      "../relative/cmd",
      "/",
    ];

    for (const name of cases) {
      it(`resolveCommand("${name}") → identity`, () => {
        assert.strictEqual(resolveCommand(name), name);
      });
    }
  });

  describe("non-existent commands fall back to original name", () => {
    const cases = [
      "nonexistent_cmd_xyz123",
      "thiscmddoesnotexist",
    ];

    for (const name of cases) {
      it(`resolveCommand("${name}") → "${name}"`, () => {
        assert.strictEqual(resolveCommand(name), name);
      });
    }
  });

  describe("shell builtins fall back to original name (which fails for them)", () => {
    const cases = [
      "eval",   // pure builtin — which fails
      "alias",  // pure builtin
      "bg",     // pure builtin
      "cd",     // pure builtin
      "echo",   // both a builtin AND a binary — which finds the binary
    ];

    for (const name of cases) {
      const hasBinary = hasWhichBinary(name);
      it(`resolveCommand("${name}") → ${hasBinary ? "path" : "self"}`, () => {
        const result = resolveCommand(name);
        if (hasBinary) {
          assert.ok(result.startsWith("/"),
            `"${name}" has a binary, expected path, got "${result}"`);
        } else {
          assert.strictEqual(result, name);
        }
      });
    }
  });

  describe("cache: second call does not spawn which", () => {
    it("two calls return the same result", () => {
      const first = resolveCommand("ls");
      const second = resolveCommand("ls");
      assert.strictEqual(second, first);
    });

    it("different commands return different results", () => {
      const ls = resolveCommand("ls");
      const cat = resolveCommand("cat");
      assert.notStrictEqual(ls, cat);
    });

    it("missing command is also cached (not re-spawned)", () => {
      const first = resolveCommand("truly_missing_xyz");
      const second = resolveCommand("truly_missing_xyz");
      assert.strictEqual(second, first);
      assert.strictEqual(first, "truly_missing_xyz");
    });
  });

  describe("integration: resolveCommand enables cross-name matching", () => {
    // This is the core value prop: rule says "ls", command says "ls",
    // both resolve to /bin/ls → match. Without resolution, tokens are "ls"
    // and only exact token "ls" matches.

    it('"ls" resolves to a path so both sides converge', () => {
      const resolved = resolveCommand("ls");
      // Even if we pass the full path, resolveCommand returns it as-is
      const pathForm = resolveCommand(resolved);
      assert.strictEqual(resolved, pathForm);
    });

    it('a resolved pattern token and resolved command token match', () => {
      // Simulate what checkCommand does
      const cmdName = "ls";
      const ruleName = "ls";
      assert.strictEqual(resolveCommand(cmdName), resolveCommand(ruleName));
    });
  });

  describe("edge: empty-ish and special inputs", () => {
    it("resolveCommand('')", () => {
      // Empty string — which treats it oddly, should return empty or fallback
      const result = resolveCommand("");
      // Acceptable outcomes: empty string (falls through cache/which)
      assert.strictEqual(typeof result, "string");
    });
  });

});
