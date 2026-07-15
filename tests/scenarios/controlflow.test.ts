/**
 * Control-flow red-team tests for bash-deny.
 *
 * These verify the parser (parser.ts) walks *into* control-flow constructs —
 * for / while / until / if / case / subshell / brace group — and finds the
 * leaf `simple_command`s hidden inside them, so deny rules get a chance to
 * match. This is the §8.3 suite from parser.md.
 *
 * Every attempt here has the dangerous command as an *actual leaf* (not quoted,
 * not inside `eval`, not in a `$var`, not inside `$(...)`). Those other bypass
 * techniques are opaque word content by design (parser.md §2) and are covered
 * by `redteam.test.ts`. Here we only test that control flow is no longer a
 * hiding place.
 *
 * Each attempt is validated with `sh -n -c` to confirm bash itself accepts the
 * syntax — if bash rejects it, the test is a data error, not an engine bypass.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseFile } from "../../bash-deny/engine";
import { checkCommandDeep } from "../../bash-deny/parser";
import { assertShSyntax } from "../utils";

// ── Load test rules ────────────────────────────────────────────────

const rulesPath = join(import.meta.dirname, "controlflow.bashdeny");
const rules = parseFile(readFileSync(rulesPath, "utf8"));

// ═══════════════════════════════════════════════════════════════════
// Attempts — every one MUST be blocked by checkCommandDeep.
// ═══════════════════════════════════════════════════════════════════

interface Attempt {
  technique: string;
  cmd: string;
}

const attempts: Attempt[] = [
  { technique: "for loop",       cmd: "for x in a b; do rm -rf $x; done" },
  { technique: "while loop",     cmd: "while read x; do rm -rf $x; done" },
  { technique: "if branch",      cmd: "if true; then rm -rf /; fi" },
  { technique: "subshell",       cmd: "( rm -rf / )" },
  { technique: "brace group",    cmd: "{ rm -rf /; }" },
  { technique: "nested",         cmd: "if true; then for x in 1 2; do rm -rf $x; done; fi" },
  { technique: "elif",           cmd: "if false; then echo no; elif true; then rm -rf /; fi" },
  { technique: "backgrounded",   cmd: "rm -rf / &" },
  { technique: "negated pipe",   cmd: "! rm -rf /" },
  { technique: "case branch",    cmd: "case $x in *) rm -rf /;; esac" },
  { technique: "case multi",     cmd: "case $x in a) echo a;; b) kubectl delete pod;; esac" },
];

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

describe("control flow: parser walks into compound commands", () => {
  for (const { technique, cmd } of attempts) {
    it(`SHOULD BLOCK (${technique}): ${cmd.replace(/\n/g, "\\n")}`, () => {
      // Sanity gate: bash itself must accept the syntax.
      assertShSyntax(cmd);

      // Deep check: parses the input and walks every leaf.
      const result = checkCommandDeep(cmd, rules);

      assert.notStrictEqual(
        result,
        undefined,
        `BYPASS CONFIRMED: "${cmd.replace(/\n/g, "\\n")}" slips past the rules!\n` +
        `  The dangerous leaf is hidden inside a control-flow construct.`,
      );
    });
  }
});
