/**
 * Red-team tests for bash-deny — control-flow bypasses.
 *
 * Every entry in `attempts` is a shell command that the current engine
 * should NOT block (because the dangerous command is hidden inside a
 * control-flow construct, an eval argument, a variable, or a quoted string).
 * The test runner shows the natural red/green split:
 *
 *   green ✓ = caught by checkCommand (defense works)
 *   red   ✖ = bypassed (vulnerability — hidden command slipped through)
 *
 * Why these bypass the current engine:
 * The engine splits on metacharacters (`;`, `|`, `&&`, `||`, `&`) and then
 * does scan-forward pattern matching on each segment. The `;` accidentally
 * reveals the dangerous command in *most* control-flow cases (e.g. the
 * segment `do rm -rf $x` contains the token `rm`). The real bypasses are
 * the cases where the dangerous command is opaque to the tokenizer:
 *
 *   • quoted strings — `"rm"` is one token, not the command `rm`
 *   • eval — the engine doesn't re-parse eval's argument
 *   • variables — `$cmd` is one token, not expanded
 *   • command substitution — `$(echo rm)` is one token
 *   • awk / perl / find — sub-interpreters that take the dangerous name
 *     as a string argument
 *
 * Every attempt is also validated with `sh -n -c` to confirm bash itself
 * accepts the syntax. If bash rejects it, the test is a data error — not a
 * bypass.
 *
 * Usage: npm test
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  parseFile,
  checkCommand,
  splitCommands,
} from "../../bash-deny/engine";
import { assertShSyntax } from "../utils";

// ── Load test rules ────────────────────────────────────────────────

const rulesPath = join(import.meta.dirname, "controlflow.bashdeny");
const rules = parseFile(readFileSync(rulesPath, "utf8"));

// ═══════════════════════════════════════════════════════════════════
// Rule suites — one per command being hidden. Every entry SHOULD be blocked.
// ═══════════════════════════════════════════════════════════════════

interface Attempt {
  technique: string;
  cmd: string;
}

interface RuleSuite {
  label: string;        // human label for describe()
  rule: string;         // the rule text we expect to match
  canonical: string;    // the bare command (documentation only)
  attempts: Attempt[];
}

const suites: RuleSuite[] = [
  {
    label: "rm",
    rule: "rm",
    canonical: "rm -rf /tmp",
    attempts: [
      // ── control flow + quoted string (engine sees one token) ──
      { technique: "for + double-quoted rm",     cmd: "for x in 1; do echo \"rm -rf $x\"; done" },
      { technique: "for + single-quoted rm",     cmd: "for x in 1; do echo 'rm -rf $x'; done" },
      { technique: "if + double-quoted rm",      cmd: "if true; then echo \"rm -rf /\"; fi" },
      { technique: "while + double-quoted rm",   cmd: "while read x; do echo \"rm -rf $x\"; done" },
      { technique: "subshell + quoted rm",       cmd: "( echo \"rm -rf /\" )" },
      { technique: "brace + quoted rm",          cmd: "{ echo \"rm -rf /\"; }" },
      { technique: "case + quoted rm in body",   cmd: "case $x in *) echo \"rm -rf /\";; esac" },

      // ── control flow + eval ────────────────────────────────
      { technique: "for + eval (literal string)",cmd: "for x in 1; do eval \"rm -rf $x\"; done" },
      { technique: "if + eval",                  cmd: "if true; then eval \"rm -rf /\"; fi" },
      { technique: "while + eval",               cmd: "while read x; do eval \"rm -rf $x\"; done" },
      { technique: "subshell + eval",            cmd: "( eval \"rm -rf /\" )" },
      { technique: "case + eval in body",        cmd: "case $x in *) eval \"rm -rf /\";; esac" },

      // ── control flow + variable command ────────────────────
      { technique: "for + $cmd",                 cmd: "c=rm; for x in 1; do $c -rf $x; done" },
      { technique: "if + $cmd",                  cmd: "c=rm; if true; then $c -rf /; fi" },
      { technique: "while + $cmd",               cmd: "c=rm; while read x; do $c -rf $x; done" },
      { technique: "subshell + $cmd",            cmd: "c=rm; ( $c -rf / )" },
      { technique: "case + $cmd",                cmd: "c=rm; case $x in *) $c -rf /;; esac" },
      { technique: "for + ${!indirect}",         cmd: "c=rm; for x in 1; do ${!c} -rf $x; done" },

      // ── control flow + command substitution ────────────────
      { technique: "for + $(echo rm)",           cmd: "for x in 1; do $(echo rm) -rf $x; done" },
      { technique: "if + $(echo rm)",            cmd: "if true; then $(echo rm) -rf /; fi" },
      { technique: "subshell + backticks",       cmd: "x=`echo rm`; ( $x -rf / )" },

      // ── control flow + sub-interpreter (awk / perl / xargs) ─
      { technique: "for + awk system()",         cmd: "for x in 1; do awk 'BEGIN { system(\"rm -rf /\") }'; done" },
      { technique: "if + perl system()",         cmd: "if true; then perl -e 'system(\"rm -rf /\")'; fi" },
      { technique: "for + xargs",                cmd: "for x in 1; do echo $(echo rm) | xargs -I {} {} -rf; done" },
      { technique: "while + bash -c",            cmd: "while read x; do bash -c 'rm -rf $x'; done" },

      // ── control flow + pipe to interpreter ────────────────
      { technique: "for + bash -c",              cmd: "for x in 1; do bash -c 'rm -rf /'; done" },
      { technique: "if + sh -c",                 cmd: "if true; then sh -c 'rm -rf /'; fi" },
    ],
  },
  {
    label: "kubectl",
    rule: "kubectl",
    canonical: "kubectl delete pod",
    attempts: [
      // ── control flow + quoted string ──────────────────────
      { technique: "for + double-quoted kubectl",  cmd: "for x in a; do echo \"kubectl delete $x\"; done" },
      { technique: "if + single-quoted kubectl",   cmd: "if true; then echo 'kubectl delete pod'; fi" },
      { technique: "while + quoted kubectl",       cmd: "while read x; do echo \"kubectl delete $x\"; done" },
      { technique: "subshell + quoted kubectl",   cmd: "( echo \"kubectl delete pod\" )" },
      { technique: "case + quoted kubectl",       cmd: "case $x in *) echo \"kubectl delete pod\";; esac" },

      // ── control flow + eval ────────────────────────────────
      { technique: "for + eval",                  cmd: "for x in a; do eval \"kubectl delete $x\"; done" },
      { technique: "if + eval",                   cmd: "if true; then eval \"kubectl delete pod\"; fi" },
      { technique: "case + eval",                 cmd: "case $x in *) eval \"kubectl delete pod\";; esac" },

      // ── control flow + variable command ────────────────────
      { technique: "for + $cmd",                  cmd: "c=kubectl; for x in a; do $c delete $x; done" },
      { technique: "if + $cmd",                   cmd: "c=kubectl; if true; then $c delete pod; fi" },
      { technique: "subshell + $cmd",             cmd: "c=kubectl; ( $c delete pod )" },

      // ── control flow + command substitution ────────────────
      { technique: "for + $(echo kubectl)",       cmd: "for x in a; do $(echo kubectl) delete $x; done" },

      // ── control flow + sub-interpreter ─────────────────────
      { technique: "for + perl system()",         cmd: "for x in a; do perl -e 'system(\"kubectl delete pod\")'; done" },
      { technique: "if + xargs",                  cmd: "if true; then echo $(echo kubectl) | xargs -I {} {} delete pod; fi" },

      // ── control flow + pipe to interpreter ────────────────
      { technique: "for + bash -c",               cmd: "for x in a; do bash -c 'kubectl delete pod'; done" },
    ],
  },
];

// ═══════════════════════════════════════════════════════════════════
// Tests — one loop per rule suite. Every attempt asserts SHOULD be blocked.
// ═══════════════════════════════════════════════════════════════════

describe("red team: control flow bypasses", () => {
  for (const suite of suites) {
    describe(`rule: ${suite.label}`, () => {
      for (const { technique, cmd } of suite.attempts) {
        it(`SHOULD BLOCK (${technique}): ${cmd.replace(/\n/g, "\\n")}`, () => {
          // Sanity gate: bash itself must accept the syntax.
          // If it doesn't, the test command is malformed — not an engine bypass.
          assertShSyntax(cmd);

          // The actual check
          const result = checkCommand(cmd, rules);
          const tokens = splitCommands(cmd).map(t => `[${t.join(" ")}]`).join(" ");

          // Build vulnerability report (only shown when red ✖)
          const lines: string[] = [
            `BYPASS CONFIRMED: "${cmd.replace(/\n/g, "\\n")}" slips past the rule!`,
            `  The dangerous command is hidden inside a control-flow / string / variable / eval.`,
            `  Tokens as seen by splitCommands: ${tokens}`,
          ];

          assert.notStrictEqual(
            result,
            undefined,
            lines.join("\n")
          );
        });
      }
    });
  }
});
