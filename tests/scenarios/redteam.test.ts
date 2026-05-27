/**
 * Red-team tests for pi-deny engine.
 *
 * Every entry in `attempts` is a command that a rule SHOULD block.
 * The test runner shows the natural red/green split:
 *   green ✓ = caught (defense works)
 *   red   ✖ = bypassed (vulnerability — with shell-verified impact)
 *
 * Usage: npm test
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  parseFile,
  checkCommand,
  splitCommands,
} from "../../pi-deny/engine";

// ── Load test rules ────────────────────────────────────────────────

const rulesPath = join(import.meta.dirname, "redteam.bashdeny");
const rules = parseFile(readFileSync(rulesPath, "utf8"));

// ── Helpers ────────────────────────────────────────────────────────

const sh = (cmd: string): string =>
  execSync(cmd, { shell: "/bin/bash", encoding: "utf8", timeout: 5000 }).trim();

const sha = (s: string): string =>
  createHash("sha256").update(s).digest("hex").slice(0, 12);

let bashOk = true;
try { execSync("bash --version", { encoding: "utf8", timeout: 2000 }); } catch { bashOk = false; }

const hashCache = new Map<string, string>();
function canonicalHash(cmd: string): string {
  if (!hashCache.has(cmd)) hashCache.set(cmd, sha(sh(cmd)));
  return hashCache.get(cmd)!;
}

// ═══════════════════════════════════════════════════════════════════
// Rule suites — one flat list per rule. Every entry SHOULD be blocked.
// ═══════════════════════════════════════════════════════════════════

interface Attempt {
  technique: string;
  cmd: string;
}

interface RuleSuite {
  label: string;
  canonical: string;   // the "ground truth" command to compare shell output against
  attempts: Attempt[];
}

const suites: RuleSuite[] = [
  {
    label: "ls *",
    canonical: "ls /tmp",
    attempts: [
      // Straightforward calls — should be caught by the rule
      { technique: "plain",                       cmd: "ls /tmp" },
      { technique: "with options",                cmd: "ls -la /tmp" },
      { technique: "deep path",                   cmd: "ls /tmp/some/path" },
      { technique: "extra whitespace",            cmd: "ls   /tmp" },

      // Adversarial — try to sneak past the tokenizer
      { technique: "ANSI-C quoting",              cmd: "$'ls' /tmp" },
      { technique: "ANSI-C quoting (octal)",       cmd: `$'\\154\\163' /tmp` },
      { technique: "ANSI-C quoting (hex)",         cmd: `$'\\x6c\\x73' /tmp` },
      { technique: "full path",                    cmd: "/bin/ls /tmp" },
      { technique: "$( ) substitution",            cmd: "$(echo ls) /tmp" },
      { technique: "$( ) glued",                   cmd: "$(echo '')ls /tmp" },
      { technique: "` ` substitution",             cmd: "`echo ls` /tmp" },
      { technique: "` ` glued",                    cmd: "`echo ''`ls /tmp" },
      { technique: "brace expansion",              cmd: "{ls,/tmp}" },
      { technique: "${UNSET} expansion",           cmd: "${XX}ls /tmp" },
      { technique: "${VAR-} expansion",            cmd: "${X-}ls /tmp" },
      { technique: "${VAR:+} expansion",           cmd: "${HOME:+}ls /tmp" },
      { technique: "inline ANSI-C",                cmd: `l$'\\163' /tmp` },
      { technique: "uppercase",                    cmd: "LS /tmp" },
      { technique: "mixed case",                   cmd: "Ls /tmp" },
    ],
  },
  {
    label: "echo danger *",
    canonical: "echo danger hello",
    attempts: [
      // Straightforward
      { technique: "plain",                       cmd: "echo danger hello" },
      { technique: "other args",                  cmd: "echo danger world" },
      { technique: "extra whitespace",            cmd: "echo   danger   hello" },

      // Adversarial
      { technique: "ANSI-C quoting",              cmd: "$'echo' danger hello" },
      { technique: "full path",                    cmd: "/bin/echo danger hello" },
      { technique: "$( ) substitution",            cmd: "$(echo echo) danger hello" },
      { technique: "$( ) glued",                   cmd: "$(echo '')echo danger hello" },
      { technique: "` ` substitution",             cmd: "`echo echo` danger hello" },
      { technique: "brace expansion",              cmd: "{echo,danger,hello}" },
      { technique: "${UNSET} expansion",           cmd: "${XX}echo danger hello" },
      { technique: "${VAR-} expansion",            cmd: "${X-}echo danger hello" },
      { technique: "inline ANSI-C",                cmd: `ec$'\\150'o danger hello` },
      { technique: "uppercase",                    cmd: "ECHO danger hello" },
    ],
  },
];

// ═══════════════════════════════════════════════════════════════════
// Tests — one loop. Every attempt asserts "SHOULD be blocked."
// Green ✓ = caught.  Red ✖ = bypassed (vulnerability report).
// ═══════════════════════════════════════════════════════════════════

describe("red team: vulnerabilities", () => {
  for (const suite of suites) {
    describe(`rule: ${suite.label}`, () => {
      for (const { technique, cmd } of suite.attempts) {
        it(`SHOULD BLOCK (${technique}): ${cmd}`, () => {
          const result = checkCommand(cmd, rules);
          const tokens = splitCommands(cmd).map(t => `[${t.join(" ")}]`).join(" ");

          // Build vulnerability report (only shown when red ✖)
          const lines: string[] = [
            `BYPASS CONFIRMED: "${cmd}" slips past the rule!`,
            `  Tokens: ${tokens}`,
          ];

          if (bashOk) {
            try {
              const cHash = canonicalHash(suite.canonical);
              const aHash = sha(sh(cmd));
              assert.strictEqual(
                aHash,
                cHash,
                `Shell output mismatch!`
              );
              lines.push(`  Exploitable: produces identical shell output (sha ${aHash}).`);
            } catch (err: any) {
              lines.push(`  Shell exec failed: ${err.message}.`);
            }
          }

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
