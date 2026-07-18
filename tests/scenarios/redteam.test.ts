/**
 * Red-team tests for bash-deny engine.
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
  splitCommands,
} from "../../bash-deny/engine";
import { checkCommandDeep } from "../../bash-deny/parser";
import { assertShSyntax } from "../utils";

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
  // If set, this evasion technique is a known limitation (out of scope per
  // parser.md §2) — marked as todo, not a regression.
  limitation?: string;
}

interface RuleSuite {
  label: string;
  canonical: string;   // the "ground truth" command to compare shell output against
  attempts: Attempt[];
}

const suites: RuleSuite[] = [
  {
    label: "ls",
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
      { technique: "full path",                    cmd: "/bin/ls /tmp", limitation: "no path resolution (AGENTS.md)" },
      { technique: "relative path ./",             cmd: "./ls /tmp", limitation: "relative path bypasses PATH lookup" },
      { technique: "parent relative path ../",      cmd: "../ls /tmp", limitation: "relative path bypasses PATH lookup" },
      { technique: "$( ) substitution",            cmd: "$(echo ls) /tmp" , limitation: "cmd substitution is opaque (§2)" },
      { technique: "$( ) glued",                   cmd: "$(echo '')ls /tmp" , limitation: "cmd substitution is opaque (§2)" },
      { technique: "` ` substitution",             cmd: "`echo ls` /tmp", limitation: "backtick substitution is opaque (§2)" },
      { technique: "` ` glued",                    cmd: "`echo ''`ls /tmp", limitation: "backtick substitution is opaque (§2)" },
      { technique: "brace expansion",              cmd: "{ls,/tmp}", limitation: "brace expansion out of scope (§2)" },
      { technique: "${UNSET} expansion",           cmd: "${XX}ls /tmp" , limitation: "parameter expansion is opaque (§2)" },
      { technique: "${VAR-} expansion",            cmd: "${X-}ls /tmp" , limitation: "parameter expansion is opaque (§2)" },
      { technique: "${VAR:+} expansion",           cmd: "${HOME:+}ls /tmp" , limitation: "parameter expansion is opaque (§2)" },
      { technique: "inline ANSI-C",                cmd: `l$'\\163' /tmp` },
      { technique: "uppercase",                    cmd: "LS /tmp", limitation: "case-sensitive matching (no case normalization)" },
      { technique: "mixed case",                   cmd: "Ls /tmp", limitation: "case-sensitive matching (no case normalization)" },
    ],
  },
  {
    label: "echo danger",
    canonical: "echo danger hello",
    attempts: [
      // Straightforward
      { technique: "plain",                       cmd: "echo danger hello" },
      { technique: "other args",                  cmd: "echo danger world" },
      { technique: "extra whitespace",            cmd: "echo   danger   hello" },

      // Adversarial
      { technique: "ANSI-C quoting",              cmd: "$'echo' danger hello" },
      { technique: "full path",                    cmd: "/bin/echo danger hello", limitation: "no path resolution (AGENTS.md)" },
      { technique: "relative path ./",             cmd: "./echo danger hello", limitation: "relative path bypasses PATH lookup" },
      { technique: "$( ) substitution",            cmd: "$(echo echo) danger hello" , limitation: "cmd substitution is opaque (§2)" },
      { technique: "$( ) glued",                   cmd: "$(echo '')echo danger hello" , limitation: "cmd substitution is opaque (§2)" },
      { technique: "` ` substitution",             cmd: "`echo echo` danger hello", limitation: "backtick substitution is opaque (§2)" },
      { technique: "brace expansion",              cmd: "{echo,danger,hello}", limitation: "brace expansion out of scope (§2)" },
      { technique: "${UNSET} expansion",           cmd: "${XX}echo danger hello" , limitation: "parameter expansion is opaque (§2)" },
      { technique: "${VAR-} expansion",            cmd: "${X-}echo danger hello" , limitation: "parameter expansion is opaque (§2)" },
      { technique: "process substitution",          cmd: "cat <(echo danger hello)", limitation: "process substitution is opaque (§2)" },
      { technique: "inline ANSI-C",                cmd: `ec$'\\150'o danger hello` },
      { technique: "eval quoted",                   cmd: "eval 'echo danger hello'" },
      { technique: "uppercase",                    cmd: "ECHO danger hello", limitation: "case-sensitive matching (no case normalization)" },
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
      for (const { technique, cmd, limitation } of suite.attempts) {
        if (limitation) {
          it.todo(`KNOWN LIMITATION (${technique}): ${cmd} — ${limitation}`);
          continue;
        }
        it(`SHOULD BLOCK (${technique}): ${cmd}`, () => {
          // Sanity gate: bash itself must accept the syntax.
          // If it doesn't, the test command is malformed — not a parser bypass.
          assertShSyntax(cmd);

          const result = checkCommandDeep(cmd, rules);
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
            } catch (err: unknown) {
              lines.push(`  Shell exec failed: ${(err as Error).message}.`);
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

// ═══════════════════════════════════════════════════════════════════
// Strict mode — `--strict` closes every known limitation above.
// Every `limitation` case that slips past the plain matcher MUST be blocked
// when strict mode is on.
// ═══════════════════════════════════════════════════════════════════

describe("red team: strict mode blocks all limitations", () => {
  // Flatten every marked limitation across all suites.
  const limitations = suites.flatMap((s) =>
    s.attempts
      .filter((a) => a.limitation)
      .map((a) => ({ label: s.label, ...a }))
  );

  for (const { label, technique, cmd, limitation } of limitations) {
    it(`STRICT BLOCKS (${technique}): ${cmd}`, () => {
      assertShSyntax(cmd);

      const result = checkCommandDeep(cmd, rules, undefined, { strict: true });
      assert.notStrictEqual(
        result,
        undefined,
        `Strict mode failed to block "${cmd}" (${technique}) — limitation: ${limitation}`
      );
    });
  }

  // Strict mode must not break safe commands that the plain matcher allows.
  const safeCases = [
    "echo hello",
    "git -C /repo push origin main",
    'echo "hello world"',
    "echo $HOME",
  ];

  for (const cmd of safeCases) {
    it(`STRICT ALLOWS safe: ${cmd}`, () => {
      assert.strictEqual(
        checkCommandDeep(cmd, rules, undefined, { strict: true }),
        undefined
      );
    });
  }
});

// ═══════════════════════════════════════════════════════════════════
// Basename mode — `--basename` closes the PATH-based limitations (full
// path / ./ / ../) that the plain matcher can't see. Construct-based
// limitations ($(), backticks, ${}, brace) are NOT closed here — those
// still need -s. Only the path limitations flip from todo to blocked.
// ═══════════════════════════════════════════════════════════════════

describe("red team: basename mode blocks path limitations", () => {
  // Only the path-based limitations are closed by --basename.
  const pathLimitations = suites.flatMap((s) =>
    s.attempts
      .filter((a) => a.limitation && /path/i.test(a.limitation))
      .map((a) => ({ label: s.label, ...a }))
  );

  for (const { technique, cmd, limitation } of pathLimitations) {
    it(`BASENAME BLOCKS (${technique}): ${cmd}`, () => {
      assertShSyntax(cmd);

      const result = checkCommandDeep(cmd, rules, undefined, { basename: true });
      assert.notStrictEqual(
        result,
        undefined,
        `Basename mode failed to block "${cmd}" (${technique}) — limitation: ${limitation}`
      );
    });
  }
});
