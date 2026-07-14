/**
 * leaves tests — bash-deny parser leaf extraction.
 *
 * leaves() walks a parsed AST and yields the `tokens` of every executable
 * simple command — the arrays that go into `unwrapCommand` + `evaluate`.
 *
 * The core principle under test: **recurse into a Node field iff it's a
 * command that executes.** Fields that are *data* (not commands) are skipped:
 *
 *   - `for.var`, `for.words`      — loop var name + iteration values
 *   - `case.word`                 — match subject (string compared vs patterns)
 *   - `case.branches[].pat`       — match patterns (globs)
 *
 * Fields that *are* commands are recursed into (exit status gates execution,
 * or they run when the branch is taken):
 *
 *   - pipeline commands, and-or branches, list items
 *   - subshell/brace bodies, `for.body`
 *   - `while.cond` + `while.body`
 *   - `if.branches[].cond` + `.body`, `if.else`
 *   - `case.branches[].body`
 *
 * The regression section is the critical one: it pairs a deny-relevant token
 * in a DATA position with a safe command in the BODY. If leaves() wrongly
 * yields the data token, the deny engine blocks a safe command (false
 * positive). The case.word case is the one fixed during review.
 *
 * Test convention: data-driven `cases` array with group comments.
 *
 * Usage: node --import tsx --test tests/parser/leaves.test.ts
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { tokenize, parseList, ParserState, leaves } from "../../bash-deny/parser.js";
import { assertShSyntax } from "../utils";

// Convenience: tokenize → parseList → collect leaves into string[][].
// parseList is the top-level entry (handles `a; b` as a list of commands).
const leafTokens = (s: string): string[][] => {
  const node = parseList(new ParserState(tokenize(s)));
  return [...leaves(node)];
};

// ═══════════════════════════════════════════════════════════════════
// Test cases — one per Node kind
// ═══════════════════════════════════════════════════════════════════

const cases: [string, string[][]][] = [
  // ── simple: yields its tokens ─────────────────────────────────
  ["echo hi", [["echo", "hi"]]],
  ["kubectl delete pod", [["kubectl", "delete", "pod"]]],
  ["rm -rf /", [["rm", "-rf", "/"]]],
  // assignment prefix is part of the token array (engine strips it later)
  ["FOO=bar rm -rf /", [["FOO=bar", "rm", "-rf", "/"]]],
  // quoted separators are literal word bytes — one token
  ["echo 'a;b|c'", [["echo", "a;b|c"]]],

  // ── pipeline: yields from each segment ───────────────────────
  ["a | b", [["a"], ["b"]]],
  ["kubectl get pods | grep running", [["kubectl", "get", "pods"], ["grep", "running"]]],
  // pipeline negation (!) — bang is metadata, not a command
  ["! echo hi", [["echo", "hi"]]],
  ["! kubectl delete pod", [["kubectl", "delete", "pod"]]],

  // ── andor: yields from both sides ────────────────────────────
  ["a && b", [["a"], ["b"]]],
  ["a || b", [["a"], ["b"]]],
  ["kubectl get pods && kubectl delete pod", [["kubectl", "get", "pods"], ["kubectl", "delete", "pod"]]],

  // ── list: yields from each item ──────────────────────────────
  ["a; b", [["a"], ["b"]]],
  ["a; b; c", [["a"], ["b"], ["c"]]],
  ["echo a; echo b", [["echo", "a"], ["echo", "b"]]],
  // newline-separated list
  ["echo a\necho b", [["echo", "a"], ["echo", "b"]]],
  // background (&) separator — both commands run
  ["a & b", [["a"], ["b"]]],

  // ── subshell: yields from body ───────────────────────────────
  ["(rm -rf /)", [["rm", "-rf", "/"]]],
  ["(a; b)", [["a"], ["b"]]],
  ["(kubectl delete pod)", [["kubectl", "delete", "pod"]]],

  // ── brace group: yields from body ────────────────────────────
  ["{ rm -rf /; }", [["rm", "-rf", "/"]]],
  ["{ a; b; }", [["a"], ["b"]]],

  // ── for: yields from body ONLY (var + words are data) ────────
  ["for x in a b; do echo $x; done", [["echo", "$x"]]],
  ["for x in a b c; do kubectl get pods; done", [["kubectl", "get", "pods"]]],
  // multi-statement body
  ["for x in 1 2; do echo a; echo b; done", [["echo", "a"], ["echo", "b"]]],

  // ── while / until: yields from cond AND body ─────────────────
  ["while true; do echo hi; done", [["true"], ["echo", "hi"]]],
  ["until false; do echo hi; done", [["false"], ["echo", "hi"]]],
  // cond is a deny-relevant command — it runs, so it must be yielded
  ["while kubectl get pods; do sleep 1; done", [["kubectl", "get", "pods"], ["sleep", "1"]]],

  // ── if: yields from each cond + body + else ──────────────────
  ["if true; then echo a; fi", [["true"], ["echo", "a"]]],
  ["if true; then a; else b; fi", [["true"], ["a"], ["b"]]],
  ["if true; then a; elif false; then b; fi", [["true"], ["a"], ["false"], ["b"]]],
  ["if true; then a; elif false; then b; else c; fi", [["true"], ["a"], ["false"], ["b"], ["c"]]],
  // cond is a deny-relevant command — it runs, so it must be yielded
  ["if kubectl get pods; then echo ok; fi", [["kubectl", "get", "pods"], ["echo", "ok"]]],
  // multi-statement body
  ["if true; then rm x; echo y; fi", [["true"], ["rm", "x"], ["echo", "y"]]],

  // ── case: yields from branch bodies ONLY (word + pat are data) ──
  // ★ See regressionCases below for the false-positive guard.
  ["case x in a) echo a;; esac", [["echo", "a"]]],
  ["case x in a) echo a;; b) echo b;; esac", [["echo", "a"], ["echo", "b"]]],
  // pattern alternation (a|b) — patterns are data, not yielded
  ["case x in a|b) echo ab;; esac", [["echo", "ab"]]],
  // deny-relevant command in body — must be yielded
  ["case x in a) kubectl delete pod;; esac", [["kubectl", "delete", "pod"]]],
  // multi-statement body
  ["case x in a) echo one; echo two;; esac", [["echo", "one"], ["echo", "two"]]],
];

// ═══════════════════════════════════════════════════════════════════
// Nested / compound integration
// ═══════════════════════════════════════════════════════════════════

const nested: [string, string[][]][] = [
  // ── if inside case body ──────────────────────────────────────
  ["case x in a) if true; then echo; fi;; esac", [["true"], ["echo"]]],

  // ── case inside if body ──────────────────────────────────────
  ["if true; then case x in a) echo;; esac; fi", [["true"], ["echo"]]],

  // ── for inside while body ────────────────────────────────────
  ["while true; do for x in a; do echo $x; done; done", [["true"], ["echo", "$x"]]],

  // ── subshell inside if body ──────────────────────────────────
  ["if true; then (rm -rf /); fi", [["true"], ["rm", "-rf", "/"]]],

  // ── nested subshell ──────────────────────────────────────────
  ["( (echo a) )", [["echo", "a"]]],

  // ── pipeline of compounds ────────────────────────────────────
  ["(a) | (b)", [["a"], ["b"]]],

  // ── case inside subshell ─────────────────────────────────────
  ["(case x in a) echo;; esac)", [["echo"]]],

  // ── if inside subshell inside brace ─────────────────────────
  ["{ (if true; then echo; fi); }", [["true"], ["echo"]]],

  // ── for with case body ───────────────────────────────────────
  ["for x in 1; do case $x in a) echo;; esac; done", [["echo"]]],

  // ── multi-branch case with deny commands in each branch ───────
  // Every branch body runs (at parse time we don't know which matches),
  // so all must be yielded.
  ["case x in\nget) kubectl get pods;;\ndelete) kubectl delete pod;;\nesac",
   [["kubectl", "get", "pods"], ["kubectl", "delete", "pod"]]],

  // ── andor of compounds ────────────────────────────────────────
  ["(a) && (b)", [["a"], ["b"]]],

  // ── while inside if body ──────────────────────────────────────
  ["if true; then while false; do echo; done; fi", [["true"], ["false"], ["echo"]]],

  // ── for inside case inside subshell ──────────────────────────
  ["(case x in a) for y in 1; do echo $y; done;; esac)", [["echo", "$y"]]],
];

// ═══════════════════════════════════════════════════════════════════
// Regression: data fields must NOT be yielded (false-positive guard)
// ═══════════════════════════════════════════════════════════════════
//
// These are the critical cases. If leaves() wrongly recurses into data
// fields, the deny engine sees a false command and blocks a safe command.
// Each case pairs a deny-relevant token in a DATA position with a safe
// command in the BODY — the body must be the only leaf yielded.

const regression: { input: string; expected: string[][]; note: string }[] = [
  {
    // case.word = "kubectl" — the match subject. It is compared as a STRING
    // against patterns, never executed. If yielded, a `kubectl` deny rule
    // would block this safe case statement.
    input: "case kubectl in get) kubectl get pods;; esac",
    expected: [["kubectl", "get", "pods"]],
    note: "case.word is the match subject, not a command — must not be yielded",
  },
  {
    // case patterns contain "kubectl" — patterns are globs matched against
    // the subject string, never executed. If yielded, false positive.
    input: "case x in kubectl) echo safe;; esac",
    expected: [["echo", "safe"]],
    note: "case pattern is data (glob), not a command — must not be yielded",
  },
  {
    // for.words = ["rm", "-rf"] — iteration values. They are assigned to the
    // loop variable one at a time, never executed as a command. If yielded,
    // an `rm -rf` deny rule would block this safe loop.
    input: "for x in rm -rf; do echo safe; done",
    expected: [["echo", "safe"]],
    note: "for.words are iteration values, not commands — must not be yielded",
  },
  {
    // for.var is "x" — the loop variable name, not a command. (var is a
    // string, not a Node, so tsc prevents yield* on it; but a stray
    // `yield [node.var]` would still be a bug. This case guards that.)
    input: "for x in a; do echo $x; done",
    expected: [["echo", "$x"]],
    note: "for.var is the loop variable name, not a command — must not be yielded",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Empty-leaf cases — empty simple nodes (documented, harmless)
// ═══════════════════════════════════════════════════════════════════
//
// Stray separators and blank lines produce empty `simple` nodes (parseList
// leniency). leaves() yields their empty `[]` token array. The engine skips
// empty arrays (they match no deny rule), so this is harmless. Documented
// so a future strictness pass is visible.

const emptyLeaves: { input: string; expected: string[][]; note: string }[] = [
  {
    // `then\n` produces a leading empty body item (parseList lenient: a
    // separator with no preceding command yields an empty simple). Bash
    // collapses the blank line; we keep an empty `[]` that matches no rule.
    input: "if true\nthen\necho hi\nfi",
    expected: [["true"], [], ["echo", "hi"]],
    note: "leading empty simple from `then\\n` (bash collapses; we yield [])",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Test runner
// ═══════════════════════════════════════════════════════════════════

describe("leaves", () => {
  for (const [input, expected] of cases) {
    it(`${JSON.stringify(input)} → ${JSON.stringify(expected)}`, () => {
      assertShSyntax(input);
      assert.deepStrictEqual(leafTokens(input), expected);
    });
  }

  for (const [input, expected] of nested) {
    it(`${JSON.stringify(input)} → ${JSON.stringify(expected)}`, () => {
      assertShSyntax(input);
      assert.deepStrictEqual(leafTokens(input), expected);
    });
  }

  for (const { input, expected, note } of regression) {
    it(`${JSON.stringify(input)} (${note})`, () => {
      assertShSyntax(input);
      assert.deepStrictEqual(leafTokens(input), expected);
    });
  }

  for (const { input, expected, note } of emptyLeaves) {
    it(`${JSON.stringify(input)} (${note})`, () => {
      assertShSyntax(input);
      assert.deepStrictEqual(leafTokens(input), expected);
    });
  }
});
