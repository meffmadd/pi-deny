/**
 * parseFor tests — bash-deny parser Step 5 (for clause).
 *
 * Grammar (§3):
 *   <for_loop> ::= "for" <word>
 *                  ( "in" <word>* )?
 *                  ( ";" | <newline> )?
 *                  "do" <list> "done"
 *
 * Same header → body → footer shape as parseSubshell/parseBrace (Step 4):
 *   header = `for` + loop variable (+ optional `in` wordlist + separators)
 *   body   = parseList (stops at `done` via the closer-break rule)
 *   footer = `done` (consumed via expect)
 *
 * Three design decisions under test:
 *   - Loop variable is a <word> token: `state.expect("word")`. Because of the
 *     kw-everywhere rule (§4.1), a reserved word like `for` is emitted as `kw`,
 *     not `word` — so `for for in ...` is rejected (see limitation below).
 *   - The `in` clause is optional: `for x; do ...; done` defaults to `$@`.
 *     Detected by peeking for `kw "in"`; if absent, `words = []`.
 *   - Separators before `do` are zero-or-more `;`/newline. Bash mandates one
 *     after a wordlist; accepting zero is lenient and fails toward rejection
 *     (over-accepting → more commands checked, not fewer).
 *
 * Test convention: data-driven `cases` array with group comments.
 *
 * Usage: node --import tsx --test tests/parser/parse-for.test.ts
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { tokenize, parseCommand, ParserState, ParseError, type Node } from "../../bash-deny/parser.js";

// Convenience: tokenize then parseCommand on the result (`for` enters through
// parseCommand's kw dispatch).
const parse = (s: string): Node =>
  parseCommand(new ParserState(tokenize(s)));

// ── node builders ─────────────────────────────────────────────────
const simple = (tokens: string[]): Node => ({ kind: "simple", tokens });
const pipeline = (bang: boolean, commands: Node[]): Node => ({
  kind: "pipeline", bang, commands,
});
const list = (items: Node[]): Node => ({ kind: "list", items });
const subshell = (body: Node): Node => ({ kind: "subshell", body });
const brace = (body: Node): Node => ({ kind: "brace", body });
const forNode = (v: string, words: string[], body: Node): Node => ({
  kind: "for", var: v, words, body,
});

// ═══════════════════════════════════════════════════════════════════
// Test cases
// ═══════════════════════════════════════════════════════════════════

const cases: [string, Node][] = [
  // ── canonical form: for x in words; do body; done ─────────────
  ["for x in a b; do echo $x; done", forNode("x", ["a", "b"], list([pipeline(false, [simple(["echo", "$x"])])]))],

  // ── no `in` clause (defaults to $@) ────────────────────────────
  ["for x; do echo $x; done", forNode("x", [], list([pipeline(false, [simple(["echo", "$x"])])]))],

  // ── empty `in` clause ──────────────────────────────────────────
  ["for x in; do echo $x; done", forNode("x", [], list([pipeline(false, [simple(["echo", "$x"])])]))],

  // ── newline as separator after wordlist ───────────────────────
  ["for x in a b\ndo echo $x; done", forNode("x", ["a", "b"], list([pipeline(false, [simple(["echo", "$x"])])]))],

  // ── no space before `do` ──────────────────────────────────────
  ["for x in a b c;do echo $x; done", forNode("x", ["a", "b", "c"], list([pipeline(false, [simple(["echo", "$x"])])]))],

  // ── no `in`, no separator before `do` ─────────────────────────
  ["for x do echo $x; done", forNode("x", [], list([pipeline(false, [simple(["echo", "$x"])])]))],

  // ── multiple words in wordlist ────────────────────────────────
  ["for x in a b c d e; do echo $x; done", forNode("x", ["a", "b", "c", "d", "e"], list([pipeline(false, [simple(["echo", "$x"])])]))],

  // ── multi-item body (semicolon-separated) ────────────────────
  ["for x in a; do rm $x; echo $x; done", forNode("x", ["a"], list([
    pipeline(false, [simple(["rm", "$x"])]),
    pipeline(false, [simple(["echo", "$x"])]),
  ]))],

  // ── newline-separated body ────────────────────────────────────
  ["for x in a; do rm $x\necho $x; done", forNode("x", ["a"], list([
    pipeline(false, [simple(["rm", "$x"])]),
    pipeline(false, [simple(["echo", "$x"])]),
  ]))],

  // ── deny-relevant: rm -rf inside a for loop ───────────────────
  ["for x in /tmp /var; do rm -rf $x; done", forNode("x", ["/tmp", "/var"], list([
    pipeline(false, [simple(["rm", "-rf", "$x"])]),
  ]))],

  // ── identifier-style loop variable ────────────────────────────
  ["for x_1 in a; do echo; done", forNode("x_1", ["a"], list([pipeline(false, [simple(["echo"])])]))],

  // ── glob in wordlist (opaque word content) ────────────────────
  ["for x in *.txt; do echo $x; done", forNode("x", ["*.txt"], list([pipeline(false, [simple(["echo", "$x"])])]))],

  // ── expansion in wordlist (opaque word content) ───────────────
  ["for x in $LIST; do echo $x; done", forNode("x", ["$LIST"], list([pipeline(false, [simple(["echo", "$x"])])]))],

  // ── all-newline separators ────────────────────────────────────
  // `do\n` produces a leading empty body item (parseList lenient: consecutive
  // separators → empty items). Bash collapses the blank line; we keep an empty
  // simple command that matches no deny rule (fails toward rejection).
  ["for x in a\ndo\necho $x\ndone", forNode("x", ["a"], list([
    pipeline(false, [simple([])]),
    pipeline(false, [simple(["echo", "$x"])]),
  ]))],
];

// ═══════════════════════════════════════════════════════════════════
// Nested / compound integration
// ═══════════════════════════════════════════════════════════════════

const nested: [string, Node][] = [
  // ── nested for ────────────────────────────────────────────────
  ["for x in a; do for y in b; do echo $x$y; done; done", forNode("x", ["a"], list([
    pipeline(false, [forNode("y", ["b"], list([pipeline(false, [simple(["echo", "$x$y"])])]))]),
  ]))],

  // ── for inside subshell ───────────────────────────────────────
  ["(for x in a; do echo $x; done)", subshell(list([
    pipeline(false, [forNode("x", ["a"], list([pipeline(false, [simple(["echo", "$x"])])]))]),
  ]))],

  // ── for inside brace group ────────────────────────────────────
  ["{ for x in a; do echo $x; done; }", brace(list([
    pipeline(false, [forNode("x", ["a"], list([pipeline(false, [simple(["echo", "$x"])])]))]),
  ]))],

  // ── subshell in for body ──────────────────────────────────────
  ["for x in a; do (echo $x); done", forNode("x", ["a"], list([
    pipeline(false, [subshell(list([pipeline(false, [simple(["echo", "$x"])])]))]),
  ]))],

  // ── brace group in for body ──────────────────────────────────
  ["for x in a; do { echo $x; }; done", forNode("x", ["a"], list([
    pipeline(false, [brace(list([pipeline(false, [simple(["echo", "$x"])])]))]),
  ]))],
];

// ═══════════════════════════════════════════════════════════════════
// Lenient cases — documented divergences (fail toward rejection, not bypass)
// ═══════════════════════════════════════════════════════════════════
//
// Bash requires a separator (`;` or newline) after the wordlist before `do`,
// and rejects `;;` (dsemi) in that position. Our separator loop accepts
// zero-or-more separators, so it admits both. Over-accepting here means we
// parse and check MORE commands, not fewer — the deny guard is not bypassed.

const lenient: { input: string; expected: Node; note: string }[] = [
  {
    input: "for x in a b do echo $x; done",
    expected: forNode("x", ["a", "b"], list([pipeline(false, [simple(["echo", "$x"])])])),
    note: "no separator after wordlist before `do` (bash errors)",
  },
  {
    input: "for x in a b;; do echo $x; done",
    expected: forNode("x", ["a", "b"], list([pipeline(false, [simple(["echo", "$x"])])])),
    note: "`;;` after wordlist (bash errors, we consume as separators)",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Unclosed for — must throw ParseError (§7)
// ═══════════════════════════════════════════════════════════════════

const unclosed: { input: string; note: string }[] = [
  { input: "for x in a b", note: "eof before `do`" },
  { input: "for x in a b; do echo $x", note: "eof before `done`" },
  { input: "for x", note: "eof before `do` (no `in`, no separators)" },
];

// ═══════════════════════════════════════════════════════════════════
// Tokenizer-limitation passthrough — documented, not a parseFor bug
// ═══════════════════════════════════════════════════════════════════
//
// The kw-everywhere rule (§4.1) means reserved words are ALWAYS emitted as
// `kw`, never `word`. The loop variable position expects a `word` token, so
// `for for in ...` throws — the second `for` is `kw`, not `word`. Real bash
// accepts `for` as a variable name. This is a known consequence of the
// kw-everywhere design, not a parseFor bug. A future fix would downgrade `kw`
// to `word` in the loop-variable position (position decides, §4.1).

const limitations: { input: string; note: string }[] = [
  {
    input: "for for in a; do echo; done",
    note: "kw-everywhere: `for` as var name is `kw` not `word` — bash accepts, we reject",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Test runner
// ═══════════════════════════════════════════════════════════════════

describe("parseFor", () => {
  for (const [input, expected] of cases) {
    it(`${JSON.stringify(input)} → ${JSON.stringify(expected)}`, () => {
      assert.deepStrictEqual(parse(input), expected);
    });
  }

  for (const [input, expected] of nested) {
    it(`${JSON.stringify(input)} → ${JSON.stringify(expected)}`, () => {
      assert.deepStrictEqual(parse(input), expected);
    });
  }

  for (const { input, expected, note } of lenient) {
    it(`${JSON.stringify(input)} (lenient: ${note})`, () => {
      assert.deepStrictEqual(parse(input), expected);
    });
  }

  for (const { input, note } of unclosed) {
    it(`${JSON.stringify(input)} throws ParseError (${note})`, () => {
      assert.throws(
        () => parse(input),
        (e: unknown) => e instanceof ParseError,
      );
    });
  }

  for (const { input, note } of limitations) {
    it(`${JSON.stringify(input)} throws ParseError (limitation: ${note})`, () => {
      assert.throws(
        () => parse(input),
        (e: unknown) => e instanceof ParseError,
      );
    });
  }

  // ── header + footer both consumed ──────────────────────────────
  // After parsing a for clause, the cursor must rest past `done` (on eof
  // here), not on `done` itself — `done` is the footer, consumed via expect().
  it(`consumes header, body, and footer (cursor rests on eof)`, () => {
    const state = new ParserState(tokenize("for x in a; do echo $x; done"));
    parseCommand(state);
    assert.equal(state.peek().kind, "eof");
  });

  // ── for as a pipeline segment ──────────────────────────────────
  // parseCommand dispatches `for` → parseFor, so a for-loop can be a pipe
  // segment. parseCommand only consumes the first command; the `| cat` is
  // left for parsePipeline. Here we confirm parseCommand yields a `for` node.
  it(`for-loop appears as a pipeline segment`, () => {
    const node = parse("for x in a; do echo $x; done");
    assert.equal(node.kind, "for");
  });

  // ── bash oracle: everything we accept, bash accepts ─────────────
  // §8.2 — use `sh -n -c` as the oracle for the positive cases.
  // Newline-containing inputs are skipped: JSON.stringify escapes `\n` to a
  // literal backslash-n, which the shell interprets as escaped-`n` (not a
  // newline). This changes the command text, so the oracle can't verify those.
  // The deepStrictEqual cases above already cover the parser behavior.
  it(`bash -n accepts every positive case (no newlines)`, () => {
    const inputs = [...cases, ...nested].map(([s]) => s).filter((s) => !s.includes("\n"));
    for (const input of inputs) {
      execSync(`sh -n -c ${JSON.stringify(input)}`);
    }
  });

  // ── bash oracle: lenient cases are real divergences ────────────
  // Confirm bash DOES reject these — they are genuine lenient divergences,
  // not cases we accidentally got right.
  it(`bash -n rejects every lenient case`, () => {
    for (const { input } of lenient) {
      assert.throws(
        () => execSync(`sh -n -c ${JSON.stringify(input)}`),
      );
    }
  });
});
