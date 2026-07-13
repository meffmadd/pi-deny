/**
 * parseWhile tests — bash-deny parser Step 6 (while / until clause).
 *
 * Grammar (§3):
 *   <while_loop> ::= ( "while" | "until" ) <list>
 *                   ( ";" | <newline> )?
 *                   "do" <list> "done"
 *
 * Same header → body → footer shape as parseFor (Step 5), but the header is a
 * whole condition <list>, not a variable + wordlist. Two design decisions:
 *
 *   - `while` and `until` share ONE function and ONE AST shape
 *     `{kind:"while", cond, body, until}`. `until` is auto-detected via
 *     `state.check("kw","until")`; the boolean flag is the only difference.
 *   - The condition is a `parseList()`. It stops at `do` because `do` is in
 *     `kwClosers` (the closer-break rule) — the same mechanism that stops a
 *     `for` body at `done`. No special stopping logic is needed; `parseList`
 *     already knows `do` is a closer.
 *
 * The optional separator between cond and `do` is handled for free by
 * `parseList`'s separator loop (it consumes the `;`/newline, then peeks `do`,
 * sees a closer, and breaks).
 *
 * Test convention: data-driven `cases` array with group comments.
 *
 * Usage: node --import tsx --test tests/parser/parse-while.test.ts
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { tokenize, parseCommand, ParserState, ParseError, type Node } from "../../bash-deny/parser.js";

// Convenience: tokenize then parseCommand on the result (`while`/`until` enter
// through parseCommand's kw dispatch).
const parse = (s: string): Node =>
  parseCommand(new ParserState(tokenize(s)));

// ── node builders ─────────────────────────────────────────────────
const simple = (tokens: string[]): Node => ({ kind: "simple", tokens });
const pipeline = (bang: boolean, commands: Node[]): Node => ({
  kind: "pipeline", bang, commands,
});
const andor = (left: Node, op: "&&" | "||", right: Node): Node => ({
  kind: "andor", left, op, right,
});
const list = (items: Node[]): Node => ({ kind: "list", items });
const subshell = (body: Node): Node => ({ kind: "subshell", body });
const brace = (body: Node): Node => ({ kind: "brace", body });
const forNode = (v: string, words: string[], body: Node): Node => ({
  kind: "for", var: v, words, body,
});
const whileNode = (cond: Node, body: Node, until: boolean): Node => ({
  kind: "while", cond, body, until,
});

// ═══════════════════════════════════════════════════════════════════
// Test cases
// ═══════════════════════════════════════════════════════════════════

const cases: [string, Node][] = [
  // ── canonical form: while cond; do body; done ──────────────────
  ["while true; do echo hi; done", whileNode(
    list([pipeline(false, [simple(["true"])])]),
    list([pipeline(false, [simple(["echo", "hi"])])]),
    false,
  )],

  // ── until flips the until flag (same shape) ────────────────────
  ["until false; do echo hi; done", whileNode(
    list([pipeline(false, [simple(["false"])])]),
    list([pipeline(false, [simple(["echo", "hi"])])]),
    true,
  )],

  // ── newline as separator after condition ───────────────────────
  ["while true\ndo echo hi\ndone", whileNode(
    list([pipeline(false, [simple(["true"])])]),
    list([pipeline(false, [simple(["echo", "hi"])])]),
    false,
  )],

  // ── multi-item body (semicolon-separated) ─────────────────────
  ["while true; do rm x; echo y; done", whileNode(
    list([pipeline(false, [simple(["true"])])]),
    list([
      pipeline(false, [simple(["rm", "x"])]),
      pipeline(false, [simple(["echo", "y"])]),
    ]),
    false,
  )],

  // ── newline-separated body ─────────────────────────────────────
  ["while true\ndo rm x\necho y\ndone", whileNode(
    list([pipeline(false, [simple(["true"])])]),
    list([
      pipeline(false, [simple(["rm", "x"])]),
      pipeline(false, [simple(["echo", "y"])]),
    ]),
    false,
  )],

  // ── deny-relevant: rm -rf inside a while loop ──────────────────
  ["while true; do rm -rf /; done", whileNode(
    list([pipeline(false, [simple(["true"])])]),
    list([pipeline(false, [simple(["rm", "-rf", "/"])])]),
    false,
  )],

  // ── condition is a pipeline ────────────────────────────────────
  ["while a | b; do echo; done", whileNode(
    list([pipeline(false, [simple(["a"]), simple(["b"])])]),
    list([pipeline(false, [simple(["echo"])])]),
    false,
  )],

  // ── condition is an and-or list ───────────────────────────────
  ["while a && b; do echo; done", whileNode(
    list([andor(pipeline(false, [simple(["a"])]), "&&", pipeline(false, [simple(["b"])]))]),
    list([pipeline(false, [simple(["echo"])])]),
    false,
  )],

  // ── condition uses `test` ([ ... ]) ────────────────────────────
  ["while [ \"$x\" = y ]; do echo; done", whileNode(
    list([pipeline(false, [simple(["[", "$x", "=", "y", "]"])])]),
    list([pipeline(false, [simple(["echo"])])]),
    false,
  )],

  // ── condition with numeric comparison ──────────────────────────
  ["while [ $x -gt 0 ]; do echo; done", whileNode(
    list([pipeline(false, [simple(["[", "$x", "-gt", "0", "]"])])]),
    list([pipeline(false, [simple(["echo"])])]),
    false,
  )],

  // ── all-newline separators ─────────────────────────────────────
  // `do\n` produces a leading empty body item (parseList lenient: consecutive
  // separators → empty items). Bash collapses the blank line; we keep an empty
  // simple command that matches no deny rule (fails toward rejection).
  ["while true\ndo\necho hi\ndone", whileNode(
    list([pipeline(false, [simple(["true"])])]),
    list([
      pipeline(false, [simple([])]),
      pipeline(false, [simple(["echo", "hi"])]),
    ]),
    false,
  )],
];

// ═══════════════════════════════════════════════════════════════════
// Nested / compound integration
// ═══════════════════════════════════════════════════════════════════

const condTrueBodyEcho = whileNode(
  list([pipeline(false, [simple(["true"])])]),
  list([pipeline(false, [simple(["echo"])])]),
  false,
);

const nested: [string, Node][] = [
  // ── nested while ──────────────────────────────────────────────
  ["while true; do while false; do echo; done; done", whileNode(
    list([pipeline(false, [simple(["true"])])]),
    list([pipeline(false, [whileNode(
      list([pipeline(false, [simple(["false"])])]),
      list([pipeline(false, [simple(["echo"])])]),
      false,
    )])]),
    false,
  )],

  // ── while inside subshell ─────────────────────────────────────
  ["(while true; do echo; done)", subshell(list([pipeline(false, [condTrueBodyEcho])]))],

  // ── while inside brace group ──────────────────────────────────
  ["{ while true; do echo; done; }", brace(list([pipeline(false, [condTrueBodyEcho])]))],

  // ── subshell in while body ────────────────────────────────────
  ["while true; do (echo); done", whileNode(
    list([pipeline(false, [simple(["true"])])]),
    list([pipeline(false, [subshell(list([pipeline(false, [simple(["echo"])])]))])]),
    false,
  )],

  // ── brace group in while body ─────────────────────────────────
  ["while true; do { echo; }; done", whileNode(
    list([pipeline(false, [simple(["true"])])]),
    list([pipeline(false, [brace(list([pipeline(false, [simple(["echo"])])]))])]),
    false,
  )],

  // ── for inside while ──────────────────────────────────────────
  ["while true; do for x in a; do echo; done; done", whileNode(
    list([pipeline(false, [simple(["true"])])]),
    list([pipeline(false, [forNode("x", ["a"], list([pipeline(false, [simple(["echo"])])]))])]),
    false,
  )],

  // ── while inside for ──────────────────────────────────────────
  ["for x in a; do while true; do echo; done; done", forNode(
    "x", ["a"],
    list([pipeline(false, [condTrueBodyEcho])]),
  )],
];

// ═══════════════════════════════════════════════════════════════════
// Lenient cases — documented divergences (fail toward rejection, not bypass)
// ═══════════════════════════════════════════════════════════════════
//
// Bash requires a real command in the body and rejects empty commands. Our
// `parseList` accepts an empty simple command (a bare separator yields a
// `simple` with no tokens). Over-accepting here means we parse and check MORE
// commands, not fewer — the deny guard is not bypassed.

const lenient: { input: string; expected: Node; note: string }[] = [
  {
    input: "while true; do ; done",
    expected: whileNode(
      list([pipeline(false, [simple(["true"])])]),
      list([pipeline(false, [simple([])])]),
      false,
    ),
    note: "empty body (bash errors on empty command)",
  },
  {
    input: "while true; do echo hi; ; done",
    expected: whileNode(
      list([pipeline(false, [simple(["true"])])]),
      list([
        pipeline(false, [simple(["echo", "hi"])]),
        pipeline(false, [simple([])]),
      ]),
      false,
    ),
    note: "trailing empty command via `;` before `done` (bash errors)",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Unclosed / malformed while — must throw ParseError (§7)
// ═══════════════════════════════════════════════════════════════════

const unclosed: { input: string; note: string }[] = [
  { input: "while", note: "eof before condition/do" },
  { input: "while true", note: "eof before `do`" },
  { input: "while true; do echo hi", note: "eof before `done`" },
  { input: "while true;; do echo hi; done", note: "`;;` after condition (dsemi is a closer; expect `do` fails)" },
  { input: "while true; do echo hi;; done", note: "`;;` in body before `done` (both reject)" },
];

// ═══════════════════════════════════════════════════════════════════
// Test runner
// ═══════════════════════════════════════════════════════════════════

describe("parseWhile", () => {
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

  // ── header + footer both consumed ──────────────────────────────
  // After parsing a while clause, the cursor must rest past `done` (on eof
  // here), not on `done` itself — `done` is the footer, consumed via expect().
  it(`consumes header, body, and footer (cursor rests on eof)`, () => {
    const state = new ParserState(tokenize("while true; do echo hi; done"));
    parseCommand(state);
    assert.equal(state.peek().kind, "eof");
  });

  // ── while as a pipeline segment ────────────────────────────────
  // parseCommand dispatches `while` → parseWhile, so a while-loop can be a pipe
  // segment. parseCommand only consumes the first command; the `| cat` is
  // left for parsePipeline. Here we confirm parseCommand yields a `while` node.
  it(`while-loop appears as a pipeline segment`, () => {
    const node = parse("while true; do echo hi; done");
    assert.equal(node.kind, "while");
  });

  // ── bash oracle: everything we accept, bash accepts ──────────────
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

  // ── bash oracle: lenient cases are real divergences ─────────────
  // Confirm bash DOES reject these — they are genuine lenient divergences,
  // not cases we accidentally got right.
  it(`bash -n rejects every lenient case`, () => {
    for (const { input } of lenient) {
      assert.throws(
        () => execSync(`sh -n -c ${JSON.stringify(input)}`),
        /syntax error/,
      );
    }
  });

  // ── bash oracle: unclosed cases are real errors ─────────────────
  // Confirm bash also rejects these (sanity check on the error bucket).
  it(`bash -n rejects every unclosed case`, () => {
    for (const { input } of unclosed) {
      assert.throws(
        () => execSync(`sh -n -c ${JSON.stringify(input)}`),
        /syntax error/,
      );
    }
  });
});
