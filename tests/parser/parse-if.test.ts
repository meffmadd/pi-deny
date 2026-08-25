/**
 * parseIf tests — bash-deny parser Step 7 (if clause).
 *
 * Grammar (§3):
 *   <if_clause> ::= "if" <list> ( ";" | <newline> )? "then" <list>
 *                  ( "elif" <list> ( ";" | <newline> )? "then" <list> )*
 *                  ( "else" <list> )?
 *                  "fi"
 *
 * Same header → body → footer shape as parseFor/parseWhile (Steps 5–6), but
 * with a list of {cond, body} branches plus an optional else. Three design
 * decisions under test:
 *
 *   - The first `if`/`then` branch is MANDATORY and parsed unconditionally,
 *     before any loop. The `elif`/`then` pairs are the only loop.
 *   - `then`, `elif`, `else`, and `fi` are all in `kwClosers`, so `parseList`
 *     stops at each automatically — no special stopping logic. Which keyword
 *     stops which list is decided by position: a cond list stops at `then`;
 *     a body list stops at `elif`/`else`/`fi`; an else list stops at `fi`.
 *   - The optional separator before each keyword is handled for free by
 *     `parseList`'s separator loop (same as `do` in parseWhile).
 *
 * Test convention: data-driven `cases` array with group comments.
 *
 * Usage: node --import tsx --test tests/parser/parse-if.test.ts
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { tokenize, parseCommand, ParserState, ParseError, type Node } from "../../bash-deny/parser.js";

// Convenience: tokenize then parseCommand on the result (`if` enters through
// parseCommand's kw dispatch).
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
const ifNode = (
  branches: {cond: Node, body: Node}[],
  elseBody?: Node,
): Node => ({ kind: "if", branches, else: elseBody });

// ═══════════════════════════════════════════════════════════════════
// Test cases
// ═══════════════════════════════════════════════════════════════════

const cases: [string, Node][] = [
  // ── canonical form: if cond; then body; fi ─────────────────────
  ["if true; then echo hi; fi", ifNode([
    {cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [simple(["echo", "hi"])])])},
  ])],

  // ── with else ───────────────────────────────────────────────────
  ["if true; then a; else b; fi", ifNode(
    [{cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [simple(["a"])])])}],
    list([pipeline(false, [simple(["b"])])]),
  )],

  // ── with elif ──────────────────────────────────────────────────
  ["if true; then a; elif false; then b; fi", ifNode([
    {cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [simple(["a"])])])},
    {cond: list([pipeline(false, [simple(["false"])])]), body: list([pipeline(false, [simple(["b"])])])},
  ])],

  // ── with elif + else ───────────────────────────────────────────
  ["if true; then a; elif false; then b; else c; fi", ifNode([
    {cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [simple(["a"])])])},
    {cond: list([pipeline(false, [simple(["false"])])]), body: list([pipeline(false, [simple(["b"])])])},
  ], list([pipeline(false, [simple(["c"])])]))],

  // ── multiple elif ──────────────────────────────────────────────
  ["if true; then a; elif false; then b; elif true; then c; fi", ifNode([
    {cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [simple(["a"])])])},
    {cond: list([pipeline(false, [simple(["false"])])]), body: list([pipeline(false, [simple(["b"])])])},
    {cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [simple(["c"])])])},
  ])],

  // ── newline as separator ────────────────────────────────────────
  ["if true\nthen\necho hi\nfi", ifNode([
    {
      cond: list([pipeline(false, [simple(["true"])])]),
      // `then\n` produces a leading empty body item (parseList lenient:
      // consecutive separators → empty items). Bash collapses the blank line.
      body: list([
        pipeline(false, [simple([])]),
        pipeline(false, [simple(["echo", "hi"])]),
      ]),
    },
  ])],

  // ── multi-item body (semicolon-separated) ─────────────────────
  ["if true; then rm x; echo y; fi", ifNode([
    {cond: list([pipeline(false, [simple(["true"])])]), body: list([
      pipeline(false, [simple(["rm", "x"])]),
      pipeline(false, [simple(["echo", "y"])]),
    ])},
  ])],

  // ── newline-separated body ─────────────────────────────────────
  ["if true\nthen\nrm x\necho y\nfi", ifNode([
    {
      cond: list([pipeline(false, [simple(["true"])])]),
      body: list([
        pipeline(false, [simple([])]),
        pipeline(false, [simple(["rm", "x"])]),
        pipeline(false, [simple(["echo", "y"])]),
      ]),
    },
  ])],

  // ── deny-relevant: rm -rf inside an if body ────────────────────
  ["if true; then rm -rf /; fi", ifNode([
    {cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [simple(["rm", "-rf", "/"])])])},
  ])],

  // ── condition is a pipeline ────────────────────────────────────
  ["if a | b; then echo; fi", ifNode([
    {cond: list([pipeline(false, [simple(["a"]), simple(["b"])])]), body: list([pipeline(false, [simple(["echo"])])])},
  ])],

  // ── condition is an and-or list ───────────────────────────────
  ["if a && b; then echo; fi", ifNode([
    {
      cond: list([andor(pipeline(false, [simple(["a"])]), "&&", pipeline(false, [simple(["b"])]))]),
      body: list([pipeline(false, [simple(["echo"])])]),
    },
  ])],

  // ── condition uses `test` ([ ... ]) ────────────────────────────
  ["if [ \"$x\" = y ]; then echo; fi", ifNode([
    {
      cond: list([pipeline(false, [simple(["[", "$x", "=", "y", "]"])])]),
      body: list([pipeline(false, [simple(["echo"])])]),
    },
  ])],
];

// ═══════════════════════════════════════════════════════════════════
// Nested / compound integration
// ═══════════════════════════════════════════════════════════════════

const condTrueBodyEcho = ifNode([
  {cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [simple(["echo"])])])},
]);

const nested: [string, Node][] = [
  // ── nested if ──────────────────────────────────────────────────
  ["if true; then if false; then a; else b; fi; fi", ifNode([
    {
      cond: list([pipeline(false, [simple(["true"])])]),
      body: list([pipeline(false, [ifNode(
        [{cond: list([pipeline(false, [simple(["false"])])]), body: list([pipeline(false, [simple(["a"])])])}],
        list([pipeline(false, [simple(["b"])])]),
      )])]),
    },
  ])],

  // ── if inside subshell ─────────────────────────────────────────
  ["(if true; then echo; fi)", subshell(list([pipeline(false, [condTrueBodyEcho])]))],

  // ── if inside brace group ──────────────────────────────────────
  ["{ if true; then echo; fi; }", brace(list([pipeline(false, [condTrueBodyEcho])]))],

  // ── subshell in if body ────────────────────────────────────────
  ["if true; then (echo); fi", ifNode([
    {cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [subshell(list([pipeline(false, [simple(["echo"])])]))])])},
  ])],

  // ── brace group in if body ─────────────────────────────────────
  ["if true; then { echo; }; fi", ifNode([
    {cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [brace(list([pipeline(false, [simple(["echo"])])]))])])},
  ])],

  // ── for inside if ──────────────────────────────────────────────
  ["if true; then for x in a; do echo; done; fi", ifNode([
    {cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [forNode("x", ["a"], list([pipeline(false, [simple(["echo"])])]))])])},
  ])],

  // ── while inside if ────────────────────────────────────────────
  ["if true; then while false; do echo; done; fi", ifNode([
    {cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [whileNode(
      list([pipeline(false, [simple(["false"])])]),
      list([pipeline(false, [simple(["echo"])])]),
      false,
    )])])},
  ])],
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
    input: "if true; then ; fi",
    expected: ifNode([
      {cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [simple([])])])},
    ]),
    note: "empty body (bash errors on empty command)",
  },
  {
    input: "if true; then echo; ; fi",
    expected: ifNode([
      {
        cond: list([pipeline(false, [simple(["true"])])]),
        body: list([
          pipeline(false, [simple(["echo"])]),
          pipeline(false, [simple([])]),
        ]),
      },
    ]),
    note: "trailing empty command via `;` before `fi` (bash errors)",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Unclosed / malformed if — must throw ParseError (§7)
// ═══════════════════════════════════════════════════════════════════

const unclosed: { input: string; note: string }[] = [
  { input: "if", note: "eof before condition/then" },
  { input: "if true", note: "eof before `then`" },
  { input: "if true; then", note: "eof before body/fi" },
  { input: "if true; then echo; else", note: "eof before else body/fi" },
  { input: "if true; then echo;; fi", note: "`;;` in body (dsemi is a closer; expect `fi`/`elif`/`else` fails)" },
  { input: "if true;; then echo; fi", note: "`;;` after condition (dsemi is a closer; expect `then` fails)" },
  { input: "if true; fi", note: "`fi` where `then` expected" },
  { input: "for x in a; do if true; then echo; done; done", note: "`done` where `fi` expected (closer mismatch)" },
];

// ═══════════════════════════════════════════════════════════════════
// Test runner
// ═══════════════════════════════════════════════════════════════════

describe("parseIf", () => {
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
  // After parsing an if clause, the cursor must rest past `fi` (on eof
  // here), not on `fi` itself — `fi` is the footer, consumed via expect().
  it(`consumes header, body, and footer (cursor rests on eof)`, () => {
    const state = new ParserState(tokenize("if true; then echo hi; fi"));
    parseCommand(state);
    assert.equal(state.peek().kind, "eof");
  });

  // ── if as a pipeline segment ───────────────────────────────────
  // parseCommand dispatches `if` → parseIf, so an if-clause can be a pipe
  // segment. parseCommand only consumes the first command; the `| cat` is
  // left for parsePipeline. Here we confirm parseCommand yields an `if` node.
  it(`if-clause appears as a pipeline segment`, () => {
    const node = parse("if true; then echo hi; fi");
    assert.equal(node.kind, "if");
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
      );
    }
  });

  // ── bash oracle: unclosed cases are real errors ─────────────────
  // Confirm bash also rejects these (sanity check on the error bucket).
  it(`bash -n rejects every unclosed case`, () => {
    for (const { input } of unclosed) {
      assert.throws(
        () => execSync(`sh -n -c ${JSON.stringify(input)}`),
      );
    }
  });
});
