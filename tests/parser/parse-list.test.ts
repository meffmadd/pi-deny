/**
 * parseList tests — bash-deny parser Step 2 (list production, the top of the spine).
 *
 * Grammar (§3): <list> ::= <and_or> ( (";" | "&" | <newline>) <and_or> )*
 *
 * parseList sits at the top of the Step-2 spine (parseSimple → parsePipeline →
 * parseAndOr → parseList). It collects and_or items into a FLAT array
 * (`items: Node[]`), consuming separators between them. Separator kind (`;` vs
 * `&` vs newline) is discarded — §5 models the list without per-item separators.
 *
 * Trailing-separator + closer-break rule (Position B):
 *   after consuming a separator, parseList BREAKS (does not push another item)
 *   if the next token cannot start a command — i.e. is a structural closer:
 *     eof, rparen, rbrace, dsemi, or a kw closer (done/fi/esac/then/else/elif/do/in).
 *   This makes trailing `a;` and nested bodies like `...; done` / `...; )` clean
 *   (no spurious empty trailing item). kw OPENERS (for/while/until/if/case) do
 *   NOT break — they can start a command. This is what lets the compound-command
 *   bodies (Step 4+) parse cleanly.
 *
 * Caller precondition: parseList assumes it is called at a command-start
 * position. Calling it on a stream beginning with `(` or `{` (an opener it
 * doesn't own) yields an empty first item — that input is the caller's job
 * (parseSubshell/parseBrace consume the opener first). See the caveat test.
 *
 * Test convention: data-driven `cases` array with group comments.
 *
 * Usage: node --import tsx --test tests/parser/parse-list.test.ts
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { tokenize, parseList, ParserState, type Node } from "../../bash-deny/parser.js";

// Convenience: tokenize then parseList on the result.
const parse = (s: string): Node =>
  parseList(new ParserState(tokenize(s)));

// ── node builders ─────────────────────────────────────────────────
const simple = (tokens: string[]): Node => ({ kind: "simple", tokens });
const pipeline = (bang: boolean, commands: Node[]): Node => ({
  kind: "pipeline", bang, commands,
});
const andor = (left: Node, op: "&&" | "||", right: Node): Node => ({
  kind: "andor", left, op, right,
});
const list = (items: Node[]): Node => ({ kind: "list", items });

// ═══════════════════════════════════════════════════════════════════
// Test cases
// ═══════════════════════════════════════════════════════════════════

const cases: [string, Node][] = [
  // ── single item (no separator) ─────────────────────────────────
  ["echo hi", list([pipeline(false, [simple(["echo", "hi"])])])],
  ["a | b", list([pipeline(false, [simple(["a"]), simple(["b"])])])],
  ["a && b", list([andor(pipeline(false, [simple(["a"])]), "&&", pipeline(false, [simple(["b"])]))])],

  // ── semicolon-separated ────────────────────────────────────────
  ["a; b", list([pipeline(false, [simple(["a"])]), pipeline(false, [simple(["b"])])])],
  ["a; b; c", list([
    pipeline(false, [simple(["a"])]),
    pipeline(false, [simple(["b"])]),
    pipeline(false, [simple(["c"])]),
  ])],
  ["a; b; c; d; e", list([
    pipeline(false, [simple(["a"])]),
    pipeline(false, [simple(["b"])]),
    pipeline(false, [simple(["c"])]),
    pipeline(false, [simple(["d"])]),
    pipeline(false, [simple(["e"])]),
  ])],

  // ── newline-separated ──────────────────────────────────────────
  ["a\nb", list([pipeline(false, [simple(["a"])]), pipeline(false, [simple(["b"])])])],

  // ── amp (background) as separator ──────────────────────────────
  ["a & b", list([pipeline(false, [simple(["a"])]), pipeline(false, [simple(["b"])])])],
  // amp and semi are interchangeable as separators (kind discarded)
  ["a; b & c; d", list([
    pipeline(false, [simple(["a"])]),
    pipeline(false, [simple(["b"])]),
    pipeline(false, [simple(["c"])]),
    pipeline(false, [simple(["d"])]),
  ])],

  // ── mixed separators ───────────────────────────────────────────
  ["a; b\nc", list([
    pipeline(false, [simple(["a"])]),
    pipeline(false, [simple(["b"])]),
    pipeline(false, [simple(["c"])]),
  ])],
  ["a && b || c; d | e && f", list([
    andor(
      andor(pipeline(false, [simple(["a"])]), "&&", pipeline(false, [simple(["b"])])),
      "||",
      pipeline(false, [simple(["c"])])),
    andor(
      pipeline(false, [simple(["d"]), simple(["e"])]),
      "&&",
      pipeline(false, [simple(["f"])])),
  ])],

  // ── trailing separator: no spurious empty item ─────────────────
  ["a;", list([pipeline(false, [simple(["a"])])])],
  ["a; b;", list([pipeline(false, [simple(["a"])]), pipeline(false, [simple(["b"])])])],
  ["a\nb\n", list([pipeline(false, [simple(["a"])]), pipeline(false, [simple(["b"])])])],
  ["a &", list([pipeline(false, [simple(["a"])])])],

  // ── bang per-item ──────────────────────────────────────────────
  ["! a; ! b; ! c", list([
    pipeline(true, [simple(["a"])]),
    pipeline(true, [simple(["b"])]),
    pipeline(true, [simple(["c"])]),
  ])],

  // ── decision #2/#3 propagate ───────────────────────────────────
  // kw-as-word survives into list items (parseSimple consumes kw as words
  // before parseList ever sees a kw at item-start)
  ["echo if; echo done", list([
    pipeline(false, [simple(["echo", "if"])]),
    pipeline(false, [simple(["echo", "done"])]),
  ])],
  // assignment serialization preserved across items
  ["FOO=bar rm; grep x", list([
    pipeline(false, [simple(["FOO=bar", "rm"])]),
    pipeline(false, [simple(["grep", "x"])]),
  ])],
];

// ═══════════════════════════════════════════════════════════════════
// Closer-break — Position B: stops at structural closers, no empty item
// ═══════════════════════════════════════════════════════════════════
//
// After a separator, parseList breaks if the next token is a closer it does
// not own. This is what makes compound-command bodies parse cleanly once
// parseFor/parseIf/parseCase/parseSubshell exist: their `done`/`fi`/`esac`/
// `)`/`}`/`;;` legitimately follow a separator, and parseList must stop there
// rather than consume an empty item. kw OPENERS (for/while/if/case) do NOT
// break — they start a command (handled once parseCommand dispatches).

const closerBreak: { input: string; expected: Node; note: string }[] = [
  {
    input: "a; done",
    expected: list([pipeline(false, [simple(["a"])])]),
    note: "kw closer `done` after `;` → break (for/while body terminator)",
  },
  {
    input: "a; fi",
    expected: list([pipeline(false, [simple(["a"])])]),
    note: "kw closer `fi` after `;` → break (if body terminator)",
  },
  {
    input: "a; esac",
    expected: list([pipeline(false, [simple(["a"])])]),
    note: "kw closer `esac` after `;` → break (case terminator)",
  },
  {
    input: "a; then",
    expected: list([pipeline(false, [simple(["a"])])]),
    note: "kw closer `then` after `;` → break (if-cond/body separator)",
  },
  {
    input: "a; }",
    expected: list([pipeline(false, [simple(["a"])])]),
    note: "rbrace after `;` → break (brace-group closer)",
  },
  {
    input: "a;; b",
    expected: list([pipeline(false, [simple(["a"])])]),
    note: "dsemi (`;;`) is a case-clause terminator, NOT a list separator → loop never runs",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Lenient cases — documented divergences (fail toward rejection, not bypass)
// ═══════════════════════════════════════════════════════════════════
//
// Consecutive separators produce empty items. Real bash errors on `a; ; b`
// and collapses blank lines (`a\n\nb` runs a then b with no empty command).
// parseList treats each separator as starting a new item, so an empty item
// appears between consecutive separators. An empty item matches no deny rule
// (fails toward rejection), so this is a cosmetic divergence, not a bypass.

const lenient: { input: string; expected: Node; note: string }[] = [
  {
    input: "a; ; b",
    expected: list([
      pipeline(false, [simple(["a"])]),
      pipeline(false, [simple([])]),
      pipeline(false, [simple(["b"])]),
    ]),
    note: "consecutive `; ;` → empty middle item (bash errors)",
  },
  {
    input: "a\n\nb",
    expected: list([
      pipeline(false, [simple(["a"])]),
      pipeline(false, [simple([])]),
      pipeline(false, [simple(["b"])]),
    ]),
    note: "blank line → empty middle item (bash collapses)",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Test runner
// ═══════════════════════════════════════════════════════════════════

describe("parseList", () => {
  for (const [input, expected] of cases) {
    it(`${JSON.stringify(input)} → ${JSON.stringify(expected)}`, () => {
      assert.deepStrictEqual(parse(input), expected);
    });
  }

  for (const { input, expected, note } of closerBreak) {
    it(`${JSON.stringify(input)} (closer-break: ${note})`, () => {
      assert.deepStrictEqual(parse(input), expected);
    });
  }

  for (const { input, expected, note } of lenient) {
    it(`${JSON.stringify(input)} (lenient: ${note})`, () => {
      assert.deepStrictEqual(parse(input), expected);
    });
  }

  // ── cursor rests on the token parseList does NOT own ───────────
  // After a full list, cursor rests on eof. After a closer-break, cursor
  // rests on the closer (so the caller — parseFor/parseSubshell/etc. — can
  // consume it).

  it(`rests on eof after a full list`, () => {
    const state = new ParserState(tokenize("a; b; c"));
    parseList(state);
    assert.equal(state.peek().kind, "eof");
  });

  it(`rests on the kw closer after a closer-break (done)`, () => {
    const state = new ParserState(tokenize("a; done"));
    parseList(state);
    assert.equal(state.peek().kind, "kw");
    assert.equal((state.peek() as { value: string }).value, "done");
  });

  it(`rests on rbrace after a closer-break`, () => {
    const state = new ParserState(tokenize("a; }"));
    parseList(state);
    assert.equal(state.peek().kind, "rbrace");
  });

  it(`rests on dsemi (it is not a list separator)`, () => {
    const state = new ParserState(tokenize("a;; b"));
    parseList(state);
    assert.equal(state.peek().kind, "dsemi");
  });

  // ── flat-array shape (not a binary tree) ───────────────────────
  it(`collects items into a flat array, not a nested tree`, () => {
    const node = parse("a; b; c; d") as { kind: "list"; items: Node[] };
    assert.equal(node.items.length, 4);
    // every item is a pipeline, not a nested list
    for (const item of node.items) {
      assert.equal(item.kind, "pipeline");
    }
  });

  // ── caller precondition caveat ─────────────────────────────────
  // parseList assumes it is called at command-start. Calling it on a stream
  // beginning with an opener it doesn't own (lparen/lbrace) yields an empty
  // first item — that input belongs to parseSubshell/parseBrace, which
  // consume the opener first. Recorded so the boundary is explicit.
  it(`caller-precondition: starting on lparen yields an empty first item`, () => {
    const node = parse("(a; )") as { kind: "list"; items: Node[] };
    // first item is empty (parseSimple stopped at lparen); this is the caller's
    // responsibility, not parseList's. parseSubshell will consume `(` first.
    assert.equal(node.items.length, 1);
    assert.deepStrictEqual(node.items[0], pipeline(false, [simple([])]));
  });
});
