/**
 * parseAndOr tests — bash-deny parser Step 2 (and_or production).
 *
 * Grammar (§3): <and_or> ::= <pipeline> ( ("&&" | "||") <pipeline> )*
 *
 * parseAndOr sits above parsePipeline and below parseList:
 *  - operands are parsePipeline (| binds tighter than &&/||)
 *  - zero operators → returns the pipeline alone (no andor wrap)
 *  - the `*` is implemented as an accumulator loop → LEFT-associative trees
 *
 * Associativity (deliberate, enforced by these tests):
 *   a && b && c  →  ((a && b) && c)          left-associative
 *   a && b || c  →  ((a && b) || c)         same precedence for && and ||
 * Real bash gives && higher precedence than || (a || b && c → a || (b && c));
 * this parser models them at one precedence level (§3 simplification). The
 * walker reaches the same leaves either way, so this is not a bypass risk.
 *
 * Test convention: data-driven `cases` array with group comments.
 *
 * Usage: node --import tsx --test tests/parser/parse-andor.test.ts
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { tokenize, parseAndOr, ParserState, type Node } from "../../bash-deny/parser.js";

// Convenience: tokenize then parseAndOr on the result.
const parse = (s: string): Node =>
  parseAndOr(new ParserState(tokenize(s)));

// ── node builders ─────────────────────────────────────────────────
const simple = (tokens: string[]): Node => ({ kind: "simple", tokens });
const pipeline = (bang: boolean, commands: Node[]): Node => ({
  kind: "pipeline", bang, commands,
});
const andor = (left: Node, op: "&&" | "||", right: Node): Node => ({
  kind: "andor", left, op, right,
});

// ═══════════════════════════════════════════════════════════════════
// Test cases
// ═══════════════════════════════════════════════════════════════════

const cases: [string, Node][] = [
  // ── single pipeline, no operator (returns pipeline alone) ──────
  ["echo hi", pipeline(false, [simple(["echo", "hi"])])],
  ["a | b", pipeline(false, [simple(["a"]), simple(["b"])])],
  ["! a | b", pipeline(true, [simple(["a"]), simple(["b"])])],

  // ── single operator ────────────────────────────────────────────
  ["a && b", andor(pipeline(false, [simple(["a"])]), "&&", pipeline(false, [simple(["b"])]))],
  ["a || b", andor(pipeline(false, [simple(["a"])]), "||", pipeline(false, [simple(["b"])]))],

  // ── left-associativity (the accumulator pattern) ───────────────
  // a && b && c → ((a && b) && c)
  ["a && b && c",
    andor(
      andor(pipeline(false, [simple(["a"])]), "&&", pipeline(false, [simple(["b"])])),
      "&&",
      pipeline(false, [simple(["c"])]))],
  // a || b || c → ((a || b) || c)
  ["a || b || c",
    andor(
      andor(pipeline(false, [simple(["a"])]), "||", pipeline(false, [simple(["b"])])),
      "||",
      pipeline(false, [simple(["c"])]))],

  // ── pipeline operands: | binds tighter than &&/|| ──────────────
  // a | b && c → (a | b) && c
  ["a | b && c",
    andor(pipeline(false, [simple(["a"]), simple(["b"])]), "&&", pipeline(false, [simple(["c"])]))],
  // a | b || c | d → (a | b) || (c | d)
  ["a | b || c | d",
    andor(
      pipeline(false, [simple(["a"]), simple(["b"])]),
      "||",
      pipeline(false, [simple(["c"]), simple(["d"])]))],
  // long chain with mixed pipe and andor
  // a | b || c | d && e → ((a | b) || (c | d)) && e
  ["a | b || c | d && e",
    andor(
      andor(
        pipeline(false, [simple(["a"]), simple(["b"])]),
        "||",
        pipeline(false, [simple(["c"]), simple(["d"])])),
      "&&",
      pipeline(false, [simple(["e"])]))],

  // ── bang scopes to the pipeline operand, not the andor ─────────
  // ! a && b → (!a) && b
  ["! a && b",
    andor(pipeline(true, [simple(["a"])]), "&&", pipeline(false, [simple(["b"])]))],
  // ! a || b → (!a) || b
  ["! a || b",
    andor(pipeline(true, [simple(["a"])]), "||", pipeline(false, [simple(["b"])]))],

  // ── decision #2 / #3 propagate through andor ─────────────────
  // kw as word survives into operands
  ["echo if && grep for",
    andor(pipeline(false, [simple(["echo", "if"])]), "&&", pipeline(false, [simple(["grep", "for"])]))],
  // assignment serialization preserved in operands
  ["FOO=bar rm && grep x",
    andor(pipeline(false, [simple(["FOO=bar", "rm"])]), "&&", pipeline(false, [simple(["grep", "x"])]))],
];

// ═══════════════════════════════════════════════════════════════════
// Same-precedence behavior — documented divergence from bash (not a bug)
// ═══════════════════════════════════════════════════════════════════
//
// §3 models && and || at one precedence level, so a || b && c parses as
// (a || b) && c (left-assoc, no precedence climb). Real bash would give
// a || (b && c) because && binds tighter. The walker reaches the same
// leaves either way, so this is recorded as a documented simplification.

const samePrecedence: { input: string; expected: Node; note: string }[] = [
  {
    input: "a || b && c",
    expected: andor(
      andor(pipeline(false, [simple(["a"])]), "||", pipeline(false, [simple(["b"])])),
      "&&",
      pipeline(false, [simple(["c"])])),
    note: "same precedence: (a || b) && c; bash would give a || (b && c)",
  },
  {
    input: "a && b || c && d",
    expected: andor(
      andor(
        andor(pipeline(false, [simple(["a"])]), "&&", pipeline(false, [simple(["b"])])),
        "||",
        pipeline(false, [simple(["c"])])),
      "&&",
      pipeline(false, [simple(["d"])])),
    note: "flat left-assoc chain ((a && b) || c) && d",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Test runner
// ═══════════════════════════════════════════════════════════════════

describe("parseAndOr", () => {
  for (const [input, expected] of cases) {
    it(`${JSON.stringify(input)} → ${JSON.stringify(expected)}`, () => {
      assert.deepStrictEqual(parse(input), expected);
    });
  }

  for (const { input, expected, note } of samePrecedence) {
    it(`${JSON.stringify(input)} (same-prec: ${note})`, () => {
      assert.deepStrictEqual(parse(input), expected);
    });
  }

  // ── cursor rests on the token parseAndOr does NOT own ───────────
  // parseAndOr owns && and ||; it must leave ;/&/newline/eof for parseList.

  it(`rests on eof after a full andor`, () => {
    const state = new ParserState(tokenize("a && b"));
    parseAndOr(state);
    assert.equal(state.peek().kind, "eof");
  });

  it(`rests on ; after an andor that stops at a list separator`, () => {
    const state = new ParserState(tokenize("a && b; c"));
    parseAndOr(state);
    assert.equal(state.peek().kind, "semi");
  });

  it(`rests on & (amp) after an andor`, () => {
    const state = new ParserState(tokenize("a && b &"));
    parseAndOr(state);
    assert.equal(state.peek().kind, "amp");
  });

  it(`rests on newline after an andor`, () => {
    const state = new ParserState(tokenize("a && b\nc"));
    parseAndOr(state);
    assert.equal(state.peek().kind, "nl");
  });

  // ── no operator → no andor wrap (returns the pipeline node) ─────
  it(`returns a pipeline node (not andor) when there is no operator`, () => {
    const node = parse("a | b");
    assert.equal(node.kind, "pipeline");
  });

  // ── left-associativity invariant ───────────────────────────────
  // For a homogeneous chain, the left child of the root must itself be an
  // andor (the chain nests leftward), and the right child must be a plain
  // pipeline (the last element).
  it(`builds left-associative trees for chains`, () => {
    const node = parse("a && b && c && d") as {
      kind: "andor"; left: Node; right: Node;
    };
    assert.equal(node.kind, "andor");
    assert.equal(node.right.kind, "pipeline");        // right is the last element
    assert.equal(node.left.kind, "andor");            // left is the nested chain
    // and the nested chain's right is also a pipeline (c), left is andor (a&&b)
    const inner = node.left as { kind: "andor"; left: Node; right: Node };
    assert.equal(inner.right.kind, "pipeline");
    assert.equal(inner.left.kind, "andor");
  });
});
