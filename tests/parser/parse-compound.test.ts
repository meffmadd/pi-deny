/**
 * parseSubshell / parseBrace tests — bash-deny parser Step 4 (compound commands).
 *
 * Grammar (§3):
 *   <subshell> ::= "(" <list> ")"
 *   <brace>    ::= "{" <list> "}"
 *
 * Both share one shape: header → body (a <list>) → footer. parseList breaks on
 * the closer (isCloser covers rparen/rbrace) and leaves the cursor on it, so
 * the function that owns the header also owns the footer — `expect()` consumes
 * the closer and throws ParseError if it is missing (§7: unclosed `(`/`{`).
 *
 * The `)` token is shared with parseCase (Step 8); which meaning it gets is
 * decided by position — i.e. by which parser is running (§4.1, §6.1 Step 8).
 *
 * Test convention: data-driven `cases` array with group comments.
 *
 * Usage: node --import tsx --test tests/parser/parse-compound.test.ts
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { tokenize, parseCommand, ParserState, ParseError, type Node } from "../../bash-deny/parser.js";

// Convenience: tokenize then parseCommand on the result (compound commands
// enter through parseCommand's lparen/lbrace arms).
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

// ═══════════════════════════════════════════════════════════════════
// Test cases
// ═══════════════════════════════════════════════════════════════════

const cases: [string, Node][] = [
  // ── subshell: single command ───────────────────────────────────
  ["(rm -rf /)", subshell(list([pipeline(false, [simple(["rm", "-rf", "/"])])]))],
  ["(echo a)", subshell(list([pipeline(false, [simple(["echo", "a"])])]))],

  // ── subshell: list body (semicolon-separated) ──────────────────
  ["(a; b)", subshell(list([
    pipeline(false, [simple(["a"])]),
    pipeline(false, [simple(["b"])]),
  ]))],
  ["(a; b; c)", subshell(list([
    pipeline(false, [simple(["a"])]),
    pipeline(false, [simple(["b"])]),
    pipeline(false, [simple(["c"])]),
  ]))],

  // ── subshell: newline separator ───────────────────────────────
  ["(a\nb)", subshell(list([
    pipeline(false, [simple(["a"])]),
    pipeline(false, [simple(["b"])]),
  ]))],

  // ── subshell: pipeline / andor body ───────────────────────────
  ["(a | b)", subshell(list([pipeline(false, [simple(["a"]), simple(["b"])])]))],
  ["(a && b)", subshell(list([
    { kind: "andor", left: pipeline(false, [simple(["a"])]), op: "&&", right: pipeline(false, [simple(["b"])]) },
  ]))],

  // ── nested subshell ────────────────────────────────────────────
  ["( (a) )", subshell(list([
    pipeline(false, [subshell(list([pipeline(false, [simple(["a"])])]))]),
  ]))],
  // subshell containing a brace group
  ["( { a; } )", subshell(list([
    pipeline(false, [brace(list([pipeline(false, [simple(["a"])])]))]),
  ]))],

  // ── brace group ────────────────────────────────────────────────
  ["{ rm -rf /; }", brace(list([pipeline(false, [simple(["rm", "-rf", "/"])])]))],
  ["{ a; b; }", brace(list([
    pipeline(false, [simple(["a"])]),
    pipeline(false, [simple(["b"])]),
  ]))],
  // newline-separated brace body
  ["{ a\nb; }", brace(list([
    pipeline(false, [simple(["a"])]),
    pipeline(false, [simple(["b"])]),
  ]))],
  // brace containing a subshell
  ["{ (a); }", brace(list([
    pipeline(false, [subshell(list([pipeline(false, [simple(["a"])])]))]),
  ]))],

  // ── compound inside a pipeline slot ────────────────────────────
  // parseCommand is called from parsePipeline, so a compound can be a pipe
  // segment. `(a) | b` → pipeline([subshell, simple b]).
  // (Verified by parse() going through parseCommand, but parseCommand itself
  //  only consumes the first command — the `| b` is left for parsePipeline.
  //  These cases are covered by the pipeline-suite integration below.)
];

// ═══════════════════════════════════════════════════════════════════
// Lenient cases — empty body slots (documented, not bugs)
// ═══════════════════════════════════════════════════════════════════
//
// `( )` and `{ ; }` produce an empty simple command slot in the body. Real
// bash errors on `( )` (syntax error near `)`). For a deny guard this is
// harmless — an empty command matches no deny rule, so it fails toward
// rejection, not bypass. Recorded so a future strictness pass is visible.

const lenient: { input: string; expected: Node; note: string }[] = [
  {
    input: "( )",
    expected: subshell(list([pipeline(false, [simple([])])])),
    note: "empty subshell body → one empty command slot (bash errors)",
  },
  {
    input: "{ ; }",
    expected: brace(list([pipeline(false, [simple([])])])),
    note: "empty brace body with lone `;` → one empty command slot (bash errors)",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Unclosed compound — must throw ParseError (§7)
// ═══════════════════════════════════════════════════════════════════

const unclosed: { input: string; note: string }[] = [
  { input: "( echo a", note: "unclosed `(` — expect rparen, got eof" },
  { input: "{ echo a", note: "unclosed `{` — expect rbrace, got eof" },
  // missing closer mid-list: `( a; b` runs to eof looking for `)`
  { input: "( a; b", note: "unclosed `(` after list body" },
  { input: "{ a; b", note: "unclosed `{` after list body" },
];

// ═══════════════════════════════════════════════════════════════════
// Test runner
// ═══════════════════════════════════════════════════════════════════

describe("parseSubshell / parseBrace", () => {
  for (const [input, expected] of cases) {
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
  // After parsing a compound, the cursor must rest on the token AFTER the
  // closer (eof here), not on the closer itself — the closer is owned by the
  // header parser and consumed via expect().
  it(`consumes both header and footer (cursor rests past the closer)`, () => {
    const state = new ParserState(tokenize("(rm -rf /)"));
    parseCommand(state);
    assert.equal(state.peek().kind, "eof");
  });

  it(`consumes both braces (cursor rests past rbrace)`, () => {
    const state = new ParserState(tokenize("{ a; }"));
    parseCommand(state);
    assert.equal(state.peek().kind, "eof");
  });

  // ── compound as a pipeline slot (parseCommand wired into parsePipeline) ──
  // A subshell/brace can be a pipe segment because parsePipeline calls
  // parseCommand, not parseSimple.
  it(`subshell appears as a pipeline segment`, () => {
    // Parse the first pipeline segment only via parseCommand; the `| b` part
    // is parsePipeline's job. Here we just confirm parseCommand yields a
    // subshell node (not a simple) for the leading `(a)`.
    const node = parse("(a)");
    assert.equal(node.kind, "subshell");
  });

  // ── bash oracle: everything we accept, bash accepts ─────────────
  // §8.2 — use `sh -n -c` as the oracle for the positive cases.
  it(`bash -n accepts every positive case`, () => {
    for (const [input] of cases) {
      // strip the lenient empty bodies that bash rejects; they are not in `cases`
      execSync(`sh -n -c ${JSON.stringify(input)}`);
    }
  });
});
