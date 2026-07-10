/**
 * parsePipeline tests — bash-deny parser Step 2 (pipeline production).
 *
 * Grammar (§3): <pipeline> ::= "!"? <command> ("|" <command>)*
 *
 * parsePipeline handles two things:
 *  - the optional leading `!` (bang) → pipeline.bang
 *  - the `|` operator chain → pipeline.commands (one command per segment)
 *
 * It does NOT own `&&`/`||` (those are parseAndOr's job) or `;`/`&`/newline
 * (parseList's job). When it sees `op` with value `&&`/`||`, it stops and leaves
 * that token for the caller.
 *
 * NOTE: the field name is `commands` (this project's chosen spelling; §5 uses
 * `cmds` — the project diverges here deliberately).
 *
 * Until parseCommand exists (Step 3), the command slots are filled by parseSimple,
 * so pipelines of compound commands (a | (subshell)) are not yet covered here.
 *
 * Test convention: data-driven `cases` array with group comments.
 *
 * Usage: node --import tsx --test tests/parser/parse-pipeline.test.ts
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { tokenize, parsePipeline, ParserState, type Node } from "../../bash-deny/parser.js";

// Convenience: tokenize then parsePipeline on the result.
const parse = (s: string): Node =>
  parsePipeline(new ParserState(tokenize(s)));

// ── node builders ─────────────────────────────────────────────────
const simple = (tokens: string[]): Node => ({ kind: "simple", tokens });
const pipeline = (bang: boolean, commands: Node[]): Node => ({
  kind: "pipeline", bang, commands,
});

// ═══════════════════════════════════════════════════════════════════
// Test cases
// ═══════════════════════════════════════════════════════════════════

const cases: [string, Node][] = [
  // ── single command (no pipe, no bang) ───────────────────────────
  ["echo hi", pipeline(false, [simple(["echo", "hi"])])],
  ["kubectl delete pod", pipeline(false, [simple(["kubectl", "delete", "pod"])])],

  // ── pipe chains ─────────────────────────────────────────────────
  ["a | b", pipeline(false, [simple(["a"]), simple(["b"])])],
  ["a | b | c", pipeline(false, [simple(["a"]), simple(["b"]), simple(["c"])])],
  ["a | b | c | d | e", pipeline(false, [simple(["a"]), simple(["b"]), simple(["c"]), simple(["d"]), simple(["e"])])],
  // assignment serialization preserved across pipe segments
  ["FOO=bar rm | grep x", pipeline(false, [simple(["FOO=bar", "rm"]), simple(["grep", "x"])])],

  // ── bang (pipeline negation) ────────────────────────────────────
  ["! a", pipeline(true, [simple(["a"])])],
  ["! a | b", pipeline(true, [simple(["a"]), simple(["b"])])],
  ["! a | b | c", pipeline(true, [simple(["a"]), simple(["b"]), simple(["c"])])],

  // ── decision #2: kw as word survives into pipeline segments ─────
  ["echo if | grep for", pipeline(false, [simple(["echo", "if"]), simple(["grep", "for"])])],

  // ── stops at && / || (leaves them for parseAndOr) ───────────────
  // parsePipeline owns only `|`; on `&&`/`||` it returns what it has and the
  // cursor rests on the andor operator.
  ["a && b", pipeline(false, [simple(["a"])])],
  ["a || b", pipeline(false, [simple(["a"])])],
  ["a | b && c", pipeline(false, [simple(["a"]), simple(["b"])])],
  ["a | b || c", pipeline(false, [simple(["a"]), simple(["b"])])],
  // bang then andor — bang applies to the whole pipeline; && is left for parseAndOr
  ["! a && b", pipeline(true, [simple(["a"])])],
];

// ═══════════════════════════════════════════════════════════════════
// Lenient cases — empty command slots (documented, not bugs)
// ═══════════════════════════════════════════════════════════════════
//
// parsePipeline does not currently reject malformed input like a trailing
// `|` with no command, or a bare `!`. It produces an empty simple command in
// the slot. For a deny guard this is harmless (an empty command matches
// nothing) and fails toward rejection, not bypass. These are recorded so a
// future strictness pass is visible. Real bash errors on these.

const lenient: { input: string; expected: Node; note: string }[] = [
  {
    input: "",
    expected: pipeline(false, [simple([])]),
    note: "empty input → one empty command slot",
  },
  {
    input: "!",
    expected: pipeline(true, [simple([])]),
    note: "bare bang → negated pipeline with empty command (bash errors)",
  },
  {
    input: "a |",
    expected: pipeline(false, [simple(["a"]), simple([])]),
    note: "trailing pipe → empty command slot (bash errors)",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Test runner
// ═══════════════════════════════════════════════════════════════════

describe("parsePipeline", () => {
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

  // ── cursor rests on the token parsePipeline does NOT own ─────────
  // After parsePipeline returns, the cursor must rest on whichever token
  // stopped it, so the caller (parseAndOr/parseList) can dispatch on it.

  it(`rests on eof after a full pipeline`, () => {
    const state = new ParserState(tokenize("a | b"));
    parsePipeline(state);
    assert.equal(state.peek().kind, "eof");
  });

  it(`rests on && after a pipeline that stops at andor`, () => {
    const state = new ParserState(tokenize("a | b && c"));
    parsePipeline(state);
    assert.equal(state.peek().kind, "op");
    assert.equal((state.peek() as { value: string }).value, "&&");
  });

  it(`rests on || after a pipeline that stops at andor`, () => {
    const state = new ParserState(tokenize("a || b"));
    parsePipeline(state);
    assert.equal(state.peek().kind, "op");
    assert.equal((state.peek() as { value: string }).value, "||");
  });

  it(`rests on ; after a pipeline that stops at a list separator`, () => {
    const state = new ParserState(tokenize("a | b; c"));
    parsePipeline(state);
    assert.equal(state.peek().kind, "semi");
  });

  // ── bang is consumed, not left behind ───────────────────────────
  it(`consumes the bang token`, () => {
    const state = new ParserState(tokenize("! a | b"));
    parsePipeline(state);
    assert.notEqual(state.peek().kind, "bang");
    // after ! a | b the cursor is on eof
    assert.equal(state.peek().kind, "eof");
  });

  // ── | is distinguished from || ──────────────────────────────────
  it(`treats || as a stop, not a pipe`, () => {
    // a || b: parsePipeline should return just [a] and rest on ||
    const node = parse("a || b") as { kind: "pipeline"; commands: Node[] };
    assert.equal(node.commands.length, 1);
    assert.deepStrictEqual(node.commands[0], simple(["a"]));
  });
});
