/**
 * parseSimple tests — bash-deny parser Step 2 (leaf production).
 *
 * parseSimple is the bottom of the grammar: it greedily consumes word/kw/assign
 * tokens into `tokens: string[]` until it hits a stop token (any structural
 * separator or compound-command opener). It is the ONLY node the engine
 * consumes, so its `tokens` shape is the contract with engine.ts.
 *
 * Three design decisions under test:
 *  - Decision #3 (serialization): `assign` → `name=value`, `word`/`kw` → `.value`.
 *  - Decision #2 (kw everywhere): `kw` is NOT a stop token — `echo if` consumes
 *    `if` as a word argument, matching real bash.
 *  - Stop set: parseSimple stops at every kind that begins a larger production
 *    (semi/amp/nl/op/lparen/rparen/lbrace/rbrace/dsemi/bang/eof).
 *
 * Test convention: data-driven `cases` array with group comments.
 *
 * Usage: node --import tsx --test tests/parser/parse-simple.test.ts
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { tokenize, parseSimple, ParserState, type Node } from "../../bash-deny/parser.js";

// Convenience: tokenize then parseSimple on the result.
const parse = (s: string): Node =>
  parseSimple(new ParserState(tokenize(s)));

// ── helpers ──────────────────────────────────────────────────────
// Build a `simple` expectation concisely.
const simple = (tokens: string[]): Node => ({ kind: "simple", tokens });

// ═══════════════════════════════════════════════════════════════════
// Test cases
// ═══════════════════════════════════════════════════════════════════

const cases: [string, Node][] = [
  // ── empty / whitespace (no tokens consumed) ─────────────────────
  ["", simple([])],
  ["  ", simple([])],
  ["\t", simple([])],

  // ── the three lesson cases ──────────────────────────────────────
  ["echo hi", simple(["echo", "hi"])],
  ["FOO=bar rm -rf /", simple(["FOO=bar", "rm", "-rf", "/"])],
  ["echo if", simple(["echo", "if"])],

  // ── single command ──────────────────────────────────────────────
  ["echo", simple(["echo"])],
  ["kubectl delete pod", simple(["kubectl", "delete", "pod"])],
  ["kubectl delete pod mypod --force", simple(["kubectl", "delete", "pod", "mypod", "--force"])],

  // ── decision #2: kw consumed as word argument ───────────────────
  // kw is NOT in the stop set — position decides, and here kw is in
  // argument position, so it is folded into tokens as a plain word.
  ["echo for", simple(["echo", "for"])],
  ["echo while", simple(["echo", "while"])],
  ["echo done", simple(["echo", "done"])],
  ["echo then", simple(["echo", "then"])],

  // ── decision #3: assignment serialization ───────────────────────
  // assign → "name=value" (engine.ts isEnvAssignment must still match).
  ["FOO=bar cmd", simple(["FOO=bar", "cmd"])],
  ["A=1 B=2 cmd", simple(["A=1", "B=2", "cmd"])],
  // assignment with value containing colons (PATH-style)
  ["PATH=/usr/bin:/bin grep foo", simple(["PATH=/usr/bin:/bin", "grep", "foo"])],
  // assignment with quoted value containing a space — value preserves the space
  ['FOO="a b" cmd', simple(["FOO=a b", "cmd"])],
  // assignment only, no command word
  ["FOO=bar", simple(["FOO=bar"])],

  // ── quoted content: separators become literal word bytes ────────
  ["echo 'a;b|c'", simple(["echo", "a;b|c"])],
  ["echo 'a&&b'", simple(["echo", "a&&b"])],
  // single-quoted empty word → "" preserved in tokens
  ["echo ''", simple(["echo", ""])],
  // double-quoted empty word → "" preserved in tokens
  ['echo ""', simple(["echo", ""])],
  // adjacent quoted/unquoted segments concatenate into one word
  ['echo "a"b"c"', simple(["echo", "abc"])],
  // single quotes inside double quotes are literal
  ['echo "it\'s"', simple(["echo", "it's"])],
  // double quotes inside single quotes are literal
  ["echo 'say \"hi\"'", simple(["echo", 'say "hi"'])],

  // ── backslash escapes outside quotes ────────────────────────────
  // escaped separator becomes a literal word byte (no split)
  ["echo\\;hi", simple(["echo;hi"])],
  ["echo \\\\", simple(["echo", "\\"])],

  // ── parameter / variable expansion words ───────────────────────
  ["echo $x", simple(["echo", "$x"])],
  ["echo ${VAR:-x}", simple(["echo", "${VAR:-x}"])],
  // ── opaque sub-constructs are one word (§4.1) ──
  // $(...) command substitution — opaque
  ["echo $(rm)", simple(["echo", "$(rm)"])],
  // empty $() → one word
  ["echo $()", simple(["echo", "$()"])],
  // $'...' ANSI-C quoting — escapes evaluated (so $'ls' ≡ ls)
  ["echo $'ls'", simple(["echo", "ls"])],
  // backticks without internal space — one word (opaque word content)
  ["echo `rm`", simple(["echo", "`rm`"])],

  // ── comments: # at word boundary consumes rest of line ──────────
  // parseSimple stops before the comment; comment produces no token here.
  ["echo # foo", simple(["echo"])],
  ["echo a # c\nb", simple(["echo", "a"])],

  // ── stop-token boundaries ───────────────────────────────────────
  // parseSimple must STOP at each structural kind and return what it has.
  // semi
  ["echo a; b", simple(["echo", "a"])],
  // chained semi — stops at first
  ["echo a;; b", simple(["echo", "a"])],
  // amp (background)
  ["echo a &", simple(["echo", "a"])],
  // newline
  ["echo a\nb", simple(["echo", "a"])],
  ["echo a\necho b", simple(["echo", "a"])],
  // op | (pipeline — parsePipeline's job)
  ["echo a | b", simple(["echo", "a"])],
  // op && (andor — parseAndOr's job)
  ["echo a && b", simple(["echo", "a"])],
  // op || (andor)
  ["echo a || b", simple(["echo", "a"])],
  // lparen (subshell opener) — stops immediately when parseSimple starts on it
  ["(echo a)", simple([])],
  // rparen (subshell closer) — stops before the closer
  ["echo a)", simple(["echo", "a"])],
  // lbrace (brace-group opener) — stops immediately when starting on it
  ["{ echo a", simple([])],
  // bang (pipeline negation) — stops immediately when starting on it
  ["! echo a", simple([])],
  // ── not a stop: glued structural chars are word bytes ──
  // `}` glued to a word is part of the word (two-token window: rbrace only at
  // command position). parseSimple does not stop — it keeps consuming.
  ["echo a}", simple(["echo", "a}"])],
];

// ═══════════════════════════════════════════════════════════════════
// Tokenizer-limitation passthrough — documented, not parseSimple bugs
// ═══════════════════════════════════════════════════════════════════
//
// These inputs hit the tokenizer's known opaque-construct limitations
// (Tier 3 F/G: $(...) and $'...' are not treated as one opaque word). They
// are included here so parseSimple's behavior on the ACTUAL token stream is
// recorded. parseSimple itself is correct — it faithfully aggregates whatever
// tokens it receives. If the tokenizer is later fixed, these expectations flip
// and the fix becomes visible.

const limitations: { input: string; expected: Node; note: string }[] = [
  {
    input: "echo `echo rm`",
    expected: simple(["echo", "`echo", "rm`"]),
    note: "backticks with internal space split (opaque construct limitation)",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Test runner
// ═══════════════════════════════════════════════════════════════════

describe("parseSimple", () => {
  for (const [input, expected] of cases) {
    it(`${JSON.stringify(input)} → ${JSON.stringify(expected)}`, () => {
      assert.deepStrictEqual(parse(input), expected);
    });
  }

  for (const { input, expected, note } of limitations) {
    it(`${JSON.stringify(input)} (limitation: ${note})`, () => {
      assert.deepStrictEqual(parse(input), expected);
    });
  }

  // ── serialization contract with engine.ts ──────────────────────
  // isEnvAssignment in engine.ts must still recognise the serialized form.
  // Importing engine creates a circular concern; instead assert the shape:
  // an assign token serializes to a string matching /^[A-Za-z_][A-Za-z0-9_]*=/.
  it(`assign serialization matches engine's assignment shape`, () => {
    const node = parse("FOO=bar rm") as { kind: "simple"; tokens: string[] };
    const assignTok = node.tokens[0];
    assert.match(assignTok, /^[A-Za-z_][A-Za-z0-9_]*=.+/);
    assert.equal(assignTok, "FOO=bar");
  });

  // ── decision #2 invariant: kw in argument position is never a stop ──
  it(`every reserved word as an argument is consumed as a word`, () => {
    for (const kw of ["if", "then", "elif", "else", "fi", "for", "in", "while", "until", "do", "done", "case", "esac"]) {
      const node = parse(`echo ${kw}`) as { kind: "simple"; tokens: string[] };
      assert.deepStrictEqual(node.tokens, ["echo", kw], `kw=${kw}`);
    }
  });

  // ── parseSimple does not consume the stop token ─────────────────
  // After parseSimple returns, the cursor must rest ON the stop token so the
  // caller (parsePipeline/parseAndOr/...) can dispatch on it.
  it(`leaves the stop token unconsumed for the caller`, () => {
    const state = new ParserState(tokenize("echo a; b"));
    parseSimple(state);
    // cursor should be on the semi now
    assert.equal(state.peek().kind, "semi");
  });
});
