/**
 * parseCase tests — bash-deny parser Step 8 (case clause).
 *
 * Grammar (§3):
 *   <case_clause>  ::= "case" <word> "in"
 *                      <pattern_list> ")" <list> ";;"
 *                      ( <pattern_list> ")" <list> ";;" )*
 *                      "esac"
 *   <pattern_list> ::= <word> ( "|" <word> )*
 *
 * Same header → body → footer shape as parseFor/parseIf (Steps 5–7), but the
 * body is a list of branches, not a single <list>. Four design decisions under
 * test:
 *
 *   - The `word` after `case` is stored as a Node (a single `simple`), per
 *     §6.1 Step 8. It is the value being matched.
 *   - `pattern_list` uses `|` as pattern ALTERNATION (`a|b` = "match a or b"),
 *     not a pipeline. The tokenizer emits both as `op "|"`; the parser
 *     disambiguates by position — between `in` and `)` it's an alternator
 *     (§3 note, §6.1 Step 8). Patterns are collected as `string[]` (globs like
 *     `*` are opaque word content).
 *   - The `)` that ends the patterns is the SAME token as subshell-close
 *     (`rparen`). The tokenizer emits `rparen` either way; the parser decides
 *     by position — inside parseCase it ends the pattern list, inside
 *     parseSubshell it closes the subshell (§6.1 Step 8).
 *   - `;;` (`dsemi`) is mandatory on EVERY branch, including the last (§3
 *     grammar, §7). Newlines are tolerated after `in`, between branches, and
 *     before `esac` (§7: newline is a list separator).
 *
 * Bash oracle: assertShSyntax (spawnSync with explicit argv) passes multiline
 * commands through cleanly, so newline-containing cases ARE validated against
 * `sh -n` (unlike the execSync oracle in parse-for/parse-if, which skips them).
 *
 * Test convention: data-driven `cases` array with group comments.
 *
 * Usage: node --import tsx --test tests/parser/parse-case.test.ts
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { tokenize, parseCommand, ParserState, ParseError, type Node } from "../../bash-deny/parser.js";
import { assertShSyntax } from "../utils";

// Convenience: tokenize then parseCommand on the result (`case` enters through
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
const whileNode = (cond: Node, body: Node, until: boolean): Node => ({
  kind: "while", cond, body, until,
});
const ifNode = (
  branches: { cond: Node, body: Node }[],
  elseBody?: Node,
): Node => ({ kind: "if", branches, else: elseBody });
const branch = (pat: string[], body: Node) => ({ pat, body });
const caseNode = (word: Node, branches: { pat: string[], body: Node }[]): Node => ({
  kind: "case", word, branches,
});

// ── bash oracle helper (inverse of assertShSyntax) ────────────────
function shRejects(cmd: string): boolean {
  const r = spawnSync("sh", ["-n", "-c", cmd], { encoding: "utf8", timeout: 5000 });
  return r.status !== 0;
}

// ═══════════════════════════════════════════════════════════════════
// Test cases
// ═══════════════════════════════════════════════════════════════════

const cases: [string, Node][] = [
  // ── canonical form: single branch, single pattern ─────────────
  ["case x in a) echo a;; esac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [simple(["echo", "a"])])])),
  ])],

  // ── default glob pattern ───────────────────────────────────────
  ["case $x in *) echo default;; esac", caseNode(simple(["$x"]), [
    branch(["*"], list([pipeline(false, [simple(["echo", "default"])])])),
  ])],

  // ── two branches ───────────────────────────────────────────────
  ["case x in a) echo a;; b) echo b;; esac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [simple(["echo", "a"])])])),
    branch(["b"], list([pipeline(false, [simple(["echo", "b"])])])),
  ])],

  // ── pattern alternation a|b (§3 note: | is alternation, not pipeline) ──
  ["case x in a|b) echo ab;; esac", caseNode(simple(["x"]), [
    branch(["a", "b"], list([pipeline(false, [simple(["echo", "ab"])])])),
  ])],

  // ── alternation with spaces around | ──────────────────────────
  ["case x in a | b) echo ab;; esac", caseNode(simple(["x"]), [
    branch(["a", "b"], list([pipeline(false, [simple(["echo", "ab"])])])),
  ])],

  // ── three-way alternation ─────────────────────────────────────
  ["case x in a|b|c) echo abc;; esac", caseNode(simple(["x"]), [
    branch(["a", "b", "c"], list([pipeline(false, [simple(["echo", "abc"])])])),
  ])],

  // ── glob alternation ──────────────────────────────────────────
  ["case x in *.txt|*.md) echo;; esac", caseNode(simple(["x"]), [
    branch(["*.txt", "*.md"], list([pipeline(false, [simple(["echo"])])])),
  ])],

  // ── newline after `in` (§7: newline is a list separator) ──────
  ["case x in\na) echo a;;\nesac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [simple(["echo", "a"])])])),
  ])],

  // ── newline between branches ──────────────────────────────────
  ["case x in\na) echo a;;\nb) echo b;;\nesac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [simple(["echo", "a"])])])),
    branch(["b"], list([pipeline(false, [simple(["echo", "b"])])])),
  ])],

  // ── newline before `;;` ───────────────────────────────────────
  ["case x in\na) echo a\n;;\nesac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [simple(["echo", "a"])])])),
  ])],

  // ── full multiline form (nl before ;; on every branch) ────────
  ["case x in\na) echo a\n;;\nb) echo b\n;;\nesac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [simple(["echo", "a"])])])),
    branch(["b"], list([pipeline(false, [simple(["echo", "b"])])])),
  ])],

  // ── compact form (no separators between branches / before esac) ──
  ["case x in a) echo a;;b) echo b;;esac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [simple(["echo", "a"])])])),
    branch(["b"], list([pipeline(false, [simple(["echo", "b"])])])),
  ])],

  // ── multi-statement body (semicolon-separated) ────────────────
  ["case x in a) echo one; echo two;; esac", caseNode(simple(["x"]), [
    branch(["a"], list([
      pipeline(false, [simple(["echo", "one"])]),
      pipeline(false, [simple(["echo", "two"])]),
    ])),
  ])],

  // ── multi-statement body (newline-separated) ──────────────────
  ["case x in a) echo one\necho two\n;; esac", caseNode(simple(["x"]), [
    branch(["a"], list([
      pipeline(false, [simple(["echo", "one"])]),
      pipeline(false, [simple(["echo", "two"])]),
    ])),
  ])],

  // ── deny-relevant: rm -rf inside a case body ──────────────────
  ["case x in a) rm -rf /;; esac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [simple(["rm", "-rf", "/"])])])),
  ])],

  // ── glob patterns, multiline ─────────────────────────────────
  ["case $host in\n*.example.com) echo;;\n*) echo default;;\nesac", caseNode(simple(["$host"]), [
    branch(["*.example.com"], list([pipeline(false, [simple(["echo"])])])),
    branch(["*"], list([pipeline(false, [simple(["echo", "default"])])])),
  ])],

  // ── body starts on the next line after `)` (leading empty simple) ──
  // `a)\n` produces a leading empty body item (parseList lenient: a separator
  // with no preceding command yields an empty simple). Bash collapses the
  // blank line; we keep an empty simple that matches no deny rule.
  ["case x in\na)\necho a\n;;\nesac", caseNode(simple(["x"]), [
    branch(["a"], list([
      pipeline(false, [simple([])]),
      pipeline(false, [simple(["echo", "a"])]),
    ])),
  ])],

  // ── quoted word after `case` ──────────────────────────────────
  ["case \"$x\" in a) echo;; esac", caseNode(simple(["$x"]), [
    branch(["a"], list([pipeline(false, [simple(["echo"])])])),
  ])],

  // ── deny-relevant: kubectl inside a case body ─────────────────
  ["case $x in a) kubectl delete pod;; esac", caseNode(simple(["$x"]), [
    branch(["a"], list([pipeline(false, [simple(["kubectl", "delete", "pod"])])])),
  ])],
];

// ═══════════════════════════════════════════════════════════════════
// Nested / compound integration
// ═══════════════════════════════════════════════════════════════════

const nested: [string, Node][] = [
  // ── subshell in body ──────────────────────────────────────────
  ["case x in a) (echo);; esac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [subshell(list([pipeline(false, [simple(["echo"])])]))])])),
  ])],

  // ── brace group in body ───────────────────────────────────────
  ["case x in a) { echo; };; esac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [brace(list([pipeline(false, [simple(["echo"])])]))])])),
  ])],

  // ── if in body ────────────────────────────────────────────────
  ["case x in a) if true; then echo; fi;; esac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [ifNode([
      { cond: list([pipeline(false, [simple(["true"])])]), body: list([pipeline(false, [simple(["echo"])])]) },
    ])])])),
  ])],

  // ── for in body ───────────────────────────────────────────────
  ["case x in a) for y in 1; do echo; done;; esac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [forNode("y", ["1"], list([pipeline(false, [simple(["echo"])])]))])])),
  ])],

  // ── while in body ─────────────────────────────────────────────
  ["case x in a) while false; do echo; done;; esac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [whileNode(
      list([pipeline(false, [simple(["false"])])]),
      list([pipeline(false, [simple(["echo"])])]),
      false,
    )])])),
  ])],

  // ── case in subshell ──────────────────────────────────────────
  ["(case x in a) echo;; esac)", subshell(list([pipeline(false, [caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [simple(["echo"])])])),
  ])])]))],

  // ── case in brace group ───────────────────────────────────────
  ["{ case x in a) echo;; esac; }", brace(list([pipeline(false, [caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [simple(["echo"])])])),
  ])])]))],

  // ── nested case ───────────────────────────────────────────────
  ["case x in a) case y in b) echo;; esac;; esac", caseNode(simple(["x"]), [
    branch(["a"], list([pipeline(false, [caseNode(simple(["y"]), [
      branch(["b"], list([pipeline(false, [simple(["echo"])])])),
    ])])])),
  ])],
];

// ═══════════════════════════════════════════════════════════════════
// Lenient cases — documented divergences (fail toward rejection, not bypass)
// ═══════════════════════════════════════════════════════════════════
//
// Bash only allows NEWLINES (not `;`) after `in` and between branches. Our
// skipSeparators accepts `;` too. Over-accepting here means we parse and check
// MORE commands, not fewer — the deny guard is not bypassed.

const lenient: { input: string; expected: Node; note: string }[] = [
  {
    input: "case x in; a) echo;; esac",
    expected: caseNode(simple(["x"]), [branch(["a"], list([pipeline(false, [simple(["echo"])])]))]),
    note: "`;` after `in` (bash rejects `;`, only newlines allowed here)",
  },
  {
    input: "case x in a) echo;; ; b) echo;; esac",
    expected: caseNode(simple(["x"]), [
      branch(["a"], list([pipeline(false, [simple(["echo"])])])),
      branch(["b"], list([pipeline(false, [simple(["echo"])])])),
    ]),
    note: "`;` after `;;` between branches (bash rejects `;`, only newlines)",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Limitations — bash accepts, we reject (documented spec divergences)
// ═══════════════════════════════════════════════════════════════════
//
// Three bash-isms the §3 grammar deliberately does not model. Each throws
// ParseError. These reject VALID bash, so for a deny guard the Step 10 wiring
// must treat a ParseError as fail-CLOSED (block) — otherwise a malicious
// command hidden in one of these forms would bypass. Revisit before wiring.

const limitations: { input: string; note: string }[] = [
  {
    input: "case x in (a) echo;; esac",
    note: "POSIX optional leading `(` before pattern — §3 grammar omits it",
  },
  {
    input: "case x in a) echo a\nesac",
    note: "bash allows omitting `;;` on the last branch; §3/§7 require `;;` on every branch",
  },
  {
    input: "case x in esac",
    note: "bash allows zero branches; §3 grammar requires one-or-more (first branch mandatory)",
  },
];

// ═══════════════════════════════════════════════════════════════════
// Unclosed / malformed case — must throw ParseError (§7)
// ═══════════════════════════════════════════════════════════════════

const unclosed: { input: string; note: string }[] = [
  { input: "case x in a) echo esac", note: "missing `;;` (esac where dsemi expected)" },
  { input: "case x in a) echo;;", note: "eof before `esac`" },
  { input: "case x in", note: "eof after `in` (no branches)" },
  { input: "case x a) echo;; esac", note: "missing `in` between word and patterns" },
  { input: "case x in a|b echo;; esac", note: "missing `)` after pattern alternation" },
  { input: "case x in a) echo;; b) echo esac", note: "missing `;;` on a middle branch" },
  { input: "case", note: "eof after `case` (no word)" },
  { input: "case x in a) echo", note: "eof in body (no `;;`)" },
];

// ═══════════════════════════════════════════════════════════════════
// Test runner
// ═══════════════════════════════════════════════════════════════════

describe("parseCase", () => {
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

  for (const { input, note } of limitations) {
    it(`${JSON.stringify(input)} throws ParseError (limitation: ${note})`, () => {
      assert.throws(
        () => parse(input),
        (e: unknown) => e instanceof ParseError,
      );
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
  // After parsing a case clause, the cursor must rest past `esac` (on eof
  // here), not on `esac` itself — `esac` is the footer, consumed via expect().
  it(`consumes header, body, and footer (cursor rests on eof)`, () => {
    const state = new ParserState(tokenize("case x in a) echo a;; esac"));
    parseCommand(state);
    assert.equal(state.peek().kind, "eof");
  });

  // ── case as a pipeline segment ─────────────────────────────────
  // parseCommand dispatches `case` → parseCase, so a case-clause can be a
  // pipe segment. Here we confirm parseCommand yields a `case` node.
  it(`case-clause appears as a pipeline segment`, () => {
    const node = parse("case x in a) echo a;; esac");
    assert.equal(node.kind, "case");
  });

  // ── bash oracle: everything we accept, bash accepts ─────────────
  // §8.2 — assertShSyntax uses spawnSync (explicit argv), so newline-containing
  // cases pass through cleanly and ARE validated (unlike the execSync oracle
  // in parse-for/parse-if, which must skip them).
  it(`bash -n accepts every positive case (incl. newlines)`, () => {
    for (const [input] of [...cases, ...nested]) {
      assertShSyntax(input);
    }
  });

  // ── bash oracle: lenient cases are real divergences ────────────
  // Confirm bash DOES reject these — they are genuine lenient divergences,
  // not cases we accidentally got right.
  it(`bash -n rejects every lenient case`, () => {
    for (const { input } of lenient) {
      assert.equal(shRejects(input), true, `bash unexpectedly accepted: ${JSON.stringify(input)}`);
    }
  });

  // ── bash oracle: limitation cases ARE valid bash ───────────────
  // Confirm bash accepts these — they are genuine bash-isms we reject on
  // purpose (spec grammar design), not data errors.
  it(`bash -n accepts every limitation case`, () => {
    for (const { input } of limitations) {
      assertShSyntax(input);
    }
  });

  // ── bash oracle: unclosed cases are real errors ────────────────
  // Confirm bash also rejects these (sanity check on the error bucket).
  it(`bash -n rejects every unclosed case`, () => {
    for (const { input } of unclosed) {
      assert.equal(shRejects(input), true, `bash unexpectedly accepted: ${JSON.stringify(input)}`);
    }
  });
});
