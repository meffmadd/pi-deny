/**
 * Tests for the pure `loadRulesPure` helper.
 *
 * No temp files, no fs mocking — pass strings in, assert LoadResult out.
 * The impure `loadRules` I/O shell is exercised by tests/cli/cli.test.ts.
 *
 * Usage: npm test
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { loadRulesPure } from "../bash-deny/cli";

describe("loadRulesPure", () => {
  const cases: [
    string,                                  // name
    string | undefined,                      // fileContent
    string | undefined,                      // inlineRules
    { ok: true; count: number } | { ok: false; error: string },
  ][] = [
    // ── file content only ────────────────────────────────────
    ["both undefined → empty patterns",         undefined, undefined,        { ok: true, count: 0 }],
    ["single deny line from file",              "kubectl", undefined,        { ok: true, count: 1 }],
    ["multiple lines, comments skipped",        "# header\nkubectl\n\n! kubectl logs\n", undefined, { ok: true, count: 2 }],

    // ── inline only ──────────────────────────────────────────
    ["single inline rule",                      undefined, "kubectl",        { ok: true, count: 1 }],
    ["inline with allow-exception",             undefined, "kubectl;! kubectl logs", { ok: true, count: 2 }],
    ["inline splits on ;",                      undefined, "kubectl; git push --force; rm -rf", { ok: true, count: 3 }],
    ["inline trims whitespace",                 undefined, "  kubectl  ;   rm -rf  ", { ok: true, count: 2 }],
    ["inline skips empty segments",             undefined, ";;kubectl;;",   { ok: true, count: 1 }],
    ["inline skips # comment segments",         undefined, "# top;rm -rf",  { ok: true, count: 1 }],
    ["inline: only # comments → empty",         undefined, "# only a comment", { ok: true, count: 0 }],
    ["inline: only semicolons → empty",         undefined, ";;;",          { ok: true, count: 0 }],

    // ── file + inline merged (last wins) ─────────────────────
    ["file + inline merge (file first)",        "kubectl", "! kubectl logs", { ok: true, count: 2 }],
    ["inline can re-deny a file allow",         "! kubectl", "kubectl",     { ok: true, count: 2 }],
  ];

  for (const [name, fileContent, inlineRules, expected] of cases) {
    it(name, () => {
      const r = loadRulesPure(fileContent, inlineRules);
      if (!expected.ok) {
        assert.strictEqual(r.ok, false);
        if (r.ok === false) assert.strictEqual(r.error, expected.error);
      } else {
        assert.strictEqual(r.ok, true, `expected ok, got error: ${r.ok ? "" : r.error}`);
        if (r.ok) assert.strictEqual(r.patterns.length, expected.count);
      }
    });
  }
});
