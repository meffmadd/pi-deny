import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseLine } from "../../bash-deny/engine";
import { checkCommandDeep, prepareHereDocs } from "../../bash-deny/parser";

describe("here-document handling", () => {
  const cases: [string, string[], { strict?: boolean }, boolean][] = [
    // ── bodies are data, not executable command leaves ─────────────
    ["cat <<EOF\nrm -rf /\nEOF", ["rm -rf"], {}, false],
    ["cat <<EOF\nsafe\nEOF\nrm -rf /", ["rm -rf"], {}, true],

    // ── strict expansion behavior follows delimiter quoting ────────
    ["cat <<'EOF'\n$(rm)\nEOF", [], { strict: true }, false],
    ["cat <<EOF\n$(rm)\nEOF", [], { strict: true }, true],
    ["cat <<EOF\n${cmd}\nEOF", [], { strict: true }, true],
  ];

  for (const [input, rules, options, expectDenied] of cases) {
    it(`${JSON.stringify(input)} → ${expectDenied ? "deny" : "allow"}`, () => {
      const result = checkCommandDeep(input, rules.map((rule) => parseLine(rule)), undefined, options);
      assert.strictEqual(result !== undefined, expectDenied);
    });
  }

  it("masks bodies and delimiters while preserving following source", () => {
    const prepared = prepareHereDocs("cat <<EOF\nhello\nEOF\necho ok");
    assert.strictEqual(prepared.executable, "cat <<EOF\n\n\necho ok");
    assert.deepStrictEqual(prepared.activeHereDocBodies, ["hello\n"]);
  });

  it("rejects an unterminated here-document", () => {
    const result = checkCommandDeep("cat <<EOF\nhello", []);
    assert.ok(result);
    assert.strictEqual(result.reason, "invalid");
    assert.match(result.rule, /unterminated here-document/);
  });
});
