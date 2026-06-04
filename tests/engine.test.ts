/**
 * Tests for bashdeny engine
 *
 * Usage: npm test  (or: node --import tsx --test tests/engine.test.ts)
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  splitCommands,
  matchPattern,
  evaluate,
  parseLine,
  parseFile,
  checkCommand,
} from "../pi-deny/engine";

// ═══════════════════════════════════════════════════════════════════
// splitCommands
// ═══════════════════════════════════════════════════════════════════

describe("splitCommands", () => {
  const cases: [string, string[][]][] = [
    // Simple commands
    ["kubectl delete pod", [["kubectl", "delete", "pod"]]],
    ["kubectl   delete   pod", [["kubectl", "delete", "pod"]]],
    ["kubectl describe delete-pod", [["kubectl", "describe", "delete-pod"]]],

    // Command separators
    ["echo hello && kubectl delete pod", [["echo", "hello"], ["kubectl", "delete", "pod"]]],
    ["cmd1 || cmd2 && cmd3", [["cmd1"], ["cmd2"], ["cmd3"]]],
    ["cmd1; cmd2 | cmd3 & cmd4", [["cmd1"], ["cmd2"], ["cmd3"], ["cmd4"]]],

    // Quotes — separators inside quotes are NOT split
    ['echo "hello && world"', [["echo", "hello && world"]]],
    ["echo 'it is; ok'", [["echo", "it is; ok"]]],

    // Escapes
    ['echo hello\\ world', [["echo", "hello world"]]],

    // Flags interspersed (not stripped — that's matchPattern's job)
    ["git -C /x push --force origin", [["git", "-C", "/x", "push", "--force", "origin"]]],
    ["sudo kubectl delete pod", [["sudo", "kubectl", "delete", "pod"]]],

    // Edge cases
    ["", []],
    ["   ", []],
    ["&&", []],
    ["cmd && ", [["cmd"]]],
  ];

  for (const [input, expected] of cases) {
    it(`"${input}"`, () => {
      assert.deepStrictEqual(splitCommands(input), expected);
    });
  }
});

// ═══════════════════════════════════════════════════════════════════
// matchPattern
// ═══════════════════════════════════════════════════════════════════

describe("matchPattern", () => {
  const cases: [string[], string[], boolean][] = [
    // Basic scan-forward with implicit trailing
    [["kubectl", "delete", "pod"], ["kubectl", "delete"], true],
    [["kubectl", "delete"], ["kubectl", "delete"], true],
    [["kubectl", "describe", "delete-pod"], ["kubectl", "delete"], false],
    [["echo", "hello"], ["kubectl", "delete"], false],

    // Scan-forward (skips interspersed flags, implicit trailing)
    [["git", "-C", "/x", "push", "--force", "origin"], ["git", "push", "--force"], true],
    [["git", "push", "origin", "main"], ["git", "push", "--force"], false],
    [["sudo", "kubectl", "delete", "pod"], ["kubectl", "delete"], true],
    [["sudo", "-u", "root", "kubectl", "delete", "pod"], ["kubectl", "delete"], true],

    // Implicit trailing (extra tokens after last pattern token are allowed)
    [["git", "push"], ["git", "push"], true],
    [["git", "push", "--force"], ["git", "push"], true],
    [["git"], ["git", "push"], false],
    [["git", "push", "extra"], ["git", "push"], true],

    // Implicit trailing (path args after the last pattern token don't matter)
    [["rm", "-rf", "/", "foo"], ["rm", "-rf"], true],
    [["rm", "-r", "/tmp"], ["rm", "-rf"], false],

    // Single token matches any command starting with it
    [["kubectl", "logs", "nginx"], ["kubectl"], true],
    [["kubectl"], ["kubectl"], true],
    [["docker", "rm", "container"], ["kubectl"], false],

    // Implicit trailing: partial match at end works
    [["ls", "-la", "/tmp"], ["ls"], true],
    [["echo", "-s", "danger", "hello"], ["echo", "danger"], true],
    [["echo", "-s", "hello"], ["echo", "danger"], false],
  ];

  for (const [tokens, pat, expected] of cases) {
    it(`${JSON.stringify(tokens)} vs ${JSON.stringify(pat)}`, () => {
      assert.strictEqual(matchPattern(tokens, pat), expected);
    });
  }
});

// ═══════════════════════════════════════════════════════════════════
// evaluate (last-match-wins with ! overrides)
// ═══════════════════════════════════════════════════════════════════

describe("evaluate", () => {
  const rules = [
    parseLine("kubectl"),
    parseLine("! kubectl logs"),
    parseLine("git push --force"),
    parseLine("rm -rf"),
  ];

  const cases: [string[], "deny" | "pass"][] = [
    // Denied by kubectl *
    [["kubectl", "delete", "pod"], "deny"],
    [["kubectl", "get", "pod"], "deny"],

    // Allowed by ! kubectl logs *
    [["kubectl", "logs", "nginx"], "pass"],

    // Denied by git push --force *
    [["git", "push", "--force", "origin"], "deny"],

    // No match
    [["git", "push", "origin"], "pass"],
    [["echo", "hello"], "pass"],

    // Denied by rm -rf *
    [["rm", "-rf", "/"], "deny"],

    // No match (rm -r != rm -rf)
    [["rm", "-r", "/tmp"], "pass"],
  ];

  for (const [tokens, expected] of cases) {
    it(`${JSON.stringify(tokens)} → ${expected}`, () => {
      assert.strictEqual(evaluate(tokens, rules), expected);
    });
  }

  it("later rule overrides earlier (last-match-wins)", () => {
    // `kubectl` denies, then `! kubectl delete` allows — last wins
    const rules = [
      parseLine("kubectl"),
      parseLine("! kubectl delete"),
    ];
    assert.strictEqual(evaluate(["kubectl", "delete", "pod"], rules), "pass");
    assert.strictEqual(evaluate(["kubectl", "get", "pod"], rules), "deny");
  });
});

// ═══════════════════════════════════════════════════════════════════
// parseLine / parseFile
// ═══════════════════════════════════════════════════════════════════

describe("parseLine", () => {
  it("parses deny rule", () => {
    const p = parseLine("kubectl delete");
    assert.strictEqual(p.allow, false);
    assert.deepStrictEqual(p.tokens, ["kubectl", "delete"]);
    assert.strictEqual(p.raw, "kubectl delete");
  });

  it("parses allow rule", () => {
    const p = parseLine("! kubectl logs");
    assert.strictEqual(p.allow, true);
    assert.deepStrictEqual(p.tokens, ["kubectl", "logs"]);
    assert.strictEqual(p.raw, "! kubectl logs");
  });

  it("handles extra whitespace", () => {
    const p = parseLine("  !  git   push  --force  ");
    assert.strictEqual(p.allow, true);
    assert.deepStrictEqual(p.tokens, ["git", "push", "--force"]);
  });
});

describe("parseFile", () => {
  it("filters comments and empty lines", () => {
    const content = `
# Deny all kubectl
kubectl

# But allow logs
! kubectl logs

git push --force
`;
    const patterns = parseFile(content);
    assert.strictEqual(patterns.length, 3);
    assert.deepStrictEqual(patterns[0].tokens, ["kubectl"]);
    assert.deepStrictEqual(patterns[1].tokens, ["kubectl", "logs"]);
    assert.deepStrictEqual(patterns[2].tokens, ["git", "push", "--force"]);
  });
});

// ═══════════════════════════════════════════════════════════════════
// checkCommand (end-to-end convenience)
// ═══════════════════════════════════════════════════════════════════

describe("checkCommand", () => {
  const rules = [
    parseLine("kubectl delete"),
    parseLine("git push --force"),
    parseLine("rm -rf"),
  ];

  const cases: [string, string | undefined][] = [
    // Simple deny
    ["kubectl delete pod", "kubectl delete pod"],

    // Whitespace normalized
    ["kubectl   delete   pod", "kubectl delete pod"],

    // No match
    ["kubectl describe delete-pod", undefined],
    ["git push origin", undefined],
    ["echo hello", undefined],

    // Multi-segment: first passes, second denied
    ["echo hello && kubectl delete pod", "kubectl delete pod"],

    // Multi-segment: second passes, first denied
    ["kubectl delete pod || echo safe", "kubectl delete pod"],

    // Quotes protect separators
    ['echo "kubectl && delete" && kubectl delete pod', "kubectl delete pod"],

    // Flags interspersed
    ["git -C /repo push --force origin main", "git -C /repo push --force origin main"],
  ];

  for (const [input, expected] of cases) {
    it(`"${input}" → ${expected ? `deny "${expected}"` : "pass"}`, () => {
      const result = checkCommand(input, rules);
      if (expected) {
        assert.ok(result, `expected deny but got pass`);
        assert.strictEqual(result.join(" "), expected);
      } else {
        assert.strictEqual(result, undefined);
      }
    });
  }
});
