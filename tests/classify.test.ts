/**
 * Tests for the pure `classify` helper.
 *
 * Pass cmd + patterns in, assert CommandVerdict out. Mirrors the deny/allow
 * matrix from checkCommandDeep without going through the CLI.
 *
 * Usage: npm test
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { classify, type CommandVerdict } from "../bash-deny/cli";
import { parseLine, parseFile } from "../bash-deny/engine";
import { assertShSyntax } from "./utils";

const isDeny  = (v: CommandVerdict): v is { kind: "deny"; message: string } => v.kind === "deny";

// ═══════════════════════════════════════════════════════════════════
// Simple rule sets
// ═══════════════════════════════════════════════════════════════════

describe("classify — basic allow / deny", () => {
  const rules = [
    parseLine("kubectl delete"),
    parseLine("git push --force"),
    parseLine("rm -rf"),
  ];

  const cases: [string, "allow" | "deny"][] = [
    // Allow
    ["echo hello", "allow"],
    ["kubectl describe pod", "allow"],
    ["kubectl delete-pod foo", "allow"],
    ["git push origin", "allow"],
    ["git push --set-upstream origin feature", "allow"],
    ["rm single-file.txt", "allow"],
    ["rm -r /tmp", "allow"],

    // Deny (direct match)
    ["kubectl delete pod", "deny"],
    ["kubectl   delete   pod", "deny"],
    ["git push --force origin main", "deny"],
    ["rm -rf /", "deny"],
    ["rm -rf /tmp/foo", "deny"],

    // Deny (flags interspersed — scan-forward still matches)
    ["git -C /repo push --force origin main", "deny"],
    ["sudo kubectl delete pod", "deny"],
  ];

  for (const [cmd, expected] of cases) {
    it(`"${cmd}" → ${expected}`, () => {
      assertShSyntax(cmd);
      const v = classify(cmd, rules);
      assert.strictEqual(v.kind, expected);
      if (expected === "deny" && isDeny(v)) {
        // The denial message should mention the matched command text
        assert.ok(v.message.includes("bash-deny: blocked:"));
        assert.ok(v.message.includes("kubectl delete pod") || v.message.includes("git") || v.message.includes("rm -rf") || v.message.includes("kubectl"));
      }
    });
  }
});

// ═══════════════════════════════════════════════════════════════════
// Last-match-wins with ! exceptions
// ═══════════════════════════════════════════════════════════════════

describe("classify — ! allow-exceptions", () => {
  const rules = [
    parseLine("kubectl"),
    parseLine("! kubectl logs"),
  ];

  const cases: [string, "allow" | "deny"][] = [
    ["kubectl delete pod", "deny"],   // matches `kubectl`, no exception
    ["kubectl logs nginx", "allow"],  // `! kubectl logs` overrides `kubectl`
    ["kubectl apply -f x", "deny"],
  ];

  for (const [cmd, expected] of cases) {
    it(`"${cmd}" → ${expected}`, () => {
      assertShSyntax(cmd);
      assert.strictEqual(classify(cmd, rules).kind, expected);
    });
  }
});

// ═══════════════════════════════════════════════════════════════════
// Multi-segment commands
// ═══════════════════════════════════════════════════════════════════

describe("classify — multi-segment", () => {
  const rules = [parseLine("kubectl delete"), parseLine("rm -rf")];

  const cases: [string, "allow" | "deny"][] = [
    ["echo hello", "allow"],
    ["echo hello && kubectl delete pod", "deny"],   // first segment passes, second denied
    ["kubectl delete pod || echo safe", "deny"],    // first segment denied
    ["echo safe && echo also safe", "allow"],
    ['echo "kubectl && delete" && kubectl delete pod', "deny"],  // quotes protect sep, second still denied
  ];

  for (const [cmd, expected] of cases) {
    it(`"${cmd}" → ${expected}`, () => {
      assertShSyntax(cmd);
      assert.strictEqual(classify(cmd, rules).kind, expected);
    });
  }
});

// ═══════════════════════════════════════════════════════════════════
// Deny message shape
// ═══════════════════════════════════════════════════════════════════

describe("classify — deny message", () => {
  const rules = [parseLine("kubectl delete")];

  it("includes the matched token text and the rule text", () => {
    const cmd = "kubectl delete pod";
    assertShSyntax(cmd);
    const v = classify(cmd, rules);
    assert.ok(isDeny(v));
    assert.match(v.message, /bash-deny: blocked: "kubectl delete pod"/);
    assert.match(v.message, /\(rule: "kubectl delete"\)/);
  });

  it("for wrapped commands, mentions the original (wrapped) tokens", () => {
    const cmd = "sudo kubectl delete pod";
    assertShSyntax(cmd);
    const v = classify(cmd, rules);
    assert.ok(isDeny(v));
    assert.match(v.message, /bash-deny: blocked: "sudo kubectl delete pod"/);
    assert.match(v.message, /\(rule: "kubectl delete"\)/);
  });

  it("for invalid wrapper usage, says so", () => {
    const cmd = "su - root";
    assertShSyntax(cmd);
    const v = classify(cmd, rules);
    assert.ok(isDeny(v));
    assert.match(v.message, /\(rule: "\(invalid wrapper usage\)"\)/);
  });
});

// ═══════════════════════════════════════════════════════════════════
// Empty rules
// ═══════════════════════════════════════════════════════════════════

describe("classify — empty rule set", () => {
  it("everything is allowed", () => {
    for (const cmd of ["kubectl delete pod", "rm -rf /"]) assertShSyntax(cmd);
    assert.strictEqual(classify("kubectl delete pod", []).kind, "allow");
    assert.strictEqual(classify("rm -rf /", []).kind, "allow");
  });

  it("uses default wrappers even with no rules", () => {
    const cmd = "sudo rm -rf /";
    assertShSyntax(cmd);
    // unwrapCommand still strips sudo, but with no rules nothing matches
    assert.strictEqual(classify(cmd, []).kind, "allow");
  });
});

// ═══════════════════════════════════════════════════════════════════
// Real-world rule file (smoke test)
// ═══════════════════════════════════════════════════════════════════

describe("classify — .pi/.bashdeny smoke", () => {
  const rules = parseFile(`# test
kubectl
! kubectl logs
git push --force
rm -rf
`);

  const cases: [string, "allow" | "deny"][] = [
    ["kubectl logs nginx", "allow"],
    ["kubectl delete pod", "deny"],
    ["git push --force origin", "deny"],
    ["git push origin", "allow"],
    ["rm -rf /tmp/foo", "deny"],
    ["echo hello", "allow"],
  ];

  for (const [cmd, expected] of cases) {
    it(`"${cmd}" → ${expected}`, () => {
      assertShSyntax(cmd);
      assert.strictEqual(classify(cmd, rules).kind, expected);
    });
  }
});

// ═══════════════════════════════════════════════════════════════════
// --basename normalization
// ═══════════════════════════════════════════════════════════════════

describe("classify — --basename normalization", () => {
  const rules = [parseLine("ls"), parseLine("rm ls")];

  const cases: [string, boolean, "allow" | "deny"][] = [
    // ── basename normalizes path-based command words ──────────────
    ["/bin/ls /tmp", true, "deny"],
    ["./ls /tmp", true, "deny"],
    ["../ls /tmp", true, "deny"],
    ["sudo /bin/ls /tmp", true, "deny"],

    // ── args are not normalized ────────────────────────────────────
    ["rm /bin/ls", true, "allow"],   // /bin/ls is an arg; rule 'rm ls' doesn't match

    // ── safe / non-matching ────────────────────────────────────────
    ["echo hello", true, "allow"],

    // ── without basename, path slips past ─────────────────────────
    ["/bin/ls /tmp", false, "allow"],
  ];

  for (const [cmd, basename, expected] of cases) {
    it(`"${cmd}" (basename=${basename}) → ${expected}`, () => {
      assertShSyntax(cmd);
      assert.strictEqual(classify(cmd, rules, false, basename).kind, expected);
    });
  }
});
