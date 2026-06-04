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
  checkCommandDetailed,
  unwrapCommand,
  WRAPPERS,
  type WrapperDef,
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
// unwrapCommand
// ═══════════════════════════════════════════════════════════════════

describe("unwrapCommand", () => {
  // ── bare command (no wrapper) ──────────────────────────────────

  it("bare command passes through unchanged", () => {
    assert.deepStrictEqual(
      unwrapCommand(["kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("bare command with flags unchanged", () => {
    assert.deepStrictEqual(
      unwrapCommand(["git", "-C", "/x", "push", "--force"]),
      ["git", "-C", "/x", "push", "--force"],
    );
  });

  // ── passthrough wrappers ───────────────────────────────────────

  it("strips sudo", () => {
    assert.deepStrictEqual(
      unwrapCommand(["sudo", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("strips sudo with boolean flag", () => {
    assert.deepStrictEqual(
      unwrapCommand(["sudo", "-E", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("sudo -u consumes the user value, command follows", () => {
    assert.deepStrictEqual(
      unwrapCommand(["sudo", "-u", "kubectl", "echo", "hello"]),
      ["echo", "hello"],
    );
  });

  it("sudo -u root (user is not the command)", () => {
    assert.deepStrictEqual(
      unwrapCommand(["sudo", "-u", "root", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("sudo --user=root (inline value, no extra token consumed)", () => {
    assert.deepStrictEqual(
      unwrapCommand(["sudo", "--user=root", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("sudo -u kubectl echo (value looks like a command but is -u value)", () => {
    // -u consumes "kubectl" as the user, leaving "echo" as the real command
    assert.deepStrictEqual(
      unwrapCommand(["sudo", "-u", "kubectl", "echo", "hello"]),
      ["echo", "hello"],
    );
  });

  it("sudo with multiple flags", () => {
    assert.deepStrictEqual(
      unwrapCommand(["sudo", "-E", "-u", "root", "-g", "admin", "rm", "-rf", "/"]),
      ["rm", "-rf", "/"],
    );
  });

  it("strips nohup", () => {
    assert.deepStrictEqual(
      unwrapCommand(["nohup", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("strips nice -n", () => {
    assert.deepStrictEqual(
      unwrapCommand(["nice", "-n", "-5", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("strips watch -n2", () => {
    // -n2 is one token (flag with inline value)
    assert.deepStrictEqual(
      unwrapCommand(["watch", "-n2", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("strips watch -n 2", () => {
    // -n takes the next token as value
    assert.deepStrictEqual(
      unwrapCommand(["watch", "-n", "2", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("strips ionice", () => {
    assert.deepStrictEqual(
      unwrapCommand(["ionice", "-c", "3", "rm", "-rf", "/"]),
      ["rm", "-rf", "/"],
    );
  });

  it("strips time", () => {
    assert.deepStrictEqual(
      unwrapCommand(["time", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("strips setsid", () => {
    assert.deepStrictEqual(
      unwrapCommand(["setsid", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("strips taskset -c", () => {
    assert.deepStrictEqual(
      unwrapCommand(["taskset", "-c", "0-3", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("strips stdbuf", () => {
    assert.deepStrictEqual(
      unwrapCommand(["stdbuf", "-o0", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("strips systemd-run", () => {
    assert.deepStrictEqual(
      unwrapCommand(["systemd-run", "--user", "--property=CPUQuota=50%", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("strips unshare", () => {
    assert.deepStrictEqual(
      unwrapCommand(["unshare", "-n", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("strips nsenter -t", () => {
    assert.deepStrictEqual(
      unwrapCommand(["nsenter", "-t", "1234", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  // ── env ────────────────────────────────────────────────────────

  it("env strips VAR=val assignments", () => {
    assert.deepStrictEqual(
      unwrapCommand(["env", "FOO=bar", "DEBUG=1", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("env with no assignments", () => {
    assert.deepStrictEqual(
      unwrapCommand(["env", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("env with flags mixed in", () => {
    assert.deepStrictEqual(
      unwrapCommand(["env", "-i", "FOO=bar", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  // ── chroot ─────────────────────────────────────────────────────

  it("chroot strips root path", () => {
    assert.deepStrictEqual(
      unwrapCommand(["chroot", "/newroot", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  // ── flock ──────────────────────────────────────────────────────

  it("flock strips lock file", () => {
    assert.deepStrictEqual(
      unwrapCommand(["flock", "/var/lock/mylock", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("flock with flags and lock file", () => {
    assert.deepStrictEqual(
      unwrapCommand(["flock", "-x", "-w", "5", "/var/lock/mylock", "rm", "-rf", "/"]),
      ["rm", "-rf", "/"],
    );
  });

  // ── c-wrappers (su -c, bash -c, etc.) ─────────────────────────

  it("su -c extracts sub-command", () => {
    assert.deepStrictEqual(
      unwrapCommand(["su", "-c", "kubectl delete pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("su -c with multi-word command (quotes already stripped by splitCommands)", () => {
    // splitCommands strips shell quotes from the input, so the -c argument
    // token arrives without surrounding quote characters.
    assert.deepStrictEqual(
      unwrapCommand(["su", "-c", "rm -rf /"]),
      ["rm", "-rf", "/"],
    );
  });

  it("su - user -c extracts sub-command", () => {
    assert.deepStrictEqual(
      unwrapCommand(["su", "-", "root", "-c", "rm -rf /"]),
      ["rm", "-rf", "/"],
    );
  });

  it("bash -c extracts sub-command", () => {
    assert.deepStrictEqual(
      unwrapCommand(["bash", "-c", "kubectl delete pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("sh -c extracts sub-command", () => {
    assert.deepStrictEqual(
      unwrapCommand(["sh", "-c", "kubectl delete pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("zsh -c extracts sub-command", () => {
    assert.deepStrictEqual(
      unwrapCommand(["zsh", "-c", "kubectl delete pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("dash -c extracts sub-command", () => {
    assert.deepStrictEqual(
      unwrapCommand(["dash", "-c", "kubectl delete pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("su without -c returns null (interactive)", () => {
    assert.strictEqual(
      unwrapCommand(["su", "-", "root"]),
      null,
    );
  });

  it("su with -c but no argument returns null", () => {
    assert.strictEqual(
      unwrapCommand(["su", "-c"]),
      null,
    );
  });

  it("bash without -c returns null", () => {
    assert.strictEqual(
      unwrapCommand(["bash"]),
      null,
    );
  });

  // ── chained wrappers ───────────────────────────────────────────

  it("sudo nice (chained passthrough)", () => {
    assert.deepStrictEqual(
      unwrapCommand(["sudo", "nice", "-n", "-5", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("sudo su -c (passthrough + c-wrapper)", () => {
    assert.deepStrictEqual(
      unwrapCommand(["sudo", "su", "-c", "kubectl delete pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  it("sudo bash -c (passthrough + c-wrapper)", () => {
    assert.deepStrictEqual(
      unwrapCommand(["sudo", "bash", "-c", "rm -rf /"]),
      ["rm", "-rf", "/"],
    );
  });

  it("sudo nice su -c (three wrappers deep)", () => {
    assert.deepStrictEqual(
      unwrapCommand(["sudo", "nice", "-n", "-5", "su", "-c", "rm -rf /"]),
      ["rm", "-rf", "/"],
    );
  });

  it("sudo -u root nice -n -20 bash -c (flags + three wrappers)", () => {
    assert.deepStrictEqual(
      unwrapCommand(["sudo", "-u", "root", "nice", "-n", "-20", "bash", "-c", "kubectl delete pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  // ── nested -c (wrapper inside -c string) ───────────────────────

  it("su -c with wrapper inside the -c string", () => {
    assert.deepStrictEqual(
      unwrapCommand(["su", "-c", "sudo kubectl delete pod"]),
      ["kubectl", "delete", "pod"],
    );
  });

  // ── edge cases ─────────────────────────────────────────────────

  it("empty tokens returns null", () => {
    assert.strictEqual(unwrapCommand([]), null);
  });

  it("only wrapper, no command returns null", () => {
    assert.strictEqual(unwrapCommand(["sudo"]), null);
  });

  it("only wrapper with flags, no command returns null", () => {
    assert.strictEqual(unwrapCommand(["sudo", "-E", "-u", "root"]), null);
  });

  it("unknown first token is NOT stripped (treated as command)", () => {
    assert.deepStrictEqual(
      unwrapCommand(["unknown_wrapper", "kubectl", "delete"]),
      ["unknown_wrapper", "kubectl", "delete"],
    );
  });

  it("custom wrappers map works", () => {
    const custom: Record<string, WrapperDef> = {
      mysudo: { kind: "passthrough", valuedFlags: new Set(["-u"]) },
    };
    assert.deepStrictEqual(
      unwrapCommand(["mysudo", "-u", "admin", "rm", "-rf", "/"], custom),
      ["rm", "-rf", "/"],
    );
  });

  it("custom wrappers map: unknown without the custom map", () => {
    // mysudo is not in default WRAPPERS — treated as command
    assert.deepStrictEqual(
      unwrapCommand(["mysudo", "kubectl", "delete"]),
      ["mysudo", "kubectl", "delete"],
    );
  });

  it("prlimit (passthrough with no valued flags)", () => {
    assert.deepStrictEqual(
      unwrapCommand(["prlimit", "kubectl", "delete", "pod"]),
      ["kubectl", "delete", "pod"],
    );
  });
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

    // ── with unwrapping ──────────────────────────────────────────

    // sudo kubectl delete → unwraps to kubectl delete → denied
    ["sudo kubectl delete pod", "sudo kubectl delete pod"],

    // sudo git push --force → denied
    ["sudo git -C /repo push --force origin main", "sudo git -C /repo push --force origin main"],

    // su -c "kubectl delete pod" → unwraps → denied
    ["su -c 'kubectl delete pod'", "su -c kubectl delete pod"],

    // bash -c "rm -rf /" → denied
    ["bash -c \"rm -rf /\"", "bash -c rm -rf /"],

    // su without -c → denied (interactive, unsafe)
    ["su - root", "su - root"],

    // env kubectl → unwraps, denied
    ["env FOO=bar kubectl delete pod", "env FOO=bar kubectl delete pod"],

    // chroot /x kubectl delete → denied
    ["chroot /newroot kubectl delete pod", "chroot /newroot kubectl delete pod"],

    // wrapper with no deny match → passes
    ["sudo echo hello", undefined],
    ["sudo git push origin", undefined],
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

  it("checkCommandDetailed with unwrapping", () => {
    const rules = [parseLine("kubectl delete")];

    // Direct match
    let result = checkCommandDetailed("kubectl delete pod", rules);
    assert.ok(result);
    assert.strictEqual(result.tokens.join(" "), "kubectl delete pod");
    assert.strictEqual(result.rule, "kubectl delete");

    // Wrapped match
    result = checkCommandDetailed("sudo kubectl delete pod", rules);
    assert.ok(result);
    assert.strictEqual(result.tokens.join(" "), "sudo kubectl delete pod");
    assert.strictEqual(result.rule, "kubectl delete");

    // Invalid wrapper (su without -c)
    result = checkCommandDetailed("su - root", rules);
    assert.ok(result);
    assert.strictEqual(result.rule, "(invalid wrapper usage)");
  });
});
