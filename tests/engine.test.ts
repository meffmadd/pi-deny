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
  unwrapCommand,
  normalizeCommandWord,
  type WrapperDef,
} from "../bash-deny/engine";
import { checkCommandDeep } from "../bash-deny/parser";

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
  const cases: [string[], string[] | null][] = [
    // ═══════════════════════════════════════════════════════════
    // bare command (no wrapper)
    // ═══════════════════════════════════════════════════════════

    [["kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["git", "-C", "/x", "push", "--force"], ["git", "-C", "/x", "push", "--force"]],

    // ═══════════════════════════════════════════════════════════
    // sudo
    // ═══════════════════════════════════════════════════════════

    [["sudo", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["sudo", "-E", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    // -u consumes next token as user value (even if it looks like a command name)
    [["sudo", "-u", "kubectl", "echo", "hello"], ["echo", "hello"]],
    [["sudo", "-u", "root", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["sudo", "--user=root", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["sudo", "-E", "-u", "root", "-g", "admin", "rm", "-rf", "/"], ["rm", "-rf", "/"]],

    // ═══════════════════════════════════════════════════════════
    // other passthrough wrappers
    // ═══════════════════════════════════════════════════════════

    [["nohup", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["nice", "-n", "-5", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    // watch -n2 (inline value, one token)
    [["watch", "-n2", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    // watch -n 2 (space-separated value)
    [["watch", "-n", "2", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["ionice", "-c", "3", "rm", "-rf", "/"], ["rm", "-rf", "/"]],
    [["time", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["setsid", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["taskset", "-c", "0-3", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["stdbuf", "-o0", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["systemd-run", "--user", "--property=CPUQuota=50%", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["unshare", "-n", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["nsenter", "-t", "1234", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["prlimit", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],

    // ═══════════════════════════════════════════════════════════
    // env
    // ═══════════════════════════════════════════════════════════

    [["env", "FOO=bar", "DEBUG=1", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["env", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["env", "-i", "FOO=bar", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],

    // ═══════════════════════════════════════════════════════════
    // chroot / flock (consume one positional arg)
    // ═══════════════════════════════════════════════════════════

    [["chroot", "/newroot", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["flock", "/var/lock/mylock", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["flock", "-x", "-w", "5", "/var/lock/mylock", "rm", "-rf", "/"], ["rm", "-rf", "/"]],

    // ═══════════════════════════════════════════════════════════
    // c-wrappers (su -c, bash -c, etc.)
    // ═══════════════════════════════════════════════════════════

    [["su", "-c", "kubectl delete pod"], ["kubectl", "delete", "pod"]],
    [["su", "-c", "rm -rf /"], ["rm", "-rf", "/"]],
    [["su", "-", "root", "-c", "rm -rf /"], ["rm", "-rf", "/"]],
    [["bash", "-c", "kubectl delete pod"], ["kubectl", "delete", "pod"]],
    [["sh", "-c", "kubectl delete pod"], ["kubectl", "delete", "pod"]],
    [["zsh", "-c", "kubectl delete pod"], ["kubectl", "delete", "pod"]],
    [["dash", "-c", "kubectl delete pod"], ["kubectl", "delete", "pod"]],

    // ═══════════════════════════════════════════════════════════
    // eval (concat-wrapper: join args with spaces, re-tokenize)
    // ═══════════════════════════════════════════════════════════

    [["eval", "rm", "-rf", "/"], ["rm", "-rf", "/"]],
    [["eval", "rm -rf /"], ["rm", "-rf", "/"]],
    [["eval", "echo", "danger", "hello"], ["echo", "danger", "hello"]],
    [["eval", "echo danger hello"], ["echo", "danger", "hello"]],
    // eval with no payload → nothing to run
    [["eval"], null],
    // eval chained under a passthrough wrapper
    [["sudo", "eval", "rm", "-rf", "/"], ["rm", "-rf", "/"]],
    // eval nested inside a -c wrapper (re-tokenized recursively)
    [["bash", "-c", "eval rm -rf /"], ["rm", "-rf", "/"]],
    // eval with multiple quoted args gets concatenated then re-split
    [["eval", "echo", "rm -rf", "/"], ["echo", "rm", "-rf", "/"]],

    // ═══════════════════════════════════════════════════════════
    // chained wrappers
    // ═══════════════════════════════════════════════════════════

    [["sudo", "nice", "-n", "-5", "kubectl", "delete", "pod"], ["kubectl", "delete", "pod"]],
    [["sudo", "su", "-c", "kubectl delete pod"], ["kubectl", "delete", "pod"]],
    [["sudo", "bash", "-c", "rm -rf /"], ["rm", "-rf", "/"]],
    [["sudo", "nice", "-n", "-5", "su", "-c", "rm -rf /"], ["rm", "-rf", "/"]],
    [["sudo", "-u", "root", "nice", "-n", "-20", "bash", "-c", "kubectl delete pod"], ["kubectl", "delete", "pod"]],

    // ═══════════════════════════════════════════════════════════
    // nested -c (wrapper inside -c string)
    // ═══════════════════════════════════════════════════════════

    [["su", "-c", "sudo kubectl delete pod"], ["kubectl", "delete", "pod"]],

    // ═══════════════════════════════════════════════════════════
    // null returns (invalid / unwrappable)
    // ═══════════════════════════════════════════════════════════

    [[], null],
    [["sudo"], null],
    [["sudo", "-E", "-u", "root"], null],
    [["su", "-", "root"], null],
    [["su", "-c"], null],
    [["bash"], null],

    // ═══════════════════════════════════════════════════════════
    // unknown wrapper passes through unchanged
    // ═══════════════════════════════════════════════════════════

    [["unknown_wrapper", "kubectl", "delete"], ["unknown_wrapper", "kubectl", "delete"]],
  ];

  for (const [input, expected] of cases) {
    it(`${JSON.stringify(input)} → ${expected === null ? "null" : JSON.stringify(expected)}`, () => {
      if (expected === null) {
        assert.strictEqual(unwrapCommand(input), null);
      } else {
        assert.deepStrictEqual(unwrapCommand(input), expected);
      }
    });
  }

  // ── custom wrappers ──────────────────────────────────────────

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
    assert.deepStrictEqual(
      unwrapCommand(["mysudo", "kubectl", "delete"]),
      ["mysudo", "kubectl", "delete"],
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
// checkCommandDeep (end-to-end convenience)
// ═══════════════════════════════════════════════════════════════════

describe("checkCommandDeep", () => {
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
      const result = checkCommandDeep(input, rules);
      if (expected) {
        assert.ok(result, `expected deny but got pass`);
        assert.strictEqual(result!.tokens.join(" "), expected);
      } else {
        assert.strictEqual(result, undefined);
      }
    });
  }

  it("checkCommandDeep with unwrapping", () => {
    const rules = [parseLine("kubectl delete")];

    // Direct match
    let result = checkCommandDeep("kubectl delete pod", rules);
    assert.ok(result);
    assert.strictEqual(result!.tokens.join(" "), "kubectl delete pod");
    assert.strictEqual(result!.rule, "kubectl delete");

    // Wrapped match
    result = checkCommandDeep("sudo kubectl delete pod", rules);
    assert.ok(result);
    assert.strictEqual(result!.tokens.join(" "), "sudo kubectl delete pod");
    assert.strictEqual(result!.rule, "kubectl delete");

    // Invalid wrapper (su without -c)
    result = checkCommandDeep("su - root", rules);
    assert.ok(result);
    assert.strictEqual(result!.rule, "(invalid wrapper usage)");
  });
});

// ═══════════════════════════════════════════════════════════════════
// normalizeCommandWord
// ═══════════════════════════════════════════════════════════════════

describe("normalizeCommandWord", () => {
  const cases: [string, string][] = [
    // ── absolute paths ─────────────────────────────────────────────
    ["/bin/ls", "ls"],
    ["/usr/bin/env", "env"],
    ["/opt/homebrew/bin/node", "node"],

    // ── relative paths ──────────────────────────────────────────────
    ["./rm", "rm"],
    ["../rm", "rm"],
    ["./foo/bar", "bar"],
    ["subdir/prog", "prog"],

    // ── trailing slash stripped first ──────────────────────────────
    ["/bin/ls/", "ls"],
    ["./rm/", "rm"],
    ["foo/", "foo"],
    ["./foo/bar/", "bar"],

    // ── degenerate: all slashes — left unchanged (no empty basename) ──
    ["/", "/"],
    ["//", "//"],
    ["///", "///"],

    // ── degenerate: basename is "." or ".." — left unchanged ──────
    ["./", "./"],
    ["../", "../"],
    ["/bin/ls/.", "/bin/ls/."],

    // ── bare command (no slash) passes through unchanged ───────────
    ["ls", "ls"],
    ["kubectl", "kubectl"],
  ];

  for (const [word, expected] of cases) {
    it(`${JSON.stringify(word)} → ${JSON.stringify(expected)}`, () => {
      assert.strictEqual(normalizeCommandWord(word), expected);
    });
  }
});

// ═══════════════════════════════════════════════════════════════════
// Review regressions
// ═══════════════════════════════════════════════════════════════════

describe("review regressions", () => {
  const rmRules = [parseLine("rm -rf")];
  const cases: [string, boolean, boolean?][] = [
    // ── every wrapper payload segment is checked ───────────────────
    ["bash -c 'echo safe; rm -rf /'", true],
    ["eval 'echo safe; rm -rf /'", true],
    ["flock -c 'rm -rf /'", true],

    // ── command prefixes do not hide the executable ───────────────
    ["FOO=x /bin/rm -rf /", true, true],
    [">out /bin/rm -rf /", true, true],
    ["command /bin/rm -rf /", true, true],
    ["exec /bin/rm -rf /", true, true],
    ["env -u FOO /bin/rm -rf /", true, true],
    ["systemd-run --user /bin/rm victim", true, true],

    // ── canonical lexer is used for payloads and fallback ─────────
    ["bash -c \"$'rm' -rf /\"", true],
    ["f() { echo ok; }; $'rm' -rf /", true],

    // ── malformed ANSI-C Unicode remains non-fatal ─────────────────
    ["$'\\UFFFFFFFF'", false],
  ];

  for (const [input, denied, strict] of cases) {
    it(`${JSON.stringify(input)} → ${denied ? "deny" : "pass"}`, () => {
      assert.strictEqual(
        checkCommandDeep(input, rmRules, undefined, { strict: strict ?? false }) !== undefined,
        denied,
      );
    });
  }

  it("allow-exceptions cannot skip positional arguments", () => {
    const rules = [parseLine("kubectl"), parseLine("! kubectl logs")];
    assert.ok(checkCommandDeep("kubectl delete pod logs", rules));
    assert.strictEqual(checkCommandDeep("kubectl logs pod", rules), undefined);
  });
});
