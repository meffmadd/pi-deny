/**
 * Tests for strict-mode evasion detection.
 *
 * Usage: npm test  (or: node --import tsx --test tests/strict.test.ts)
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  detectStrictConstruct,
  isPathCommand,
} from "../bash-deny/strict";
import { matchPattern, findMatch, parseLine, type Pattern } from "../bash-deny/engine";
import { checkCommandDeep } from "../bash-deny/parser";
import type { StrictViolation } from "../bash-deny/strict";

// ═══════════════════════════════════════════════════════════════════
// detectStrictConstruct
// ═══════════════════════════════════════════════════════════════════

describe("detectStrictConstruct", () => {
  // `null` means "clean" (no violation); otherwise the construct name expected.
  const cases: [string, string | null][] = [
    // ── clean (no evasion constructs) ─────────────────────────────
    ["echo hello", null],
    ["kubectl delete pod", null],
    ["rm -rf /tmp", null],
    ["git -C /repo push origin main", null],
    ["VAR=value command --flag arg", null],
    ["echo $HOME", null],              // plain $VAR is NOT flagged (too common)
    ["echo $PATH", null],
    ["echo 'safe $(rm)' || true", null], // $(rm) inside single quotes = literal

    // ── command substitution $(...) ───────────────────────────────
    ["echo $(rm -rf /)", "command substitution $(...)"],
    ["$(echo ls) /tmp", "command substitution $(...)"],
    ["$(echo '')ls /tmp", "command substitution $(...)"],
    ['echo "result: $(date)"', "command substitution $(...)"], // active in double quotes
    ["echo $(date) && safe", "command substitution $(...)"],

    // ── backtick substitution ──────────────────────────────────────
    ["echo `rm -rf /`", "backtick substitution `...`"],
    ["`echo ls` /tmp", "backtick substitution `...`"],
    ["`echo ''`ls /tmp", "backtick substitution `...`"],
    ['echo "`date`"', "backtick substitution `...`"], // active in double quotes
    ["echo '`safe`' || true", null],  // backtick inside single quotes = literal

    // ── parameter expansion ${...} ────────────────────────────────
    ["echo ${HOME}", "parameter expansion ${...}"],
    ["${XX}ls /tmp", "parameter expansion ${...}"],
    ["${X-}ls /tmp", "parameter expansion ${...}"],
    ["${HOME:+}ls /tmp", "parameter expansion ${...}"],
    ['echo "${UNSET}foo"', "parameter expansion ${...}"], // active in double quotes
    ["echo '${UNSET}foo'", null],      // literal inside single quotes

    // ── ANSI-C quoting $'...' — NOT flagged (tokenizer decodes it) ──
    ["$'ls' /tmp", null],                // tokenizes to `ls` → plain rule matches
    ["$'\\154\\163' /tmp", null],        // octal → decodes to `ls`
    ["l$'\\163' /tmp", null],            // → `ls`
    ['echo "$\'safe\'"', null],        // $' inside double quotes is NOT ANSI-C quoting
    ["echo $'$(rm)'", null],           // $(rm) is literal inside $'...' — safe

    // ── brace expansion {a,b} / {1..5} ────────────────────────────
    ["{ls,/tmp}", "brace expansion {...}"],
    ["{echo,danger,hello}", "brace expansion {...}"],
    ["echo {a,b}", "brace expansion {...}"],
    ["echo {1..5}", "brace expansion {...}"],
    ["x{a,b}y", "brace expansion {...}"],
    // not brace expansion:
    ["{ echo; }", null],               // brace group (space after {)
    ["echo {a}", null],               // no comma/.. → literal in bash
    ["echo {", null],                 // no close brace
    ['echo "{a,b}"', null],           // quoted braces are literal

    // ── escape handling ────────────────────────────────────────────
    ["echo \\$(rm)", null],            // backslash escapes $ → literal
    ["echo \\`rm\\`", null],           // backslash escapes backtick

    // ── process substitution <(...) / >(...) ──────────────────────
    ["cat <(rm -rf /)", "process substitution <(...)"],
    ["echo >(rm -rf /)", "process substitution >(...)"],
    ["cat <( ls ) <(rm)", "process substitution <(...)"],   // first one wins
    // not process substitution:
    ["cat << EOF", null],               // << here-doc (not <( )
    ["cat <<< word", null],             // <<< here-string (not <( )
    ["echo '<(rm)'", null],             // single-quoted <( is literal
    ["echo \"<(rm)\"", null],            // double-quoted <( is literal
    // here-string feeds a command sub — the $() is what's flagged:
    ["cat <<< $(rm)", "command substitution $(...)"],

    // ── arithmetic $((...)) — pure NOT flagged; $(...) inside still caught ──
    ["echo $((1+1))", null],            // pure arithmetic — safe
    ["x=$((1+1))", null],
    ["echo \"$((1+1))\"", null],         // arithmetic inside double quotes — safe
    ["echo $(( $(rm) ))", "command substitution $(...)"],   // cmd-sub inside → caught
    ["echo $((a[$(rm)]))", "command substitution $(...)"],  // array-sub cmd-sub

    // ── comments — # at a word boundary hides the rest from the shell ──
    ["echo hi # $(rm)", null],          // $(rm) in a comment — not run
    ["echo hi # `rm`", null],           // backtick in a comment
    ["echo hi; # ${x}", null],           // after ;
    ["# $(rm)", null],                  // comment at start of line
    ["echo a#b", null],                 // mid-word # is literal, nothing to run
    ["echo a#$(rm)", "command substitution $(...)"],  // mid-word # literal; $(rm) runs
  ];

  for (const [input, expected] of cases) {
    it(`${JSON.stringify(input)} → ${expected ? expected : "clean"}`, () => {
      const result = detectStrictConstruct(input);
      if (expected === null) {
        assert.strictEqual(result, null);
      } else {
        assert.ok(result, `expected violation "${expected}" but got null`);
        assert.strictEqual((result as StrictViolation).construct, expected);
      }
    });
  }

  it("returns the FIRST violation found", () => {
    // $() appears before backtick → command substitution wins
    const r = detectStrictConstruct("echo $(x) `y`");
    assert.strictEqual(r?.construct, "command substitution $(...)");

    // backtick appears before ${} → backtick wins
    const r2 = detectStrictConstruct("echo `x` ${y}");
    assert.strictEqual(r2?.construct, "backtick substitution `...`");
  });
});

// ═══════════════════════════════════════════════════════════════════
// isPathCommand
// ═══════════════════════════════════════════════════════════════════

describe("isPathCommand", () => {
  const cases: [string[], boolean][] = [
    // ── absolute paths ─────────────────────────────────────────────
    [["/bin/ls"], true],
    [["/bin/ls", "/tmp"], true],
    [["/usr/bin/env", "python3"], true],

    // ── relative paths (also path-based) ──────────────────────
    [["./ls"], true],
    [["./rm", "-rf", "/"], true],
    [["../ls"], true],
    [["subdir/prog"], true],
    [["./foo/bar"], true],

    // ── bare commands (PATH lookup, not a path) ───────────
    [["ls", "/tmp"], false],
    [["kubectl", "delete", "pod"], false],
    [["rm", "-rf", "/"], false],      // / is an arg, not the command
    [["script.sh"], false],          // no slash → bare command
    [[], false],
  ];

  for (const [tokens, expected] of cases) {
    it(`${JSON.stringify(tokens)} → ${expected}`, () => {
      assert.strictEqual(isPathCommand(tokens), expected);
    });
  }
});

// ═══════════════════════════════════════════════════════════════════
// case-insensitive matching (strict mode)
// ═══════════════════════════════════════════════════════════════════

describe("matchPattern (case-insensitive)", () => {
  const cases: [string[], string[], boolean, boolean][] = [
    // tokens, pattern, caseInsensitive, expected
    // ── case-insensitive (strict) ──────────────────────────────────
    [["LS", "/tmp"], ["ls"], true, true],
    [["Ls", "/tmp"], ["ls"], true, true],
    [["KUBECTL", "DELETE", "pod"], ["kubectl", "delete"], true, true],
    [["ls", "/tmp"], ["ls"], true, true],  // exact still matches under CI
    // ── case-sensitive (default) ───────────────────────────────────
    [["LS", "/tmp"], ["ls"], false, false],
    [["KUBECTL", "delete"], ["kubectl", "delete"], false, false],
    [["ls", "/tmp"], ["ls"], false, true],
  ];

  for (const [tokens, pat, ci, expected] of cases) {
    it(`${JSON.stringify(tokens)} vs ${JSON.stringify(pat)} (ci=${ci}) → ${expected}`, () => {
      assert.strictEqual(matchPattern(tokens, pat, ci), expected);
    });
  }
});

describe("findMatch (case-insensitive)", () => {
  const rules = [parseLine("ls"), parseLine("! ls /safe")];

  it("CI matches upper-case command against lower-case rule", () => {
    const m = findMatch(["LS", "/tmp"], rules, true);
    assert.ok(m);
    assert.strictEqual(m!.allow, false);
  });

  it("CI allow-exception also matches case-insensitively", () => {
    const m = findMatch(["LS", "/SAFE"], rules, true);
    assert.ok(m);
    assert.strictEqual(m!.allow, true);
  });

  it("case-sensitive does NOT match upper-case command", () => {
    const m = findMatch(["LS", "/tmp"], rules, false);
    assert.strictEqual(m, undefined);
  });
});

// ═══════════════════════════════════════════════════════════════════
// checkCommandDeep with { strict: true }
// ═══════════════════════════════════════════════════════════════════

describe("checkCommandDeep (strict mode)", () => {
  const rules = [parseLine("ls"), parseLine("echo danger")];

  // [label, input, expectDenied]
  const cases: [string, string, boolean][] = [
    // ── construct detection blocks evasions (opaque to plain matcher) ──
    ["$( ) substitution", "$(echo ls) /tmp", true],
    ["$( ) glued", "$(echo '')ls /tmp", true],
    ["backtick substitution", "`echo ls` /tmp", true],
    ["backtick glued", "`echo ''`ls /tmp", true],
    ["brace expansion", "{ls,/tmp}", true],
    ["${UNSET} expansion", "${XX}ls /tmp", true],
    ["${VAR-} expansion", "${X-}ls /tmp", true],
    ["${VAR:+} expansion", "${HOME:+}ls /tmp", true],

    // ── path-based command (absolute / ./ / ../) ────────────
    ["absolute path", "/bin/ls /tmp", true],
    ["absolute path (echo)", "/bin/echo danger hello", true],
    ["absolute path after wrapper", "sudo /bin/ls /tmp", true],
    ["relative path ./", "./ls /tmp", true],
    ["parent relative path ../", "../ls /tmp", true],
    ["relative rm", "./rm -rf /", true],
    ["relative path after wrapper", "sudo ./ls /tmp", true],
    ["cd /bin && ./rm -rf", "cd /bin && ./rm -rf", true],

    // ── case-insensitive matching ──────────────────────────────────
    ["uppercase command", "LS /tmp", true],
    ["mixed case command", "Ls /tmp", true],
    ["uppercase echo", "ECHO danger hello", true],

    // ── construct hidden in a later segment ────────────────────────
    ["construct in second segment", "echo safe && $(rm -rf /)", true],

    // ── process substitution ───────────────────────────────────────
    ["process sub <(rm)", "cat <(rm -rf /)", true],
    ["process sub >(rm)", "echo >(rm -rf /)", true],
    ["process sub in second segment", "echo ok && cat <(rm)", true],

    // ── arithmetic (pure allowed; cmd-sub inside blocked) ─────────
    ["pure arithmetic allowed", "echo $((1+1))", false],
    ["pure arithmetic assign", "x=$((1+1))", false],
    ["cmd-sub in arithmetic", "echo $(( $(rm) ))", true],
    ["array-sub cmd-sub in arithmetic", "echo $((a[$(rm)]))", true],

    // ── comments (construct in a comment is allowed) ─────────────
    ["comment hides $()", "echo hi # $(rm)", false],
    ["comment hides backtick", "echo hi # `rm`", false],
    ["comment at start", "# $(rm)", false],
    ["literal # + $() runs", "echo a#$(rm)", true],

    // ── eval (concat-wrapper: payload unwrapped and re-checked) ───
    ["eval quoted payload", "eval 'ls /tmp'", true],
    ["eval unquoted", "eval ls /tmp", true],
    ["eval multi-arg", "eval 'echo' 'danger' hello", true],
    ["eval construct payload", "eval 'echo $(rm)'", true],

    // ── construct inside a re-parsing wrapper payload ─────────────
    ["bash -c construct payload", "bash -c 'echo $(rm)'", true],
    ["su -c construct payload", "su -c 'echo $(rm)'", true],
    ["sh -c construct payload", "sh -c 'echo $(rm)'", true],

    // ── strict does not over-block safe commands ───────────────────
    ["safe command still allowed", "echo hello", false],
    ["rule match still works", "ls /tmp", true],
    ["double-quoted safe string", 'echo "hello world"', false],
    ["plain variable not flagged", "echo $HOME", false],
    ["assignment not flagged", "FOO=bar ls /tmp", true], // ls still matches rule
  ];

  for (const [label, input, expectDenied] of cases) {
    it(`${label}: ${JSON.stringify(input)} → ${expectDenied ? "deny" : "allow"}`, () => {
      const result = checkCommandDeep(input, rules, undefined, { strict: true });
      if (expectDenied) {
        assert.ok(result, `expected deny but got allow for: ${input}`);
      } else {
        assert.strictEqual(result, undefined, `expected allow but got: ${JSON.stringify(result)}`);
      }
    });
  }

  it("strict rule string identifies the construct", () => {
    const r = checkCommandDeep("$(echo ls) /tmp", rules, undefined, { strict: true });
    assert.ok(r);
    assert.match(r!.rule, /strict: command substitution/);
  });

  it("strict rule string identifies process substitution", () => {
    const r = checkCommandDeep("cat <(rm -rf /)", rules, undefined, { strict: true });
    assert.ok(r);
    assert.match(r!.rule, /strict: process substitution/);
  });

  it("strict rule string identifies path-based command", () => {
    const r = checkCommandDeep("/bin/ls /tmp", rules, undefined, { strict: true });
    assert.ok(r);
    assert.match(r!.rule, /strict: path-based command/);
  });

  it("non-strict mode does NOT block the evasions (regression guard)", () => {
    // Without -s, the opaque constructs slip past (the documented limitations).
    assert.strictEqual(
      checkCommandDeep("$(echo ls) /tmp", rules, undefined, { strict: false }),
      undefined,
    );
    assert.strictEqual(
      checkCommandDeep("/bin/ls /tmp", rules, undefined, { strict: false }),
      undefined,
    );
    assert.strictEqual(
      checkCommandDeep("LS /tmp", rules, undefined, { strict: false }),
      undefined,
    );
    // Strict-only constructs must stay allowed without -s:
    assert.strictEqual(
      checkCommandDeep("cat <(rm -rf /)", rules, undefined, { strict: false }),
      undefined,
    );
    assert.strictEqual(
      checkCommandDeep("echo $((1+1))", rules, undefined, { strict: false }),
      undefined,
    );
    assert.strictEqual(
      checkCommandDeep("echo hi # $(rm)", rules, undefined, { strict: false }),
      undefined,
    );
    // eval payload IS unwrapped without -s (it's a wrapper, not a strict check),
    // so a matching rule still fires — but a construct payload is not rescanned:
    assert.ok(
      checkCommandDeep("eval 'ls /tmp'", rules, undefined, { strict: false }),
    );
    assert.strictEqual(
      checkCommandDeep("eval 'echo $(rm)'", rules, undefined, { strict: false }),
      undefined,
    );
  });
});

// ═══════════════════════════════════════════════════════════════════
// checkCommandDeep with { basename: true }
// ═══════════════════════════════════════════════════════════════════

describe("checkCommandDeep (basename mode)", () => {
  const lsRules = [parseLine("ls")];
  const rmLsRules = [parseLine("rm ls")];
  const rmRules = [parseLine("rm")];

  // [label, input, rules, options, expectDenied]
  const cases: [string, string, Pattern[], { strict?: boolean; basename?: boolean }, boolean][] = [
    // ── --basename normalizes path-based command words ───────────
    ["absolute path", "/bin/ls /tmp", lsRules, { basename: true }, true],
    ["relative ./", "./ls /tmp", lsRules, { basename: true }, true],
    ["parent relative ../", "../ls /tmp", lsRules, { basename: true }, true],
    ["deep absolute path", "/usr/bin/ls /tmp", lsRules, { basename: true }, true],
    ["trailing slash stripped", "/bin/ls/ /tmp", lsRules, { basename: true }, true],

    // ── wrapper-unwrapped path commands are normalized ────────────
    ["sudo /bin/ls", "sudo /bin/ls /tmp", lsRules, { basename: true }, true],
    ["sudo ./ls", "sudo ./ls /tmp", lsRules, { basename: true }, true],
    ["sh -c /bin/ls", "sh -c '/bin/ls /tmp'", lsRules, { basename: true }, true],
    ["bash -c /bin/ls", "bash -c '/bin/ls /tmp'", lsRules, { basename: true }, true],
    ["su -c /bin/ls", "su -c '/bin/ls /tmp'", lsRules, { basename: true }, true],
    ["env /bin/ls", "env FOO=bar /bin/ls /tmp", lsRules, { basename: true }, true],

    // ── command word only, args are data ────────────────────────
    ["arg /bin/ls NOT normalized", "rm /bin/ls", rmLsRules, { basename: true }, false],
    ["xargs /bin/rm gap", "xargs /bin/rm", rmRules, { basename: true }, false],

    // ── case NOT folded under --basename alone ───────────────────
    ["case not folded (absolute)", "/bin/LS /tmp", lsRules, { basename: true }, false],
    ["case not folded (relative)", "./LS /tmp", lsRules, { basename: true }, false],

    // ── -s --basename: normalized + case-folded ──────────────────
    ["normalized + case-folded", "/bin/LS /tmp", lsRules, { strict: true, basename: true }, true],
    ["normalized + case-folded ./", "./LS /tmp", lsRules, { strict: true, basename: true }, true],

    // ── -s alone still blocks paths (basename doesn't weaken -s) ──
    ["-s alone blocks path", "/bin/ls /tmp", lsRules, { strict: true }, true],

    // ── no basename, no strict: path slips past (regression guard) ──
    ["no flags: path slips", "/bin/ls /tmp", lsRules, {}, false],

    // ── basename does not over-normalize safe bare commands ──────
    ["bare command still matches", "ls /tmp", lsRules, { basename: true }, true],
    ["bare non-matching passes", "echo hello", lsRules, { basename: true }, false],

    // ── degenerate paths not normalized to empty ─────────────────
    ["root path unchanged", "/ /tmp", lsRules, { basename: true }, false],
    ["./ unchanged", "./ /tmp", lsRules, { basename: true }, false],

    // ── basename allows an ! exception on a normalized path ─────
    ["! exception matches normalized path", "/bin/ls /safe", [parseLine("ls"), parseLine("! ls /safe")], { basename: true }, false],
  ];

  for (const [label, input, rules, opts, expectDenied] of cases) {
    it(`${label}: ${JSON.stringify(input)} → ${expectDenied ? "deny" : "allow"}`, () => {
      const result = checkCommandDeep(input, rules, undefined, opts);
      if (expectDenied) {
        assert.ok(result, `expected deny but got allow for: ${input}`);
      } else {
        assert.strictEqual(result, undefined, `expected allow but got: ${JSON.stringify(result)}`);
      }
    });
  }

  it("deny reports the original (wrapped/path) tokens, not the normalized ones", () => {
    const r = checkCommandDeep("/bin/ls /tmp", lsRules, undefined, { basename: true });
    assert.ok(r);
    assert.deepStrictEqual(r!.tokens, ["/bin/ls", "/tmp"]);
    assert.strictEqual(r!.rule, "ls");
  });
});
