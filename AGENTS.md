# bash-deny

CLI shell command guard. Blocks dangerous bash commands using token-level deny patterns with `!` allow-exceptions — like `.gitignore` for your shell. Zero runtime dependencies.

## How it works

| Layer | What |
|-------|------|
| `bash-deny/engine.ts` | Pure functions: `splitCommands`, `matchPattern`, `evaluate`, `parseFile`, `unwrapCommand` (passthrough/c-wrapper/concat) — zero deps, fully tested |
| `bash-deny/strict.ts` | Strict-mode construct detection (`$()`, backticks, `${}`, `{,}`, process sub `<()>`, path-based commands, case folding) — zero deps |
| `bash-deny/cli.ts` | CLI entry point — `bash-deny` command, `-f`/`-r` rule loading, stdin/`-i` input, `-s` strict mode |

## Rule format

```
# .bashdeny — one pattern per line
kubectl                 # deny all kubectl
! kubectl logs           # except logs
git push --force         # deny force pushes
rm -rf                   # deny recursive force remove
```

- Trailing tokens are **implicitly allowed** — `rm -rf` matches `rm -rf /tmp`
- `!` prefix = allow-exception (last matching rule wins)
- Shell-style quoting and inline `#` comments are supported
- Rules are anchored to the executable; scan-forward matching applies after it
- `rm -rf` and `git push --force` compile to command-aware policies covering documented equivalent dangerous forms
- Rules are loaded from `-f` files and/or `-r` inline rules. Inline rules come second and can override file rules via last-match-wins.

## Matching behavior

**Executable-anchored scan-forward matching** — the executable must match, then interspersed flags may be skipped:

```
Rule:      git push --force
Command:   git -C /repo push --force origin main  →  DENIED
           git push origin main                    →  PASS (no --force)
```

**Implicit trailing** — arguments after the last pattern token are allowed:

```
Rule:      rm -rf
Command:   rm -rf /          →  DENIED
           rm -rf /tmp/foo   →  DENIED
```

**Command separation** — splits on `&&`, `||`, `;`, `|`, `&` (respecting quotes):

```
echo "safe && stuff" && kubectl delete pod
              ↑ literal        ↑ separator → second segment checked
```

**Wrapper awareness** — distinguishes direct argv, shell-string, split-string, and concatenated shell-string execution. It detects `sudo`, `su -c`, `bash -c`, `watch`, `env -S`, `eval`, `nohup`, `nice`, `chroot`, `flock`, and others, then checks the effective command underneath.

**Strict mode** (`-s`) — adds fail-closed detection for known opaque constructs that the token matcher cannot inspect. It is defense in depth, not a complete Bash sandbox or standalone security boundary:

```
Command:   echo $(rm -rf /)        →  DENIED  (command substitution)
           echo `rm -rf /`        →  DENIED  (backtick substitution)
           ${XX}ls /tmp            →  DENIED  (parameter expansion)
           {ls,/tmp}               →  DENIED  (brace expansion)
           cat <(rm -rf /)        →  DENIED  (process substitution)
           eval 'rm -rf /'        →  DENIED  (eval payload unwrapped → rule match)
           bash -c 'echo $(rm)'   →  DENIED  (construct rescanned after wrapper re-parse)
           /bin/ls /tmp            →  DENIED  (path-based command, vs rule `ls`)
           ./ls /tmp               →  DENIED  (relative path, vs rule `ls`)
           ../ls /tmp              →  DENIED  (parent-relative path)
           LS /tmp                  →  DENIED  (case-insensitive match vs rule `ls`)
           echo 'safe $(rm)'        →  PASS    (construct inside single quotes is literal)
           echo hi # $(rm)          →  PASS    (construct inside a # comment is not run)
           echo $((1+1))            →  PASS    (pure arithmetic can't run commands)
           echo "hello world"        →  PASS    (no construct)
```

Strict checks run on every command segment (after `&&`/`||`/`|`/`;` splitting) and on the unwrapped command under wrappers (`sudo`, `bash -c`, `eval`, …). Strict verdicts compose with rule verdicts: any deny wins.

Strict mode is quote-aware — constructs inside single quotes are treated as literal text and not flagged, matching how the shell would evaluate them. It is also comment-aware: an unquoted `#` at a word boundary starts a comment, and the rest of the line is not scanned (bash never runs it). A mid-word `#` (e.g. `a#$(rm)`) is literal, so a construct glued after it is still caught.

Arithmetic `$((...))` is **not** blocked on its own: it can't run commands (only the `$(...)` inside it can, and that is still caught as command substitution). So `echo $((1+1))` passes while `echo $(( $(rm) ))` is denied.

ANSI-C quoting (`$'...'`) is **not** a strict-mode block: the parser's tokenizer decodes it into plain characters, so `$'ls'` and `$'\154\163'` tokenize identically to `ls` and are caught by ordinary rule matching — no strict escalation needed.

`eval` is a concat-wrapper (like `bash -c`): its arguments are joined and re-tokenized, so `eval 'rm -rf /'` is checked as `rm -rf /` and caught by an `rm` rule. In strict mode, every source string a wrapper re-parses (the `-c` argument of `bash`/`su`/`sh`, or `eval`'s joined args) is rescanned for evasion constructs — a `$(rm)` hidden inside the quoted payload of `bash -c 'echo $(rm)'` is flagged even when the outer single quotes made it literal to the first scan.

**Deliberate strict-mode tradeoffs** (not blocked, by design):
- `exec 'rm -rf /'` — `exec` with a single quoted argument is **not** a real bypass: the shell treats the whole string as a literal filename to exec, so `rm` never runs (verified). `exec rm -rf /` (unquoted) is caught normally by scan-forward matching.
- A plain `$VAR` used as the command word (e.g. `cmd=rm; $cmd /tmp`) is not flagged. It's indistinguishable from legitimate `$EDITOR file` / `$SHELL script` patterns, and requires the variable to be assigned elsewhere first. `${cmd}` as the command word *is* blocked (parameter expansion is opaque).

## CLI usage

```
bash-deny [options]

Options:
  -f, --file <path>    Load rules from a .bashdeny file
  -r, --rules <rules>  Inline rules (;-separated, same format as file lines)
  -i, --input <cmd>    The command string to check
  -s, --strict        Strict mode — block opaque shell constructs ($(), `${}`, backticks, brace expansion, path-based commands) and match case-insensitively
      --basename      Normalize path-based command words before matching instead of blocking them
  -n, --dry-run        Print what would be blocked but always exit 0
  -q, --quiet          No output — exit code only (1 if denied, 0 if allowed)
  -h, --help           Print usage and exit
  -V, --version        Print version and exit
```

- `-i` provides a single command string.
- Piped stdin reads one command per line (first deny stops processing).
- If both `-i` and stdin are provided, `-i` wins.
- `-n` and `-q` are mutually exclusive.
- `-s` (strict) works with or without rules; works with `-n` and `-q`.
- `--basename` normalizes `/bin/ls`, `./ls`, and `../ls` to `ls`; with `-s`, other strict checks remain active.
- Malformed input exits nonzero without a stack trace; unsupported strict syntax fails closed.
- Here-document bodies are parsed as data. Strict mode scans active expansions only in unquoted here-docs.
- Exit codes: 0 = allowed (or dry-run), 1 = denied/blocked, 2 = usage error or invalid shell command syntax.

### Examples

```bash
# File-based rules
bash-deny -f .pi/.bashdeny -i "kubectl delete pod"

# Inline rules
bash-deny -r "kubectl;! kubectl logs;rm -rf" -i "kubectl delete pod"

# Stdin, multiple lines
bash-deny -f rules.txt << 'EOF'
kubectl delete pod
git push --force origin
echo safe
EOF

# Dry run (CI / pre-commit hooks)
bash-deny -f .pi/.bashdeny -n -i "kubectl delete pod"

# Quiet (exit code only)
bash-deny -f .pi/.bashdeny -q -i "kubectl get pods" && echo "allowed"

# Strict mode (blocks $(), backticks, ${}, brace expansion, path-based commands)
bash-deny -s -i 'echo $(rm -rf /)'
bash-deny -s -f .pi/.bashdeny -i "kubectl delete pod"
```

## Install

```bash
# Global install
npm install -g .

# Or run directly with npx
npx tsx bash-deny/cli.ts -f rules.txt -i "kubectl delete pod"
```

Requires Node.js >= 20 (for `util.parseArgs`).

## Development

```bash
npm install
npm test                 # engine + scenarios + CLI tests
```

## Release

```bash
npx bumpp               # prompts for patch/minor/major, commits + tags
npx bumpp 1.2.3          # exact version
npx bumpp -y             # skip confirmation
```

## Structure

```
bash-deny/
  bash-deny/
    engine.ts            # splitCommands, matchPattern, evaluate, parseFile, unwrapCommand
    strict.ts             # strict-mode construct detection (detectStrict, strictVerdict)
    cli.ts               # CLI entry point (bash-deny)
  tests/
    engine.test.ts       # core engine tests
    strict.test.ts        # strict-mode detection tests
    cli/
      cli.test.ts        # CLI tests (arg parsing, stdin, exit codes, --strict)
    scenarios/
      redteam.bashdeny   # red team rule set
      redteam.test.ts    # red team evasion tests (plain + strict mode)
      controlflow.bashdeny
      controlflow.test.ts
  .pi/
    .bashdeny            # example rule file
  package.json
  AGENTS.md
  cli.md                 # design doc
```

## Test conventions

Tests use a data-driven `cases` format: define an array of `[input, expected]` tuples with group comments, then iterate to generate one `it()` per case.

```ts
describe("functionName", () => {
  const cases: [InputType, ExpectedType][] = [
    // ── group comment ────────────────────────────────────
    [input1, expected1],
    [input2, expected2],
  ];

  for (const [input, expected] of cases) {
    it(`${JSON.stringify(input)} → ${JSON.stringify(expected)}`, () => {
      assert.deepStrictEqual(functionName(input), expected);
    });
  }
});
```

- Group related cases with `// ── group name ──` comment dividers (keep the dashes aligned).
- For cases with different return types (e.g. `T | null`), use a union type and branch the assertion.
- Prefer this format over individual `it()` calls. Use individual `it()` blocks only when test setup differs from the standard pattern (e.g. custom parameters, async setup).
- This keeps tests compact while preserving one-failure-per-case granularity in the test runner.

## Architecture notes

- `splitCommands` is a hand-rolled quote-aware shell tokenizer. It does NOT expand variables, execute subshells, or resolve globs — that's the shell's job. It only splits into segments for matching.
- `matchPattern` uses scan-forward: each pattern token advances through the command tokens, skipping non-matching ones. This naturally handles `sudo`, `-C`, and other interspersed flags.
- The engine is fully independent — you could use it in any Node.js project.
- No runtime dependencies. Only `tsx` for running tests and development.
- The engine does NOT resolve command names to paths (no `which`). Rules match token-for-token against what the user types. A rule for `ls` matches `ls /tmp` but not `/bin/ls /tmp`. This is correct for a CLI: users write rules against the command text they type. Strict mode (`-s`) closes this gap: it flags any command word containing a `/` (absolute `/bin/ls`, relative `./rm`, `../rm`) so path-based invocations are blocked even without an explicit rule.
