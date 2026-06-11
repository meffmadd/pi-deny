# bash-deny

CLI shell command guard. Blocks dangerous bash commands using token-level deny patterns with `!` allow-exceptions — like `.gitignore` for your shell. Zero runtime dependencies.

## How it works

| Layer | What |
|-------|------|
| `bash-deny/engine.ts` | Pure functions: `splitCommands`, `matchPattern`, `evaluate` — zero deps, fully tested |
| `bash-deny/cli.ts` | CLI entry point — `bash-deny` command, `-f`/`-r` rule loading, stdin/`-i` input |

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
- `#` lines are comments
- Rules are loaded from `-f` files and/or `-r` inline rules. Inline rules come second and can override file rules via last-match-wins.

## Matching behavior

**Scan-forward matching** — skips interspersed flags automatically:

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

**Wrapper awareness** — detects `sudo`, `su -c`, `bash -c`, `env`, `nohup`, `nice`, `chroot`, `flock`, and others, and checks the command underneath.

## CLI usage

```
bash-deny [options]

Options:
  -f, --file <path>    Load rules from a .bashdeny file
  -r, --rules <rules>  Inline rules (;-separated, same format as file lines)
  -i, --input <cmd>    The command string to check
  -n, --dry-run        Print what would be blocked but always exit 0
  -q, --quiet          No output — exit code only (1 if denied, 0 if allowed)
  -h, --help           Print usage and exit
  -V, --version        Print version and exit
```

- `-i` provides a single command string.
- Piped stdin reads one command per line (first deny stops processing).
- If both `-i` and stdin are provided, `-i` wins.
- `-n` and `-q` are mutually exclusive.
- Exit codes: 0 = allowed (or dry-run), 1 = denied/blocked, 2 = usage error.

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
    cli.ts               # CLI entry point (bash-deny)
  tests/
    engine.test.ts       # core engine tests
    cli/
      cli.test.ts        # CLI tests (arg parsing, stdin, exit codes)
    scenarios/
      redteam.bashdeny   # red team rule set
      redteam.test.ts    # red team evasion tests
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
- The engine does NOT resolve command names to paths (no `which`). Rules match token-for-token against what the user types. A rule for `ls` matches `ls /tmp` but not `/bin/ls /tmp`. This is correct for a CLI: users write rules against the command text they type.
