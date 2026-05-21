# pi-deny

Shell command guard extension for [pi](https://github.com/earendil-works/pi-mono). Blocks dangerous bash commands using token-level deny patterns with `!` allow-exceptions — like `.gitignore` for your shell.

## How it works

| Layer | What |
|-------|------|
| `src/engine.ts` | Pure functions: `splitCommands`, `matchPattern`, `evaluate` — zero deps, fully tested |
| `src/index.ts` | pi extension entry point — hooks `tool_call` (LLM) and `user_bash` (`!` commands) |
| `.pi/.bashdeny` | Project-local rules |
| `~/.pi/.bashdeny` | Global rules (applies everywhere) |

## Rule format

```
# .bashdeny — one pattern per line
kubectl *               # deny all kubectl
! kubectl logs *         # except logs
git push --force *       # deny force pushes
rm -rf *                 # deny recursive force remove
eval *                   # deny eval (built-in default)
```

- `*` matches any remaining tokens (prefix + wildcard)
- `!` prefix = allow-exception (last matching rule wins)
- `#` lines are comments
- Rules cascade: **built-ins < global < project** — project rules can override everything with `!`

## Matching behavior

**Scan-forward matching** — skips interspersed flags automatically:

```
Rule:      git push --force *
Command:   git -C /repo push --force origin main  →  DENIED
           git push origin main                    →  PASS (no --force)
```

**Command separation** — splits on `&&`, `||`, `;`, `|`, `&` (respecting quotes):

```
echo "safe && stuff" && kubectl delete pod
              ↑ literal        ↑ separator → second segment checked
```

## Install

### Global (all projects)

```bash
# Copy the extension
cp -r src ~/.pi/agent/extensions/pi-deny/

# Create your global rules
cat > ~/.pi/.bashdeny << 'EOF'
git push --force *
rm -rf *
EOF
```

### Project-local rules only

```bash
# Just create a .pi/.bashdeny file in your project
cat > .pi/.bashdeny << 'EOF'
kubectl delete *
! kubectl logs *
EOF
```

The extension automatically picks up both.

## Development

```bash
npm install
npm test                 # 55 tests, all pure functions
```

## Structure

```
pi-deny/
  src/
    engine.ts            # splitCommands, matchPattern, evaluate, parseFile
    index.ts             # pi extension entry point
  tests/
    engine.test.ts       # node:test suite
  .pi/
    .bashdeny            # example project-local rules
  package.json
  AGENTS.md
```

## Architecture notes

- `splitCommands` is a hand-rolled quote-aware shell tokenizer. It does NOT expand variables, execute subshells, or resolve globs — that's the shell's job. It only splits into segments for matching.
- `matchPattern` uses scan-forward: each pattern token advances through the command tokens, skipping non-matching ones. This naturally handles `sudo`, `-C`, and other interspersed flags.
- The engine is fully separate from pi — you could use it in any Node.js project.
- No runtime dependencies. Only `tsx` for running tests during development.
