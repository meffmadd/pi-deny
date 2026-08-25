# bash-deny

CLI shell command guard. Blocks dangerous bash commands with `.gitignore`-like syntax. Zero runtime dependencies.

```
bash-deny -f rules.txt -i "kubectl delete pod"
```

## Install

```bash
npm install --global @meffmadd/bash-deny
```

Or run it without installing:

```bash
npx @meffmadd/bash-deny -r "rm -rf" -i "rm -rf /tmp/example"
```

Requires Node.js >= 20.

## Quick start

```bash
# Create a rule file
cat > rules.bashdeny << 'EOF'
kubectl
! kubectl logs
git push --force
rm -rf
EOF

# Block dangerous commands
bash-deny -f rules.bashdeny -i "kubectl delete pod"
# → bash-deny: blocked: "kubectl delete pod" (rule: "kubectl")

# Allow exceptions
bash-deny -f rules.bashdeny -i "kubectl logs nginx"
# → (allowed, exit 0)
```

## Rule format

```
# .bashdeny — one pattern per line
kubectl                  # deny all kubectl
! kubectl logs           # except logs
git push --force         # deny force pushes
rm -rf                   # deny recursive force remove
```

- Trailing tokens are **implicitly allowed** — `rm -rf` matches `rm -rf /tmp`
- `!` prefix = allow-exception (last matching rule wins)
- Shell-style quoting and inline `#` comments are supported
- Rules are executable-anchored: `kubectl` matches `kubectl get`, not `echo kubectl`
- The documented `rm -rf` and `git push --force` rules compile to command-aware policies:
  - `rm -rf` also catches `-fr`, `-r -f`, `-Rf`, and `--recursive --force`
  - `git push --force` also catches `-f`, `--force-with-lease`, and `+ref` force-push refspecs

## Matching behavior

**Executable-anchored, scan-forward matching** — the command must match the first rule token; later tokens may skip interspersed flags:

```
Rule:      git push --force
Command:   git -C /repo push --force origin main  →  DENIED
           git push origin main                    →  PASS (no --force)
```

**Command separation** — splits on `&&`, `||`, `;`, `|`, `&` (respecting quotes):

```
echo "safe && stuff" && kubectl delete pod
              ↑ literal        ↑ separator → second segment checked
```

**Wrapper awareness** — detects direct-argv wrappers and commands that reparse strings, including `sudo`, `su -c`, `bash -c`, `watch`, `env -S`, `eval`, `nohup`, `nice`, `chroot`, and `flock`.

**Here-documents** — bodies are data rather than commands. Strict mode still scans active expansions in unquoted here-docs; quoted delimiters suppress that scan.

## CLI usage

```
bash-deny [options]

Options:
  -f, --file <path>    Load rules from a .bashdeny file
  -r, --rules <rules>  Inline rules (;-separated)
  -i, --input <cmd>    The command string to check
  -s, --strict        Strict mode — block opaque shell constructs ($(), backticks, `${}`, brace expansion, path-based commands) and match case-insensitively
      --basename      Normalize path-based command words before matching instead of blocking them
  -n, --dry-run        Print what would be blocked but always exit 0
  -q, --quiet          No output — exit code only
  -h, --help           Print usage and exit
  -V, --version        Print version and exit
```

### Stdin

```bash
echo "kubectl delete pod" | bash-deny -f rules.txt

# Multiple lines: first deny stops processing
bash-deny -f rules.txt << 'EOF'
kubectl delete pod
git push --force origin
echo safe
EOF
```

### Dry run (CI / pre-commit hooks)

```bash
bash-deny -f rules.txt -n -i "kubectl delete pod"
# → bash-deny: blocked: "kubectl delete pod" (rule: "kubectl")
# → exit 0 (always)
```

### Quiet (exit code only)

```bash
bash-deny -f rules.txt -q -i "kubectl get pods" && echo "allowed"
```

### Strict mode

Strict mode (`-s`) adds fail-closed detection for known opaque constructs that the literal token matcher cannot inspect. The matcher never expands variables, runs subshells, resolves globs, or looks up command paths. Strict mode is defense in depth, not a complete Bash sandbox or a standalone security boundary:

```bash
bash-deny -s -i 'echo $(rm -rf /)'   # DENIED: command substitution
bash-deny -s -i 'echo `rm -rf /`'   # DENIED: backtick substitution
bash-deny -s -i '${XX}ls /tmp'     # DENIED: parameter expansion
bash-deny -s -i '{ls,/tmp}'        # DENIED: brace expansion
bash-deny -s -i 'cat <(rm -rf /)'   # DENIED: process substitution
bash-deny -s -r rm -i "eval 'rm -rf /'"  # DENIED: eval payload unwrapped
bash-deny -s -i "bash -c 'echo \$(rm)'"   # DENIED: construct rescanned after re-parse
bash-deny -s -r ls -i "/bin/ls /tmp"   # DENIED: path-based command (absolute)
bash-deny -s -r ls -i "./ls /tmp"      # DENIED: path-based command (relative)
bash-deny -s -r ls -i "LS /tmp"         # DENIED: case-insensitive match

# Constructs inside single quotes are literal — not flagged
bash-deny -s -i "echo 'safe \$(rm)'"   # PASS
# A construct inside a # comment isn't run — not flagged
bash-deny -s -i 'echo hi # $(rm)'     # PASS
# Pure arithmetic can't run commands — not flagged
bash-deny -s -i 'echo $((1+1))'       # PASS
```

Strict works with or without rules, and composes with `-n` / `-q`. Any deny wins. Malformed or unsupported strict-mode input is rejected rather than sent through the shallow fallback.

`eval` is unwrapped like `bash -c` (its args are joined and re-checked), so `eval 'rm -rf /'` is caught by an `rm` rule. In strict mode, any source a wrapper re-parses (`bash -c`/`su -c`/`eval`) is rescanned, so `bash -c 'echo $(rm)'` is denied even though the `$(rm)` hides inside single quotes.

ANSI-C quoting (`$'...'`) is not a strict block — the parser decodes it, so `$'ls'` matches a rule for `ls` via ordinary matching.

Notable deliberate tradeoffs: `exec 'rm -rf /'` is allowed (exec treats the quoted string as a literal filename, so `rm` never runs — not a real bypass); a plain `$VAR` as the command word (e.g. `cmd=rm; $cmd /tmp`) is allowed (indistinguishable from legit `$EDITOR file`). `${cmd}` as the command word *is* blocked.

### Basename mode

`--basename` normalizes path-based command words before matching: `/bin/ls`, `./ls`, and `../ls` become `ls`. With `-s --basename`, paths are normalized while all other strict checks and case folding remain enabled. Without `--basename`, strict mode blocks path-based commands outright.

### Inline rules

```bash
bash-deny -r "kubectl;! kubectl logs;rm -rf" -i "kubectl delete pod"

# Merge file and inline (inline can override with !)
bash-deny -f rules.txt -r "! kubectl delete" -i "kubectl delete pod"
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Command allowed (or dry run) |
| 1 | Command denied/blocked |
| 2 | Usage error or invalid shell command syntax |

## Development

```bash
npm install
npm test
```
