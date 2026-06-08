# pi-deny

CLI shell command guard. Blocks dangerous bash commands with `.gitignore`-like syntax. Zero runtime dependencies.

```
bash-deny -f rules.txt -i "kubectl delete pod"
```

## Install

```bash
npm install -g .
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
kubectl                 # deny all kubectl
! kubectl logs           # except logs
git push --force         # deny force pushes
rm -rf                   # deny recursive force remove
```

- Trailing tokens are **implicitly allowed** — `rm -rf` matches `rm -rf /tmp`
- `!` prefix = allow-exception (last matching rule wins)
- `#` lines are comments

## Matching behavior

**Scan-forward matching** — skips interspersed flags automatically:

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

**Wrapper awareness** — detects `sudo`, `su -c`, `bash -c`, `env`, `nohup`, `nice`, `chroot`, `flock`, and others.

## CLI usage

```
bash-deny [options]

Options:
  -f, --file <path>    Load rules from a .bashdeny file
  -r, --rules <rules>  Inline rules (;-separated)
  -i, --input <cmd>    The command string to check
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
| 2 | Usage error |

## Development

```bash
npm install
npm test
```
