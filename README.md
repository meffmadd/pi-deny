# pi-deny

Block bash commands in [Pi](https://github.com/earendil-works/pi-mono) with a `.gitignore`-like syntax.

## Install

```bash
pi install https://github.com/meffmadd/pi-deny
```

## Configure

Create `.pi/.bashdeny` in your project, or `~/.pi/.bashdeny` for all projects:

```
git *
! git log *
```

- `*` matches any remaining tokens
- `!` prefix = allow exception (last match wins)
- Rules cascade: **built-ins → global → project**

This blocks any `git` command **except** `git log`.

## How it works

The extension hooks Pi's `tool_call` event. When the LLM calls `bash`, the command is matched against the configured patterns. User-typed `!` commands are never blocked. Commands are split on `&&`, `||`, `;`, `|`, `&` and each segment is checked independently. Scan-forward matching skips interspersed flags.

```
Rule:      git *
Command:   git -C /repo push origin main  →  blocked
           git log                         →  allowed
```

