/**
 * bash-deny — Shell command parsing and pattern matching engine
 */

// `tokenize` is the canonical shell lexer. This import is intentionally a
// runtime cycle (parser imports matching helpers from this module); neither
// module invokes the other while it is being initialized.
import { tokenize } from "./parser";

// ── Types ──────────────────────────────────────────────────────────

export type Pattern = {
  readonly allow: boolean;
  readonly tokens: ReadonlyArray<string>;
  readonly raw: string;
};

export type Verdict = "deny" | "pass";

// ── Wrapper definitions ────────────────────────────────────────────

/** Type of wrapper command. */
export type WrapperKind = "passthrough" | "c" | "concat";

/** Definition for a known wrapper command. */
export interface WrapperDef {
  kind: WrapperKind;
  /** Flags that consume the NEXT token as a value (space-separated, not =inline). */
  valuedFlags?: Set<string>;
}

/** Built-in wrapper commands. Passthrough wrappers are stripped with their flags;
 *  c-wrappers extract the -c argument and re-tokenize it. */
export const WRAPPERS: Readonly<Record<string, WrapperDef>> = {
  // Passthrough: strip name + flags/args, whatever's left is the real command
  sudo:        { kind: "passthrough", valuedFlags: new Set(["-u", "-g", "--user", "--group", "-p", "--prompt", "-C", "--close-from", "-r", "--role", "-t", "--type", "-h", "--host", "-T", "--timeout"]) },
  watch:       { kind: "passthrough", valuedFlags: new Set(["-n", "--interval", "--title"]) },
  nohup:       { kind: "passthrough" },
  nice:        { kind: "passthrough", valuedFlags: new Set(["-n", "--adjustment"]) },
  ionice:      { kind: "passthrough", valuedFlags: new Set(["-c", "--class", "-n", "--classdata", "-p", "--pid"]) },
  time:        { kind: "passthrough", valuedFlags: new Set(["-f", "--format", "-o", "--output"]) },
  setsid:      { kind: "passthrough" },
  taskset:     { kind: "passthrough", valuedFlags: new Set(["-c", "--cpu-list", "-p", "--pid"]) },
  prlimit:     { kind: "passthrough" },
  stdbuf:      { kind: "passthrough", valuedFlags: new Set(["-i", "--input", "-o", "--output", "-e", "--error"]) },
  "systemd-run": { kind: "passthrough", valuedFlags: new Set(["-p", "--property", "-u", "--uid", "--gid", "-M", "--machine", "-E", "--setenv"]) },
  unshare:     { kind: "passthrough", valuedFlags: new Set(["-R", "--root", "-w", "--wd", "-S", "--setuid", "-G", "--setgid"]) },
  nsenter:     { kind: "passthrough", valuedFlags: new Set(["-t", "--target"]) },
  // env: strip name, then consume VAR=val assignments
  env:         { kind: "passthrough", valuedFlags: new Set(["-u", "--unset"]) },
  // chroot: strip name + flags, consume one positional (new root), rest is command
  chroot:      { kind: "passthrough" },
  // flock: strip name + flags, consume one positional (lock file), rest is command
  flock:       { kind: "passthrough", valuedFlags: new Set(["-w", "--wait", "-E", "--conflict-exit-code"]) },
  // Shell builtins that execute their remaining command.
  command:     { kind: "passthrough" },
  exec:        { kind: "passthrough", valuedFlags: new Set(["-a"]) },

  // c-wrappers: extract the -c argument and re-tokenize it
  su:          { kind: "c" },
  bash:        { kind: "c" },
  sh:          { kind: "c" },
  zsh:         { kind: "c" },
  dash:        { kind: "c" },

  // concat-wrapper: join all args with spaces and re-tokenize (eval re-parses
  // its concatenated arguments as a fresh command).
  eval:        { kind: "concat" },
};

// ── Shell command segmenter ────────────────────────────────────────

/**
 * Split a shell command string into command segments.
 * Respects single/double quotes and backslash escapes.
 * Splits on: && || | |& ; ;; & (background)
 *
 *   "echo hello && kubectl delete pod"
 *   → [["echo","hello"], ["kubectl","delete","pod"]]
 *
 *   "echo \"hello && world\""
 *   → [["echo","hello && world"]]
 */
export function splitCommands(input: string): string[][] {
  const out: string[][] = [];
  let segment: string[] = [];
  const cut = () => {
    if (segment.length > 0) out.push(segment);
    segment = [];
  };

  // Keep segmentation and all reparsing on exactly the same lexer as the AST
  // parser. In particular, this decodes ANSI-C words ($'\\154\\163') before
  // wrapper payloads are inspected.
  for (const token of tokenize(input)) {
    switch (token.kind) {
      case "word": segment.push(token.value); break;
      case "assign": segment.push(`${token.name}=${token.value}`); break;
      case "kw": segment.push(token.value); break;
      case "semi": case "dsemi": case "nl": case "op": case "amp": cut(); break;
      // Parentheses/braces delimit compound commands. The AST path handles
      // those precisely; keeping their words in separate fallback segments is
      // safer than treating syntax as an executable word.
      case "lparen": case "rparen": case "lbrace": case "rbrace": cut(); break;
      case "bang": case "eof": break;
    }
  }
  cut();
  return out;
}

// ── Pattern matching ───────────────────────────────────────────────

/** Scan-forward token match. Skips interspersed tokens. Trailing tokens implicitly allowed.
 *  When `caseInsensitive` is true (strict mode), tokens are compared lowercased so
 *  `LS` matches a rule for `ls` — closing the case-folding evasion hole. */
export function matchPattern(
  tokens: ReadonlyArray<string>,
  pat: ReadonlyArray<string>,
  caseInsensitive = false,
): boolean {
  let idx = 0;
  for (const pt of pat) {
    const target = caseInsensitive ? pt.toLowerCase() : pt;
    let found = false;
    while (idx < tokens.length) {
      const tok = caseInsensitive ? tokens[idx].toLowerCase() : tokens[idx];
      idx++;
      if (tok === target) { found = true; break; }
    }
    if (!found) return false;
  }
  return true;
}

// ── Wrapper-aware command unwrapping ──────────────────────────────

function isFlag(tok: string): boolean {
  return tok.startsWith("-") && tok !== "-" && tok.length > 1 && !/^-\d/.test(tok);
}

function flagName(tok: string): string {
  const eq = tok.indexOf("=");
  return eq === -1 ? tok : tok.slice(0, eq);
}

function hasInlineValue(tok: string): boolean {
  return tok.includes("=") && tok[0] !== "=";
}

function isEnvAssignment(tok: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(tok);
}

/**
 * Strip known wrapper commands and their flags/arguments to reveal the
 * effective command underneath. Handles chained wrappers (sudo nice su -c …).
 *
 * Returns the unwrapped token array, or null if the wrapping is invalid
 * (e.g. `su` without `-c`, all tokens consumed with no command left).
 *
 *   unwrapCommand(["sudo","kubectl","delete"]) → ["kubectl","delete"]
 *   unwrapCommand(["su","-c","rm -rf /"])       → ["rm","-rf","/"]
 *   unwrapCommand(["su","-l"])                  → null (interactive)
 */
/** Optional callback invoked with each source string a wrapper re-parses
 *  (the `-c` argument of a c-wrapper, or the joined args of `eval`). Strict
 *  mode uses this to rescan the re-parsed source for evasion constructs that
 *  were hidden inside quotes in the original input. */
export function unwrapCommands(
  tokens: ReadonlyArray<string>,
  wrappers?: Readonly<Record<string, WrapperDef>>,
  onReparse?: (source: string) => void,
): string[][] | null {
  const wm = wrappers ?? WRAPPERS;
  let i = 0;

  while (i < tokens.length) {
    const name = tokens[i];
    const def = wm[name];

    if (!def) {
      // Not a wrapper — whatever's left is the effective command
      return [tokens.slice(i)];
    }

    if (def.kind === "passthrough") {
      i++; // consume wrapper name

      // flock -c/--command reparses its value as shell source; unlike its
      // lock-file form it has no command token after the option.
      if (name === "flock") {
        for (let j = i; j < tokens.length; j++) {
          if (tokens[j] === "-c" || tokens[j] === "--command") {
            const source = tokens[j + 1];
            if (source === undefined) return null;
            onReparse?.(source);
            const segments = splitCommands(source);
            const unwrapped = segments.map((seg) => unwrapCommands(seg, wm, onReparse));
            return unwrapped.every((commands): commands is string[][] => commands !== null)
              ? unwrapped.flat()
              : null;
          }
        }
      }

      // env: consume flags and VAR=val assignments (interleaved, any order)
      if (name === "env") {
        while (i < tokens.length) {
          const tok = tokens[i];
          if (isFlag(tok)) {
            i++;
            const fname = flagName(tok);
            if (def.valuedFlags?.has(fname) && !hasInlineValue(tok)) {
              if (i < tokens.length) i++;
            }
          } else if (isEnvAssignment(tok)) {
            i++;
          } else {
            break;
          }
        }
      } else {
        // Consume flags and their values
        while (i < tokens.length && isFlag(tokens[i])) {
          const flag = tokens[i];
          i++;
          const fname = flagName(flag);
          if (def.valuedFlags?.has(fname) && !hasInlineValue(flag)) {
            if (i < tokens.length) i++; // consume value
          }
        }
      }

      // chroot / flock: consume one positional argument before the command
      if ((name === "chroot" || name === "flock") && i < tokens.length) {
        i++; // consume path / lock-file
      }

      continue; // check for chained wrappers
    }

    if (def.kind === "c") {
      i++; // consume wrapper name

      // Consume flags until we find -c (or run out)
      while (i < tokens.length) {
        const token = tokens[i];

        if (token === "-c") {
          i++;
          if (i >= tokens.length) return null; // -c with no argument
          const subCmd = tokens[i];
          // The wrapper re-parses this string — let strict mode rescan it.
          onReparse?.(subCmd);
          // Re-tokenize and check every command the shell will execute.
          const commands = splitCommands(subCmd).map((seg) => unwrapCommands(seg, wm, onReparse));
          return commands.every((value): value is string[][] => value !== null)
            ? commands.flat()
            : null;
        }

        // Not -c: consume flag (and possibly its value)
        i++;
        if (def.valuedFlags?.has(token) && i < tokens.length && !hasInlineValue(token)) {
          i++;
        }
      }

      // No -c found — interactive shell, can't check
      return null;
    }

    if (def.kind === "concat") {
      i++; // consume wrapper name
      // eval concatenates ALL its arguments with spaces and re-parses the
      // result as a fresh command — so re-tokenize the join and unwrap that.
      const rest = tokens.slice(i);
      if (rest.length === 0) return null;
      const joined = rest.join(" ");
      // The wrapper re-parses this string — let strict mode rescan it.
      onReparse?.(joined);
      const commands = splitCommands(joined).map((seg) => unwrapCommands(seg, wm, onReparse));
      return commands.every((value): value is string[][] => value !== null)
        ? commands.flat()
        : null;
    }
  }

  // All tokens consumed by wrappers, nothing left
  return null;
}

/** Backwards-compatible convenience for callers interested in a single command.
 * Deep checking uses `unwrapCommands` so no wrapper payload segment is lost. */
export function unwrapCommand(
  tokens: ReadonlyArray<string>,
  wrappers?: Readonly<Record<string, WrapperDef>>,
  onReparse?: (source: string) => void,
): string[] | null {
  return unwrapCommands(tokens, wrappers, onReparse)?.[0] ?? null;
}

/**
 * Evaluate a token array against an ordered list of patterns.
 * Last matching pattern wins (enables `!` allow-exceptions).
 *
 * Returns "deny" if the last matching rule is a deny,
 * "pass" if the last matching rule is an allow or no rule matched.
 */
export function evaluate(tokens: ReadonlyArray<string>, patterns: ReadonlyArray<Pattern>): Verdict {
  const match = findMatch(tokens, patterns);
  return match && !match.allow ? "deny" : "pass";
}

// ── Rule file parser ───────────────────────────────────────────────

/**
 * Parse a single .bashdeny line into a Pattern.
 * Lines starting with ! are allow-exceptions.
 */
export function parseLine(line: string): Pattern {
  const trimmed = line.trim();
  const allow = trimmed.startsWith("!");
  const body = allow ? trimmed.slice(1).trim() : trimmed;
  return { allow, tokens: body.split(/\s+/), raw: line };
}

/**
 * Parse a .bashdeny file content into Pattern[].
 * Empty lines and #-comments are skipped.
 */
export function parseFile(content: string): Pattern[] {
  return content
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map(parseLine);
}

/**
 * Merge multiple pattern lists. Later lists override earlier ones
 * (enables cascade: builtins < global < project).
 */
export function mergePatterns(...lists: ReadonlyArray<ReadonlyArray<Pattern>>): Pattern[] {
  return lists.flat();
}

/** Find the last matching pattern, or undefined if none match.
 *  `caseInsensitive` is forwarded to `matchPattern` (strict mode). */
/** Allow-exceptions are deliberately narrower than deny patterns. A deny can
 * scan forward through arbitrary arguments, but an allow must name the actual
 * executable and cannot skip a positional argument to reach a later token.
 * This prevents `! kubectl logs` from authorizing `kubectl delete pod logs`.
 */
function matchAllowPattern(
  tokens: ReadonlyArray<string>,
  pat: ReadonlyArray<string>,
  caseInsensitive: boolean,
): boolean {
  if (tokens.length < pat.length || pat.length === 0) return false;
  const equal = (left: string, right: string) => caseInsensitive
    ? left.toLowerCase() === right.toLowerCase()
    : left === right;
  if (!equal(tokens[0], pat[0])) return false;

  let index = 1;
  for (let p = 1; p < pat.length; p++) {
    // Options may be interspersed, but a positional argument may not: it
    // changes the command/subcommand being authorized.
    while (index < tokens.length && isFlag(tokens[index])) index++;
    if (index >= tokens.length || !equal(tokens[index], pat[p])) return false;
    index++;
  }
  return true;
}

export function findMatch(
  tokens: ReadonlyArray<string>,
  patterns: ReadonlyArray<Pattern>,
  caseInsensitive = false,
): Pattern | undefined {
  let last: Pattern | undefined;
  for (const p of patterns) {
    const matches = p.allow
      ? matchAllowPattern(tokens, p.tokens, caseInsensitive)
      : matchPattern(tokens, p.tokens, caseInsensitive);
    if (matches) last = p;
  }
  return last;
}

// ── Command word normalization ────────────────────────────────────

/**
 * Normalize a path-based command word to its basename. Called only when the
 * command word contains a `/` (i.e. `isPathCommand` is true). Pure string
 * math — no PATH lookup, no shell, no side effects.
 *
 *   "/bin/ls"  → "ls"     "./rm"   → "rm"     "../rm"  → "rm"
 *   "/bin/ls/" → "ls"     "ls"     → (not called — no "/")
 *
 * Degenerate basenames (empty, ".", "..") are left unchanged so a path like
 * "/" or "./" can't normalize to something that spuriously matches a rule:
 *
 *   "/"  → "/"  (unchanged)    "./" → "./" (unchanged)    "//" → "//"
 */
export function normalizeCommandWord(word: string): string {
  // Strip trailing "/" runs first: "/bin/ls/" → "/bin/ls", "./" → "."
  const w = word.replace(/\/+$/, "");
  if (w === "") return word; // all slashes ("/", "//") — don't normalize to empty
  const idx = w.lastIndexOf("/");
  const base = idx === -1 ? w : w.slice(idx + 1);
  // Degenerate basenames ("", ".", "..") are meaningless as commands — leave
  // the word unchanged so it can't spuriously match a rule.
  if (base === "" || base === "." || base === "..") return word;
  return base;
}
