/**
 * bash-deny — Shell command parsing and pattern matching engine
 */

// ── Types ──────────────────────────────────────────────────────────

export type Pattern = {
  readonly allow: boolean;
  readonly tokens: ReadonlyArray<string>;
  readonly raw: string;
};

export type Verdict = "deny" | "pass";

// ── Wrapper definitions ────────────────────────────────────────────

/** Type of wrapper command. */
export type WrapperKind = "passthrough" | "c";

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
  watch:       { kind: "passthrough", valuedFlags: new Set(["-n", "--interval", "--title", "-x", "--exec"]) },
  nohup:       { kind: "passthrough" },
  nice:        { kind: "passthrough", valuedFlags: new Set(["-n", "--adjustment"]) },
  ionice:      { kind: "passthrough", valuedFlags: new Set(["-c", "--class", "-n", "--classdata", "-p", "--pid"]) },
  time:        { kind: "passthrough", valuedFlags: new Set(["-f", "--format", "-o", "--output"]) },
  setsid:      { kind: "passthrough", valuedFlags: new Set(["-w", "--wait"]) },
  taskset:     { kind: "passthrough", valuedFlags: new Set(["-c", "--cpu-list", "-p", "--pid"]) },
  prlimit:     { kind: "passthrough" },
  stdbuf:      { kind: "passthrough", valuedFlags: new Set(["-i", "--input", "-o", "--output", "-e", "--error"]) },
  "systemd-run": { kind: "passthrough", valuedFlags: new Set(["-p", "--property", "-u", "--user", "--uid", "--gid", "-M", "--machine", "-E", "--setenv"]) },
  unshare:     { kind: "passthrough", valuedFlags: new Set(["-R", "--root", "-w", "--wd", "-S", "--setuid", "-G", "--setgid"]) },
  nsenter:     { kind: "passthrough", valuedFlags: new Set(["-t", "--target"]) },
  // env: strip name, then consume VAR=val assignments
  env:         { kind: "passthrough" },
  // chroot: strip name + flags, consume one positional (new root), rest is command
  chroot:      { kind: "passthrough" },
  // flock: strip name + flags, consume one positional (lock file), rest is command
  flock:       { kind: "passthrough", valuedFlags: new Set(["-c", "--command", "-w", "--wait", "-E", "--conflict-exit-code"]) },

  // c-wrappers: extract the -c argument and re-tokenize it
  su:          { kind: "c" },
  bash:        { kind: "c" },
  sh:          { kind: "c" },
  zsh:         { kind: "c" },
  dash:        { kind: "c" },
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
const TWO_CHAR_SEPARATORS = new Set(["&&", "||", "|&", ";;"]);
const SINGLE_CHAR_SEPARATORS = new Set([";", "|", "&"]);

export function splitCommands(input: string): string[][] {
  const out: string[][] = [];
  let seg: string[] = [];
  let tok = "";
  let sq = false; // inside 'single' quotes
  let dq = false; // inside "double" quotes
  let esc = false; // backslash escape (next char is literal)

  const flush = () => { if (tok) { seg.push(tok); tok = ""; } };
  const cut = () => { flush(); if (seg.length) out.push(seg); seg = []; };

  for (let i = 0; i < input.length; i++) {
    const c = input[i];
    const n2 = input.slice(i, i + 2);
    const n = n2[1] ?? "";

    if (esc) { tok += c; esc = false; continue; }

    // Inside single quotes — everything literal, only ' ends it
    if (sq) {
      if (c === "'") sq = false;
      else tok += c;
      continue;
    }

    // Inside double quotes — $ ` " \ \n are special
    if (dq) {
      if (c === "\\" && "$`\"\\\n".includes(n)) { esc = true; continue; }
      if (c === '"') dq = false;
      else tok += c;
      continue;
    }

    // Quote start
    if (c === "'") { sq = true; continue; }
    if (c === '"') { dq = true; continue; }
    if (c === "\\") { esc = true; continue; }

    // Whitespace
    if (c === " " || c === "\t" || c === "\n") { flush(); continue; }

    // Two-character separators
    if (TWO_CHAR_SEPARATORS.has(n2)) { cut(); i++; continue; }

    // Single-character separators
    if (SINGLE_CHAR_SEPARATORS.has(c)) { cut(); continue; }

    tok += c;
  }

  cut();
  return out;
}

// ── Pattern matching ───────────────────────────────────────────────

/** Scan-forward token match. Skips interspersed tokens. Trailing tokens implicitly allowed. */
export function matchPattern(tokens: ReadonlyArray<string>, pat: ReadonlyArray<string>): boolean {
  let ci = 0;
  for (const pt of pat) {
    while (ci < tokens.length && tokens[ci] !== pt) ci++;
    if (ci >= tokens.length) return false;
    ci++;
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
export function unwrapCommand(
  tokens: ReadonlyArray<string>,
  wrappers?: Readonly<Record<string, WrapperDef>>,
): string[] | null {
  const wm = wrappers ?? WRAPPERS;
  let i = 0;

  while (i < tokens.length) {
    const name = tokens[i];
    const def = wm[name];

    if (!def) {
      // Not a wrapper — whatever's left is the effective command
      return tokens.slice(i);
    }

    if (def.kind === "passthrough") {
      i++; // consume wrapper name

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
          // Re-tokenize the -c argument as a shell command
          const segments = splitCommands(subCmd);
          // Unwrap the first non-empty segment recursively
          for (const seg of segments) {
            if (seg.length > 0) return unwrapCommand(seg, wm);
          }
          return null;
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
  }

  // All tokens consumed by wrappers, nothing left
  return null;
}

/**
 * Evaluate a token array against an ordered list of patterns.
 * Last matching pattern wins (enables `!` allow-exceptions).
 *
 * Returns "deny" if the last matching rule is a deny,
 * "pass" if the last matching rule is an allow or no rule matched.
 */
export function evaluate(tokens: ReadonlyArray<string>, patterns: ReadonlyArray<Pattern>): Verdict {
  let last: boolean | undefined;
  for (const p of patterns) {
    if (matchPattern(tokens, p.tokens)) last = p.allow;
  }
  if (last === undefined) return "pass";
  return last ? "pass" : "deny";
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

/** Find the last matching pattern, or undefined if none match. */
export function findMatch(tokens: ReadonlyArray<string>, patterns: ReadonlyArray<Pattern>): Pattern | undefined {
  let last: Pattern | undefined;
  for (const p of patterns) {
    if (matchPattern(tokens, p.tokens)) last = p;
  }
  return last;
}
