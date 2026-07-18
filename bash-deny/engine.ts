/**
 * bash-deny — Shell command parsing and pattern matching engine
 */

// `tokenize` is the canonical shell lexer. This import is intentionally a
// runtime cycle (parser imports matching helpers from this module); neither
// module invokes the other while it is being initialized.
import { tokenize } from "./parser";

// ── Types ──────────────────────────────────────────────────────────

export type RuleSource = {
  readonly name: string;
  readonly line: number;
};

export type SemanticPolicy = "rm-recursive-force" | "git-force-push";

export type Pattern = {
  readonly allow: boolean;
  readonly tokens: ReadonlyArray<string>;
  readonly raw: string;
  readonly source?: RuleSource;
  /** Command-aware policy inferred for the two documented destructive rules. */
  readonly semantic?: SemanticPolicy;
};

export class RuleParseError extends Error {
  constructor(message: string, source?: RuleSource) {
    super(source ? `${source.name}:${source.line}: ${message}` : message);
  }
}

export type Verdict = "deny" | "pass";

// ── Wrapper definitions ────────────────────────────────────────────

/** Type of wrapper command. */
export type WrapperKind = "passthrough" | "c" | "concat" | "shell-string" | "split-string";

/** Definition for a known wrapper command. */
export interface WrapperDef {
  kind: WrapperKind;
  /** Flags that consume the NEXT token as a value (space-separated, not =inline). */
  valuedFlags?: Set<string>;
}

/** Built-in wrapper commands. Execution modes distinguish direct argv from
 * shell strings, split strings, -c payloads, and concatenated eval payloads. */
export const WRAPPERS: Readonly<Record<string, WrapperDef>> = {
  // Passthrough: strip name + flags/args, whatever's left is the real command
  sudo:        { kind: "passthrough", valuedFlags: new Set(["-u", "-g", "--user", "--group", "-p", "--prompt", "-C", "--close-from", "-r", "--role", "-t", "--type", "-h", "--host", "-T", "--timeout"]) },
  // watch joins its remaining argv and gives it to `sh -c`; --exec/-x opts
  // into direct argv execution.
  watch:       { kind: "shell-string", valuedFlags: new Set(["-n", "--interval", "--equexit", "--shotsdir"]) },
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
  // env normally executes direct argv; -S/--split-string first splits one
  // string into argv using env's split-string facility.
  env:         { kind: "split-string", valuedFlags: new Set(["-u", "--unset", "-C", "--chdir", "--default-signal", "--ignore-signal", "--block-signal"]) },
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
  if (tokens.length === 0 || pat.length === 0) return false;
  const fold = (value: string) => caseInsensitive ? value.toLowerCase() : value;

  // A rule always names the executable. Wrapper stripping happens before this
  // function, so scanning from arbitrary argv positions would make a rule for
  // `kubectl` incorrectly match `echo kubectl`.
  if (fold(tokens[0]) !== fold(pat[0])) return false;

  let idx = 1;
  for (let p = 1; p < pat.length; p++) {
    const target = fold(pat[p]);
    let found = false;
    while (idx < tokens.length) {
      const tok = fold(tokens[idx]);
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
/** Optional callback invoked with each source string a wrapper reparses or
 * splits (`-c`, watch, env -S, or eval). Strict mode uses this to rescan source
 * that was hidden inside quotes in the original input. */
export function unwrapCommands(
  tokens: ReadonlyArray<string>,
  wrappers?: Readonly<Record<string, WrapperDef>>,
  onReparse?: (source: string) => void,
  normalizeWrapperPaths = false,
): string[][] | null {
  const wm = wrappers ?? WRAPPERS;
  let i = 0;

  const unwrapSegments = (source: string): string[][] | null => {
    onReparse?.(source);
    const nested = splitCommands(source).map((segment) =>
      unwrapCommands(segment, wm, onReparse, normalizeWrapperPaths));
    return nested.every((commands): commands is string[][] => commands !== null)
      ? nested.flat()
      : null;
  };

  while (i < tokens.length) {
    const rawName = tokens[i];
    const name = normalizeWrapperPaths && rawName.includes("/")
      ? normalizeCommandWord(rawName)
      : rawName;
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
            return unwrapSegments(source);
          }
        }
      }

      // Consume flags and their values.
      while (i < tokens.length && isFlag(tokens[i])) {
        const flag = tokens[i];
        i++;
        const fname = flagName(flag);
        if (def.valuedFlags?.has(fname) && !hasInlineValue(flag)) {
          if (i < tokens.length) i++; // consume value
        }
      }

      // chroot / flock: consume one positional argument before the command
      if ((name === "chroot" || name === "flock") && i < tokens.length) {
        i++; // consume path / lock-file
      }

      continue; // check for chained wrappers
    }

    if (def.kind === "shell-string") {
      i++; // consume watch
      let direct = false;
      while (i < tokens.length && isFlag(tokens[i])) {
        const option = tokens[i];
        if (option === "--exec" || option === "-x") direct = true;
        i++;
        const fname = flagName(option);
        if (def.valuedFlags?.has(fname) && !hasInlineValue(option) && i < tokens.length) i++;
      }
      if (i >= tokens.length) return null;
      if (direct) continue;
      return unwrapSegments(tokens.slice(i).join(" "));
    }

    if (def.kind === "split-string") {
      i++; // consume env
      let split: string | undefined;
      const trailing: string[] = [];
      while (i < tokens.length) {
        const token = tokens[i];
        if (token === "-S" || token === "--split-string") {
          if (tokens[i + 1] === undefined) return null;
          split = tokens[i + 1];
          i += 2;
        } else if (token.startsWith("-S") && token.length > 2) {
          split = token.slice(2);
          i++;
        } else if (token.startsWith("--split-string=")) {
          split = token.slice("--split-string=".length);
          i++;
        } else if (isFlag(token)) {
          i++;
          const fname = flagName(token);
          if (def.valuedFlags?.has(fname) && !hasInlineValue(token) && i < tokens.length) i++;
        } else if (isEnvAssignment(token)) {
          i++;
        } else {
          trailing.push(...tokens.slice(i));
          i = tokens.length;
        }
      }
      if (split === undefined) {
        // Bare `env` is a valid command that prints the environment; there is
        // no underlying argv to unwrap.
        if (trailing.length === 0) return [[name]];
        return unwrapCommands(trailing, wm, onReparse, normalizeWrapperPaths);
      }
      // env -S performs argv splitting, not shell execution. The shell lexer is
      // a conservative approximation; separators produce multiple commands and
      // are all checked rather than ignored.
      onReparse?.(split);
      const segments = splitCommands(split);
      if (segments.length === 0) return null;
      const expanded = segments.map((segment, index) =>
        index === segments.length - 1 ? [...segment, ...trailing] : segment);
      // Feed inserted argv back through env option/assignment handling: the
      // split string may itself begin with env options or NAME=value entries.
      const nested = expanded.map((segment) =>
        unwrapCommands(["env", ...segment], wm, onReparse, normalizeWrapperPaths));
      return nested.every((commands): commands is string[][] => commands !== null)
        ? nested.flat()
        : null;
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
          return unwrapSegments(subCmd);
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
      return unwrapSegments(joined);
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
export function parseLine(line: string, source?: RuleSource): Pattern {
  const trimmed = line.trim();
  const allow = trimmed.startsWith("!");
  const body = allow ? trimmed.slice(1).trim() : trimmed;
  if (body === "" || body.startsWith("#")) {
    throw new RuleParseError("empty rule", source);
  }

  let lexed;
  try {
    lexed = tokenize(body);
  } catch (error) {
    throw new RuleParseError(error instanceof Error ? error.message : "invalid rule", source);
  }
  const tokens: string[] = [];
  for (const token of lexed) {
    if (token.kind === "eof") continue;
    if (token.kind === "word" || token.kind === "kw") tokens.push(token.value);
    else if (token.kind === "assign") tokens.push(`${token.name}=${token.value}`);
    else throw new RuleParseError("shell operators are not valid in a rule; quote them to match literally", source);
  }
  if (tokens.length === 0) throw new RuleParseError("empty rule", source);

  let semantic: SemanticPolicy | undefined;
  if (!allow && tokens.length === 2 && tokens[0] === "rm" && tokens[1] === "-rf") {
    semantic = "rm-recursive-force";
  } else if (!allow && tokens.length === 3 && tokens[0] === "git" && tokens[1] === "push" && tokens[2] === "--force") {
    semantic = "git-force-push";
  }
  return { allow, tokens, raw: line, source, semantic };
}

/**
 * Parse a .bashdeny file content into Pattern[].
 * Empty lines and #-comments are skipped.
 */
export function parseFile(content: string, sourceName = "<rules>"): Pattern[] {
  const patterns: Pattern[] = [];
  for (const [index, raw] of content.split("\n").entries()) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    patterns.push(parseLine(raw, { name: sourceName, line: index + 1 }));
  }
  return patterns;
}

/** Split -r's semicolon-separated rules without splitting quoted semicolons. */
export function splitRuleList(input: string): string[] {
  const rules: string[] = [];
  let current = "";
  let sq = false, dq = false, ansi = false, esc = false;
  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    if (esc) { current += char; esc = false; continue; }
    if (ansi) {
      current += char;
      if (char === "\\") esc = true;
      else if (char === "'") ansi = false;
      continue;
    }
    if (sq) { current += char; if (char === "'") sq = false; continue; }
    if (dq) {
      current += char;
      if (char === "\\") esc = true;
      else if (char === '"') dq = false;
      continue;
    }
    if (char === "$" && input[i + 1] === "'") { current += "$'"; ansi = true; i++; continue; }
    if (char === "'") { current += char; sq = true; continue; }
    if (char === '"') { current += char; dq = true; continue; }
    if (char === "\\") { current += char; esc = true; continue; }
    if (char === ";") { rules.push(current); current = ""; continue; }
    current += char;
  }
  if (sq || dq || ansi || esc) throw new RuleParseError("unclosed quote or escape in inline rules");
  rules.push(current);
  return rules;
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
const VALUED_OPTIONS: Readonly<Record<string, ReadonlySet<string>>> = {
  kubectl: new Set(["--context", "--namespace", "-n", "--kubeconfig", "--cluster", "--user", "--server", "--token", "--request-timeout", "--as", "--as-group", "--cache-dir", "--certificate-authority", "--client-certificate", "--client-key", "--tls-server-name"]),
  git: new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace"]),
};

function skippableOptionWidth(command: string, tokens: ReadonlyArray<string>, index: number): number {
  const option = tokens[index];
  if (!isFlag(option)) return 0;
  if (hasInlineValue(option)) return 1;
  const name = flagName(option);
  if (VALUED_OPTIONS[command]?.has(name)) return index + 1 < tokens.length ? 2 : 0;
  // Unknown options are not skipped by allow rules: accidentally treating a
  // positional as their value could widen an exception.
  return 0;
}

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
    while (index < tokens.length && !equal(tokens[index], pat[p])) {
      const width = skippableOptionWidth(pat[0], tokens, index);
      if (width === 0) return false;
      index += width;
    }
    if (index >= tokens.length) return false;
    index++;
  }
  return true;
}

function matchesSemanticPolicy(tokens: ReadonlyArray<string>, policy: SemanticPolicy, caseInsensitive: boolean): boolean {
  const fold = (value: string) => caseInsensitive ? value.toLowerCase() : value;
  if (policy === "rm-recursive-force") {
    if (fold(tokens[0] ?? "") !== "rm") return false;
    let recursive = false, force = false;
    for (const token of tokens.slice(1)) {
      if (token === "--") break;
      const option = fold(token);
      if (option === "--recursive") recursive = true;
      else if (option === "--force") force = true;
      else if (/^-[^-]/.test(option)) {
        const flags = option.slice(1);
        if (flags.includes("r")) recursive = true;
        if (caseInsensitive ? flags.includes("r") : flags.includes("R")) recursive = true;
        if (flags.includes("f")) force = true;
      }
    }
    return recursive && force;
  }

  if (fold(tokens[0] ?? "") !== "git") return false;
  const push = tokens.findIndex((token, index) => index > 0 && fold(token) === "push");
  if (push === -1) return false;
  return tokens.slice(push + 1).some((token) => {
    const value = fold(token);
    return value === "-f" || value === "--force" || value.startsWith("--force-with-lease") || token.startsWith("+");
  });
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
      : p.semantic
        ? matchesSemanticPolicy(tokens, p.semantic, caseInsensitive)
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
