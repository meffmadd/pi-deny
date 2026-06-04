/**
 * pi-deny — Shell command parsing and pattern matching engine
 *
 * No dependencies. Pure functions, easy to test.
 */

// ── Types ──────────────────────────────────────────────────────────

export type Pattern = { allow: boolean; tokens: string[]; raw: string };

export type Verdict = "deny" | "pass";

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
  let esc = false;

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
export function matchPattern(tokens: string[], pat: string[]): boolean {
  let ci = 0;
  for (const pt of pat) {
    while (ci < tokens.length && tokens[ci] !== pt) ci++;
    if (ci >= tokens.length) return false;
    ci++;
  }
  return true;
}

/**
 * Evaluate a token array against an ordered list of patterns.
 * Last matching pattern wins (enables `!` allow-exceptions).
 *
 * Returns "deny" if the last matching rule is a deny,
 * "pass" if the last matching rule is an allow or no rule matched.
 */
export function evaluate(tokens: string[], patterns: Pattern[]): Verdict {
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
export function mergePatterns(...lists: Pattern[][]): Pattern[] {
  return lists.flat();
}

// ── Command checking (convenience) ─────────────────────────────────

/**
 * Check a raw command string against a list of patterns.
 * Returns the first denied segment token array, or undefined if all pass.
 */
export function checkCommand(input: string, patterns: Pattern[]): string[] | undefined {
  for (const tokens of splitCommands(input)) {
    if (tokens.length === 0) continue;
    if (evaluate(tokens, patterns) === "deny") return tokens;
  }
  return undefined;
}

/**
 * Like checkCommand, but also returns the matching deny rule text.
 * Returns { tokens, rule } for the first denied segment, or undefined if all pass.
 */
export function checkCommandDetailed(
  input: string,
  patterns: Pattern[],
): { tokens: string[]; rule: string } | undefined {
  for (const tokens of splitCommands(input)) {
    if (tokens.length === 0) continue;
    const match = findMatch(tokens, patterns);
    if (match && !match.allow) {
      return { tokens, rule: match.raw };
    }
  }
  return undefined;
}

/** Find the last matching pattern, or undefined if none match. */
function findMatch(tokens: string[], patterns: Pattern[]): Pattern | undefined {
  let last: Pattern | undefined;
  for (const p of patterns) {
    if (matchPattern(tokens, p.tokens)) last = p;
  }
  return last;
}
