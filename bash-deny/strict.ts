/**
 * bash-deny — strict-mode evasion detection.
 *
 * Strict mode blocks shell constructs that are opaque to token-level matching
 * and are routinely used to sneak past deny rules:
 *
 *   - command substitution  `$(...)`
 *   - backtick substitution  `` `...` ``
 *   - parameter expansion    `${...}`
 *   - brace expansion        `{a,b}` / `{1..5}`
 *   - process substitution  `<(...)` / `>(...)`
 *
 * It also refuses commands invoked by path (absolute `/bin/ls`, relative
 * `./rm`, `../rm` — anything with a `/` in the command word, since the shell
 * then treats it as a path lookup rather than a PATH search) and matches rules
 * case-insensitively, closing the remaining red-team evasion holes (path
 * resolution and case folding — both deliberate non-goals of the core engine
 * per AGENTS.md / parser.md §2).
 *
 * Detection is quote-aware: constructs inside single quotes are literal and
 * left alone; inside double quotes `$(...)`, `${...}`, and backticks remain
 * active and are flagged.
 *
 * ANSI-C quoting (`$'...'`) is intentionally NOT flagged here: the parser's
 * tokenizer decodes it into plain characters, so `$'ls'` and `$'\154\163'`
 * tokenize identically to `ls` and are caught by ordinary rule matching. It is
 * not opaque the way `$(...)` is.
 *
 * These checks are pure and side-effect free; the engine and parser thread a
 * `strict` flag through `checkCommandDeep` to opt into them.
 */

/** A shell construct that strict mode refuses. */
export type StrictViolation = {
  /** Human-readable construct name, e.g. "command substitution $(...)". */
  construct: string;
  /** The offending source snippet. */
  snippet: string;
};

/** Options accepted by the deep/shallow command checkers. */
export type CheckOptions = {
  /** Enable strict-mode evasion detection. */
  strict?: boolean;
};

// ── Brace expansion detection ──────────────────────────────────────

/**
 * If `input[open]` (`{`) starts a brace expansion, return the index of its
 * matching `}`. Otherwise return -1.
 *
 * A brace expansion is `{` immediately followed by a word-ish character (not
 * whitespace, not `{`/`}`) and containing a `,` or `..` before the matching
 * close. This distinguishes `{a,b}` (expansion) from `{ cmd; }` (brace group,
 * space after `{`) and `{a}` (literal — no comma/sequence). Scanning stops at a
 * quote so quoted braces can't throw off nesting.
 */
function braceClose(input: string, open: number): number {
  const first = input[open + 1];
  if (!first || /[\s{}]/.test(first)) return -1;

  let depth = 0;
  let hasComma = false;
  let hasSeq = false;
  for (let i = open + 1; i < input.length; i++) {
    const c = input[i];
    if (c === "{") {
      depth++;
    } else if (c === "}") {
      if (depth === 0) return hasComma || hasSeq ? i : -1;
      depth--;
    } else if (c === ",") {
      hasComma = true;
    } else if (c === "." && input[i + 1] === ".") {
      hasSeq = true;
    } else if (c === "'" || c === '"') {
      return -1; // quoted braces are too intricate to classify safely
    }
  }
  return -1;
}

// ── Construct scanner ─────────────────────────────────────────────

/**
 * Quote-aware scan of `input` for active evasion constructs. Returns the first
 * violation found, or null if the input is clean.
 *
 * "Active" = not inside single quotes and not backslash-escaped. Inside double
 * quotes `$(...)`, `${...}`, and backticks stay active and are flagged; ANSI-C
 * `$'...'` is only active unquoted.
 */
export function detectStrictConstruct(input: string): StrictViolation | null {
  let sq = false; // inside 'single' quotes — everything literal
  let dq = false; // inside "double" quotes — $ ` " \ \n special
  let esc = false; // backslash-escaped next char

  for (let i = 0; i < input.length; i++) {
    const c = input[i];
    const n = input[i + 1] ?? "";

    if (esc) { esc = false; continue; }

    // Comment: an unquoted `#` at a word boundary (start of input, or right
    // after whitespace / a word-separating metacharacter) starts a comment to
    // end of line. Bash never runs anything in a comment, so stop scanning. A
    // mid-word `#` (e.g. `a#b`) is literal — fall through and keep scanning, so
    // a construct glued after it (e.g. `a#$(rm)`, which bash DOES run) is caught.
    if (!sq && !dq && c === "#") {
      const prev = i > 0 ? input[i - 1] : "";
      if (i === 0 || /[\s;|&()]/.test(prev)) {
        while (i < input.length && input[i] !== "\n") i++;
        continue;
      }
    }

    if (sq) {
      if (c === "'") sq = false;
      continue;
    }

    if (dq) {
      if (c === "\\") { esc = true; continue; }
      if (c === '"') { dq = false; continue; }
      if (c === "$") {
        if (n === "(") {
          // $((...)) is arithmetic — can't run commands on its own; only the
          // $(...) inside it can, and that's still caught by the scan below as
          // command substitution. Don't block pure arithmetic like $((1+1)).
          if (input[i + 2] === "(") { continue; }
          return { construct: "command substitution $(...)", snippet: "$(" };
        }
        if (n === "{") return { construct: "parameter expansion ${...}", snippet: "${" };
      }
      if (c === "`") return { construct: "backtick substitution `...`", snippet: "`" };
      continue;
    }

    // unquoted
    switch (c) {
      case "'": sq = true; continue;
      case '"': dq = true; continue;
      case "\\": esc = true; continue;
      case "$":
        if (n === "(") {
          // $((...)) is arithmetic — can't run commands on its own; only the
          // $(...) inside it can, and that's still caught by the scan below as
          // command substitution. Don't block pure arithmetic like $((1+1)).
          if (input[i + 2] === "(") { continue; }
          return { construct: "command substitution $(...)", snippet: "$(" };
        }
        if (n === "{") return { construct: "parameter expansion ${...}", snippet: "${" };
        // Note: $'...' (ANSI-C quoting) is NOT flagged — the parser tokenizer
        // decodes it, so ordinary rule matching already catches it.
        continue;
      case "`":
        return { construct: "backtick substitution `...`", snippet: "`" };
      case "<":
        // <(...) process substitution runs a command in a subshell. Don't confuse
        // with << (here-doc) / <<< (here-string): only a bare <( — not preceded
        // by another < — is process substitution.
        if (n === "(" && input[i - 1] !== "<") {
          return { construct: "process substitution <(...)", snippet: "<(" };
        }
        continue;
      case ">":
        // >(...) process substitution. (>> is append redirect, not a construct here.)
        if (n === "(" && input[i - 1] !== ">") {
          return { construct: "process substitution >(...)", snippet: ">(" };
        }
        continue;
      case "{": {
        const close = braceClose(input, i);
        if (close !== -1) {
          return { construct: "brace expansion {...}", snippet: input.slice(i, close + 1) };
        }
        continue;
      }
      default:
        continue;
    }
  }

  return null;
}

// ── Path-based command detection ─────────────────────────────────

/**
 * True if the effective command word is a path rather than a bare command
 * name — i.e. it contains a `/`. The shell treats any command word with a `/`
 * as a path to the executable (absolute `/bin/ls`, relative `./rm`, `../rm`,
 * `subdir/prog`) instead of a PATH lookup, so a rule for `ls` won't catch
 * `/bin/ls` or `./ls`.
 *
 * Operates on the unwrapped token list (after `sudo`/`env`/etc. are stripped)
 * so `sudo /bin/ls` is caught too. Argument paths (`cat /etc/passwd`) are
 * fine — only the command word is checked.
 */
export function isPathCommand(tokens: ReadonlyArray<string>): boolean {
  if (tokens.length === 0) return false;
  return tokens[0].includes("/");
}
