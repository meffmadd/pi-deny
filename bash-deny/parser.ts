import { findMatch, splitCommands, unwrapCommand, type Pattern, type WrapperDef } from "./engine";

export type ReservedWord =
 // loops
 | "for"
 | "while"
 | "until"
 | "do"
 | "done"
 | "in"
 // conditionals
 | "if"
 | "then"
 | "elif"
 | "else"
 | "fi"
 | "case"
 | "esac"

export type Tok =
 // structural tokens
 | {kind: "semi"}
 | {kind: "dsemi"}
 | {kind: "nl"}
 | {kind: "op", value: "&&" | "||" | "|"}
 | {kind: "amp"}
 | {kind: "bang"}
 | {kind: "lparen"}
 | {kind: "rparen"}
 | {kind: "lbrace"}
 | {kind: "rbrace"}
 // content tokens
 | {kind: "word", value: string}
 | {kind: "assign", name: string, value: string}
 | {kind: "kw", value: ReservedWord}
 | {kind: "eof"}


export class ParseError extends Error {
  readonly pos: number;

  constructor(message: string, pos: number) {
    super(message);
    this.pos = pos;
  }
}

/**
 * Evaluate a single ANSI-C escape sequence. `input[bi]` is the backslash;
 * `input[bi+1]` is the escape character. Returns the decoded string and the
 * number of source characters consumed (including the backslash).
 *
 *   \n → "\n" (consumed 2)   \154 → "l" (consumed 4)   \x6c → "l" (consumed 4)
 *
 * Unknown escapes preserve the backslash + char (bash's behavior).
 */
function evalAnsiCEscape(input: string, bi: number): { value: string; consumed: number } {
  const e = input[bi + 1];
  switch (e) {
    case "a": return { value: "\x07", consumed: 2 };
    case "b": return { value: "\b", consumed: 2 };
    case "e": case "E": return { value: "\x1b", consumed: 2 };
    case "f": return { value: "\f", consumed: 2 };
    case "n": return { value: "\n", consumed: 2 };
    case "r": return { value: "\r", consumed: 2 };
    case "t": return { value: "\t", consumed: 2 };
    case "v": return { value: "\v", consumed: 2 };
    case "\\": return { value: "\\", consumed: 2 };
    case "'": return { value: "'", consumed: 2 };
    case '"': return { value: '"', consumed: 2 };
    case "?": return { value: "?", consumed: 2 };
    case "0": case "1": case "2": case "3": case "4": case "5": case "6": case "7": {
      // \nnn — 1 to 3 octal digits
      let oct = "";
      let k = 0;
      while (k < 3 && /[0-7]/.test(input[bi + 1 + k] ?? "")) { oct += input[bi + 1 + k]; k++; }
      return { value: String.fromCodePoint(parseInt(oct, 8) & 0xff), consumed: 1 + k };
    }
    case "x": {
      // \xHH — 1 to 2 hex digits (at least one required)
      let hex = "";
      let k = 0;
      while (k < 2 && /[0-9a-fA-F]/.test(input[bi + 2 + k] ?? "")) { hex += input[bi + 2 + k]; k++; }
      if (hex) return { value: String.fromCodePoint(parseInt(hex, 16) & 0xff), consumed: 2 + k };
      return { value: "\\x", consumed: 2 };
    }
    case "u": {
      // \uHHHH — 1 to 4 hex digits
      let hex = "";
      let k = 0;
      while (k < 4 && /[0-9a-fA-F]/.test(input[bi + 2 + k] ?? "")) { hex += input[bi + 2 + k]; k++; }
      if (hex) return { value: String.fromCodePoint(parseInt(hex, 16)), consumed: 2 + k };
      return { value: "\\u", consumed: 2 };
    }
    case "U": {
      // \UHHHHHHHH — 1 to 8 hex digits
      let hex = "";
      let k = 0;
      while (k < 8 && /[0-9a-fA-F]/.test(input[bi + 2 + k] ?? "")) { hex += input[bi + 2 + k]; k++; }
      if (hex) return { value: String.fromCodePoint(parseInt(hex, 16)), consumed: 2 + k };
      return { value: "\\U", consumed: 2 };
    }
    case "c": {
      // \cX — control character (X & 0x1f)
      const ctrl = input[bi + 2];
      if (ctrl === undefined) return { value: "\\c", consumed: 2 };
      return { value: String.fromCodePoint(ctrl.toUpperCase().charCodeAt(0) & 0x1f), consumed: 3 };
    }
    default:
      // unknown escape — bash preserves the backslash + char
      return { value: "\\" + e, consumed: 2 };
  }
}

class TokenizeState {
  sq: boolean = false;
  dq: boolean = false;
  esc: boolean = false;
  tok: string = "";
  quoted: boolean = false;

  i: number = 0;
  input: string;
  output: Tok[] = [];


  constructor(input: string) {
    this.input = input;
  }

  public peek(): string {
  if (this.i + 1 < this.input.length) {
      return this.input[this.i+1];
    } else {
      return ""
    }
  }

  public done(): boolean {
    return this.i >= this.input.length;
  }

  public flush() {
    if (!this.tok && !this.quoted) { return; }

    const assign = this.tok.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)/);
    if (ReservedWords.has(this.tok)) {
      this.output.push({kind: "kw", value: this.tok as ReservedWord});
    } else if (assign) {
      const [, name, value] = assign;
      this.output.push({kind: "assign", name, value});
    } else {
      this.output.push({kind: "word", value: this.tok});
    }
    this.tok = "";
    this.quoted = false;
  }

  public emit(t: Tok) {
    this.flush();
    this.output.push(t);
  }
}


export function tokenize(_input: string): Tok[] {
  let state = new TokenizeState(_input);
  while (!state.done()) {
    const b: string = state.input[state.i];
    if (state.esc) {
      state.esc = false;
      if (b !== "\n") state.tok += b
    } else if (state.sq) {
      switch (b) {
        case "'":
          state.quoted = true;
          state.sq = false;
          break;
        default:
          state.tok += b;
      }
    } else if (state.dq) {
      switch (b) {
        case "\"":
          state.quoted = true;
          state.dq = false;
          break;
        case "\\":
          if (EscapedChars.has(state.peek())) {
            state.esc = true;
          } else {
            state.tok += "\\";
          }
          break;
        default:
          state.tok += b;
      }
    } else {
      switch (b) {
        case "\\":
          state.esc = true;
          break;
        case " ":
        case "\t":
          state.flush();
          break;
        case "\n":
          state.emit({kind: "nl"});
          break;
        case ";":
          if (state.peek() == ";") {
            state.i++;
            state.emit({kind: "dsemi"});
          } else {
            state.emit({kind: "semi"});
          }
          break;
        case "!":
          if (!state.tok && Separators.has(state.peek())) {
            state.emit({kind: "bang"});
          } else {
            state.tok += b;
          }
          break;
        case "&":
          if (state.peek() == "&") {
            state.i++;
            state.emit({kind: "op", value: "&&"});
          } else {
            state.emit({kind: "amp"});
          }
          break;
        case "|":
          if (state.peek() == "|") {
            state.i++;
            state.emit({kind: "op", value: "||"});
          } else {
            state.emit({kind: "op", value: "|"});
          }
          break;
        case "(":
          state.emit({kind: "lparen"});
          break;
        case ")":
          state.emit({kind: "rparen"});
          break;
        case "'":
          state.sq = true;
          break;
        case "\"":
          state.dq = true;
          break;
        case "#":
          if (!state.tok) {          
            for(state.i; (!state.done() && state.input[state.i] !== "\n"); state.i++) {}
            state.i--; // stop on character before new line; while-loop increment then move it to point to \n again
          } else {
            state.tok += b;
          }
          break;
        case "{":
          if (!state.tok && Separators.has(state.peek())) {
            state.emit({kind: "lbrace"});
          } else {
            state.tok += b;
          }
          break;
        case "}":
          if (!state.tok && Separators.has(state.peek())) {
            state.emit({kind: "rbrace"});
          } else {
            state.tok += b;
          }
          break;
        case "$":
          if (state.peek() === "(") {
            // $(...) — opaque command substitution
            state.quoted = true;
            state.tok += "$(";
            state.i += 2;
            let depth = 1, sq = false, dq = false, esc = false;
            while (!state.done() && depth > 0) {
              const c = state.input[state.i];
              if (esc) { state.tok += c; esc = false; }
              else if (sq) { if (c === "'") sq = false; state.tok += c; }
              else if (dq) { if (c === '"') dq = false; else if (c === "\\") esc = true; state.tok += c; }
              else if (c === "(") { depth++; state.tok += c; }
              else if (c === ")") { depth--; state.tok += c; if (depth === 0) break; }
              else if (c === "'") { sq = true; state.tok += c; }
              else if (c === '"') { dq = true; state.tok += c; }
              else if (c === "\\") { esc = true; state.tok += c; }
              else state.tok += c;
              state.i++;
            }
          } else if (state.peek() === "{") {
            // ${...} — opaque parameter expansion
            state.quoted = true;
            state.tok += "${";
            state.i += 2;
            let depth = 1, sq = false, dq = false, esc = false;
            while (!state.done() && depth > 0) {
              const c = state.input[state.i];
              if (esc) { state.tok += c; esc = false; }
              else if (sq) { if (c === "'") sq = false; state.tok += c; }
              else if (dq) { if (c === '"') dq = false; else if (c === "\\") esc = true; state.tok += c; }
              else if (c === "{") { depth++; state.tok += c; }
              else if (c === "}") { depth--; state.tok += c; if (depth === 0) break; }
              else if (c === "'") { sq = true; state.tok += c; }
              else if (c === '"') { dq = true; state.tok += c; }
              else if (c === "\\") { esc = true; state.tok += c; }
              else state.tok += c;
              state.i++;
            }
          } else if (state.peek() === "'") {
            // $'...' — ANSI-C quoting. Evaluate backslash escapes and append
            // the decoded characters (not the raw source), so $'ls' tokenizes
            // identically to ls and deny rules match both forms.
            state.quoted = true;
            state.i += 2; // skip $'
            while (!state.done()) {
              const c = state.input[state.i];
              if (c === "'") { break; } // closing quote
              if (c !== "\\") { state.tok += c; state.i++; continue; }
              if (state.i + 1 >= state.input.length) { break; } // trailing backslash
              const esc = evalAnsiCEscape(state.input, state.i);
              state.tok += esc.value;
              state.i += esc.consumed;
            }
          } else {
            state.tok += b;
          }
          break;
        default:
          state.tok += b;
      }
    }
    state.i++;
  }

  if (state.sq) {
    throw new ParseError("unclosed single quote", state.i);
  } else if (state.dq) {
    throw new ParseError("unclosed doulbe quote", state.i);
  } else if (state.esc) {
    throw new ParseError("dangling escape", state.i);
  }
  
  state.emit({kind: "eof"});
  return state.output;
}

type TokKind =
 | "semi"
 | "dsemi"
 | "nl"
 | "op"
 | "amp"
 | "bang"
 | "lparen"
 | "rparen"
 | "lbrace"
 | "rbrace"
 | "word"
 | "assign"
 | "kw"
 | "eof"

export type Node =
 | {kind: "simple", tokens: string[]}
 | {kind: "pipeline", bang: boolean, commands: Node[]}
 | {kind: "andor", left: Node, op: "&&" | "||", right: Node}
 | {kind: "list", items: Node[]}
 | {kind: "subshell", body: Node}
 | {kind: "brace", body: Node}
 | {kind: "for", var: string, words: string[], body: Node}
 | {kind: "while", cond: Node, body: Node, until: boolean}
 | {kind: "if", branches: {cond: Node, body: Node}[], else?: Node}
 | {kind: "case", word: Node, branches: {pat: string[], body: Node}[]}

export class ParserState {
  tokens: Tok[];
  i: number = 0;

  constructor(tokens: Tok[]) {
    this.tokens = tokens;
  }

  public peek(): Tok {
    if (this.i < this.tokens.length) {
      return this.tokens[this.i];
    } else {
      return this.tokens[this.tokens.length - 1]; // EOF
    }
  }

  public consume(): Tok {
    const tok = this.peek();
    if (tok.kind !== "eof") this.i++;
    return tok;    
  }

  public check(kind: TokKind, value?: ReservedWord | "&&" | "||" | "|"): boolean {
    const tok = this.peek();
    if (tok.kind != kind) return false;
    if (value && (tok.kind === "op" || tok.kind === "kw") && tok.value !== value) return false;
    return true;
  }

  public expect(kind: TokKind, value?: ReservedWord | "&&" | "||" | "|"): Tok {
    if (!this.check(kind, value)) {
      throw new ParseError(`assert failed for kind ${kind}`, this.i);
    }
    return this.consume();
  }
}

const ReservedWords = new Set(["for", "while", "until", "do", "done", "in", "if", "then", "elif", "else", "fi", "case", "esac"])

const EscapedChars = new Set(['`', '$', '"', '\\', '\n']);

const Separators = new Set([" ", "\t", "\n", ";", "&", "|", "(", ")", ""]); // empty string is EOF

export function parseSimple(state: ParserState): {kind: "simple", tokens: string[]} {
  const tokens: string[] = []
  const StopTokens = new Set(["semi", "amp", "nl", "op", "lparen", "rparen", "lbrace", "rbrace", "dsemi", "bang", "eof"] as TokKind[]);
  while (!StopTokens.has(state.peek().kind)) {
    const tok = state.consume();
    switch (tok.kind) {
      case "assign":
        tokens.push(`${tok.name}=${tok.value}`);
        break;
      case "kw":
        tokens.push(tok.value);
        break;
      case "word":
        tokens.push(tok.value);
        break;
      default:
        throw new ParseError("should not happen", state.i);
    }
  }
  return {kind: "simple", tokens};
}

export function parsePipeline(state: ParserState): {kind: "pipeline", bang: boolean, commands: Node[]} {
  const pipeline = {kind: "pipeline" as "pipeline", bang: false, commands: [] as Node[]};
  if (state.peek().kind === "bang") {
    pipeline.bang = true;
    state.consume();
  }

  pipeline.commands.push(parseCommand(state));
  let next = state.peek()
  while (next.kind === "op" && next.value === "|") {
    state.consume();
    pipeline.commands.push(parseCommand(state));
    next = state.peek();
  }

  return pipeline;
}

export function parseAndOr(state: ParserState): Node  {
  let left: Node = parsePipeline(state);
  let op = state.peek();
  let right: Node | undefined = undefined;
  while (op.kind === "op" && (op.value === "&&" || op.value == "||")) {
    state.consume(); // op
    right = parsePipeline(state);
    left = {kind: "andor", left, op: op.value, right}
    op = state.peek();
  }

  return left;
}


const kwClosers: Set<ReservedWord> = new Set(["done", "fi", "esac", "then", "else", "elif", "do", "in"]);

const kwOpeners: Set<ReservedWord> = new Set(["for", "while", "until", "if", "case"]);

function isCloser(tok: Tok): boolean {
  switch (tok.kind) {
    case "eof":
    case "rparen":
    case "rbrace":
    case "dsemi":
      return true;
    case "kw":
      return kwClosers.has(tok.value);
  }
  
  return false;
}

function isOpener(tok: Tok): boolean {
  return tok.kind === "kw" && kwOpeners.has(tok.value);
}

export function parseList(state: ParserState): Node {
  const items: Node[] = [parseAndOr(state)];
  let op = state.peek();
  while (op.kind === "semi" || op.kind === "amp" || op.kind === "nl") {
    state.consume();
    if (isCloser(state.peek())) break;
    items.push(parseAndOr(state));
    op = state.peek();
  }

  return {kind: "list", items};
}

function parseSubshell(state: ParserState): {kind: "subshell", body: Node} {
  state.expect("lparen");
  const body = parseList(state);
  state.expect("rparen");
  return {kind: "subshell", body};
}

function parseBrace(state: ParserState): {kind: "brace", body: Node} {
  state.expect("lbrace");
  const body = parseList(state);
  state.expect("rbrace");
  return {kind: "brace", body};
}

function parseFor(state: ParserState): {kind: "for", var: string, words: string[], body: Node} {
  state.expect("kw", "for");
  const v = (state.expect("word") as {kind: "word", value: string}).value;
  const words: string[] = [];
  let word = state.peek();
  if (word.kind === "kw" && word.value === "in") {
    state.consume();
    word = state.peek();
    while (word.kind === "word") {
      words.push(word.value);
      state.consume();
      word = state.peek();
    }   
  }
  while (word.kind !== "eof" && !(word.kind === "kw" && word.value === "do")) {
    state.consume();
    word = state.peek();
  }
  state.expect("kw", "do");
  const body = parseList(state);
  state.expect("kw", "done");
  return {kind: "for", var: v, words, body};
}

function parseWhile(state: ParserState): {kind: "while", cond: Node, body: Node, until: boolean} {
  const until = state.check("kw", "until");
  if (until) {
    state.consume();
  } else {
    state.expect("kw", "while");
  }
  const cond = parseList(state);
  state.expect("kw", "do");
  const body = parseList(state);
  state.expect("kw", "done");
  return {kind: "while", cond, body, until};
}

function parseIf(state: ParserState): {kind: "if", branches: {cond: Node, body: Node}[], else?: Node} {
  state.expect("kw", "if");
  const branches: {cond: Node, body: Node}[] = [];

  let cond = parseList(state);
  state.expect("kw", "then");
  let body = parseList(state);
  branches.push({cond, body});

  while (state.check("kw", "elif")) {
    state.consume();
    cond = parseList(state);
    state.expect("kw", "then");
    body = parseList(state);
    branches.push({cond, body});
  }

  let _else: Node | undefined = undefined;
  if (state.check("kw", "else")) {
    state.consume();
    _else = parseList(state);
  }
  state.expect("kw", "fi");
  return {kind: "if", branches, else: _else};
}

function wordValue(tok: Tok): string {
  return (tok as {kind: "word", value: string}).value;
}

function skipSeparators(state: ParserState): void {
  while (state.peek().kind === "nl" || state.peek().kind === "semi") {
    state.consume();
  }
}

function parseCase(state: ParserState): {kind: "case", word: Node, branches: {pat: string[], body: Node}[]} {
  state.expect("kw", "case");
  const word: Node = {kind: "simple", tokens: [wordValue(state.expect("word"))]};
  state.expect("kw", "in");
  const branches: {pat: string[], body: Node}[] = [];
  do {
    // Tolerate newlines/semicolons after `in`, between branches, before `esac`.
    skipSeparators(state);
    const pat: string[] = [wordValue(state.expect("word"))];
    while (state.check("op", "|")) {
      state.consume();
      pat.push(wordValue(state.expect("word")));
    }
    state.expect("rparen");
    const body = parseList(state);   // stops at `dsemi` (a closer)
    state.expect("dsemi");            // `;;` terminator — mandatory per §3/§7
    branches.push({pat, body});
    skipSeparators(state);            // newline before `esac` or next pattern
  } while (!state.check("kw", "esac"));
  state.expect("kw", "esac");
  return {kind: "case", word, branches};
}

export function parseCommand(state: ParserState): Node {
  if (state.check("kw", "for")) return parseFor(state);
  if (state.check("kw", "while") || state.check("kw", "until")) return parseWhile(state);
  if (state.check("kw", "if")) return parseIf(state);
  if (state.check("kw", "case")) return parseCase(state);
  if (isOpener(state.peek())) {
    throw new ParseError("not yet", state.i);
  }
  if (state.check("lparen")) return parseSubshell(state);
  if (state.check("lbrace")) return parseBrace(state);

  return parseSimple(state);
}

export function* leaves(node: Node): Generator<string[]> {
  switch (node.kind) {
    case "simple":
      yield node.tokens;
      return;

    case "pipeline":
      for (const cmd of node.commands) yield* leaves(cmd);
      return;

    case "andor":
      yield* leaves(node.left);
      yield* leaves(node.right);
      return;

    case "list":
      for (const item of node.items) yield* leaves(item);
      return;

    case "subshell":
      yield* leaves(node.body);
      return;

    case "brace":
      yield* leaves(node.body);
      return;

    case "for":
      // `var` and `words` are data, not commands.
      yield* leaves(node.body);
      return;

    case "while":
      yield* leaves(node.cond);
      yield* leaves(node.body);
      return;

    case "if":
      for (const b of node.branches) {
        yield* leaves(b.cond);
        yield* leaves(b.body);
      }
      if (node.else) yield* leaves(node.else);
      return;

    case "case":
      // `word` is the match subject (data); `branches[].pat` are patterns
      // (data). Neither executes — only `branches[].body` runs.
      for (const b of node.branches) yield* leaves(b.body);
      return;
  }
}

/** Top-level entry: tokenize input and parse it as a list. */
function parse(input: string): Node {
  const tokens = tokenize(input);
  const state = new ParserState(tokens);
  return parseList(state);
}

/**
 * Deep command check: parse the input into an AST and walk every leaf
 * `simple_command`, checking each against the patterns. Returns the first
 * denied leaf's tokens and the matching deny rule, or undefined if all pass.
 *
 * Uses the parser's `leaves()` walker instead of `splitCommands`, so commands
 * hidden inside control-flow constructs (for/while/if/case/subshell/brace) are
 * found.
 *
 * For input the parser can't fully consume — out-of-scope constructs like
 * function definitions and arithmetic (parser.md §2), or malformed input — it
 * falls back to the `splitCommands`-based shallow check, so behavior is never
 * worse than the pre-parser engine. The fallback only triggers when the parser
 * throws or leaves leftover tokens; fully-parsed input uses the AST (which is
 * more precise, e.g. it doesn't treat `for x in rm` loop values as commands).
 */
export function checkCommandDeep(
  input: string,
  patterns: ReadonlyArray<Pattern>,
  wrappers?: Readonly<Record<string, WrapperDef>>,
): { tokens: string[]; rule: string } | undefined {
  // Deep path: parse and walk AST leaves (catches control-flow hidden commands).
  try {
    const state = new ParserState(tokenize(input));
    const ast = parseList(state);
    if (state.peek().kind === "eof") {
      for (const leaf of leaves(ast)) {
        if (leaf.length === 0) continue;
        const unwrapped = unwrapCommand(leaf, wrappers);
        if (unwrapped === null) return { tokens: leaf, rule: "(invalid wrapper usage)" };
        const match = findMatch(unwrapped, patterns);
        if (match && !match.allow) return { tokens: leaf, rule: match.raw };
      }
      return undefined;
    }
    // Leftover tokens: an out-of-scope construct the parser doesn't handle.
    // Fall through to the shallow path.
  } catch (e) {
    if (!(e instanceof ParseError)) throw e;
    // Malformed input (e.g. unclosed construct). Fall through to the shallow path.
  }
  return checkCommandShallow(input, patterns, wrappers);
}

/**
 * Shallow `splitCommands`-based check — the fallback for input the parser can't
 * fully handle. Splits on metacharacters and checks each segment. This is the
 * pre-parser engine path, kept as a safety net so no input regresses.
 */
function checkCommandShallow(
  input: string,
  patterns: ReadonlyArray<Pattern>,
  wrappers?: Readonly<Record<string, WrapperDef>>,
): { tokens: string[]; rule: string } | undefined {
  for (const tokens of splitCommands(input)) {
    if (tokens.length === 0) continue;
    const unwrapped = unwrapCommand(tokens, wrappers);
    if (unwrapped === null) return { tokens, rule: "(invalid wrapper usage)" };
    const match = findMatch(unwrapped, patterns);
    if (match && !match.allow) return { tokens, rule: match.raw };
  }
  return undefined;
}



