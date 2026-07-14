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

export function parseSubshell(state: ParserState): {kind: "subshell", body: Node} {
  state.expect("lparen");
  const body = parseList(state);
  state.expect("rparen");
  return {kind: "subshell", body};
}

export function parseBrace(state: ParserState): {kind: "brace", body: Node} {
  state.expect("lbrace");
  const body = parseList(state);
  state.expect("rbrace");
  return {kind: "brace", body};
}

export function parseFor(state: ParserState): {kind: "for", var: string, words: string[], body: Node} {
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

export function parseWhile(state: ParserState): {kind: "while", cond: Node, body: Node, until: boolean} {
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

export function parseIf(state: ParserState): {kind: "if", branches: {cond: Node, body: Node}[], else?: Node} {
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

export function parseCase(state: ParserState): {kind: "case", word: Node, branches: {pat: string[], body: Node}[]} {
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



