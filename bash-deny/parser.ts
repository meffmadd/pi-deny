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
 | {kind: "case", word: Node, branches: {pat: string[], body: Node}}


const ReservedWords = new Set(["for", "while", "until", "do", "done", "in", "if", "then", "elif", "else", "fi", "case", "esac"])

const EscapedChars = new Set(['`', '$', '"', '\\', '\n']);

const Separators = new Set([" ", "\t", "\n", ";", "&", "|", "(", ")", ""]); // empty string is EOF

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

