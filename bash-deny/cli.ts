#!/usr/bin/env tsx
/**
 * bash-deny — CLI shell command guard
 *
 * Blocks bash commands matching deny patterns, with ! allow-exceptions.
 * Reads one command per line from stdin, or a single command via -i.
 *
 *   bash-deny -f .pi/.bashdeny -i "kubectl delete pod"
 *   echo "kubectl delete pod" | bash-deny -f .pi/.bashdeny
 */

import { parseArgs } from "node:util";
import { type Pattern, parseFile, parseLine, splitRuleList } from "./engine";
import { checkCommandDeep } from "./parser";
import { readFileSync, existsSync, realpathSync } from "node:fs";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import packageJson from "../package.json" with { type: "json" };

// ── Version ──────────────────────────────────────────────────────
const VERSION = packageJson.version;

// ── Usage ────────────────────────────────────────────────────────

function printUsage(stream: NodeJS.WritableStream): void {
  stream.write(`Usage: bash-deny [options]

Options:
  -f, --file <path>    Load rules from a .bashdeny file
  -r, --rules <rules>  Inline rules (;-separated, same format as file lines)
  -i, --input <cmd>    The command string to check
  -s, --strict         Block evasion constructs ($(), \`\`, \${}, {a,b}, <()>),
                      path-based commands (/bin/ls, ./rm, ../rm), match
                      case-insensitively, and rescan wrapper payloads
                      (bash -c, su -c, eval). Works with no rules — blocks
                      suspicious constructs as-is.
      --basename        Normalize path-based command words (/bin/ls → ls,
                      ./rm → rm, ../rm → rm) before matching instead of
                      blocking them. Replaces -s's path-based block with
                      normalize-and-match. Requires rules or -s.
  -n, --dry-run        Print what would be blocked but always exit 0
  -q, --quiet          No output — exit code only (1 if denied, 0 if allowed)
  -h, --help           Print usage and exit
  -V, --version        Print version and exit

Command input (exactly one required):
  -i flag:             bash-deny -f rules.txt -i "kubectl delete pod"
  Piped stdin:         echo "kubectl delete pod" | bash-deny -f rules.txt
                       Each line is one command; first deny stops processing.

If both -i and stdin are provided, -i wins.
`);
}

// ── Rule loading ─────────────────────────────────────────────────

export type LoadResult =
  | { ok: true; patterns: ReadonlyArray<Pattern> }
  | { ok: false; error: string };

/** Parse file content and/or inline rules into a Pattern list. */
export function loadRulesPure(
  fileContent: string | undefined,
  inlineRules: string | undefined,
  fileSource = "<file>",
): LoadResult {
  const patterns: Pattern[] = [];
  try {
    if (fileContent !== undefined) {
      for (const p of parseFile(fileContent, fileSource)) patterns.push(p);
    }
    if (inlineRules !== undefined) {
      for (const [index, segment] of splitRuleList(inlineRules).entries()) {
        const trimmed = segment.trim();
        if (trimmed === "" || trimmed.startsWith("#")) continue;
        patterns.push(parseLine(segment, { name: "<inline>", line: index + 1 }));
      }
    }
    return { ok: true, patterns };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : "invalid rules" };
  }
}

/** Read a rule file (if given) and return the merged pattern list. */
function loadRules(
  filePath: string | undefined,
  inlineRules: string | undefined,
): LoadResult {
  let fileContent: string | undefined;
  if (filePath) {
    if (!existsSync(filePath)) {
      return { ok: false, error: `file not found: ${filePath}` };
    }
    try {
      fileContent = readFileSync(filePath, "utf-8");
    } catch {
      return { ok: false, error: `could not read file: ${filePath}` };
    }
  }
  return loadRulesPure(fileContent, inlineRules, filePath ?? "<file>");
}

// ── Check one command ────────────────────────────────────────────

export type CommandVerdict =
  | { kind: "allow" }
  | { kind: "deny"; message: string }
  | { kind: "invalid"; message: string };

/** Classify a command as allowed or denied, with a human-readable deny message. */
export function classify(cmd: string, patterns: ReadonlyArray<Pattern>, strict = false, basename = false): CommandVerdict {
  const match = checkCommandDeep(cmd, patterns, undefined, { strict, basename });
  if (!match) return { kind: "allow" };
  if (match.reason === "invalid") {
    return { kind: "invalid", message: `bash-deny: error: ${match.rule}` };
  }
  return {
    kind: "deny",
    message: `bash-deny: blocked: "${match.tokens.join(" ")}" (rule: "${match.rule}")`,
  };
}

type ReportResult = "allow" | "deny" | "invalid";

/** Print a verdict (or nothing if quiet) and return its disposition. */
function reportVerdict(v: CommandVerdict, dryRun: boolean, quiet: boolean): ReportResult {
  if (v.kind === "allow") return "allow";
  if (!quiet) {
    if (dryRun && v.kind === "deny") console.log(v.message);
    else console.error(v.message);
  }
  return v.kind;
}

// ── Main ─────────────────────────────────────────────────────────

function main(): void {
  let values: Record<string, unknown> = {};
  try {
    const parsed = parseArgs({
      args: process.argv.slice(2),
      options: {
        file:     { type: "string", short: "f" },
        rules:    { type: "string", short: "r" },
        input:    { type: "string", short: "i" },
        strict:   { type: "boolean", short: "s" },
        basename: { type: "boolean" },
        "dry-run": { type: "boolean", short: "n" },
        quiet:    { type: "boolean", short: "q" },
        help:     { type: "boolean", short: "h" },
        version:  { type: "boolean", short: "V" },
      },
      allowPositionals: false,
      strict: true,
    });
    values = parsed.values;
  } catch (err) {
    console.error(`bash-deny: error: ${(err as Error).message}`);
    process.exit(2);
  }

  // --help
  if (values.help) {
    printUsage(process.stdout);
    process.exit(0);
  }

  // --version
  if (values.version) {
    console.log(`bash-deny ${VERSION}`);
    process.exit(0);
  }

  // Validate mutual exclusivity
  if (values["dry-run"] && values.quiet) {
    console.error("bash-deny: error: --dry-run and --quiet are mutually exclusive");
    process.exit(2);
  }

  const filePath = values.file as string | undefined;
  const inlineRules = values.rules as string | undefined;
  const inputCmd = values.input as string | undefined;
  const strict = (values.strict as boolean) ?? false;
  const basename = (values.basename as boolean) ?? false;
  const dryRun = (values["dry-run"] as boolean) ?? false;
  const quiet = (values.quiet as boolean) ?? false;

  // Must have rules, unless --strict is set (strict blocks evasion constructs on
  // its own, with no rules needed).
  if (!filePath && !inlineRules && !strict) {
    console.error("bash-deny: error: no rules provided (use -f, -r, or -s)");
    printUsage(process.stderr);
    process.exit(2);
  }

  const result = loadRules(filePath, inlineRules);
  if (!result.ok) {
    console.error(`bash-deny: error: ${result.error}`);
    process.exit(1);
  }
  const patterns = result.patterns;

  // Command from -i takes priority over stdin
  if (inputCmd !== undefined) {
    if (inputCmd === "") {
      console.error("bash-deny: error: no command provided (use -i or pipe stdin)");
      printUsage(process.stderr);
      process.exit(2);
    }
    const v = classify(inputCmd, patterns, strict, basename);
    const disposition = reportVerdict(v, dryRun, quiet);
    process.exit(disposition === "invalid" ? 2 : disposition === "deny" && !dryRun ? 1 : 0);
  }

  // Check if stdin is a TTY (no pipe)
  if (process.stdin.isTTY) {
    console.error("bash-deny: error: no command provided (use -i or pipe stdin)");
    printUsage(process.stderr);
    process.exit(2);
  }

  // Read stdin line by line
  const rl = createInterface({ input: process.stdin });
  let disposition: ReportResult = "allow";
  rl.on("line", (line: string) => {
    if (disposition === "allow") {
      const v = classify(line, patterns, strict, basename);
      const result = reportVerdict(v, dryRun, quiet);
      if (result === "invalid" || (result === "deny" && !dryRun)) {
        disposition = result;
        rl.close();
      }
    }
  });
  rl.on("close", () => {
    process.exit(disposition === "invalid" ? 2 : disposition === "deny" && !dryRun ? 1 : 0);
  });
}

// Run main() only when this file is the entry point. Allows tests to import
// loadRulesPure / classify without triggering main(). Resolves symlinks so a
// `npm link` global install (where argv[1] is the symlink) still runs.
const _entry = process.argv[1] ? realpathSync(process.argv[1]) : "";
if (_entry === fileURLToPath(import.meta.url)) {
  main();
}
