#!/usr/bin/env node
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
import { type Pattern, parseFile, parseLine, checkCommandDetailed } from "./engine";
import { readFileSync, existsSync } from "node:fs";
import { createInterface } from "node:readline";

// ── Version ──────────────────────────────────────────────────────
const VERSION = "0.2.0";

// ── Usage ────────────────────────────────────────────────────────

function printUsage(stream: NodeJS.WritableStream): void {
  stream.write(`Usage: bash-deny [options]

Options:
  -f, --file <path>    Load rules from a .bashdeny file
  -r, --rules <rules>  Inline rules (;-separated, same format as file lines)
  -i, --input <cmd>    The command string to check
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

function loadRules(filePath?: string, inlineRules?: string): Pattern[] {
  const patterns: Pattern[] = [];

  // -f: read and parse file
  if (filePath) {
    if (!existsSync(filePath)) {
      console.error(`bash-deny: error: file not found: ${filePath}`);
      process.exit(1);
    }
    let content: string;
    try {
      content = readFileSync(filePath, "utf-8");
    } catch {
      console.error(`bash-deny: error: could not read file: ${filePath}`);
      process.exit(1);
    }
    patterns.push(...parseFile(content));
  }

  // -r: split on ;, trim, filter empty, parse each segment
  if (inlineRules) {
    for (const segment of inlineRules.split(";")) {
      const trimmed = segment.trim();
      if (trimmed === "" || trimmed.startsWith("#")) continue;
      patterns.push(parseLine(trimmed));
    }
  }

  return patterns;
}

// ── Check one command ────────────────────────────────────────────

function checkOne(
  cmd: string,
  patterns: Pattern[],
  dryRun: boolean,
  quiet: boolean,
): boolean {
  const match = checkCommandDetailed(cmd, patterns);
  if (match) {
    const msg = `bash-deny: blocked: "${match.tokens.join(" ")}" (rule: "${match.rule}")`;
    if (quiet) return true; // quiet: no output, just indicate denied
    if (dryRun) {
      console.log(msg);
    } else {
      console.error(msg);
    }
    return true; // denied
  }
  return false; // allowed
}

// ── Main ─────────────────────────────────────────────────────────

function main(): void {
  let values: Record<string, unknown>;
  try {
    const parsed = parseArgs({
      args: process.argv.slice(2),
      options: {
        file:     { type: "string", short: "f" },
        rules:    { type: "string", short: "r" },
        input:    { type: "string", short: "i" },
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
  const dryRun = (values["dry-run"] as boolean) ?? false;
  const quiet = (values.quiet as boolean) ?? false;

  // Must have rules
  if (!filePath && !inlineRules) {
    console.error("bash-deny: error: no rules provided (use -f or -r)");
    printUsage(process.stderr);
    process.exit(2);
  }

  const patterns = loadRules(filePath, inlineRules);

  // Command from -i takes priority over stdin
  if (inputCmd !== undefined) {
    if (inputCmd === "") {
      console.error("bash-deny: error: no command provided (use -i or pipe stdin)");
      printUsage(process.stderr);
      process.exit(2);
    }
    const denied = checkOne(inputCmd, patterns, dryRun, quiet);
    process.exit(denied && !dryRun ? 1 : 0);
  }

  // Check if stdin is a TTY (no pipe)
  if (process.stdin.isTTY) {
    console.error("bash-deny: error: no command provided (use -i or pipe stdin)");
    printUsage(process.stderr);
    process.exit(2);
  }

  // Read stdin line by line
  const rl = createInterface({ input: process.stdin });
  let denied = false;
  rl.on("line", (line: string) => {
    if (!denied) {
      const result = checkOne(line, patterns, dryRun, quiet);
      if (result && !dryRun) {
        denied = true;
        rl.close();
      }
    }
  });
  rl.on("close", () => {
    process.exit(denied && !dryRun ? 1 : 0);
  });
}

main();
