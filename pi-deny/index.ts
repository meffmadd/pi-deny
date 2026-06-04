/**
 * pi-deny — Shell command guard extension for pi
 *
 * Blocks bash commands matching deny patterns.
 * Rule files cascade: .pi/.bashdeny (project) > ~/.pi/.bashdeny (global) > built-ins.
 *
 * Format:
 *   git push --force       # deny — trailing args implicitly allowed
 *   ! kubectl logs         # allow exception (last match wins, ! prefix)
 *   # comments             # skipped
 *
 * Guards LLM-executed bash calls (tool_call). User ! commands are never blocked.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import {
  type Pattern,
  parseFile,
  checkCommandDetailed,
} from "./engine";

// ── Built-in defaults (always active, lowest priority) ─────────────

const BUILTIN_RULES = `
eval
`.trim();

function loadPatterns(cwd: string): Pattern[] {
  const builtins = parseFile(BUILTIN_RULES);
  const globalPath = join(homedir(), ".pi", ".bashdeny");
  const projectPath = join(cwd, ".pi", ".bashdeny");

  const global = loadFile(globalPath);
  const project = loadFile(projectPath);

  return [...builtins, ...global, ...project];
}

function loadFile(path: string): Pattern[] {
  if (!existsSync(path)) return [];
  try {
    return parseFile(readFileSync(path, "utf-8"));
  } catch {
    return [];
  }
}

// ── Extension ──────────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
  let patterns: Pattern[] = [];

  pi.on("session_start", (_event, ctx) => {
    patterns = loadPatterns(ctx.cwd);
    const userCount = patterns.length - parseFile(BUILTIN_RULES).length;
    if (userCount > 0) {
      ctx.ui.notify(`pi-deny: ${userCount} user rules loaded`, "info");
    }
  });

  // ── Guard LLM-executed bash ──────────────────────────────────

  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "bash") return;

    const match = checkCommandDetailed(event.input.command as string, patterns);
    if (!match) return;

    const msg = `command disallowed! Commands of the form "${match.rule}" are blocked.`;
    if (ctx.hasUI) {
      ctx.ui.notify(`pi-deny: ${msg}`, "error");
    }
    return { block: true, reason: `pi-deny: ${msg}` };
  });

}
