/**
 * pi-deny — Shell command guard extension for pi
 *
 * Blocks bash commands matching deny patterns.
 * Rule files cascade: .pi/.bashdeny (project) > ~/.pi/.bashdeny (global) > built-ins.
 *
 * Format:
 *   git push --force *     # deny (with * wildcard for remaining args)
 *   ! kubectl logs *       # allow exception (last match wins, ! prefix)
 *   # comments             # skipped
 *
 * Guards both LLM-executed bash calls (tool_call) and user ! commands (user_bash).
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import {
  type Pattern,
  splitCommands,
  evaluate,
  parseFile,
  checkCommand,
} from "./src/engine";

// ── Built-in defaults (always active, lowest priority) ─────────────

const BUILTIN_RULES = `
eval *
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

    const denied = checkCommand(event.input.command as string, patterns);
    if (!denied) return;

    if (ctx.hasUI) {
      ctx.ui.notify(`pi-deny: blocked "${denied.join(" ")}"`, "warning");
    }
    return { block: true, reason: `pi-deny: ${denied.join(" ")}` };
  });

  // ── Guard user ! commands ────────────────────────────────────

  pi.on("user_bash", (event, ctx) => {
    const denied = checkCommand(event.command, patterns);
    if (!denied) return;

    if (ctx.hasUI) {
      ctx.ui.notify(`pi-deny: blocked "${denied.join(" ")}"`, "warning");
    }
    return {
      result: {
        output: `[pi-deny] blocked: ${denied.join(" ")}`,
        exitCode: 1,
        cancelled: false,
        truncated: false,
      },
    };
  });
}
