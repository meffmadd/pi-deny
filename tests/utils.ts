/**
 * Test helpers.
 */

import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";

/**
 * Assert that `sh -n -c <cmd>` accepts a shell command.
 *
 * Used as a sanity gate in tests that take shell command strings as input.
 * If bash rejects the syntax, the test is a data error — not a behavior bug.
 *
 * `spawnSync` is used with explicit args (no outer shell) so multi-line
 * commands pass through cleanly without quoting issues.
 */
export function assertShSyntax(cmd: string): void {
  const r = spawnSync("sh", ["-n", "-c", cmd], {
    encoding: "utf8",
    timeout: 5000,
  });
  if (r.status === 0) return;
  const stderr = (r.stderr ?? "").trim() || `sh -n exited with status ${r.status}`;
  assert.fail(
    `Bash rejected syntax for "${cmd}":\n  ${stderr}\n` +
    `Test data error — fix the command string, not the engine.`
  );
}
