#!/usr/bin/env node
/**
 * Cross-platform launcher for the BlastShield MCP server.
 *
 * OpenCode spawns this script (Node is already a prerequisite for the
 * dashboard). It locates a Python interpreter that has the backend
 * dependencies installed and then hands stdio straight through to
 * `backend/mcp_server.py`, so the MCP protocol is untouched.
 *
 * Resolution order:
 *   1. $BLASTSHIELD_PYTHON (explicit override)
 *   2. .venv/Scripts/python.exe   (Windows virtualenv)
 *   3. .venv/bin/python           (macOS / Linux virtualenv)
 *   4. python3, then python       (whatever is on PATH)
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const server = join(root, "backend", "mcp_server.py");

const candidates = [
  process.env.BLASTSHIELD_PYTHON,
  join(root, ".venv", "Scripts", "python.exe"),
  join(root, ".venv", "bin", "python"),
  "python3",
  "python",
].filter(Boolean);

const bare = new Set(["python", "python3"]);
const interpreter = candidates.find((c) => bare.has(c) || existsSync(c));

if (!interpreter) {
  console.error(
    "[blastshield] No Python interpreter found. Create the venv (see README) " +
      "or set BLASTSHIELD_PYTHON to your interpreter's path."
  );
  process.exit(1);
}

if (!existsSync(server)) {
  console.error(`[blastshield] MCP server not found at ${server}`);
  process.exit(1);
}

const child = spawn(interpreter, [server], {
  stdio: "inherit",
  env: { ...process.env, PYTHONUNBUFFERED: "1", PYTHONIOENCODING: "utf-8" },
});

child.on("error", (err) => {
  console.error(`[blastshield] failed to start '${interpreter}': ${err.message}`);
  process.exit(1);
});
child.on("exit", (code) => process.exit(code ?? 0));
