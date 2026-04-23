#!/usr/bin/env node
/**
 * CIDAS npm shim — transparent wrapper around the real npm binary.
 *
 * When `npm install [pkg...]` or `npm i [pkg...]` is detected:
 *   1. Each explicit package name is POSTed to the CIDAS daemon at
 *      http://127.0.0.1:7355/api/v1/scan.
 *   2. BLOCK → print a red error and exit(1) (respects CIDAS_BYPASS=1 escape hatch).
 *   3. WARN  → print a yellow warning and continue.
 *   4. ALLOW → print a green confirmation and continue.
 *
 * If the daemon is unreachable the shim ALWAYS passes through — it fails open
 * to avoid breaking developer workflows when the daemon is stopped.
 *
 * Configuration (environment variables):
 *   CIDAS_DAEMON_URL  — override daemon base URL (default http://127.0.0.1:7355)
 *   CIDAS_BYPASS=1    — skip all checks (emergency escape hatch)
 *   CIDAS_REAL_NPM    — path to the real npm binary (auto-detected if unset)
 */
"use strict";

const { spawnSync } = require("child_process");
const http  = require("http");
const https = require("https");
const path  = require("path");
const os    = require("os");
const fs    = require("fs");

const DAEMON_URL = process.env.CIDAS_DAEMON_URL || "http://127.0.0.1:7355";
const BYPASS     = Boolean(process.env.CIDAS_BYPASS);
const REAL_NPM   = process.env.CIDAS_REAL_NPM || _findRealNpm();

function _findRealNpm() {
  const saved = path.join(os.homedir(), ".cidas", "real-npm");
  try { return fs.readFileSync(saved, "utf8").trim(); } catch { /**/ }
  const shimDir = path.dirname(process.argv[1]);
  for (const dir of (process.env.PATH || "").split(path.delimiter).filter((d) => d !== shimDir)) {
    const cand = path.join(dir, "npm");
    try { fs.accessSync(cand, fs.constants.X_OK); return cand; } catch { /**/ }
  }
  return "npm";
}

const args   = process.argv.slice(2);
const subcmd = args[0];
const isInstall = subcmd === "install" || subcmd === "i" || subcmd === "add";

if (!isInstall || BYPASS) {
  _passthrough();
}

const packages = args
  .slice(1)
  .filter((a) => !a.startsWith("-") && a !== "install" && a !== "i");

if (packages.length === 0) {
  // Bare `npm install` — installs from package.json; nothing to screen
  _passthrough();
}

(async () => {
  let blocked = false;

  for (const pkg of packages) {
    // Handle scoped packages: @scope/name@version → split on last @
    const lastAt = pkg.lastIndexOf("@");
    const name    = lastAt > 0 ? pkg.slice(0, lastAt) : pkg;
    const version = lastAt > 0 ? pkg.slice(lastAt + 1) : null;

    process.stdout.write(`\x1b[36m[CIDAS]\x1b[0m Scanning \x1b[1m${pkg}\x1b[0m…\n`);

    let result;
    try {
      result = await _scan(name, version);
    } catch (err) {
      process.stderr.write(
        `\x1b[33m[CIDAS]\x1b[0m Daemon unreachable (${err.message}) — proceeding without scan.\n`
      );
      continue;
    }

    const { decision, risk_score, explanation } = result;

    if (decision === "BLOCK") {
      process.stderr.write(`\x1b[31m[CIDAS BLOCKED]\x1b[0m ${explanation}\n`);
      blocked = true;
    } else if (decision === "WARN") {
      process.stderr.write(`\x1b[33m[CIDAS WARNING]\x1b[0m ${explanation}\n`);
    } else {
      process.stdout.write(`\x1b[32m[CIDAS ALLOW]\x1b[0m ${explanation}\n`);
    }
  }

  if (blocked) {
    process.stderr.write(
      "\x1b[31m[CIDAS]\x1b[0m Install aborted. " +
      "Set \x1b[1mCIDAS_BYPASS=1\x1b[0m to override (not recommended).\n"
    );
    process.exit(1);
  }

  _passthrough();
})();

// ── Helpers ───────────────────────────────────────────────────────────────────

function _scan(name, version) {
  return new Promise((resolve, reject) => {
    const url    = new URL("/api/v1/scan", DAEMON_URL);
    const body   = JSON.stringify({
      package_name: name,
      version: version || null,
      project_path: process.cwd(),
      ai_suggested: false,
      requesting_tool: "npm-shim",
    });
    const lib    = url.protocol === "https:" ? https : http;
    const headers = {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body),
    };
    const options = {
      hostname: url.hostname,
      port: Number(url.port) || (url.protocol === "https:" ? 443 : 80),
      path: url.pathname,
      method: "POST",
      headers,
      timeout: 10_000,
    };
    const req = lib.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error(`Invalid JSON from daemon: ${data.slice(0, 200)}`)); }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Daemon request timed out after 10 s")); });
    req.write(body);
    req.end();
  });
}

function _passthrough() {
  const result = spawnSync(REAL_NPM, args, { stdio: "inherit" });
  process.exit(result.status ?? 0);
}
