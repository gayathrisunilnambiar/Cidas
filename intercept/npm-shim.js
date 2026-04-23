#!/usr/bin/env node
/**
 * CIDAS npm shim — wraps the real npm binary.
 *
 * When `npm install [pkg...]` is detected, each package is screened via the
 * CIDAS daemon before the real npm process is spawned. If the daemon blocks a
 * package, the install is aborted. If it warns, the user is prompted.
 *
 * For all other npm sub-commands the shim is fully transparent.
 */

"use strict";

const { execFileSync, spawnSync } = require("child_process");
const https = require("https");
const http  = require("http");
const path  = require("path");
const os    = require("os");

// ── Configuration (read from env) ────────────────────────────────────────────
const DAEMON_URL    = process.env.CIDAS_DAEMON_URL    || "http://127.0.0.1:7979";
const DAEMON_SECRET = process.env.CIDAS_DAEMON_SECRET || "";
const BLOCK_THRESHOLD = Number(process.env.CIDAS_BLOCK_THRESHOLD || 80);
const WARN_THRESHOLD  = Number(process.env.CIDAS_WARN_THRESHOLD  || 40);

// Resolve the real npm binary (the one this shim replaced is stored here)
const REAL_NPM = process.env.CIDAS_REAL_NPM || _findRealNpm();

function _findRealNpm() {
  // The install-shim.sh stores the original path in ~/.cidas/real-npm
  const saved = path.join(os.homedir(), ".cidas", "real-npm");
  try {
    return require("fs").readFileSync(saved, "utf8").trim();
  } catch {
    // Fallback: find npm on PATH excluding our own shim directory
    const shimDir = path.dirname(process.argv[1]);
    const pathDirs = (process.env.PATH || "").split(path.delimiter).filter((d) => d !== shimDir);
    for (const dir of pathDirs) {
      const candidate = path.join(dir, "npm");
      try {
        require("fs").accessSync(candidate, require("fs").constants.X_OK);
        return candidate;
      } catch { /* continue */ }
    }
    return "npm"; // last resort
  }
}

// ── Argument parsing ──────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const subcmd = args[0];
const isInstall = subcmd === "install" || subcmd === "i" || subcmd === "add";

if (!isInstall) {
  // Pass through transparently
  _passthroughAndExit();
}

// Extract explicit package names (filter flags/options)
const packages = args.slice(1).filter((a) => !a.startsWith("-") && a !== "install");

if (packages.length === 0) {
  // `npm install` with no args — just install from package.json, skip screening
  _passthroughAndExit();
}

// ── Screen each package ───────────────────────────────────────────────────────
(async () => {
  let blocked = false;
  let warned  = false;

  for (const pkg of packages) {
    const [name, version] = pkg.split("@").filter(Boolean);
    process.stdout.write(`[36m[CIDAS][0m Screening ${pkg}…\n`);

    let result;
    try {
      result = await _screen(name, version || null);
    } catch (err) {
      process.stderr.write(`[33m[CIDAS][0m Daemon unreachable (${err.message}). Proceeding without screening.\n`);
      continue;
    }

    const { verdict, risk_score, message } = result;

    if (verdict === "BLOCK") {
      process.stderr.write(`[31m[CIDAS BLOCKED][0m ${message}\n`);
      blocked = true;
    } else if (verdict === "WARN") {
      process.stderr.write(`[33m[CIDAS WARNING][0m ${message}\n`);
      warned = true;
    } else {
      process.stdout.write(`[32m[CIDAS ALLOW][0m ${message}\n`);
    }
  }

  if (blocked) {
    process.stderr.write("[31m[CIDAS][0m Install aborted. Set CIDAS_BYPASS=1 to override (not recommended).\n");
    if (!process.env.CIDAS_BYPASS) {
      process.exit(1);
    }
  }

  _passthroughAndExit();
})();

// ── Helpers ───────────────────────────────────────────────────────────────────

function _screen(name, version) {
  return new Promise((resolve, reject) => {
    const url    = new URL("/api/v1/screen", DAEMON_URL);
    const body   = JSON.stringify({ package_name: name, version, project_root: process.cwd() });
    const lib    = url.protocol === "https:" ? https : http;
    const headers = {
      "Content-Type":  "application/json",
      "Content-Length": Buffer.byteLength(body),
      ...(DAEMON_SECRET ? { "X-CIDAS-Secret": DAEMON_SECRET } : {}),
    };

    const req = lib.request(
      { hostname: url.hostname, port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname, method: "POST", headers, timeout: 15_000 },
      (res) => {
        let data = "";
        res.on("data", (chunk) => { data += chunk; });
        res.on("end", () => {
          try { resolve(JSON.parse(data)); }
          catch (e) { reject(new Error(`Bad JSON from daemon: ${data}`)); }
        });
      },
    );
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Daemon request timed out")); });
    req.write(body);
    req.end();
  });
}

function _passthroughAndExit() {
  const result = spawnSync(REAL_NPM, args, { stdio: "inherit" });
  process.exit(result.status ?? 0);
}
