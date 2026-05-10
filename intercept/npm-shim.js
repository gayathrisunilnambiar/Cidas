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
 *   CIDAS_BYPASS=1    — skip all checks (emergency escape hatch; audited)
 *   CIDAS_REAL_NPM    — path to the real npm binary (auto-detected if unset)
 *
 * Admin configuration (~/.cidas/config.json):
 *   bypass_disabled: true  — prevents CIDAS_BYPASS=1 from working (CI enforcement)
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

// ── Helpers ───────────────────────────────────────────────────────────────────

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

/** Read ~/.cidas/config.json; returns {} when the file is absent or invalid JSON. */
function _readCidasConfig() {
  const configPath = path.join(os.homedir(), ".cidas", "config.json");
  try {
    return JSON.parse(fs.readFileSync(configPath, "utf8"));
  } catch {
    return {};
  }
}

/**
 * Look up a package in ~/.cidas/offline-cache.json (written by the daemon
 * after every ALLOW verdict). Returns the cache entry when it is a valid,
 * unexpired ALLOW; null otherwise. Used only when the daemon is unreachable.
 */
function _checkOfflineCache(packageName) {
  const cachePath = path.join(os.homedir(), ".cidas", "offline-cache.json");
  let cache;
  try {
    cache = JSON.parse(fs.readFileSync(cachePath, "utf8"));
  } catch {
    return null;
  }
  const entry = cache && cache[packageName];
  if (!entry || entry.verdict !== "ALLOW") return null;

  const ts = Date.parse(entry.timestamp);
  if (!Number.isFinite(ts)) return null;
  const ageHours = (Date.now() - ts) / 3_600_000;
  const ttlHours = Number(entry.ttl_hours);
  if (!Number.isFinite(ttlHours) || ageHours > ttlHours) return null;

  return entry;
}

/**
 * Append one structured JSON line to ~/.cidas/audit.log.
 * Creates the directory if it does not exist; silently swallows write errors
 * so a log failure never blocks an install.
 */
function _writeAuditLog(packageNames) {
  const cidasDir = path.join(os.homedir(), ".cidas");
  try { fs.mkdirSync(cidasDir, { recursive: true }); } catch { /**/ }
  const entry = JSON.stringify({
    timestamp:     new Date().toISOString(),
    package_names: packageNames,
    bypass_reason: "env_var",
    user:          process.env.USER || process.env.USERNAME || "unknown",
    cwd:           process.cwd(),
  });
  try {
    fs.appendFileSync(path.join(cidasDir, "audit.log"), entry + "\n");
  } catch (err) {
    process.stderr.write(`\x1b[33m[CIDAS]\x1b[0m Warning: could not write audit log: ${err.message}\n`);
  }
}

/**
 * Handle a CIDAS_BYPASS=1 request.
 *
 * If the admin config has bypass_disabled: true, print an error and exit 1.
 * Otherwise, write an audit log entry, print a visible warning, and return
 * so the caller can proceed with the passthrough.
 */
function _handleBypass(packageNames) {
  const config = _readCidasConfig();
  if (config.bypass_disabled) {
    process.stderr.write(
      "\x1b[31m[CIDAS]\x1b[0m CIDAS_BYPASS is disabled by admin configuration. " +
      "Contact your security team or remove bypass_disabled from ~/.cidas/config.json.\n"
    );
    process.exit(1);
    return; // unreachable; keeps static analysers happy
  }
  _writeAuditLog(packageNames);
  process.stderr.write(
    "\x1b[33m[CIDAS BYPASS]\x1b[0m Install proceeding without security check. " +
    "Logged to ~/.cidas/audit.log\n"
  );
}

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

// ── Main execution (skipped when require()'d by tests) ────────────────────────

const args = process.argv.slice(2);

function _main() {
  const subcmd    = args[0];
  const isInstall = subcmd === "install" || subcmd === "i" || subcmd === "add";

  if (!isInstall) {
    _passthrough();
  }

  // Parse packages before the bypass check so the audit log captures them.
  const packages = args
    .slice(1)
    .filter((a) => !a.startsWith("-") && a !== "install" && a !== "i");

  if (BYPASS) {
    _handleBypass(packages); // exits 1 if bypass_disabled; otherwise logs + returns
    _passthrough();
  }

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
        // Daemon unreachable — try the offline cache before failing open.
        const cached = _checkOfflineCache(name);
        if (cached) {
          // Known-good package within TTL; proceed silently.
          continue;
        }
        process.stderr.write(
          `\x1b[33m[CIDAS WARNING]\x1b[0m ⚠  Daemon offline AND no cached verdict for \x1b[1m${pkg}\x1b[0m. ` +
          `Proceeding without security check — verify this package manually before using it.\n`
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
}

if (require.main === module) {
  _main();
}

module.exports = {
  _readCidasConfig,
  _writeAuditLog,
  _handleBypass,
  _checkOfflineCache,
  _scan,
};
