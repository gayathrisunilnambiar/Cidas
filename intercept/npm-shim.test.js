"use strict";

/**
 * Jest tests for intercept/npm-shim.js
 *
 * The shim guards its top-level execution with `if (require.main === module)`
 * so require()-ing it in tests is safe — no spawning, no process.exit calls
 * from the main path.
 *
 * Each test group uses beforeEach + jest.resetModules() so that module-level
 * constants (BYPASS, REAL_NPM) are re-evaluated fresh per test.
 */

const fs   = require("fs");
const os   = require("os");
const path = require("path");

const CIDAS_DIR  = path.join(os.homedir(), ".cidas");
const CONFIG_PATH = path.join(CIDAS_DIR, "config.json");
const AUDIT_PATH  = path.join(CIDAS_DIR, "audit.log");

// Keep a reference to the real fs implementations for passthrough
const _realReadFileSync = fs.readFileSync.bind(fs);

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Load a fresh copy of the shim with all fs + process.exit spies in place. */
function loadShim() {
  return require("./npm-shim");
}

// ── Setup / teardown ──────────────────────────────────────────────────────────

let shim;
let exitSpy;
let appendFileSyncSpy;
let mkdirSyncSpy;
let readFileSyncSpy;
let stderrSpy;

beforeEach(() => {
  jest.resetModules();

  exitSpy           = jest.spyOn(process, "exit").mockImplementation(() => {});
  appendFileSyncSpy = jest.spyOn(fs, "appendFileSync").mockImplementation(() => {});
  mkdirSyncSpy      = jest.spyOn(fs, "mkdirSync").mockImplementation(() => {});
  stderrSpy         = jest.spyOn(process.stderr, "write").mockImplementation(() => {});

  // Default: config file absent → _readCidasConfig returns {}
  readFileSyncSpy = jest.spyOn(fs, "readFileSync").mockImplementation((filePath, opts) => {
    if (filePath === CONFIG_PATH) {
      throw Object.assign(new Error("ENOENT: no such file"), { code: "ENOENT" });
    }
    return _realReadFileSync(filePath, opts);
  });

  delete process.env.CIDAS_BYPASS;
  shim = loadShim();
});

afterEach(() => {
  jest.restoreAllMocks();
  delete process.env.CIDAS_BYPASS;
});

// ── _readCidasConfig ──────────────────────────────────────────────────────────

describe("_readCidasConfig", () => {
  it("returns {} when config.json is absent", () => {
    expect(shim._readCidasConfig()).toEqual({});
  });

  it("returns parsed object when config.json exists", () => {
    readFileSyncSpy.mockImplementation((filePath, opts) => {
      if (filePath === CONFIG_PATH)
        return JSON.stringify({ bypass_disabled: true, extra: 42 });
      return _realReadFileSync(filePath, opts);
    });
    jest.resetModules();
    shim = loadShim();

    const cfg = shim._readCidasConfig();
    expect(cfg.bypass_disabled).toBe(true);
    expect(cfg.extra).toBe(42);
  });

  it("returns {} when config.json contains invalid JSON", () => {
    readFileSyncSpy.mockImplementation((filePath, opts) => {
      if (filePath === CONFIG_PATH) return "not-valid-json{{{";
      return _realReadFileSync(filePath, opts);
    });
    jest.resetModules();
    shim = loadShim();

    expect(shim._readCidasConfig()).toEqual({});
  });
});

// ── _writeAuditLog ────────────────────────────────────────────────────────────

describe("_writeAuditLog", () => {
  it("creates ~/.cidas directory if needed", () => {
    shim._writeAuditLog(["lodash"]);
    expect(mkdirSyncSpy).toHaveBeenCalledWith(CIDAS_DIR, { recursive: true });
  });

  it("appends one JSON line to audit.log", () => {
    shim._writeAuditLog(["lodash", "react"]);
    expect(appendFileSyncSpy).toHaveBeenCalledTimes(1);

    const [logPath, written] = appendFileSyncSpy.mock.calls[0];
    expect(logPath).toBe(AUDIT_PATH);
    expect(written).toMatch(/\n$/);                // newline-terminated

    const entry = JSON.parse(written.trim());
    expect(entry.package_names).toEqual(["lodash", "react"]);
    expect(entry.bypass_reason).toBe("env_var");
    expect(entry.cwd).toBe(process.cwd());
    expect(typeof entry.timestamp).toBe("string");
    // ISO 8601 format check
    expect(new Date(entry.timestamp).toISOString()).toBe(entry.timestamp);
  });

  it("includes USER env var in the audit entry", () => {
    const saved = process.env.USER;
    process.env.USER = "test-operator";
    shim._writeAuditLog(["axios"]);
    const entry = JSON.parse(appendFileSyncSpy.mock.calls[0][1].trim());
    expect(entry.user).toBe("test-operator");
    process.env.USER = saved;
  });

  it("falls back to USERNAME when USER is not set", () => {
    const savedUser     = process.env.USER;
    const savedUsername = process.env.USERNAME;
    delete process.env.USER;
    process.env.USERNAME = "win-user";
    shim._writeAuditLog(["pkg"]);
    const entry = JSON.parse(appendFileSyncSpy.mock.calls[0][1].trim());
    expect(entry.user).toBe("win-user");
    process.env.USER     = savedUser;
    process.env.USERNAME = savedUsername;
  });

  it("prints a warning to stderr but does not throw if appendFileSync fails", () => {
    appendFileSyncSpy.mockImplementation(() => {
      throw new Error("disk full");
    });
    expect(() => shim._writeAuditLog(["lodash"])).not.toThrow();
    const output = stderrSpy.mock.calls.map((c) => c[0]).join("");
    expect(output).toContain("Warning");
    expect(output).toContain("disk full");
  });
});

// ── _handleBypass — bypass allowed ────────────────────────────────────────────

describe("_handleBypass — bypass allowed (no bypass_disabled in config)", () => {
  it("writes the audit log when bypass is used", () => {
    shim._handleBypass(["lodash"]);
    expect(appendFileSyncSpy).toHaveBeenCalledTimes(1);
  });

  it("prints [CIDAS BYPASS] warning to stderr", () => {
    shim._handleBypass(["lodash"]);
    const output = stderrSpy.mock.calls.map((c) => c[0]).join("");
    expect(output).toContain("[CIDAS BYPASS]");
    expect(output).toContain("audit.log");
  });

  it("does NOT call process.exit when bypass is permitted", () => {
    shim._handleBypass(["lodash"]);
    expect(exitSpy).not.toHaveBeenCalled();
  });

  it("includes all requested packages in the audit entry", () => {
    shim._handleBypass(["lodash", "axios", "react"]);
    const entry = JSON.parse(appendFileSyncSpy.mock.calls[0][1].trim());
    expect(entry.package_names).toEqual(["lodash", "axios", "react"]);
  });
});

// ── _handleBypass — bypass_disabled enforcement ───────────────────────────────

describe("_handleBypass — bypass disabled by admin config", () => {
  beforeEach(() => {
    // Override readFileSync to return config with bypass_disabled: true
    readFileSyncSpy.mockImplementation((filePath, opts) => {
      if (filePath === CONFIG_PATH)
        return JSON.stringify({ bypass_disabled: true });
      return _realReadFileSync(filePath, opts);
    });
    jest.resetModules();
    shim = loadShim();
  });

  it("calls process.exit(1) when bypass_disabled is true", () => {
    shim._handleBypass(["lodash"]);
    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  it("does NOT write the audit log when bypass is blocked", () => {
    shim._handleBypass(["lodash"]);
    expect(appendFileSyncSpy).not.toHaveBeenCalled();
  });

  it("prints an error message explaining the restriction", () => {
    shim._handleBypass(["lodash"]);
    const output = stderrSpy.mock.calls.map((c) => c[0]).join("");
    expect(output).toContain("disabled by admin");
  });
});

// ── Normal scan path — bypass has no effect when CIDAS_BYPASS is unset ────────

describe("normal scan path (no bypass)", () => {
  it("_readCidasConfig returns {} and bypass_disabled is not in effect", () => {
    // Verify that when there is no bypass flag, config reads as permissive
    const cfg = shim._readCidasConfig();
    expect(cfg.bypass_disabled).toBeUndefined();
  });

  it("_writeAuditLog is not called during a normal (non-bypass) require", () => {
    // The shim's _main() is not invoked during require (require.main guard).
    // This confirms audit logging is never a side-effect of a normal install scan.
    expect(appendFileSyncSpy).not.toHaveBeenCalled();
  });

  it("_scan sends the correct JSON body to the daemon", () => {
    const http = require("http");
    const mockReq = { write: jest.fn(), end: jest.fn(), on: jest.fn() };
    jest.spyOn(http, "request").mockImplementation((_opts, callback) => {
      const mockRes = {
        on: (event, handler) => {
          if (event === "data")
            handler(JSON.stringify({ decision: "ALLOW", risk_score: 0, explanation: "ok" }));
          if (event === "end") handler();
        },
      };
      callback(mockRes);
      return mockReq;
    });

    return shim._scan("lodash", null).then((result) => {
      expect(result.decision).toBe("ALLOW");
      const body = JSON.parse(mockReq.write.mock.calls[0][0]);
      expect(body.package_name).toBe("lodash");
      expect(body.version).toBeNull();
      expect(body.requesting_tool).toBe("npm-shim");
    });
  });

  it("_scan rejects when the daemon is unreachable", () => {
    const http = require("http");
    const mockReq = {
      write: jest.fn(),
      end: jest.fn(),
      on: jest.fn((event, handler) => {
        if (event === "error") handler(new Error("ECONNREFUSED"));
      }),
    };
    jest.spyOn(http, "request").mockReturnValue(mockReq);

    return expect(shim._scan("lodash", null)).rejects.toThrow("ECONNREFUSED");
  });
});
