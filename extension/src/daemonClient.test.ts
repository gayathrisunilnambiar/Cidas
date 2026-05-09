import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { DaemonClient } from "./daemonClient";
import * as vscode from "vscode";
import { Decision } from "./types";

const PORT = 7355;
const BASE = `http://127.0.0.1:${PORT}/api/v1`;

const zeroPillar = { score: 0, confidence: 0.9, flags: [], metadata: {} };

function makeScanResponse(decision: Decision, score = 0) {
  return {
    package_name: "lodash",
    version: null,
    decision,
    risk_score: score,
    contextify: zeroPillar,
    sentinel:   zeroPillar,
    shield:     zeroPillar,
    alternatives: [],
    explanation: "test",
    latency_ms: 5,
  };
}

function mockFetchOk(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
    text: vi.fn().mockResolvedValue(JSON.stringify(body)),
  });
}

describe("DaemonClient", () => {
  let client: DaemonClient;

  beforeEach(() => {
    client = new DaemonClient(PORT);
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // ── scan() ──────────────────────────────────────────────────────────────────

  it("scan() returns ALLOW response from daemon", async () => {
    vi.stubGlobal("fetch", mockFetchOk(makeScanResponse(Decision.ALLOW, 5)));
    const result = await client.scan({ package_name: "lodash", project_path: "/tmp" });
    expect(result.decision).toBe(Decision.ALLOW);
    expect(result.package_name).toBe("lodash");
  });

  it("scan() returns BLOCK response from daemon", async () => {
    vi.stubGlobal("fetch", mockFetchOk(makeScanResponse(Decision.BLOCK, 90)));
    const result = await client.scan({ package_name: "evil-pkg", project_path: "/tmp" });
    expect(result.decision).toBe(Decision.BLOCK);
    expect(result.risk_score).toBe(90);
  });

  it("scan() posts to the correct URL with JSON body", async () => {
    const fetchMock = mockFetchOk(makeScanResponse(Decision.ALLOW));
    vi.stubGlobal("fetch", fetchMock);
    await client.scan({ package_name: "lodash", project_path: "/tmp", ai_suggested: true });
    expect(fetchMock).toHaveBeenCalledWith(
      `${BASE}/scan`,
      expect.objectContaining({ method: "POST" }),
    );
    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(body.package_name).toBe("lodash");
    expect(body.ai_suggested).toBe(true);
  });

  it("scan() fails open and returns safe ALLOW when fetch throws", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    const result = await client.scan({ package_name: "lodash", project_path: "/tmp" });
    expect(result.decision).toBe(Decision.ALLOW);
    expect(result.risk_score).toBe(0);
    expect(result.contextify.flags).toContain("daemon_offline");
  });

  it("scan() fails open on non-2xx HTTP status", async () => {
    vi.stubGlobal("fetch", mockFetchOk({}, 503));
    const result = await client.scan({ package_name: "lodash", project_path: "/tmp" });
    expect(result.decision).toBe(Decision.ALLOW);
    expect(result.contextify.flags).toContain("daemon_offline");
  });

  it("scan() shows a VS Code warning when failing open", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    await client.scan({ package_name: "lodash", project_path: "/tmp" });
    expect(vscode.window.showWarningMessage).toHaveBeenCalledOnce();
  });

  // ── health() ────────────────────────────────────────────────────────────────

  it("health() returns true when daemon responds 200", async () => {
    vi.stubGlobal("fetch", mockFetchOk({}, 200));
    expect(await client.health()).toBe(true);
  });

  it("health() returns false when daemon responds non-2xx", async () => {
    vi.stubGlobal("fetch", mockFetchOk({}, 503));
    expect(await client.health()).toBe(false);
  });

  it("health() returns false when fetch throws", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    expect(await client.health()).toBe(false);
  });

  it("health() calls the correct URL", async () => {
    const fetchMock = mockFetchOk({}, 200);
    vi.stubGlobal("fetch", fetchMock);
    await client.health();
    expect(fetchMock).toHaveBeenCalledWith(`${BASE}/health`);
  });

  // ── trust() ─────────────────────────────────────────────────────────────────

  it("trust() resolves without error on 200", async () => {
    vi.stubGlobal("fetch", mockFetchOk({ trusted: "lodash" }));
    await expect(client.trust("lodash")).resolves.toBeUndefined();
  });

  it("trust() throws on HTTP error", async () => {
    vi.stubGlobal("fetch", mockFetchOk({}, 422));
    await expect(client.trust("bad-pkg")).rejects.toThrow("422");
  });

  it("trust() sends the package name in the request body", async () => {
    const fetchMock = mockFetchOk({ trusted: "lodash" });
    vi.stubGlobal("fetch", fetchMock);
    await client.trust("lodash");
    const body = JSON.parse(fetchMock.mock.calls[0][1].body as string);
    expect(body.package_name).toBe("lodash");
  });

  // ── clearCache() ─────────────────────────────────────────────────────────────

  it("clearCache() resolves without error on 200", async () => {
    vi.stubGlobal("fetch", mockFetchOk({ purged: 3 }));
    await expect(client.clearCache()).resolves.toBeUndefined();
  });

  it("clearCache() sends DELETE to the cache endpoint", async () => {
    const fetchMock = mockFetchOk({ purged: 0 });
    vi.stubGlobal("fetch", fetchMock);
    await client.clearCache();
    expect(fetchMock).toHaveBeenCalledWith(
      `${BASE}/cache`,
      expect.objectContaining({ method: "DELETE" }),
    );
  });

  it("clearCache() throws on HTTP error", async () => {
    vi.stubGlobal("fetch", mockFetchOk({}, 500));
    await expect(client.clearCache()).rejects.toThrow("500");
  });
});
