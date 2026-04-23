/**
 * DaemonClient — HTTP client for the local CIDAS daemon.
 *
 * If the daemon is unreachable every method fails open: scan() returns a
 * safe ALLOW response with a warning flag rather than throwing, ensuring
 * that a stopped daemon never blocks the developer's workflow.
 */
import * as vscode from "vscode";
import { Decision, PackageScanRequest, ScanResponse } from "./types";

function _daemonUrl(port: number): string {
  return `http://127.0.0.1:${port}/api/v1`;
}

function _safeAllow(packageName: string, reason: string): ScanResponse {
  const zeroPillar = { score: 0, confidence: 0, flags: ["daemon_offline"], metadata: {} };
  return {
    package_name: packageName,
    version: null,
    decision: Decision.ALLOW,
    risk_score: 0,
    contextify: zeroPillar,
    sentinel: zeroPillar,
    shield: zeroPillar,
    alternatives: [],
    explanation: `CIDAS daemon unreachable — failing open. Reason: ${reason}`,
    latency_ms: 0,
  };
}

export class DaemonClient {
  private readonly port: number;

  constructor(port: number) {
    this.port = port;
  }

  /** Screen a package; returns a safe ALLOW if the daemon is offline. */
  async scan(request: PackageScanRequest): Promise<ScanResponse> {
    try {
      const resp = await fetch(`${_daemonUrl(this.port)}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
      });
      if (!resp.ok) {
        const text = await resp.text().catch(() => String(resp.status));
        throw new Error(`HTTP ${resp.status}: ${text}`);
      }
      return (await resp.json()) as ScanResponse;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      vscode.window.showWarningMessage(`CIDAS: daemon unreachable during scan — ${msg}`);
      return _safeAllow(request.package_name, msg);
    }
  }

  /** Returns true when the daemon responds to the health endpoint. */
  async health(): Promise<boolean> {
    try {
      const resp = await fetch(`${_daemonUrl(this.port)}/health`);
      return resp.ok;
    } catch {
      return false;
    }
  }

  /** Add a package to the daemon's local trust bypass list. */
  async trust(packageName: string): Promise<void> {
    const resp = await fetch(`${_daemonUrl(this.port)}/trust`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ package_name: packageName }),
    });
    if (!resp.ok) {
      throw new Error(`Trust call failed: HTTP ${resp.status}`);
    }
  }

  /** Purge expired entries from the daemon scan cache. */
  async clearCache(): Promise<void> {
    const resp = await fetch(`${_daemonUrl(this.port)}/cache`, { method: "DELETE" });
    if (!resp.ok) {
      throw new Error(`Cache clear failed: HTTP ${resp.status}`);
    }
  }
}
