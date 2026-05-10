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

  // Tracks the most recently observed daemon reachability so consumers
  // (e.g. a status-bar indicator) can react without re-probing.
  private _offline = false;
  private readonly _stateListeners: Array<(online: boolean) => void> = [];
  private _pollingTimer: ReturnType<typeof setInterval> | undefined;

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
      this._setOffline(false);
      return (await resp.json()) as ScanResponse;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this._setOffline(true);
      vscode.window.showWarningMessage(`CIDAS: daemon unreachable during scan — ${msg}`);
      return _safeAllow(request.package_name, msg);
    }
  }

  /** Returns true when the daemon responds to the health endpoint. */
  async health(): Promise<boolean> {
    let alive = false;
    try {
      const resp = await fetch(`${_daemonUrl(this.port)}/health`);
      alive = resp.ok;
    } catch {
      alive = false;
    }
    this._setOffline(!alive);
    return alive;
  }

  /** Returns true when the most recent probe found the daemon unreachable. */
  isOffline(): boolean {
    return this._offline;
  }

  /**
   * Subscribe to daemon reachability changes. The listener fires when the
   * online/offline state flips — not on every probe — so the listener can
   * map directly to a UI state transition.
   */
  onStatusChange(listener: (online: boolean) => void): vscode.Disposable {
    this._stateListeners.push(listener);
    return {
      dispose: () => {
        const idx = this._stateListeners.indexOf(listener);
        if (idx >= 0) this._stateListeners.splice(idx, 1);
      },
    };
  }

  /**
   * Start polling /health at ``intervalMs`` cadence. Returns a Disposable
   * that stops the polling. An immediate probe runs on call so the first
   * status update happens promptly.
   */
  startHealthPolling(intervalMs: number = 30_000): vscode.Disposable {
    if (this._pollingTimer) {
      clearInterval(this._pollingTimer);
    }
    // Fire-and-forget the first probe so the indicator updates immediately.
    void this.health();
    this._pollingTimer = setInterval(() => { void this.health(); }, intervalMs);
    return {
      dispose: () => {
        if (this._pollingTimer) {
          clearInterval(this._pollingTimer);
          this._pollingTimer = undefined;
        }
      },
    };
  }

  private _setOffline(offline: boolean): void {
    if (offline === this._offline) return;
    this._offline = offline;
    for (const listener of this._stateListeners) {
      try { listener(!offline); } catch { /* listener errors must not propagate */ }
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
