import * as vscode from "vscode";
import type { CidasConfig, DaemonHealth, ScreenRequest, ScreenResponse } from "./types";

function getConfig(): CidasConfig {
  const cfg = vscode.workspace.getConfiguration("cidas");
  return {
    daemonUrl: cfg.get<string>("daemonUrl", "http://127.0.0.1:7979"),
    daemonSecret: cfg.get<string>("daemonSecret", ""),
    autoScreen: cfg.get<boolean>("autoScreen", true),
    blockOnHighRisk: cfg.get<boolean>("blockOnHighRisk", true),
  };
}

async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const { daemonUrl, daemonSecret } = getConfig();
  const url = `${daemonUrl}/api/v1${path}`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(daemonSecret ? { "X-CIDAS-Secret": daemonSecret } : {}),
  };

  const response = await fetch(url, { ...options, headers: { ...headers, ...(options.headers as Record<string, string> | undefined) } });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`CIDAS daemon error ${response.status}: ${body}`);
  }
  return response.json() as Promise<T>;
}

export async function checkHealth(): Promise<DaemonHealth> {
  return apiFetch<DaemonHealth>("/health");
}

export async function screenPackage(req: ScreenRequest): Promise<ScreenResponse> {
  return apiFetch<ScreenResponse>("/screen", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export async function clearCache(): Promise<{ purged: number }> {
  return apiFetch<{ purged: number }>("/cache", { method: "DELETE" });
}
