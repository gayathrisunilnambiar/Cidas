import * as vscode from "vscode";
import type { Verdict } from "./types";

type DaemonState = "connecting" | "ready" | "offline";

export class CidasStatusBar {
  private readonly item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    this.item.command = "cidas.showStatus";
    this.setConnecting();
    this.item.show();
  }

  setConnecting(): void {
    this.item.text = "$(sync~spin) CIDAS";
    this.item.tooltip = "CIDAS: connecting to daemon…";
    this.item.backgroundColor = undefined;
  }

  setReady(): void {
    this.item.text = "$(shield) CIDAS";
    this.item.tooltip = "CIDAS: daemon ready";
    this.item.backgroundColor = undefined;
  }

  setOffline(): void {
    this.item.text = "$(shield) CIDAS $(warning)";
    this.item.tooltip = "CIDAS: daemon offline — run 'CIDAS: Start Local Daemon'";
    this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
  }

  setScreening(packageName: string): void {
    this.item.text = `$(sync~spin) CIDAS: screening ${packageName}…`;
    this.item.tooltip = `CIDAS: screening ${packageName}`;
    this.item.backgroundColor = undefined;
  }

  setVerdict(packageName: string, verdict: Verdict, score: number): void {
    const icons: Record<Verdict, string> = {
      ALLOW: "$(check)",
      WARN: "$(warning)",
      BLOCK: "$(error)",
    };
    const colors: Record<Verdict, string | undefined> = {
      ALLOW: undefined,
      WARN: "statusBarItem.warningBackground",
      BLOCK: "statusBarItem.errorBackground",
    };
    this.item.text = `${icons[verdict]} CIDAS: ${packageName} (${score.toFixed(0)})`;
    this.item.tooltip = `CIDAS: ${verdict} — risk score ${score.toFixed(1)}/100`;
    const color = colors[verdict];
    this.item.backgroundColor = color ? new vscode.ThemeColor(color) : undefined;
  }

  dispose(): void {
    this.item.dispose();
  }
}
