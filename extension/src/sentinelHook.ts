/**
 * SentinelHook — watches VS Code terminal output for npm install commands
 * and triggers daemon screening before the install proceeds.
 *
 * Because VS Code cannot intercept terminal stdin, we rely on the npm-shim
 * (intercept/npm-shim.js) which calls the daemon directly. This module
 * provides a complementary in-extension hook for workspace-level installs
 * triggered via the extension API or task providers.
 */
import * as vscode from "vscode";
import { screenPackage } from "./daemonClient";
import { showAllowNotification, showBlockNotification, showWarnNotification } from "./notificationUI";
import { CidasStatusBar } from "./statusBar";
import type { ScreenRequest, ScreenResponse } from "./types";

export class SentinelHook {
  private readonly statusBar: CidasStatusBar;

  constructor(statusBar: CidasStatusBar) {
    this.statusBar = statusBar;
  }

  /** Screen a package programmatically (called from interceptor or commands). */
  async screen(packageName: string, version?: string): Promise<ScreenResponse | null> {
    const projectRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;

    const req: ScreenRequest = {
      package_name: packageName,
      version,
      project_root: projectRoot,
    };

    this.statusBar.setScreening(packageName);

    let response: ScreenResponse;
    try {
      response = await screenPackage(req);
    } catch (err) {
      vscode.window.showErrorMessage(`CIDAS: Failed to screen '${packageName}': ${String(err)}`);
      this.statusBar.setOffline();
      return null;
    }

    this.statusBar.setVerdict(packageName, response.verdict, response.risk_score);

    switch (response.verdict) {
      case "ALLOW":
        await showAllowNotification(response);
        break;
      case "WARN": {
        const proceed = await showWarnNotification(response);
        if (!proceed) {
          return { ...response, message: "Installation cancelled by user." };
        }
        break;
      }
      case "BLOCK": {
        const override = await showBlockNotification(response);
        if (!override) {
          return { ...response, message: "Installation blocked by CIDAS." };
        }
        vscode.window.showWarningMessage(`CIDAS: User overrode block for '${packageName}'.`);
        break;
      }
    }

    return response;
  }
}
