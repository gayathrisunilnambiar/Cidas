import * as vscode from "vscode";
import type { ScreenResponse } from "./types";

const DETAILS_ACTION = "View Details";
const PROCEED_ACTION = "Proceed Anyway";
const CANCEL_ACTION = "Cancel Install";

export async function showAllowNotification(response: ScreenResponse): Promise<void> {
  const msg = `CIDAS: '${response.package_name}' passed security checks (score ${response.risk_score.toFixed(0)}/100).`;
  vscode.window.setStatusBarMessage(msg, 5000);
}

export async function showWarnNotification(response: ScreenResponse): Promise<boolean> {
  const choice = await vscode.window.showWarningMessage(
    `CIDAS Warning: '${response.package_name}' has a moderate risk score (${response.risk_score.toFixed(0)}/100).\n${response.message}`,
    { modal: false },
    PROCEED_ACTION,
    DETAILS_ACTION,
  );

  if (choice === DETAILS_ACTION) {
    _showDetailsPanel(response);
    // Ask again after showing details
    const second = await vscode.window.showWarningMessage(
      `Still proceed with installing '${response.package_name}'?`,
      { modal: true },
      PROCEED_ACTION,
      CANCEL_ACTION,
    );
    return second === PROCEED_ACTION;
  }
  return choice === PROCEED_ACTION;
}

export async function showBlockNotification(response: ScreenResponse): Promise<boolean> {
  const choice = await vscode.window.showErrorMessage(
    `CIDAS BLOCKED: '${response.package_name}' failed security screening (score ${response.risk_score.toFixed(0)}/100).\n${response.message}`,
    { modal: true },
    DETAILS_ACTION,
    PROCEED_ACTION,   // escape hatch — user can override
    CANCEL_ACTION,
  );

  if (choice === DETAILS_ACTION) {
    _showDetailsPanel(response);
    const second = await vscode.window.showErrorMessage(
      `Override CIDAS block and install '${response.package_name}'?`,
      { modal: true },
      PROCEED_ACTION,
      CANCEL_ACTION,
    );
    return second === PROCEED_ACTION;
  }
  return choice === PROCEED_ACTION;
}

function _showDetailsPanel(response: ScreenResponse): void {
  const panel = vscode.window.createWebviewPanel(
    "cidasDetails",
    `CIDAS: ${response.package_name}`,
    vscode.ViewColumn.Beside,
    { enableScripts: false },
  );

  const pillarRows = response.pillars
    .map(
      (p) =>
        `<tr>
          <td>${p.pillar}</td>
          <td>${p.score.toFixed(1)}</td>
          <td>${p.notes}</td>
        </tr>`,
    )
    .join("\n");

  panel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';">
<style>
  body { font-family: var(--vscode-font-family); padding: 16px; }
  h1   { font-size: 1.2em; }
  table{ border-collapse: collapse; width: 100%; margin-top: 12px; }
  th,td{ border: 1px solid var(--vscode-panel-border); padding: 6px 10px; text-align: left; }
  th   { background: var(--vscode-editor-background); }
  .verdict-ALLOW { color: var(--vscode-terminal-ansiGreen); }
  .verdict-WARN  { color: var(--vscode-terminal-ansiYellow); }
  .verdict-BLOCK { color: var(--vscode-terminal-ansiRed); }
</style>
</head>
<body>
<h1>CIDAS Screening Report: <code>${response.package_name}</code></h1>
<p>Verdict: <strong class="verdict-${response.verdict}">${response.verdict}</strong>
   &nbsp;|&nbsp; Risk score: <strong>${response.risk_score.toFixed(1)} / 100</strong>
   ${response.cached ? "&nbsp;|&nbsp; <em>(cached)</em>" : ""}
</p>
<p>${response.message}</p>
<table>
  <thead><tr><th>Pillar</th><th>Score</th><th>Notes</th></tr></thead>
  <tbody>${pillarRows}</tbody>
</table>
</body>
</html>`;
}
