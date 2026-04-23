import * as vscode from "vscode";
import { checkHealth, clearCache } from "./daemonClient";
import { PackageJsonInterceptor } from "./interceptor";
import { SentinelHook } from "./sentinelHook";
import { CidasStatusBar } from "./statusBar";

let statusBar: CidasStatusBar;
let sentinelHook: SentinelHook;
let interceptor: PackageJsonInterceptor;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  statusBar = new CidasStatusBar();
  sentinelHook = new SentinelHook(statusBar);
  interceptor = new PackageJsonInterceptor(sentinelHook);

  interceptor.activate(context);
  context.subscriptions.push(statusBar);

  // Probe daemon health
  _probeDaemon();

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand("cidas.screenPackage", _cmdScreenPackage),
    vscode.commands.registerCommand("cidas.startDaemon", _cmdStartDaemon),
    vscode.commands.registerCommand("cidas.stopDaemon", _cmdStopDaemon),
    vscode.commands.registerCommand("cidas.showStatus", _cmdShowStatus),
  );
}

export function deactivate(): void {
  statusBar?.dispose();
}

async function _probeDaemon(): Promise<void> {
  statusBar.setConnecting();
  try {
    await checkHealth();
    statusBar.setReady();
  } catch {
    statusBar.setOffline();
    vscode.window.showWarningMessage(
      "CIDAS daemon is not running. Start it with 'CIDAS: Start Local Daemon'.",
      "Start Daemon",
    ).then((choice) => {
      if (choice === "Start Daemon") {
        vscode.commands.executeCommand("cidas.startDaemon");
      }
    });
  }
}

async function _cmdScreenPackage(): Promise<void> {
  const input = await vscode.window.showInputBox({
    prompt: "Package name to screen (e.g. lodash or lodash@4.17.21)",
    placeHolder: "package-name[@version]",
  });
  if (!input) return;

  const [name, version] = input.split("@");
  await sentinelHook.screen(name.trim(), version?.trim());
}

async function _cmdStartDaemon(): Promise<void> {
  const terminal = vscode.window.createTerminal({ name: "CIDAS Daemon" });
  terminal.sendText("bash scripts/start-daemon.sh");
  terminal.show();
  // Give it a moment then re-probe
  setTimeout(_probeDaemon, 3000);
}

async function _cmdStopDaemon(): Promise<void> {
  const terminal = vscode.window.createTerminal({ name: "CIDAS Stop" });
  terminal.sendText("pkill -f 'cidas-daemon' || pkill -f 'uvicorn daemon.main'");
  terminal.show();
  statusBar.setOffline();
}

async function _cmdShowStatus(): Promise<void> {
  try {
    const health = await checkHealth();
    vscode.window.showInformationMessage(`CIDAS daemon v${health.version} — ${health.status}`);
  } catch {
    vscode.window.showErrorMessage("CIDAS daemon is offline.");
  }
}
