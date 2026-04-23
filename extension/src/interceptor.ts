/**
 * Interceptor — monitors file-system events for package.json changes that
 * indicate an npm install is about to happen, and screens new dependencies.
 */
import * as vscode from "vscode";
import { SentinelHook } from "./sentinelHook";

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

function parseDeps(raw: string): Set<string> {
  try {
    const pkg = JSON.parse(raw) as PackageJson;
    return new Set([
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.devDependencies ?? {}),
    ]);
  } catch {
    return new Set();
  }
}

export class PackageJsonInterceptor {
  private readonly hook: SentinelHook;
  private readonly watchers: vscode.Disposable[] = [];
  private previousDeps: Map<string, Set<string>> = new Map();

  constructor(hook: SentinelHook) {
    this.hook = hook;
  }

  activate(context: vscode.ExtensionContext): void {
    const watcher = vscode.workspace.createFileSystemWatcher("**/package.json", false, false, true);

    watcher.onDidCreate(this._onChanged, this, this.watchers);
    watcher.onDidChange(this._onChanged, this, this.watchers);

    context.subscriptions.push(watcher, ...this.watchers);
  }

  private _onChanged = async (uri: vscode.Uri): Promise<void> => {
    if (uri.fsPath.includes("node_modules")) {
      return;
    }

    const raw = await vscode.workspace.fs
      .readFile(uri)
      .then((b) => Buffer.from(b).toString("utf-8"))
      .catch(() => null);

    if (!raw) return;

    const newDeps = parseDeps(raw);
    const prev = this.previousDeps.get(uri.fsPath) ?? new Set<string>();
    const added = [...newDeps].filter((d) => !prev.has(d));

    this.previousDeps.set(uri.fsPath, newDeps);

    for (const dep of added) {
      await this.hook.screen(dep);
    }
  };
}
