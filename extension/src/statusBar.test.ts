import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { StatusBarManager } from "./statusBar";
import * as vscode from "vscode";

describe("StatusBarManager", () => {
  let manager: StatusBarManager;
  let mockItem: ReturnType<typeof vscode.window.createStatusBarItem>;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    // Capture the StatusBarItem instance created inside the constructor
    mockItem = {
      text: "",
      tooltip: "",
      backgroundColor: undefined,
      command: "",
      show: vi.fn(),
      hide: vi.fn(),
      dispose: vi.fn(),
    };
    vi.mocked(vscode.window.createStatusBarItem).mockReturnValue(mockItem);
    manager = new StatusBarManager();
  });

  afterEach(() => {
    vi.useRealTimers();
    manager.dispose();
  });

  // ── constructor ──────────────────────────────────────────────────────────────

  it("creates and shows the status bar item on construction", () => {
    expect(vscode.window.createStatusBarItem).toHaveBeenCalledOnce();
    expect(mockItem.show).toHaveBeenCalledOnce();
  });

  it("starts in idle state", () => {
    expect(mockItem.text).toContain("CIDAS ready");
  });

  // ── setState ─────────────────────────────────────────────────────────────────

  it("idle state sets correct text and clears background", () => {
    manager.setState("idle");
    expect(mockItem.text).toContain("CIDAS ready");
    expect(mockItem.backgroundColor).toBeUndefined();
  });

  it("scanning state sets spinner text", () => {
    manager.setState("scanning");
    expect(mockItem.text).toContain("scanning");
    expect(mockItem.backgroundColor).toBeUndefined();
  });

  it("blocked state sets error background color", () => {
    manager.setState("blocked");
    expect(mockItem.text).toContain("BLOCKED");
    expect(mockItem.backgroundColor).toBeInstanceOf(vscode.ThemeColor);
    expect((mockItem.backgroundColor as vscode.ThemeColor).id).toContain("error");
  });

  it("warned state sets warning background color", () => {
    manager.setState("warned");
    expect(mockItem.text).toContain("warned");
    expect(mockItem.backgroundColor).toBeInstanceOf(vscode.ThemeColor);
    expect((mockItem.backgroundColor as vscode.ThemeColor).id).toContain("warning");
  });

  it("error state shows daemon offline message", () => {
    manager.setState("error");
    expect(mockItem.text).toContain("offline");
    expect(mockItem.backgroundColor).toBeUndefined();
  });

  it("custom tooltip is applied", () => {
    manager.setState("scanning", "Scanning lodash…");
    expect(mockItem.tooltip).toBe("Scanning lodash…");
  });

  it("default tooltip is used when none is supplied", () => {
    manager.setState("idle");
    expect(typeof mockItem.tooltip).toBe("string");
    expect((mockItem.tooltip as string).length).toBeGreaterThan(0);
  });

  // ── auto-reset timer ─────────────────────────────────────────────────────────

  it("blocked state auto-resets to idle after 5 seconds", () => {
    manager.setState("blocked");
    expect(mockItem.text).toContain("BLOCKED");
    vi.advanceTimersByTime(5_000);
    expect(mockItem.text).toContain("CIDAS ready");
  });

  it("warned state auto-resets to idle after 5 seconds", () => {
    manager.setState("warned");
    vi.advanceTimersByTime(5_000);
    expect(mockItem.text).toContain("CIDAS ready");
  });

  it("setting a new state before timer fires cancels the reset", () => {
    manager.setState("blocked");
    vi.advanceTimersByTime(3_000);
    manager.setState("scanning");
    vi.advanceTimersByTime(3_000); // would have fired original timer here
    expect(mockItem.text).toContain("scanning");
  });

  it("idle and error states do not schedule an auto-reset", () => {
    manager.setState("idle");
    vi.advanceTimersByTime(10_000);
    expect(mockItem.text).toContain("CIDAS ready");

    manager.setState("error");
    vi.advanceTimersByTime(10_000);
    expect(mockItem.text).toContain("offline");
  });

  // ── dispose ──────────────────────────────────────────────────────────────────

  it("dispose calls item.dispose()", () => {
    manager.dispose();
    expect(mockItem.dispose).toHaveBeenCalledOnce();
  });

  it("dispose clears pending reset timer", () => {
    manager.setState("blocked");
    manager.dispose();
    // Timer fires after dispose — should not throw or mutate disposed item
    expect(() => vi.advanceTimersByTime(5_000)).not.toThrow();
  });
});
