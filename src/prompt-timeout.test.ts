import { afterEach, describe, expect, it, vi } from "vitest";
import {
  armPromptTimeout,
  autoPromptMessage,
  fallbackDismissMessage,
  resolvePromptTimeout,
  sudoTimeoutMessage,
} from "./prompt-timeout";

describe("resolvePromptTimeout", () => {
  it("stays off unless explicitly enabled", () => {
    expect(resolvePromptTimeout(undefined)).toEqual({
      enabled: false,
      timeoutMs: 30_000,
      action: "deny",
    });
    expect(resolvePromptTimeout({ enabled: false, action: "allow" })).toEqual({
      enabled: false,
      timeoutMs: 30_000,
      action: "allow",
    });
  });

  it("rejects non-boolean enabled and unknown actions", () => {
    expect(
      resolvePromptTimeout({
        enabled: "yes" as unknown as boolean,
        action: "approve" as unknown as "allow",
        timeoutMs: 50,
      }),
    ).toEqual({
      enabled: false,
      timeoutMs: 1000,
      action: "deny",
    });
  });

  it("floors the deadline and keeps a 1s minimum", () => {
    expect(
      resolvePromptTimeout({
        enabled: true,
        timeoutMs: 2500.9,
        action: "allow",
      }),
    ).toEqual({
      enabled: true,
      timeoutMs: 2500,
      action: "allow",
    });
  });
});

describe("timeout messages", () => {
  it("tells the agent a timeout allow is not a manual approval", () => {
    expect(
      autoPromptMessage({
        action: "allow",
        timeoutMs: 30_000,
        what: "dangerous command",
        detail: "recursive force delete",
      }),
    ).toBe(
      "Leash auto-allowed this dangerous command after 30s with no response (recursive force delete). This was a one-time timeout decision, not a manual approval.",
    );
  });

  it("refuses to auto-allow when cancel and timeout look the same", () => {
    expect(
      fallbackDismissMessage({
        action: "allow",
        timeoutMs: 5000,
        what: "dangerous command",
      }),
    ).toContain("not auto-allowed");
    expect(
      fallbackDismissMessage({
        action: "deny",
        timeoutMs: 5000,
        what: "dangerous command",
      }),
    ).toBe(
      "Leash auto-denied this dangerous command because the prompt closed with no choice within 5s.",
    );
  });

  it("never describes a password timeout as an allow", () => {
    expect(sudoTimeoutMessage(30_000, true)).toContain(
      "A password cannot be auto-accepted.",
    );
    expect(sudoTimeoutMessage(30_000, false)).not.toContain("auto-denied");
  });
});

describe("armPromptTimeout", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("fires once at the deadline and stops after dispose", () => {
    vi.useFakeTimers();
    const ticks: number[] = [];
    let fired = 0;
    const handle = armPromptTimeout(
      2500,
      { requestRender() {} },
      (seconds) => ticks.push(seconds),
      () => fired++,
    );

    expect(ticks[0]).toBe(3);
    vi.advanceTimersByTime(1000);
    expect(ticks.at(-1)).toBe(2);
    handle.dispose();
    vi.advanceTimersByTime(5000);
    expect(fired).toBe(0);
  });

  it("reports zero and does not fire twice", () => {
    vi.useFakeTimers();
    const ticks: number[] = [];
    let fired = 0;
    armPromptTimeout(
      1500,
      { requestRender() {} },
      (seconds) => ticks.push(seconds),
      () => fired++,
    );

    vi.advanceTimersByTime(1500);
    expect(fired).toBe(1);
    expect(ticks.at(-1)).toBe(0);
    vi.advanceTimersByTime(5000);
    expect(fired).toBe(1);
  });
});
