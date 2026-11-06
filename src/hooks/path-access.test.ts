import { describe, expect, it } from "vitest";
import type { ResolvedConfig } from "../config";
import { setupPathAccessHook } from "./path-access";

const config: ResolvedConfig = {
  enabled: true,
  features: { policies: false, pathAccess: true, permissionGate: false },
  policies: { rules: [] },
  pathAccess: { mode: "ask", allowedPaths: [] },
  permissionGate: {
    patterns: [],
    useBuiltinMatchers: true,
    requireConfirmation: true,
    allowedPatterns: [],
    autoDenyPatterns: [],
    explainCommands: false,
    explainModel: null,
    explainTimeout: 5_000,
    autoMode: {
      enabled: false,
      model: null,
      timeout: 10_000,
      environment: [],
      allow: [],
      softDeny: [],
      hardDeny: [],
    },
    sudoMode: {
      enabled: false,
      timeout: 30_000,
      preserveEnv: false,
      cacheEnabled: false,
      cacheTtlOptions: [],
      maxRetries: 3,
    },
  },
  promptTimeout: {
    enabled: true,
    timeoutMs: 40,
    action: "deny",
  },
};

function createHarness(action: "allow" | "deny") {
  const hookConfig = structuredClone(config);
  hookConfig.promptTimeout.action = action;
  const handlers = new Map<
    string,
    (event: unknown, ctx: unknown) => Promise<unknown>
  >();
  const messages: string[] = [];
  const rendered: string[] = [];
  const fakePi = {
    on(
      event: string,
      handler: (event: unknown, ctx: unknown) => Promise<unknown>,
    ) {
      handlers.set(event, handler);
    },
    events: { emit() {} },
    sendMessage(message: { content?: unknown }) {
      if (typeof message.content === "string") messages.push(message.content);
    },
  };
  const fakeContext = {
    hasUI: true,
    cwd: "/work/project",
    ui: {
      custom: (
        factory: (
          tui: {
            terminal: { columns: number };
            requestRender(): void;
          },
          theme: {
            fg(_color: string, text: string): string;
            bg(_color: string, text: string): string;
            bold(text: string): string;
          },
          kb: unknown,
          done: (result: unknown) => void,
        ) => {
          render(width: number): string[];
        },
      ) => {
        let resolveDone: (value: unknown) => void = () => {};
        const donePromise = new Promise((resolve) => {
          resolveDone = resolve;
        });
        const component = factory(
          { terminal: { columns: 80 }, requestRender() {} },
          {
            fg: (_color, text) => text,
            bg: (_color, text) => text,
            bold: (text) => text,
          },
          {},
          (result) => resolveDone(result),
        );
        rendered.push(component.render(80).join("\n"));
        return donePromise;
      },
      notify() {},
    },
  };

  setupPathAccessHook(fakePi as never, hookConfig);
  const toolCall = handlers.get("tool_call");
  if (!toolCall) throw new Error("Path access did not register tool_call");

  return {
    messages,
    rendered,
    dispatch(filePath: string) {
      return toolCall(
        {
          toolName: "read",
          toolCallId: filePath,
          input: { file_path: filePath },
        },
        fakeContext,
      );
    },
  };
}

describe("path access prompt timeout", () => {
  it("auto-denies outside-workspace access and tells the agent", async () => {
    const harness = createHarness("deny");

    await expect(harness.dispatch("/etc/hosts")).resolves.toMatchObject({
      block: true,
      reason: expect.stringContaining(
        "auto-denied this outside-workspace access",
      ),
    });
    expect(harness.messages[0]).toContain("/etc/hosts");
    expect(harness.messages[0]).toContain("not a manual denial");
    expect(harness.rendered[0]).toContain("timeout in 1s → auto-deny");
  });

  it("auto-allows once and asks again for the same path", async () => {
    const harness = createHarness("allow");

    await expect(harness.dispatch("/etc/hosts")).resolves.toBeUndefined();
    await expect(harness.dispatch("/etc/hosts")).resolves.toBeUndefined();
    expect(harness.rendered).toHaveLength(2);
    expect(harness.messages[0]).toContain("auto-allowed");
    expect(harness.messages[0]).toContain("not a manual approval");
    expect(harness.messages[1]).toContain("auto-allowed");
  });
});
