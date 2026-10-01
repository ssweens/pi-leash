import type * as CodingAgentModule from "@earendil-works/pi-coding-agent";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import { executeSubagent } from "./executor";

const { createAgentSessionMock } = vi.hoisted(() => ({
  createAgentSessionMock: vi.fn(),
}));

vi.mock("@earendil-works/pi-coding-agent", async (importOriginal) => ({
  ...(await importOriginal<typeof CodingAgentModule>()),
  createAgentSession: createAgentSessionMock,
  DefaultResourceLoader: class {
    async reload() {}
  },
  SettingsManager: { create: () => ({}) },
  SessionManager: { inMemory: () => ({}) },
}));

describe("subagent terminal failures", () => {
  it.each([
    {
      stopReason: "error",
      errorMessage: "Smoke provider unavailable",
      error: "Smoke provider unavailable",
      aborted: false,
    },
    {
      stopReason: "error",
      errorMessage: undefined,
      error: "Provider returned an error without details",
      aborted: false,
    },
    {
      stopReason: "aborted",
      errorMessage: "Request aborted",
      error: undefined,
      aborted: true,
    },
    {
      stopReason: "stop",
      errorMessage: undefined,
      error: undefined,
      aborted: false,
    },
  ])("preserves a $stopReason message when prompt resolves without throwing", async ({
    stopReason,
    errorMessage,
    error,
    aborted,
  }) => {
    let listener!: (event: unknown) => void;
    const unsubscribe = vi.fn();
    const dispose = vi.fn();
    createAgentSessionMock.mockResolvedValueOnce({
      session: {
        subscribe(handler: (event: unknown) => void) {
          listener = handler;
          return unsubscribe;
        },
        prompt: async () => {
          listener({
            type: "turn_end",
            message: { role: "assistant", stopReason, errorMessage },
          });
        },
        dispose,
      },
    });
    const result = await executeSubagent(
      {
        name: "classifier",
        model: { provider: "test", id: "classifier" } as never,
        systemPrompt: "Classify.",
        tools: [],
      },
      "Proposed action.",
      { cwd: "/tmp", modelRegistry: {} } as unknown as ExtensionContext,
    );
    expect(result).toMatchObject({ content: "", error, aborted });
    expect(unsubscribe).toHaveBeenCalledOnce();
    expect(dispose).toHaveBeenCalledOnce();
  });
});
