import { describe, expect, it, vi } from "vitest";
import type { ResolvedConfig } from "../config";
import { setupPoliciesHook } from "./policies";

describe("policy runtime switch", () => {
  it("bypasses policy blocks when Leash is off", async () => {
    const runtime = { enabled: false };
    const notify = vi.fn();
    let toolCall:
      | ((event: unknown, ctx: unknown) => Promise<unknown>)
      | undefined;
    const pi = {
      on(_event: string, handler: typeof toolCall) {
        toolCall = handler;
      },
      events: { emit() {} },
    };
    const config = {
      features: { policies: true },
      policies: {
        rules: [
          {
            id: "private-files",
            protection: "noAccess",
            patterns: [{ pattern: "secret.txt" }],
            onlyIfExists: false,
          },
        ],
      },
    } as unknown as ResolvedConfig;

    setupPoliciesHook(pi as never, config, runtime);
    await expect(
      toolCall?.(
        {
          toolName: "read",
          input: { file_path: "secret.txt" },
        },
        { cwd: "/work", ui: { notify } },
      ),
    ).resolves.toBeUndefined();
    expect(notify).not.toHaveBeenCalled();
  });
});
