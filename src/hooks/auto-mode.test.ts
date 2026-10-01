import { initTheme } from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import type * as ConfigModule from "../config";
import type { ResolvedConfig } from "../config";
import type * as AutoModeClassifierModule from "../lib/auto-mode-classifier";
import type { AutoModeVerdict } from "../lib/auto-mode-classifier";
import { setupAutoMode } from "./auto-mode";

const { updateAutoModeConfigMock, classifyAutoModeActionMock } = vi.hoisted(
  () => ({
    updateAutoModeConfigMock: vi.fn(),
    classifyAutoModeActionMock: vi.fn(),
  }),
);

vi.mock("../config", async (importOriginal) => ({
  ...(await importOriginal<typeof ConfigModule>()),
  updateAutoModeConfig: updateAutoModeConfigMock,
}));

vi.mock("../lib/auto-mode-classifier", async (importOriginal) => ({
  ...(await importOriginal<typeof AutoModeClassifierModule>()),
  classifyAutoModeAction: classifyAutoModeActionMock,
}));

initTheme();

const config: ResolvedConfig = {
  enabled: true,
  features: { policies: false, pathAccess: false, permissionGate: true },
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
    explainTimeout: 5000,
    autoMode: {
      enabled: false,
      model: null,
      timeout: 10000,
      environment: [],
      allow: [],
      softDeny: [],
      hardDeny: [],
    },
    sudoMode: {
      enabled: false,
      timeout: 30000,
      preserveEnv: false,
      cacheEnabled: false,
      cacheTtlOptions: [],
      maxRetries: 3,
    },
  },
};

const action = {
  toolName: "bash",
  input: { command: "rm -rf /tmp/leash-test" },
  command: "rm -rf /tmp/leash-test",
  description: "recursive force delete",
  pattern: "rm -rf",
};

function autoModeHarness() {
  const localConfig = structuredClone(config);
  localConfig.permissionGate.autoMode.enabled = true;
  const handlers = new Map<
    string,
    (event: unknown, ctx: unknown) => Promise<void>
  >();
  const commands = new Map<
    string,
    { handler(args: string, ctx: unknown): Promise<void> }
  >();
  const entries: { type: "custom"; customType: string; data: unknown }[] = [];
  const statuses = new Map<string, string | undefined>();
  const ctx = {
    hasUI: true,
    model: { provider: "test", id: "classifier" },
    ui: {
      theme: { fg: (_color: string, text: string) => text },
      notify: vi.fn(),
      setStatus(key: string, value: string | undefined) {
        statuses.set(key, value);
      },
    },
    sessionManager: { getBranch: () => entries },
  };
  const pi = {
    on(
      event: string,
      handler: (event: unknown, ctx: unknown) => Promise<void>,
    ) {
      handlers.set(event, handler);
    },
    registerCommand(
      name: string,
      command: { handler(args: string, ctx: unknown): Promise<void> },
    ) {
      commands.set(name, command);
    },
    registerShortcut() {},
    appendEntry(customType: string, data: unknown) {
      entries.push({ type: "custom", customType, data });
    },
  };
  return {
    controller: setupAutoMode(pi as never, localConfig),
    ctx,
    handlers,
    commands,
    entries,
    statuses,
    localConfig,
  };
}

describe("Leash classifier failure fallback", () => {
  it.each([
    "Auto-mode classifier timed out after 10000ms.",
    "Auto-mode classifier failed: provider unavailable.",
    "Auto-mode classifier model setup failed: model not found.",
    "Auto-mode classifier returned an invalid verdict.",
  ])("stays manual after %s until the user re-enables auto", async (reason) => {
    classifyAutoModeActionMock.mockReset();
    updateAutoModeConfigMock.mockReset();
    const {
      controller,
      ctx,
      commands,
      entries,
      handlers,
      localConfig,
      statuses,
    } = autoModeHarness();
    const fallback: AutoModeVerdict = {
      decision: "ask",
      source: "fallback",
      reason,
    };
    classifyAutoModeActionMock.mockResolvedValueOnce(fallback);
    expect(await controller.classify(action, ctx as never)).toEqual(fallback);
    controller.recordVerdict(fallback, ctx as never);
    expect(controller.isEnabled()).toBe(false);
    expect(entries).toContainEqual({
      type: "custom",
      customType: "leash-auto-mode",
      data: { enabled: false },
    });
    expect(updateAutoModeConfigMock).toHaveBeenCalledExactlyOnceWith({
      enabled: false,
    });
    expect(localConfig.permissionGate.autoMode.enabled).toBe(false);
    expect(statuses.get("leash-auto")).toBeUndefined();
    expect(statuses.get("leash-auto-pending")).toBeUndefined();
    expect(ctx.ui.notify).toHaveBeenCalledExactlyOnceWith(
      expect.stringContaining(`${reason} Switched to manual approval.`),
      "warning",
    );
    await controller.classify(action, ctx as never);
    expect(classifyAutoModeActionMock).toHaveBeenCalledTimes(1);
    await handlers.get("session_start")?.({}, ctx as never);
    expect(controller.isEnabled()).toBe(false);
    await commands.get("leash")?.handler("auto", ctx as never);
    classifyAutoModeActionMock.mockResolvedValueOnce({
      decision: "allow",
      source: "classifier",
      reason: "Recovered.",
    });
    expect(await controller.classify(action, ctx as never)).toMatchObject({
      decision: "allow",
    });
    expect(controller.isEnabled()).toBe(true);
    await handlers.get("session_shutdown")?.({}, ctx as never);
  });

  it.each([
    "allow",
    "ask",
    "deny",
  ] as const)("does not disable auto after a classifier %s", async (decision) => {
    classifyAutoModeActionMock.mockReset();
    updateAutoModeConfigMock.mockReset();
    const { controller, ctx, handlers } = autoModeHarness();
    classifyAutoModeActionMock.mockResolvedValueOnce({
      decision,
      source: "classifier",
      reason: "Policy verdict.",
    });
    expect(await controller.classify(action, ctx as never)).toMatchObject({
      decision,
    });
    expect(controller.isEnabled()).toBe(true);
    expect(updateAutoModeConfigMock).not.toHaveBeenCalled();
    expect(ctx.ui.notify).not.toHaveBeenCalled();
    await handlers.get("session_shutdown")?.({}, ctx as never);
  });

  it("requires manual approval for a late allow after a sibling classifier fails", async () => {
    classifyAutoModeActionMock.mockReset();
    updateAutoModeConfigMock.mockReset();
    const { controller, ctx, handlers } = autoModeHarness();
    let resolveLate!: (verdict: AutoModeVerdict) => void;
    classifyAutoModeActionMock.mockResolvedValueOnce({
      decision: "ask",
      source: "fallback",
      reason: "Provider failed.",
    });
    classifyAutoModeActionMock.mockReturnValueOnce(
      new Promise<AutoModeVerdict>((resolve) => {
        resolveLate = resolve;
      }),
    );
    const failed = controller.classify(action, ctx as never);
    const late = controller.classify(action, ctx as never);
    await failed;
    resolveLate({
      decision: "allow",
      source: "classifier",
      reason: "Late approval.",
    });
    expect(await late).toMatchObject({ decision: "ask", source: "fallback" });
    expect(updateAutoModeConfigMock).toHaveBeenCalledTimes(1);
    expect(ctx.ui.notify).toHaveBeenCalledTimes(1);
    await handlers.get("session_shutdown")?.({}, ctx as never);
  });

  it("warns before a short configured timeout", async () => {
    vi.useFakeTimers();
    classifyAutoModeActionMock.mockReset();
    updateAutoModeConfigMock.mockReset();
    try {
      const { controller, ctx, localConfig, statuses } = autoModeHarness();
      localConfig.permissionGate.autoMode.timeout = 1000;
      let resolveClassifier!: (verdict: AutoModeVerdict) => void;
      classifyAutoModeActionMock.mockReturnValueOnce(
        new Promise<AutoModeVerdict>((resolve) => {
          resolveClassifier = resolve;
        }),
      );
      const pending = controller.classify(action, ctx as never);
      await vi.advanceTimersByTimeAsync(360);
      expect(ctx.ui.notify).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(180);
      expect(ctx.ui.notify).toHaveBeenCalledWith(
        expect.stringContaining("times out after 1s"),
        "warning",
      );
      resolveClassifier({
        decision: "ask",
        source: "fallback",
        reason: "Auto-mode classifier timed out after 1000ms.",
      });
      await pending;
      expect(statuses.get("leash-auto-pending")).toBeUndefined();
      const noticeCount = ctx.ui.notify.mock.calls.length;
      await vi.advanceTimersByTimeAsync(10_000);
      expect(ctx.ui.notify).toHaveBeenCalledTimes(noticeCount);
    } finally {
      vi.useRealTimers();
    }
  });

  it("remains manual if saving the fallback setting fails", async () => {
    classifyAutoModeActionMock.mockReset();
    updateAutoModeConfigMock.mockReset();
    updateAutoModeConfigMock.mockImplementationOnce(() => {
      throw new Error("Read-only config");
    });
    const { controller, ctx, handlers } = autoModeHarness();
    classifyAutoModeActionMock.mockResolvedValueOnce({
      decision: "ask",
      source: "fallback",
      reason: "Provider failed.",
    });
    expect(await controller.classify(action, ctx as never)).toMatchObject({
      decision: "ask",
    });
    expect(controller.isEnabled()).toBe(false);
    expect(ctx.ui.notify).toHaveBeenCalledWith(
      expect.stringContaining("could not save manual mode"),
      "warning",
    );
    await handlers.get("session_shutdown")?.({}, ctx as never);
  });
});

describe("Leash auto-mode controls", () => {
  it("toggles through the slash command and keyboard shortcut, persists session state, and updates status", async () => {
    const eventHandlers = new Map<
      string,
      (event: unknown, ctx: unknown) => Promise<void>
    >();
    const commands = new Map<
      string,
      { handler(args: string, ctx: unknown): Promise<void> }
    >();
    const shortcuts = new Map<
      string,
      { handler(ctx: unknown): Promise<void> }
    >();
    const statuses = new Map<string, string | undefined>();
    const notices: string[] = [];
    const entries: unknown[] = [];

    const pi = {
      on(
        event: string,
        handler: (event: unknown, ctx: unknown) => Promise<void>,
      ) {
        eventHandlers.set(event, handler);
      },
      registerCommand(
        name: string,
        definition: { handler(args: string, ctx: unknown): Promise<void> },
      ) {
        commands.set(name, definition);
      },
      registerShortcut(
        key: string,
        definition: { handler(ctx: unknown): Promise<void> },
      ) {
        shortcuts.set(key, definition);
      },
      appendEntry(_type: string, data: unknown) {
        entries.push(data);
      },
    };
    const ctx = {
      hasUI: true,
      model: { provider: "test", id: "classifier" },
      ui: {
        theme: { fg: (_color: string, text: string) => text },
        setStatus(key: string, value: string | undefined) {
          statuses.set(key, value);
        },
        notify(message: string) {
          notices.push(message);
        },
      },
      sessionManager: { getBranch: () => [] },
    };

    const controller = setupAutoMode(pi as never, config);
    await eventHandlers.get("session_start")?.({}, ctx as never);

    await commands.get("leash")?.handler("auto", ctx as never);
    controller.recordVerdict(
      {
        decision: "allow",
        reason: "Fresh scratch cleanup.",
        source: "classifier",
      },
      ctx as never,
    );
    expect(controller.isEnabled()).toBe(true);
    expect(entries).toMatchObject([
      { enabled: true },
      {
        decision: "allow",
        reason: "Fresh scratch cleanup.",
        source: "classifier",
      },
    ]);
    expect(statuses.get("leash-auto")).toBe("⏵⏵ leash auto");
    expect(statuses.get("leash-auto-verdict")).toContain("leash allow");

    await commands.get("leash")?.handler("status", ctx as never);
    expect(notices.at(-1)).toContain("allow 1 · ask 0 · deny 0");
    expect(notices.at(-1)).toContain("Last: allow [classifier]");

    await shortcuts.get("ctrl+alt+l")?.handler(ctx as never);
    expect(controller.isEnabled()).toBe(false);
    expect(entries).toHaveLength(3);
    expect(entries.at(-1)).toEqual({ enabled: false });
    expect(statuses.get("leash-auto")).toBeUndefined();
    expect(notices).toContain(
      "Leash auto mode enabled. Dangerous Bash actions are classifier-gated.",
    );
  });

  it("rotates only the auto marker while the classifier is pending", async () => {
    vi.useFakeTimers();
    classifyAutoModeActionMock.mockReset();
    try {
      const eventHandlers = new Map<
        string,
        (event: unknown, ctx: unknown) => Promise<void>
      >();
      const commands = new Map<
        string,
        { handler(args: string, ctx: unknown): Promise<void> }
      >();
      const statuses = new Map<string, string | undefined>();
      const notify = vi.fn();
      let resolveClassifier!: (verdict: {
        decision: "allow";
        reason: string;
        source: "classifier";
      }) => void;
      classifyAutoModeActionMock.mockReturnValueOnce(
        new Promise((resolve) => {
          resolveClassifier = resolve;
        }),
      );

      const pi = {
        on(
          event: string,
          handler: (event: unknown, ctx: unknown) => Promise<void>,
        ) {
          eventHandlers.set(event, handler);
        },
        registerCommand(
          name: string,
          definition: { handler(args: string, ctx: unknown): Promise<void> },
        ) {
          commands.set(name, definition);
        },
        registerShortcut() {},
        appendEntry() {},
      };
      const ctx = {
        hasUI: true,
        model: { provider: "test", id: "classifier" },
        ui: {
          theme: {
            fg: (color: string, text: string) => `<${color}>${text}</${color}>`,
          },
          setStatus(key: string, value: string | undefined) {
            statuses.set(key, value);
          },
          notify,
        },
        sessionManager: { getBranch: () => [] },
      };

      const controller = setupAutoMode(pi as never, structuredClone(config));
      await eventHandlers.get("session_start")?.({}, ctx as never);
      await commands.get("leash")?.handler("auto", ctx as never);

      const pending = controller.classify(
        {
          toolName: "bash",
          input: { command: "rm -rf /tmp/leash-test" },
          command: "rm -rf /tmp/leash-test",
          description: "recursive force delete",
          pattern: "rm -rf",
        },
        ctx as never,
      );

      expect(statuses.get("leash-auto")).toBe(
        "<accent>⏵</accent><warning>⏵</warning> <accent>leash auto</accent>",
      );
      expect(statuses.get("leash-auto-pending")).toBe(
        "<dim>leash waiting for test/classifier · 0s/10s</dim>",
      );
      await vi.advanceTimersByTimeAsync(180);
      expect(statuses.get("leash-auto")).toBe(
        "<warning>⏵</warning><success>⏵</success> <accent>leash auto</accent>",
      );
      notify.mockClear();
      await vi.advanceTimersByTimeAsync(4_680);
      expect(notify).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(180);
      expect(statuses.get("leash-auto-pending")).toBe(
        "<warning>leash waiting for test/classifier · 5s/10s</warning>",
      );
      expect(notify).toHaveBeenCalledWith(
        expect.stringContaining("still waiting for test/classifier"),
        "warning",
      );
      await vi.advanceTimersByTimeAsync(1_080);
      expect(notify).toHaveBeenCalledTimes(1);

      resolveClassifier({
        decision: "allow",
        reason: "Bounded test cleanup.",
        source: "classifier",
      });
      await pending;
      expect(statuses.get("leash-auto")).toBe("<accent>⏵⏵ leash auto</accent>");
      expect(statuses.get("leash-auto-pending")).toBeUndefined();
      await vi.advanceTimersByTimeAsync(10_000);
      expect(notify).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("restores auto verdict counts and the last decision from the session", async () => {
    const eventHandlers = new Map<
      string,
      (event: unknown, ctx: unknown) => Promise<void>
    >();
    const commands = new Map<
      string,
      { handler(args: string, ctx: unknown): Promise<void> }
    >();
    const notices: string[] = [];
    const pi = {
      on(
        event: string,
        handler: (event: unknown, ctx: unknown) => Promise<void>,
      ) {
        eventHandlers.set(event, handler);
      },
      registerCommand(
        name: string,
        definition: { handler(args: string, ctx: unknown): Promise<void> },
      ) {
        commands.set(name, definition);
      },
      registerShortcut() {},
      appendEntry() {},
    };
    const ctx = {
      model: { provider: "test", id: "classifier" },
      ui: {
        theme: { fg: (_color: string, text: string) => text },
        notify(message: string) {
          notices.push(message);
        },
        setStatus() {},
      },
      sessionManager: {
        getBranch: () => [
          {
            type: "custom",
            customType: "leash-auto-mode",
            data: { enabled: true },
          },
          {
            type: "custom",
            customType: "leash-auto-verdict",
            data: {
              decision: "ask",
              reason: "Target provenance is incomplete.",
              source: "classifier",
              timestamp: 1,
            },
          },
          {
            type: "custom",
            customType: "leash-auto-verdict",
            data: {
              decision: "deny",
              reason: "Target is outside the approved boundary.",
              source: "safety",
              timestamp: 2,
            },
          },
        ],
      },
    };

    const controller = setupAutoMode(pi as never, structuredClone(config));
    await eventHandlers.get("session_start")?.({}, ctx as never);
    await commands.get("leash")?.handler("status", ctx as never);

    expect(controller.isEnabled()).toBe(true);
    expect(notices[0]).toContain("allow 0 · ask 1 · deny 1");
    expect(notices[0]).toContain("Last: deny [safety]");
  });

  it("applies the settings auto toggle to this session and uses Pi's model selector", async () => {
    updateAutoModeConfigMock.mockReset();
    const localConfig = structuredClone(config);
    const commands = new Map<
      string,
      { handler(args: string, ctx: unknown): Promise<void> }
    >();
    const entries: unknown[] = [];
    const statuses = new Map<string, string | undefined>();
    let customCall = 0;

    const pi = {
      on() {},
      registerCommand(
        name: string,
        definition: { handler(args: string, ctx: unknown): Promise<void> },
      ) {
        commands.set(name, definition);
      },
      registerShortcut() {},
      appendEntry(_type: string, data: unknown) {
        entries.push(data);
      },
    };
    const activeModel = { provider: "test", id: "active", name: "Active" };
    const ctx = {
      hasUI: true,
      model: { provider: "test", id: "active" },
      modelRegistry: {
        // Pi 0.99 keeps its ModelRuntime on the registry facade; Pi's
        // ModelSelectorComponent reads models and refreshes through it.
        runtime: {
          getAvailableSnapshot: () => [activeModel],
          getModel: (provider: string, id: string) =>
            provider === "test" && id === "active" ? activeModel : undefined,
          getError: () => undefined,
          refresh: async () => ({ aborted: false, errors: new Map() }),
        },
        refresh() {},
        getError: () => undefined,
        getAvailable: () => [
          { provider: "test", id: "active", name: "Active" },
        ],
        find: (provider: string, id: string) =>
          provider === "test" && id === "active"
            ? { provider: "test", id: "active", name: "Active" }
            : undefined,
      },
      ui: {
        theme: {
          fg: (_color: string, text: string) => text,
          bold: (text: string) => text,
        },
        setStatus(key: string, value: string | undefined) {
          statuses.set(key, value);
        },
        notify() {},
        custom<T>(
          factory: (
            tui: { requestRender(): void },
            theme: {
              fg(_color: string, text: string): string;
              bold(text: string): string;
            },
            keybindings: unknown,
            done: (value: T) => void,
          ) => { handleInput(data: string): void },
        ): Promise<T> {
          return new Promise((resolve) => {
            const component = factory(
              { requestRender() {} },
              this.theme,
              undefined,
              resolve,
            );
            if (customCall === 0) component.handleInput("\r");
            if (customCall === 1) {
              component.handleInput("\x1b[B");
              component.handleInput("\r");
            }
            if (customCall === 2) {
              queueMicrotask(() => component.handleInput("\r"));
            }
            if (customCall === 3) component.handleInput("\x1b");
            customCall += 1;
          });
        },
      },
      sessionManager: { getBranch: () => [] },
    };

    const controller = setupAutoMode(pi as never, localConfig);
    await commands.get("leash")?.handler("settings", ctx as never);

    expect(controller.isEnabled()).toBe(true);
    expect(localConfig.permissionGate.autoMode.enabled).toBe(true);
    expect(entries).toEqual([{ enabled: true }]);
    expect(updateAutoModeConfigMock).toHaveBeenNthCalledWith(1, {
      enabled: true,
    });
    expect(updateAutoModeConfigMock).toHaveBeenNthCalledWith(2, {
      model: "test/active",
    });
    expect(statuses.get("leash-auto")).toContain("leash auto");
  });
});
