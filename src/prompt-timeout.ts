/**
 * Opt-in deadlines for Leash prompts that block an agent on a person.
 *
 * A timeout is not a manual decision: allow means once, never a session or
 * persistent grant, and sudo passwords cannot be accepted on behalf of anyone.
 */

export type PromptTimeoutAction = "allow" | "deny";

export interface PromptTimeoutConfig {
  /** Dismiss unanswered prompts. Default: false. */
  enabled?: boolean;
  /**
   * How long to wait before dismissing, in milliseconds.
   * Default: 30000. Values below 1000 are raised to 1000.
   */
  timeoutMs?: number;
  /**
   * Decision applied when a prompt times out.
   * "allow" is one-time only. Default: "deny".
   */
  action?: PromptTimeoutAction;
}

export interface ResolvedPromptTimeout {
  enabled: boolean;
  timeoutMs: number;
  action: PromptTimeoutAction;
}

export function resolvePromptTimeout(
  input?: PromptTimeoutConfig,
): ResolvedPromptTimeout {
  const raw = input?.timeoutMs;
  const timeoutMs =
    typeof raw === "number" && Number.isFinite(raw)
      ? Math.max(1000, Math.floor(raw))
      : 30_000;

  return {
    enabled: input?.enabled === true,
    timeoutMs,
    action: input?.action === "allow" ? "allow" : "deny",
  };
}

export function promptTimeoutSeconds(timeoutMs: number): number {
  return Math.max(1, Math.ceil(timeoutMs / 1000));
}

export function promptTimeoutChoiceLabel(action: PromptTimeoutAction): string {
  return action === "allow" ? "auto-allow once" : "auto-deny";
}

/** Live countdown line for a custom dialog. Password prompts cannot be allowed. */
export function promptTimeoutStatus(
  timeout: ResolvedPromptTimeout,
  remainingSeconds: number,
  options?: { password?: boolean },
): string {
  if (options?.password) {
    return `timeout in ${remainingSeconds}s → auto-deny (a password cannot be auto-accepted)`;
  }
  return `timeout in ${remainingSeconds}s → ${promptTimeoutChoiceLabel(timeout.action)}`;
}

export function autoPromptMessage(input: {
  action: PromptTimeoutAction;
  timeoutMs: number;
  what: string;
  detail?: string;
}): string {
  const seconds = promptTimeoutSeconds(input.timeoutMs);
  const verb = input.action === "allow" ? "auto-allowed" : "auto-denied";
  const detail = input.detail ? ` (${input.detail})` : "";
  const scope =
    input.action === "allow"
      ? " This was a one-time timeout decision, not a manual approval."
      : " This was a timeout decision, not a manual denial.";
  return `Leash ${verb} this ${input.what} after ${seconds}s with no response${detail}.${scope}`;
}

/**
 * Plain select/input dialogs report cancel and timeout the same way.
 * Auto-allow is unsafe there: a person hitting cancel would be treated as a
 * timeout approval. Deny still dismisses; allow explains why it did not apply.
 */
export function fallbackDismissMessage(input: {
  action: PromptTimeoutAction;
  timeoutMs: number;
  what: string;
}): string {
  const seconds = promptTimeoutSeconds(input.timeoutMs);
  if (input.action === "allow") {
    return (
      `Leash denied this ${input.what}. The prompt closed with no explicit allow within ${seconds}s, ` +
      "and this host cannot tell a timeout from cancel, so it was not auto-allowed."
    );
  }
  return `Leash auto-denied this ${input.what} because the prompt closed with no choice within ${seconds}s.`;
}

export function sudoTimeoutMessage(
  timeoutMs: number,
  explicit: boolean,
): string {
  const seconds = promptTimeoutSeconds(timeoutMs);
  if (explicit) {
    return `Leash auto-denied the sudo password prompt after ${seconds}s with no response. A password cannot be auto-accepted.`;
  }
  return "Leash denied the sudo password prompt because it closed with no password. A password cannot be auto-accepted.";
}

/**
 * Dismiss a custom dialog at `timeoutMs`. `onTick` receives whole seconds
 * remaining, including the initial value, then about once a second.
 * `dispose` cancels the deadline so a manual choice cannot also time out.
 */
export function armPromptTimeout(
  timeoutMs: number,
  tui: { requestRender?: () => void },
  onTick: (remainingSeconds: number) => void,
  onTimeout: () => void,
): { dispose(): void } {
  let settled = false;
  const deadline = Date.now() + timeoutMs;
  let interval: ReturnType<typeof setInterval> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const publish = () => {
    const remainingMs = deadline - Date.now();
    onTick(Math.max(0, Math.ceil(remainingMs / 1000)));
  };

  const finish = () => {
    if (settled) return;
    settled = true;
    if (interval) clearInterval(interval);
    if (timer) clearTimeout(timer);
    onTick(0);
    tui.requestRender?.();
    onTimeout();
  };

  publish();

  interval = setInterval(() => {
    if (settled) return;
    if (Date.now() >= deadline) {
      finish();
      return;
    }
    publish();
    tui.requestRender?.();
  }, 1000);

  timer = setTimeout(finish, timeoutMs);

  for (const handle of [interval, timer]) {
    if (typeof handle.unref === "function") handle.unref();
  }

  return {
    dispose() {
      if (settled) return;
      settled = true;
      if (interval) clearInterval(interval);
      if (timer) clearTimeout(timer);
    },
  };
}
