# Test coverage

## Permission gate

`src/hooks/permission-gate.test.ts` verifies:

- five-minute dangerous-command trust applies only to its granted reason;
- a command that matches multiple reasons still requires every reason to be trusted;
- the registered Pi `tool_call` hook routes the five-minute selection through the RPC fallback, bypasses a later same-reason command, and prompts for a different or additional reason;
- the real inline dialog component renders the concrete reason label (for example, `w: allow recursive force delete for 5 min`);
- timed grants expire after five minutes, and explicitly clearing trust revokes session grants;
- dangerous command parsing, cwd scope detection, and inline-dialog height helpers continue to work.

## Auto-mode failures and feedback

- `src/hooks/auto-mode.test.ts` verifies pending footer feedback, one slow-response warning, short timeout warnings, and cleared timers/status after completion.
- The controller tests verify that each fallback cause disables auto mode, saves manual mode, restores it on session resume, skips later classifier calls, and allows explicit re-enabling. Ordinary `allow`, `ask`, and `deny` verdicts leave auto mode enabled.
- Controller tests also cover failed configuration writes and late approvals from concurrent requests after another check fails.
- `src/lib/auto-mode-classifier.test.ts` verifies sanitized returned and thrown provider failures, configured timeout reporting, and rejection of a verdict returned after the deadline.
- `src/lib/executor.test.ts` verifies propagation of error and abort messages when the SDK resolves the prompt without throwing, plus unchanged successful completion and resource disposal.

## Validation

Run from `pi-leash/`:

```bash
pnpm test
pnpm typecheck
pnpm lint
```
