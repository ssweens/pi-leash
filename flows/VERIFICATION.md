# Classifier failure feedback and manual fallback

- **Flow:** A delayed safety check identifies what is holding tool execution. A failed check switches to manual approval until the user re-enables auto mode.
- **Pending state:** Existing animated auto marker plus classifier model, elapsed seconds, and timeout. One warning after five seconds or half the configured timeout, whichever is shorter.
- **Failure state:** Model setup, provider, timeout, and invalid-response failures warn with the cause, disable auto mode, and save manual mode in the session and configuration. Later actions do not call the classifier while manual mode is active.
- **Recovery:** `/leash auto` retries for the current session. Enabling auto in `/leash settings` saves it for new sessions.
- **Preserved:** A normal classifier `ask` does not disable auto. Existing permission dialogs, manual grants, policy gates, and sudo password handling remain in place.

## Automated evidence

Run from `pi-leash/`:

- `pnpm test` passed: 9 files, 212 tests.
- `pnpm typecheck` passed.
- Biome passed for `src/hooks/auto-mode.ts`, `src/hooks/auto-mode.test.ts`, `src/lib/auto-mode-classifier.ts`, `src/lib/auto-mode-classifier.test.ts`, `src/lib/executor.ts`, and `src/lib/executor.test.ts`.
- Biome on `src/hooks/permission-gate.ts` still reports existing emoji-plugin errors and explicit-`any` warnings outside the changed notification branch.
- Tests cover every fallback cause, resume, explicit re-enabling, no repeat classifier calls, normal verdicts, persistence failure, a late concurrent approval, short timeout feedback, and SDK error messages without thrown exceptions.
- Vitest reports a missing source map for the vendored shell parser; the suite passes.

## Live TUI evidence

Loaded the real `src/index.ts` in isolated Pi sessions under tmux, using a controlled local OpenAI-compatible endpoint and isolated configuration. Dangerous commands targeted only an unused path inside the temporary smoke directory.

1. Before the change, a hanging classifier showed only animated arrows. After the ten-second timeout, the next action called the same hanging classifier again.
2. After the change, the footer showed `leash waiting for leash-smoke/classifier · 5s/10s`, accompanied by a warning that tool execution was waiting.
3. At timeout, a warning identified the model and timeout, and the existing one-time manual approval dialog appeared. The footer's pending state cleared.
4. Denied that action, then requested another dangerous action. The manual dialog appeared immediately; the endpoint request log contained no additional classifier request.
5. A new Pi session started in manual mode. Its dangerous action also prompted without a classifier request. Saved configuration contained `autoMode.enabled: false`.
6. Re-enabled with `/leash auto`. A normal classifier `ask` prompted once and retained the auto marker.
7. An HTTP 400 provider failure showed the actual provider error and switched back to manual approval.
8. Used `/leash settings` to enable auto mode. Saved configuration contained `autoMode.enabled: true`. A successful classifier `allow` completed the dangerous-tool path and restored the static auto indicator.

External providers were not contacted. These checks establish Leash's integrated failure, feedback, persistence, and recovery paths, not any external provider's availability.
