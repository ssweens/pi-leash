import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { ResolvedConfig } from "../config";
import { setupAutoMode } from "./auto-mode";
import { setupPathAccessHook } from "./path-access";
import { setupPermissionGateHook } from "./permission-gate";
import { setupPoliciesHook } from "./policies";
import type { LeashRuntimeState } from "./runtime";

export function setupLeashHooks(pi: ExtensionAPI, config: ResolvedConfig) {
  const runtime: LeashRuntimeState = { enabled: true };
  const autoMode = setupAutoMode(pi, config, runtime);
  setupPathAccessHook(pi, config, runtime); // boundary check — runs first
  setupPoliciesHook(pi, config, runtime); // policy rules — runs second
  setupPermissionGateHook(pi, config, autoMode, runtime); // dangerous commands — runs third
}
