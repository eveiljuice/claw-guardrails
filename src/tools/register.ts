import { createSafeActionTool, SafeActionToolDeps } from "./safe-action.js";
import { createSafeExecTool, SafeExecToolDeps } from "./safe-exec.js";
import { createSafeSendTool, SafeSendToolDeps } from "./safe-send.js";

import { GuardrailsPluginApi } from "../types.js";

type RegisteredTool = ReturnType<typeof createSafeExecTool>;

function registerToolCompat(api: GuardrailsPluginApi, tool: RegisteredTool): void {
  if (!api.registerTool) {
    return;
  }

  const definition = {
    id: tool.id,
    name: tool.id,
    description: tool.description,
    inputSchema: tool.inputSchema,
    handler: tool.handler,
  };

  try {
    api.registerTool(tool.id, definition);
    return;
  } catch {
    // Fall through to object-style registration.
  }

  try {
    api.registerTool(definition);
  } catch {
    // Ignore registration mismatch at this level; index.ts logs global setup errors.
  }
}

export function registerSafeTools(
  api: GuardrailsPluginApi,
  deps: SafeExecToolDeps & SafeSendToolDeps & SafeActionToolDeps,
): void {
  const safeExec = createSafeExecTool(deps);
  const safeSend = createSafeSendTool(deps);
  const safeAction = createSafeActionTool(deps);

  registerToolCompat(api, safeExec);
  registerToolCompat(api, safeSend);
  registerToolCompat(api, safeAction);
}
