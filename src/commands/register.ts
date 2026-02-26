import { ApprovalHandler } from "../approval/handler.js";
import { GuardrailsConfig, GuardrailsPluginApi } from "../types.js";

interface CommandRegistration {
  id: string;
  description: string;
  handler: (input?: unknown, invocationContext?: unknown) => Promise<unknown>;
}

export interface CommandRegistrationDeps {
  approvalHandler: ApprovalHandler;
  config: GuardrailsConfig;
}

function registerCommandCompat(api: GuardrailsPluginApi, command: CommandRegistration): void {
  if (!api.registerCommand) {
    return;
  }
  const definition = {
    id: command.id,
    name: command.id,
    description: command.description,
    handler: command.handler,
  };

  try {
    api.registerCommand(command.id, definition);
    return;
  } catch {
    // Try object-style registration.
  }

  try {
    api.registerCommand(definition);
  } catch {
    // Ignore shape mismatch, index.ts logs global setup failures.
  }
}

function parseCommandArgs(input: unknown): string[] {
  if (typeof input === "string") {
    return input.split(/\s+/).filter(Boolean);
  }
  if (Array.isArray(input)) {
    return input.filter((entry): entry is string => typeof entry === "string");
  }
  if (input && typeof input === "object") {
    const maybeObject = input as Record<string, unknown>;
    if (Array.isArray(maybeObject.args)) {
      return maybeObject.args.filter((entry): entry is string => typeof entry === "string");
    }
    if (typeof maybeObject.text === "string") {
      return maybeObject.text.split(/\s+/).filter(Boolean);
    }
  }
  return [];
}

function actorFromContext(invocationContext: unknown): string | undefined {
  if (!invocationContext || typeof invocationContext !== "object") {
    return undefined;
  }
  const context = invocationContext as Record<string, unknown>;
  const value = context.senderId ?? context.userId ?? context.actor;
  return typeof value === "string" ? value : undefined;
}

export function registerGuardrailsCommands(
  api: GuardrailsPluginApi,
  deps: CommandRegistrationDeps,
): void {
  registerCommandCompat(api, {
    id: "perms",
    description: "Show guardrails config summary and approval queue state.",
    handler: async (): Promise<unknown> => {
      const summary = await deps.approvalHandler.queueSummary();
      return {
        ok: true,
        plugin: "claw-guardrails",
        defaultAction: deps.config.defaultAction,
        approvalTimeout: deps.config.approvalTimeout,
        approvalFallback: deps.config.approvalFallback,
        policies: deps.config.policies.map((policy) => ({
          id: policy.id,
          action: policy.action,
        })),
        queue: summary,
      };
    },
  });

  registerCommandCompat(api, {
    id: "approve",
    description: "Approve pending guardrails request by id: /approve <id>",
    handler: async (input?: unknown, invocationContext?: unknown): Promise<unknown> => {
      const args = parseCommandArgs(input);
      const id = args[0];
      if (!id) {
        return {
          ok: false,
          error: "Usage: /approve <id>",
        };
      }
      const resolvedBy = actorFromContext(invocationContext);
      return deps.approvalHandler.approve(id, resolvedBy);
    },
  });

  registerCommandCompat(api, {
    id: "deny",
    description: "Deny pending guardrails request by id: /deny <id>",
    handler: async (input?: unknown, invocationContext?: unknown): Promise<unknown> => {
      const args = parseCommandArgs(input);
      const id = args[0];
      if (!id) {
        return {
          ok: false,
          error: "Usage: /deny <id>",
        };
      }
      const resolvedBy = actorFromContext(invocationContext);
      return deps.approvalHandler.deny(id, resolvedBy);
    },
  });
}
