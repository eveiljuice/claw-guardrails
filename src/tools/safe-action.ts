import { randomUUID } from "node:crypto";

import { PermissionResolver } from "../engine/resolver.js";
import {
  GuardrailsLogger,
  GuardrailsRuntimeAdapter,
  PermissionContext,
  PermissionRequest,
  PermissionResource,
  SafeActionInput,
  SafeToolResult,
} from "../types.js";

export interface SafeActionToolDeps {
  resolver: PermissionResolver;
  runtime: GuardrailsRuntimeAdapter;
  logger?: GuardrailsLogger;
}

function inferResources(action: string): PermissionResource[] {
  const lower = action.toLowerCase();
  const resources: PermissionResource[] = [];

  if (lower.includes("email") || lower.includes("gmail")) {
    resources.push({
      kind: "unknown",
      value: "email-api",
      operation: lower,
    });
  }
  if (lower.includes("channel") || lower.includes("discord") || lower.includes("telegram")) {
    resources.push({
      kind: "channel_write",
      value: "external-channel",
      operation: lower,
    });
  }
  if (lower.includes("db") || lower.includes("database") || lower.includes("sql")) {
    resources.push({
      kind: "database",
      value: "database",
      operation: lower,
    });
  }

  return resources;
}

function buildRequest(input: SafeActionInput, invocationContext: unknown): PermissionRequest {
  const contextFromInvocation = invocationContext as Partial<PermissionContext> | undefined;
  const context: PermissionContext = {
    senderId: input.context?.senderId ?? contextFromInvocation?.senderId,
    channelId: input.context?.channelId ?? contextFromInvocation?.channelId,
    channelType: input.context?.channelType ?? contextFromInvocation?.channelType,
    agentId: input.context?.agentId ?? contextFromInvocation?.agentId,
    requestedAt: new Date().toISOString(),
    timezone: input.context?.timezone ?? contextFromInvocation?.timezone,
  };

  return {
    requestId: randomUUID(),
    toolName: "safe_action",
    action: input.action,
    payload: input.payload,
    resources: [...(input.resources ?? []), ...inferResources(input.action)],
    context,
  };
}

export function createSafeActionTool(deps: SafeActionToolDeps): {
  id: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (input: SafeActionInput, invocationContext?: unknown) => Promise<SafeToolResult>;
} {
  return {
    id: "safe_action",
    description: "Run generic external actions only after guardrails permission resolution.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["action"],
      properties: {
        action: { type: "string" },
        payload: { type: "object", additionalProperties: true },
        resources: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            required: ["kind", "value"],
            properties: {
              kind: { type: "string" },
              value: { type: "string" },
              operation: { type: "string" },
            },
          },
          default: [],
        },
      },
    },
    handler: async (input: SafeActionInput, invocationContext?: unknown): Promise<SafeToolResult> => {
      const request = buildRequest(input, invocationContext);
      const resolution = await deps.resolver.resolve(request);
      if (resolution.decision.action !== "allow") {
        return {
          ok: false,
          action: resolution.decision.action,
          decision: resolution.decision,
          requestId: request.requestId,
        };
      }

      try {
        const result = await deps.runtime.action(input);
        return {
          ok: true,
          action: resolution.decision.action,
          decision: resolution.decision,
          requestId: request.requestId,
          result,
        };
      } catch (error) {
        deps.logger?.error?.("safe_action runtime failure", {
          requestId: request.requestId,
          message: error instanceof Error ? error.message : "unknown error",
        });
        return {
          ok: false,
          action: "deny",
          decision: {
            ...resolution.decision,
            action: "deny",
            code: "SAFE_ACTION_RUNTIME_ERROR",
            reason: "Action failed at runtime",
            metadata: {
              message: error instanceof Error ? error.message : String(error),
            },
          },
          requestId: request.requestId,
        };
      }
    },
  };
}
