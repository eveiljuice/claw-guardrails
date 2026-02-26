import { randomUUID } from "node:crypto";

import { PermissionResolver } from "../engine/resolver.js";
import {
  GuardrailsLogger,
  GuardrailsRuntimeAdapter,
  PermissionContext,
  PermissionRequest,
  SafeSendInput,
  SafeToolResult,
} from "../types.js";

export interface SafeSendToolDeps {
  resolver: PermissionResolver;
  runtime: GuardrailsRuntimeAdapter;
  logger?: GuardrailsLogger;
}

function buildRequest(input: SafeSendInput, invocationContext: unknown): PermissionRequest {
  const contextFromInvocation = invocationContext as Partial<PermissionContext> | undefined;
  const context: PermissionContext = {
    senderId: input.context?.senderId ?? contextFromInvocation?.senderId,
    channelId: input.channel,
    channelType: input.channelType ?? contextFromInvocation?.channelType,
    agentId: input.context?.agentId ?? contextFromInvocation?.agentId,
    requestedAt: new Date().toISOString(),
    timezone: input.context?.timezone ?? contextFromInvocation?.timezone,
  };

  return {
    requestId: randomUUID(),
    toolName: "safe_send",
    action: "send_message",
    payload: {
      message: input.message,
      metadata: input.metadata,
    },
    resources: [
      {
        kind: "channel_write",
        value: input.channel,
      },
    ],
    context,
  };
}

export function createSafeSendTool(deps: SafeSendToolDeps): {
  id: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (input: SafeSendInput, invocationContext?: unknown) => Promise<SafeToolResult>;
} {
  return {
    id: "safe_send",
    description: "Send outbound channel messages through guardrails approval flow.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["channel", "message"],
      properties: {
        channel: { type: "string" },
        message: { type: "string" },
        channelType: { type: "string" },
        metadata: { type: "object", additionalProperties: true },
      },
    },
    handler: async (input: SafeSendInput, invocationContext?: unknown): Promise<SafeToolResult> => {
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
        const result = await deps.runtime.send(input);
        return {
          ok: true,
          action: resolution.decision.action,
          decision: resolution.decision,
          requestId: request.requestId,
          result,
        };
      } catch (error) {
        deps.logger?.error?.("safe_send runtime failure", {
          requestId: request.requestId,
          message: error instanceof Error ? error.message : "unknown error",
        });
        return {
          ok: false,
          action: "deny",
          decision: {
            ...resolution.decision,
            action: "deny",
            code: "SAFE_SEND_RUNTIME_ERROR",
            reason: "Message send failed at runtime",
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
