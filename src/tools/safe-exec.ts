import { randomUUID } from "node:crypto";

import { PermissionResolver } from "../engine/resolver.js";
import {
  GuardrailsLogger,
  GuardrailsRuntimeAdapter,
  PermissionContext,
  PermissionRequest,
  PermissionResource,
  SafeExecInput,
  SafeToolResult,
} from "../types.js";

export interface SafeExecToolDeps {
  resolver: PermissionResolver;
  runtime: GuardrailsRuntimeAdapter;
  logger?: GuardrailsLogger;
}

function inferFilesystemResource(command: string, cwd?: string): PermissionResource {
  const readOnly = /^\s*(ls|cat|rg|grep|pwd|git\s+(status|diff|log))\b/i.test(command);
  return {
    kind: readOnly ? "filesystem_read" : "filesystem_write",
    value: cwd ?? ".",
  };
}

function inferNetworkResources(command: string): PermissionResource[] {
  const resources: PermissionResource[] = [];
  const urlMatches = command.match(/\bhttps?:\/\/[^\s]+/gi) ?? [];
  for (const url of urlMatches) {
    resources.push({
      kind: "network",
      value: url,
    });
  }
  return resources;
}

function buildRequest(input: SafeExecInput, invocationContext: unknown): PermissionRequest {
  const commandText = [input.command, ...(input.args ?? [])].join(" ").trim();
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
    toolName: "safe_exec",
    command: input.command,
    args: input.args ?? [],
    cwd: input.cwd,
    resources: [inferFilesystemResource(commandText, input.cwd), ...inferNetworkResources(commandText)],
    context,
  };
}

export function createSafeExecTool(deps: SafeExecToolDeps): {
  id: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (input: SafeExecInput, invocationContext?: unknown) => Promise<SafeToolResult>;
} {
  return {
    id: "safe_exec",
    description: "Execute shell commands through guardrails permission resolver.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["command"],
      properties: {
        command: { type: "string" },
        args: { type: "array", items: { type: "string" }, default: [] },
        cwd: { type: "string" },
        env: { type: "object", additionalProperties: { type: "string" } },
      },
    },
    handler: async (input: SafeExecInput, invocationContext?: unknown): Promise<SafeToolResult> => {
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
        const result = await deps.runtime.exec(input);
        return {
          ok: true,
          action: resolution.decision.action,
          decision: resolution.decision,
          requestId: request.requestId,
          result,
        };
      } catch (error) {
        deps.logger?.error?.("safe_exec runtime failure", {
          requestId: request.requestId,
          message: error instanceof Error ? error.message : "unknown error",
        });
        return {
          ok: false,
          action: "deny",
          decision: {
            ...resolution.decision,
            action: "deny",
            code: "SAFE_EXEC_RUNTIME_ERROR",
            reason: "Command failed at runtime",
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
