import { ApprovalHandler } from "./src/approval/handler.js";
import { ApprovalQueue } from "./src/approval/queue.js";
import { AuditLogger } from "./src/audit/logger.js";
import { resolveGuardrailsConfig } from "./src/config/defaults.js";
import { GuardrailsConfigSchema } from "./src/config/schema.js";
import { PermissionResolver } from "./src/engine/resolver.js";
import { registerGuardrailsCommands } from "./src/commands/register.js";
import { registerServiceRpcAndCli } from "./src/service/register.js";
import { registerSafeTools } from "./src/tools/register.js";
import {
  GuardrailsPluginApi,
  GuardrailsRuntimeAdapter,
  SafeActionInput,
  SafeExecInput,
  SafeSendInput,
} from "./src/types.js";

class OpenClawRuntimeAdapter implements GuardrailsRuntimeAdapter {
  private readonly api: GuardrailsPluginApi;

  constructor(api: GuardrailsPluginApi) {
    this.api = api;
  }

  private runtimeObj(): Record<string, unknown> | undefined {
    if (this.api.runtime && typeof this.api.runtime === "object") {
      return this.api.runtime as Record<string, unknown>;
    }
    return undefined;
  }

  private async callRuntimeFunction(functionName: string, payload: unknown): Promise<unknown> {
    const runtime = this.runtimeObj();
    const fn = runtime?.[functionName];
    if (typeof fn === "function") {
      return (fn as (arg: unknown) => Promise<unknown> | unknown)(payload);
    }
    return undefined;
  }

  private async callRuntimeTool(toolName: string, payload: unknown): Promise<unknown> {
    const runtime = this.runtimeObj();
    const runtimeCallTool = runtime?.callTool;
    if (typeof runtimeCallTool === "function") {
      return (runtimeCallTool as (name: string, args: unknown) => Promise<unknown> | unknown)(
        toolName,
        payload,
      );
    }
    const apiCallTool = (this.api as unknown as Record<string, unknown>).callTool;
    if (typeof apiCallTool === "function") {
      return (apiCallTool as (name: string, args: unknown) => Promise<unknown> | unknown)(
        toolName,
        payload,
      );
    }
    throw new Error(`No runtime adapter found for tool '${toolName}'`);
  }

  public async exec(input: SafeExecInput): Promise<unknown> {
    const command = [input.command, ...(input.args ?? [])].join(" ").trim();
    const payload = {
      command,
      cwd: input.cwd,
      env: input.env,
    };
    const directExec =
      (await this.callRuntimeFunction("exec", payload)) ??
      (await this.callRuntimeFunction("runExec", payload));
    if (directExec !== undefined) {
      return directExec;
    }
    return this.callRuntimeTool("exec", payload);
  }

  public async send(input: SafeSendInput): Promise<unknown> {
    const payload = {
      channel: input.channel,
      message: input.message,
      channelType: input.channelType,
      metadata: input.metadata,
    };
    const directSend =
      (await this.callRuntimeFunction("send", payload)) ??
      (await this.callRuntimeFunction("sendMessage", payload));
    if (directSend !== undefined) {
      return directSend;
    }
    return this.callRuntimeTool("send", payload);
  }

  public async action(input: SafeActionInput): Promise<unknown> {
    const payload = {
      action: input.action,
      payload: input.payload,
      resources: input.resources,
    };
    const directAction =
      (await this.callRuntimeFunction("action", payload)) ??
      (await this.callRuntimeFunction("runAction", payload));
    if (directAction !== undefined) {
      return directAction;
    }
    return this.callRuntimeTool("gateway", payload);
  }
}

function registerHookCompat(
  api: GuardrailsPluginApi,
  id: string,
  handler: (payload?: unknown) => Promise<void>,
): void {
  if (!api.registerHook) {
    return;
  }
  const definition = {
    id,
    name: id,
    handler,
  };
  try {
    api.registerHook(id, definition);
    return;
  } catch {
    // try object style
  }
  try {
    api.registerHook(definition);
  } catch {
    // no-op
  }
}

export async function register(api: GuardrailsPluginApi): Promise<{ dispose: () => void }> {
  const rawConfig = api.getConfig ? api.getConfig() : {};
  const config = resolveGuardrailsConfig(rawConfig);

  const auditLogger = new AuditLogger({
    enabled: config.auditLog,
    filePath: config.auditLogPath,
    logger: api.logger,
  });

  const approvalQueue = new ApprovalQueue({
    storePath: config.approvalStorePath,
    timeoutSeconds: config.approvalTimeout,
  });
  await approvalQueue.initialize();

  const approvalHandler = new ApprovalHandler(approvalQueue);
  const resolver = new PermissionResolver({
    config,
    approvalQueue,
    auditLogger,
  });
  const runtimeAdapter = new OpenClawRuntimeAdapter(api);

  registerSafeTools(api, {
    resolver,
    runtime: runtimeAdapter,
    logger: api.logger,
  });
  registerGuardrailsCommands(api, {
    approvalHandler,
    config,
  });

  const backgroundService = registerServiceRpcAndCli(api, {
    approvalHandler,
    config,
    logger: api.logger,
  });
  backgroundService.start();

  registerHookCompat(api, "message:*", async (payload?: unknown) => {
    if (!config.auditLog) {
      return;
    }
    const messagePayload = payload as Record<string, unknown> | undefined;
    await auditLogger.log({
      timestamp: new Date().toISOString(),
      requestId: `message-${Date.now()}`,
      toolName: "message_hook",
      request: {
        requestId: `message-${Date.now()}`,
        toolName: "message_hook",
        context: {
          senderId:
            typeof messagePayload?.senderId === "string" ? messagePayload.senderId : undefined,
          channelId:
            typeof messagePayload?.channelId === "string" ? messagePayload.channelId : undefined,
        },
        metadata: {
          event: "message:*",
          payload,
        },
      },
      decision: {
        stage: "resolver",
        action: "allow",
        code: "MESSAGE_AUDIT_EVENT",
        reason: "Message event audited",
      },
    });
  });

  api.logger?.info?.("claw-guardrails plugin registered", {
    policies: config.policies.length,
    auditLog: config.auditLog,
    approvalTimeout: config.approvalTimeout,
  });

  return {
    dispose: () => {
      backgroundService.stop();
    },
  };
}

const plugin = {
  id: "claw-guardrails",
  register,
  configSchema: GuardrailsConfigSchema,
};

export default plugin;
