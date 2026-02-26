import { ApprovalHandler } from "../approval/handler.js";
import { GuardrailsConfig, GuardrailsLogger, GuardrailsPluginApi } from "../types.js";

export interface ServiceRegistrationDeps {
  approvalHandler: ApprovalHandler;
  config: GuardrailsConfig;
  logger?: GuardrailsLogger;
}

export class GuardrailsBackgroundService {
  private readonly approvalHandler: ApprovalHandler;
  private readonly logger?: GuardrailsLogger;
  private readonly intervalMs: number;
  private timer: NodeJS.Timeout | undefined;

  constructor(approvalHandler: ApprovalHandler, logger?: GuardrailsLogger, intervalMs = 5000) {
    this.approvalHandler = approvalHandler;
    this.logger = logger;
    this.intervalMs = intervalMs;
  }

  public start(): void {
    if (this.timer) {
      return;
    }
    this.timer = setInterval(async () => {
      try {
        const expired = await this.approvalHandler.expirePending();
        if (expired.length > 0) {
          this.logger?.info?.("guardrails approvals expired", {
            count: expired.length,
          });
        }
      } catch (error) {
        this.logger?.error?.("guardrails service tick failed", {
          message: error instanceof Error ? error.message : String(error),
        });
      }
    }, this.intervalMs);
  }

  public stop(): void {
    if (!this.timer) {
      return;
    }
    clearInterval(this.timer);
    this.timer = undefined;
  }
}

function registerGatewayMethodCompat(
  api: GuardrailsPluginApi,
  id: string,
  handler: (payload?: unknown, invocationContext?: unknown) => Promise<unknown>,
): void {
  if (!api.registerGatewayMethod) {
    return;
  }
  const definition = {
    id,
    name: id,
    handler,
  };
  try {
    api.registerGatewayMethod(id, definition);
    return;
  } catch {
    // object-style fallback
  }
  try {
    api.registerGatewayMethod(definition);
  } catch {
    // no-op
  }
}

function registerServiceCompat(
  api: GuardrailsPluginApi,
  id: string,
  service: { start: () => void; stop: () => void },
): void {
  if (!api.registerService) {
    return;
  }
  const definition = {
    id,
    name: id,
    start: service.start,
    stop: service.stop,
  };
  try {
    api.registerService(id, definition);
    return;
  } catch {
    // object-style fallback
  }
  try {
    api.registerService(definition);
  } catch {
    // no-op
  }
}

function registerCliCompat(
  api: GuardrailsPluginApi,
  id: string,
  handler: (args?: unknown) => Promise<unknown>,
): void {
  if (!api.registerCli) {
    return;
  }
  const definition = {
    id,
    name: id,
    description: "Guardrails operational commands",
    handler,
  };
  try {
    api.registerCli(id, definition);
    return;
  } catch {
    // object-style fallback
  }
  try {
    api.registerCli(definition);
  } catch {
    // no-op
  }
}

function parseCliArgs(args: unknown): string[] {
  if (Array.isArray(args)) {
    return args.filter((entry): entry is string => typeof entry === "string");
  }
  if (typeof args === "string") {
    return args.split(/\s+/).filter(Boolean);
  }
  if (args && typeof args === "object") {
    const candidate = args as Record<string, unknown>;
    if (Array.isArray(candidate.argv)) {
      return candidate.argv.filter((entry): entry is string => typeof entry === "string");
    }
  }
  return [];
}

export function registerServiceRpcAndCli(
  api: GuardrailsPluginApi,
  deps: ServiceRegistrationDeps,
): GuardrailsBackgroundService {
  const service = new GuardrailsBackgroundService(deps.approvalHandler, deps.logger);

  registerGatewayMethodCompat(api, "guardrails.pending", async () => {
    return deps.approvalHandler.listPending();
  });

  registerGatewayMethodCompat(api, "guardrails.approve", async (payload?: unknown) => {
    const id = payload && typeof payload === "object" ? (payload as Record<string, unknown>).id : undefined;
    if (typeof id !== "string" || id.length === 0) {
      return { ok: false, error: "Missing approval id" };
    }
    return deps.approvalHandler.approve(id, "rpc:guardrails.approve");
  });

  registerGatewayMethodCompat(api, "guardrails.deny", async (payload?: unknown) => {
    const id = payload && typeof payload === "object" ? (payload as Record<string, unknown>).id : undefined;
    if (typeof id !== "string" || id.length === 0) {
      return { ok: false, error: "Missing approval id" };
    }
    return deps.approvalHandler.deny(id, "rpc:guardrails.deny");
  });

  registerGatewayMethodCompat(api, "guardrails.status", async () => {
    const summary = await deps.approvalHandler.queueSummary();
    return {
      ok: true,
      summary,
      defaultAction: deps.config.defaultAction,
      approvalTimeout: deps.config.approvalTimeout,
    };
  });

  registerServiceCompat(api, "guardrails", {
    start: () => service.start(),
    stop: () => service.stop(),
  });

  registerCliCompat(api, "guardrails", async (args?: unknown) => {
    const argv = parseCliArgs(args);
    const subcommand = argv[0] ?? "status";

    if (subcommand === "status") {
      const summary = await deps.approvalHandler.queueSummary();
      return {
        ok: true,
        summary,
      };
    }
    if (subcommand === "audit") {
      return {
        ok: true,
        enabled: deps.config.auditLog,
        path: deps.config.auditLogPath,
      };
    }
    if (subcommand === "policy") {
      return {
        ok: true,
        defaultAction: deps.config.defaultAction,
        rules: deps.config.policies.map((rule) => ({
          id: rule.id,
          action: rule.action,
          match: rule.match,
        })),
      };
    }
    return {
      ok: false,
      error: "Usage: openclaw guardrails <status|audit|policy>",
    };
  });

  return service;
}
