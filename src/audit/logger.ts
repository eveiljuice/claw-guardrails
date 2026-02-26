import os from "node:os";
import path from "node:path";
import { appendFile, mkdir } from "node:fs/promises";

import {
  AuditEntry,
  GuardrailsLogger,
  PermissionDecision,
  PermissionRequest,
  StageTraceEntry,
} from "../types.js";

export interface AuditLoggerOptions {
  enabled: boolean;
  filePath: string;
  logger?: GuardrailsLogger;
}

function expandHome(rawPath: string): string {
  if (!rawPath.startsWith("~")) {
    return rawPath;
  }
  return path.join(os.homedir(), rawPath.slice(1));
}

function sanitizeRequest(request: PermissionRequest): PermissionRequest {
  const clone = JSON.parse(JSON.stringify(request)) as PermissionRequest;
  if (!clone.metadata) {
    return clone;
  }
  const metadata = { ...clone.metadata };
  for (const key of Object.keys(metadata)) {
    const lower = key.toLowerCase();
    if (lower.includes("token") || lower.includes("secret") || lower.includes("password")) {
      metadata[key] = "[redacted]";
    }
  }
  clone.metadata = metadata;
  return clone;
}

export class AuditLogger {
  private readonly options: AuditLoggerOptions;
  private initialized = false;

  constructor(options: AuditLoggerOptions) {
    this.options = options;
  }

  public get enabled(): boolean {
    return this.options.enabled;
  }

  private get resolvedPath(): string {
    return path.resolve(expandHome(this.options.filePath));
  }

  private async ensureInitialized(): Promise<void> {
    if (this.initialized || !this.options.enabled) {
      return;
    }
    await mkdir(path.dirname(this.resolvedPath), { recursive: true });
    this.initialized = true;
  }

  public async log(entry: AuditEntry): Promise<void> {
    if (!this.options.enabled) {
      return;
    }
    await this.ensureInitialized();
    const payload = JSON.stringify(entry);
    await appendFile(this.resolvedPath, `${payload}\n`, "utf-8");
  }

  public async logDecision(
    request: PermissionRequest,
    decision: PermissionDecision,
    stageTrace: StageTraceEntry[],
  ): Promise<void> {
    if (!this.options.enabled) {
      return;
    }
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      requestId: request.requestId,
      toolName: request.toolName,
      request: sanitizeRequest(request),
      decision,
      stageTrace,
      approval: decision.approvalId
        ? {
            id: decision.approvalId,
            status: "pending",
          }
        : undefined,
    };
    try {
      await this.log(entry);
    } catch (error) {
      this.options.logger?.error?.("guardrails audit log write failed", {
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
}
