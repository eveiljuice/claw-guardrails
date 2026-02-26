import { matchContext } from "./context-matcher.js";
import { evaluatePolicy } from "./policy-engine.js";
import { classifyRisk } from "./risk-classifier.js";
import { checkResourcePermission } from "./resource-checker.js";
import { checkToolPermission } from "./tool-checker.js";

import {
  ApprovalEntry,
  GuardrailsConfig,
  PermissionDecision,
  PermissionRequest,
  StageTraceEntry,
  createDecision,
} from "../types.js";

export interface ApprovalQueueLike {
  enqueue(request: PermissionRequest, decisionSnapshot: PermissionDecision): Promise<ApprovalEntry>;
}

export interface AuditLoggerLike {
  logDecision(
    request: PermissionRequest,
    decision: PermissionDecision,
    stageTrace: StageTraceEntry[],
  ): Promise<void>;
}

export interface ResolverOptions {
  config: GuardrailsConfig;
  approvalQueue?: ApprovalQueueLike;
  auditLogger?: AuditLoggerLike;
}

export interface ResolveResult {
  decision: PermissionDecision;
  stageTrace: StageTraceEntry[];
}

function withTrace(trace: StageTraceEntry[], decision: PermissionDecision): StageTraceEntry[] {
  return [...trace, { stage: decision.stage, decision }];
}

function queueFallbackDecision(config: GuardrailsConfig): PermissionDecision {
  switch (config.approvalFallback) {
    case "allow":
      return createDecision(
        "approval-queue",
        "allow",
        "APPROVAL_QUEUE_FALLBACK_ALLOW",
        "Approval queue unavailable; fallback allows execution",
      );
    case "require_approval":
      return createDecision(
        "approval-queue",
        "require_approval",
        "APPROVAL_QUEUE_FALLBACK_REQUIRE",
        "Approval queue unavailable and fallback keeps approval requirement",
      );
    case "deny":
    default:
      return createDecision(
        "approval-queue",
        "deny",
        "APPROVAL_QUEUE_FALLBACK_DENY",
        "Approval queue unavailable; fallback denies execution",
      );
  }
}

export class PermissionResolver {
  private readonly config: GuardrailsConfig;
  private readonly approvalQueue?: ApprovalQueueLike;
  private readonly auditLogger?: AuditLoggerLike;

  constructor(options: ResolverOptions) {
    this.config = options.config;
    this.approvalQueue = options.approvalQueue;
    this.auditLogger = options.auditLogger;
  }

  private async finalize(
    request: PermissionRequest,
    decision: PermissionDecision,
    stageTrace: StageTraceEntry[],
  ): Promise<ResolveResult> {
    if (this.auditLogger) {
      await this.auditLogger.logDecision(request, decision, stageTrace);
    }
    return { decision, stageTrace };
  }

  private async escalateToApproval(
    request: PermissionRequest,
    baseDecision: PermissionDecision,
    stageTrace: StageTraceEntry[],
  ): Promise<ResolveResult> {
    if (!this.approvalQueue) {
      const fallback = queueFallbackDecision(this.config);
      const trace = withTrace(stageTrace, fallback);
      return this.finalize(request, fallback, trace);
    }

    try {
      const entry = await this.approvalQueue.enqueue(request, baseDecision);
      const approvalDecision = createDecision(
        "approval-queue",
        "require_approval",
        "APPROVAL_REQUIRED",
        "Human approval is required before execution",
        {
          approvalId: entry.id,
          risk: baseDecision.risk,
          matchedPolicyId: baseDecision.matchedPolicyId,
          metadata: {
            expiresAt: entry.expiresAt,
            originalCode: baseDecision.code,
          },
        },
      );
      const trace = withTrace(stageTrace, approvalDecision);
      return this.finalize(request, approvalDecision, trace);
    } catch {
      const fallback = queueFallbackDecision(this.config);
      const trace = withTrace(stageTrace, fallback);
      return this.finalize(request, fallback, trace);
    }
  }

  public async resolve(request: PermissionRequest): Promise<ResolveResult> {
    let trace: StageTraceEntry[] = [];

    const contextDecision = matchContext(request, this.config);
    trace = withTrace(trace, contextDecision);
    if (contextDecision.action === "deny") {
      return this.finalize(request, contextDecision, trace);
    }
    if (contextDecision.action === "require_approval") {
      return this.escalateToApproval(request, contextDecision, trace);
    }

    const toolDecision = checkToolPermission(request, this.config);
    trace = withTrace(trace, toolDecision);
    if (toolDecision.action === "deny") {
      return this.finalize(request, toolDecision, trace);
    }
    if (toolDecision.action === "require_approval") {
      return this.escalateToApproval(request, toolDecision, trace);
    }

    const resourceDecision = checkResourcePermission(request, this.config);
    trace = withTrace(trace, resourceDecision);
    if (resourceDecision.action === "deny") {
      return this.finalize(request, resourceDecision, trace);
    }
    if (resourceDecision.action === "require_approval") {
      return this.escalateToApproval(request, resourceDecision, trace);
    }

    const risk = classifyRisk(request);
    const policyDecision = evaluatePolicy(request, risk, this.config);
    trace = withTrace(trace, policyDecision);
    if (policyDecision.action === "require_approval") {
      return this.escalateToApproval(request, policyDecision, trace);
    }
    return this.finalize(request, policyDecision, trace);
  }
}
