export type DecisionAction = "allow" | "deny" | "require_approval";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type PermissionStage =
  | "context-matcher"
  | "tool-checker"
  | "resource-checker"
  | "policy-engine"
  | "approval-queue"
  | "resolver";

export type ResourceKind =
  | "filesystem_read"
  | "filesystem_write"
  | "network"
  | "database"
  | "channel_read"
  | "channel_write"
  | "exec"
  | "unknown";

export interface PermissionContext {
  senderId?: string;
  channelId?: string;
  channelType?: string;
  agentId?: string;
  requestedAt?: string;
  timezone?: string;
}

export interface PermissionResource {
  kind: ResourceKind;
  value: string;
  operation?: string;
  metadata?: Record<string, unknown>;
}

export interface PermissionRequest {
  requestId: string;
  toolName: string;
  command?: string;
  args?: string[];
  cwd?: string;
  action?: string;
  payload?: unknown;
  resources?: PermissionResource[];
  context: PermissionContext;
  metadata?: Record<string, unknown>;
}

export interface RiskPatternMatch {
  source: "shell" | "git" | "npm" | "docker" | "email" | "channel" | "generic";
  pattern: string;
  reason: string;
  level: RiskLevel;
  score: number;
}

export interface RiskAssessment {
  level: RiskLevel;
  score: number;
  reasons: string[];
  matches: RiskPatternMatch[];
}

export interface PolicyRuleMatch {
  tools?: string[];
  commands?: string[];
  resources?: string[];
  riskLevel?: RiskLevel[];
  senders?: string[];
  channels?: string[];
  agents?: string[];
}

export interface PolicyRule {
  id: string;
  description?: string;
  match: PolicyRuleMatch;
  action: DecisionAction;
  reason?: string;
}

export interface PermissionDecision {
  action: DecisionAction;
  code: string;
  reason: string;
  stage: PermissionStage;
  risk?: RiskAssessment;
  matchedPolicyId?: string;
  approvalId?: string;
  metadata?: Record<string, unknown>;
}

export interface StageTraceEntry {
  stage: PermissionStage;
  decision: PermissionDecision;
}

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export interface ApprovalEntry {
  id: string;
  status: ApprovalStatus;
  request: PermissionRequest;
  decisionSnapshot: PermissionDecision;
  createdAt: string;
  expiresAt: string;
  resolvedAt?: string;
  resolvedBy?: string;
  note?: string;
}

export interface AuditEntry {
  timestamp: string;
  requestId: string;
  toolName: string;
  request: PermissionRequest;
  decision: PermissionDecision;
  stageTrace?: StageTraceEntry[];
  approval?: {
    id: string;
    status: ApprovalStatus;
    resolvedBy?: string;
  };
}

export interface PatternAllowDeny {
  allow: string[];
  deny: string[];
}

export interface ContextTimeWindow {
  start: string;
  end: string;
  days?: number[];
  timezone?: string;
}

export interface GuardrailsContextConfig {
  senders: PatternAllowDeny;
  channels: PatternAllowDeny;
  agents: PatternAllowDeny;
  timeWindows: ContextTimeWindow[];
}

export interface GuardrailsFilesystemConfig {
  readAllow: string[];
  readDeny: string[];
  writeAllow: string[];
  writeDeny: string[];
}

export interface GuardrailsNetworkConfig {
  allow: string[];
  deny: string[];
}

export interface GuardrailsExecConfig {
  allow: string[];
  deny: string[];
  cwdAllow: string[];
  cwdDeny: string[];
}

export interface GuardrailsChannelConfig {
  readAllow: string[];
  writeAllow: string[];
  writeDeny: string[];
}

export interface GuardrailsDatabaseConfig {
  allowOperations: string[];
  denyOperations: string[];
}

export interface GuardrailsResourceConfig {
  filesystem: GuardrailsFilesystemConfig;
  network: GuardrailsNetworkConfig;
  exec: GuardrailsExecConfig;
  channels: GuardrailsChannelConfig;
  database: GuardrailsDatabaseConfig;
}

export interface GuardrailsConfig {
  defaultAction: DecisionAction;
  approvalTimeout: number;
  approvalFallback: DecisionAction;
  approvalStorePath: string;
  approvalNotifyChannel?: string;
  auditLog: boolean;
  auditLogPath: string;
  policies: PolicyRule[];
  contexts: GuardrailsContextConfig;
  resources: GuardrailsResourceConfig;
  dangerousArgPatterns: string[];
}

export interface SafeExecInput {
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  context?: Partial<PermissionContext>;
}

export interface SafeSendInput {
  channel: string;
  message: string;
  channelType?: string;
  metadata?: Record<string, unknown>;
  context?: Partial<PermissionContext>;
}

export interface SafeActionInput {
  action: string;
  payload?: unknown;
  resources?: PermissionResource[];
  context?: Partial<PermissionContext>;
}

export interface SafeToolResult {
  ok: boolean;
  action: DecisionAction;
  decision: PermissionDecision;
  requestId: string;
  result?: unknown;
}

export interface ApprovalResolutionResult {
  ok: boolean;
  entry?: ApprovalEntry;
  error?: string;
}

export interface GuardrailsRuntimeAdapter {
  exec(input: SafeExecInput): Promise<unknown>;
  send(input: SafeSendInput): Promise<unknown>;
  action(input: SafeActionInput): Promise<unknown>;
}

export interface GuardrailsLogger {
  debug?(message: string, data?: Record<string, unknown>): void;
  info?(message: string, data?: Record<string, unknown>): void;
  warn?(message: string, data?: Record<string, unknown>): void;
  error?(message: string, data?: Record<string, unknown>): void;
}

export interface GuardrailsPluginApi {
  logger?: GuardrailsLogger;
  runtime?: Record<string, unknown>;
  getConfig?: () => unknown;
  registerTool?: (...args: unknown[]) => unknown;
  registerCommand?: (...args: unknown[]) => unknown;
  registerGatewayMethod?: (...args: unknown[]) => unknown;
  registerService?: (...args: unknown[]) => unknown;
  registerCli?: (...args: unknown[]) => unknown;
  registerHook?: (...args: unknown[]) => unknown;
}

export interface ResolverDependencies {
  config: GuardrailsConfig;
  logger?: GuardrailsLogger;
}

export function createDecision(
  stage: PermissionStage,
  action: DecisionAction,
  code: string,
  reason: string,
  overrides?: Partial<PermissionDecision>,
): PermissionDecision {
  return {
    stage,
    action,
    code,
    reason,
    ...overrides,
  };
}
