import { minimatch } from "minimatch";

import {
  GuardrailsConfig,
  PermissionDecision,
  PermissionRequest,
  PolicyRule,
  RiskAssessment,
  createDecision,
} from "../types.js";

function matchField(value: string, patterns?: string[]): boolean {
  if (!patterns || patterns.length === 0) {
    return true;
  }
  return patterns.some((pattern) => minimatch(value, pattern, { nocase: true, dot: true }));
}

function matchArrayField(values: string[], patterns?: string[]): boolean {
  if (!patterns || patterns.length === 0) {
    return true;
  }
  if (values.length === 0) {
    return false;
  }
  return values.some((value) =>
    patterns.some((pattern) => minimatch(value, pattern, { nocase: true, dot: true })),
  );
}

function buildCommandText(request: PermissionRequest): string {
  return [request.command ?? "", ...(request.args ?? [])].join(" ").trim();
}

function extractResourceKeys(request: PermissionRequest): string[] {
  return (request.resources ?? []).map((resource) => `${resource.kind}:${resource.value}`);
}

function ruleMatches(rule: PolicyRule, request: PermissionRequest, risk: RiskAssessment): boolean {
  const sender = request.context.senderId ?? "unknown-sender";
  const channel = request.context.channelId ?? "unknown-channel";
  const agent = request.context.agentId ?? "unknown-agent";
  const command = buildCommandText(request);
  const resources = extractResourceKeys(request);

  if (!matchField(request.toolName, rule.match.tools)) {
    return false;
  }
  if (!matchField(command, rule.match.commands)) {
    return false;
  }
  if (!matchArrayField(resources, rule.match.resources)) {
    return false;
  }
  if (rule.match.riskLevel && rule.match.riskLevel.length > 0 && !rule.match.riskLevel.includes(risk.level)) {
    return false;
  }
  if (!matchField(sender, rule.match.senders)) {
    return false;
  }
  if (!matchField(channel, rule.match.channels)) {
    return false;
  }
  if (!matchField(agent, rule.match.agents)) {
    return false;
  }
  return true;
}

function defaultReason(action: PermissionDecision["action"]): string {
  switch (action) {
    case "allow":
      return "No policy matched; action allowed by default";
    case "deny":
      return "No policy matched; action denied by default";
    case "require_approval":
      return "No policy matched; human approval is required by default";
  }
}

export function evaluatePolicy(
  request: PermissionRequest,
  risk: RiskAssessment,
  config: GuardrailsConfig,
): PermissionDecision {
  for (const rule of config.policies) {
    if (!ruleMatches(rule, request, risk)) {
      continue;
    }
    return createDecision(
      "policy-engine",
      rule.action,
      `POLICY_MATCH_${rule.id}`,
      rule.reason ?? `Matched policy '${rule.id}'`,
      {
        matchedPolicyId: rule.id,
        risk,
      },
    );
  }

  return createDecision(
    "policy-engine",
    config.defaultAction,
    "POLICY_DEFAULT_ACTION",
    defaultReason(config.defaultAction),
    { risk },
  );
}
