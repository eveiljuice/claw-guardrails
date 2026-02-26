import { isValid, parse } from "date-fns";
import { minimatch } from "minimatch";

import {
  GuardrailsConfig,
  PatternAllowDeny,
  PermissionDecision,
  PermissionRequest,
  createDecision,
} from "../types.js";

function matchesAny(value: string, patterns: string[]): boolean {
  return patterns.some((pattern) => minimatch(value, pattern, { nocase: true, dot: true }));
}

function evalAllowDeny(
  value: string,
  subject: "sender" | "channel" | "agent",
  rules: PatternAllowDeny,
): PermissionDecision | undefined {
  if (rules.deny.length > 0 && matchesAny(value, rules.deny)) {
    return createDecision(
      "context-matcher",
      "deny",
      `CONTEXT_${subject.toUpperCase()}_DENYLIST`,
      `${subject} is blocked by denylist`,
      { metadata: { subject, value } },
    );
  }

  if (rules.allow.length > 0 && !matchesAny(value, rules.allow)) {
    return createDecision(
      "context-matcher",
      "deny",
      `CONTEXT_${subject.toUpperCase()}_NOT_ALLOWED`,
      `${subject} is not included in allowlist`,
      { metadata: { subject, value } },
    );
  }

  return undefined;
}

function parseMinutes(raw: string): number | null {
  const parsed = parse(raw, "HH:mm", new Date());
  if (!isValid(parsed)) {
    return null;
  }
  return parsed.getHours() * 60 + parsed.getMinutes();
}

function isInsideTimeWindow(request: PermissionRequest, config: GuardrailsConfig): boolean {
  const windows = config.contexts.timeWindows;
  if (windows.length === 0) {
    return true;
  }

  const now = request.context.requestedAt ? new Date(request.context.requestedAt) : new Date();
  if (Number.isNaN(now.getTime())) {
    return false;
  }
  const nowMinutes = now.getHours() * 60 + now.getMinutes();
  const currentDay = now.getDay();

  for (const window of windows) {
    if (window.days && window.days.length > 0 && !window.days.includes(currentDay)) {
      continue;
    }
    const startMinutes = parseMinutes(window.start);
    const endMinutes = parseMinutes(window.end);
    if (startMinutes === null || endMinutes === null) {
      continue;
    }
    if (startMinutes <= endMinutes) {
      if (nowMinutes >= startMinutes && nowMinutes <= endMinutes) {
        return true;
      }
      continue;
    }
    if (nowMinutes >= startMinutes || nowMinutes <= endMinutes) {
      return true;
    }
  }

  return false;
}

export function matchContext(
  request: PermissionRequest,
  config: GuardrailsConfig,
): PermissionDecision {
  const sender = request.context.senderId ?? "unknown-sender";
  const channel = request.context.channelId ?? "unknown-channel";
  const agent = request.context.agentId ?? "unknown-agent";

  const senderDecision = evalAllowDeny(sender, "sender", config.contexts.senders);
  if (senderDecision) {
    return senderDecision;
  }

  const channelDecision = evalAllowDeny(channel, "channel", config.contexts.channels);
  if (channelDecision) {
    return channelDecision;
  }

  const agentDecision = evalAllowDeny(agent, "agent", config.contexts.agents);
  if (agentDecision) {
    return agentDecision;
  }

  const timeAllowed = isInsideTimeWindow(request, config);
  if (!timeAllowed) {
    return createDecision(
      "context-matcher",
      "deny",
      "CONTEXT_TIME_WINDOW_DENY",
      "Request is outside allowed time windows",
      { metadata: { requestedAt: request.context.requestedAt } },
    );
  }

  return createDecision(
    "context-matcher",
    "allow",
    "CONTEXT_ALLOW",
    "Context checks passed",
    {
      metadata: {
        sender,
        channel,
        agent,
      },
    },
  );
}
