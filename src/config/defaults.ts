import {
  DecisionAction,
  GuardrailsConfig,
  PatternAllowDeny,
  PolicyRule,
  ResourceKind,
} from "../types.js";

const DEFAULT_POLICIES: PolicyRule[] = [
  {
    id: "allow-safe-reads",
    description: "Allow known low-risk read-only operations",
    match: {
      riskLevel: ["LOW"],
    },
    action: "allow",
  },
  {
    id: "block-critical",
    description: "Block critical operations without exception",
    match: {
      riskLevel: ["CRITICAL"],
    },
    action: "deny",
    reason: "Critical risk operations are blocked by default policy",
  },
  {
    id: "approve-medium-high",
    description: "Require approval for medium/high risk operations",
    match: {
      riskLevel: ["MEDIUM", "HIGH"],
    },
    action: "require_approval",
  },
  {
    id: "channel-write-needs-approval",
    description: "Writing to channels requires approval unless explicitly allowed",
    match: {
      resources: ["channel_write:*"],
    },
    action: "require_approval",
  },
];

export const defaultGuardrailsConfig: GuardrailsConfig = {
  defaultAction: "deny",
  approvalTimeout: 300,
  approvalFallback: "deny",
  approvalStorePath: "~/.openclaw/guardrails/pending.json",
  auditLog: true,
  auditLogPath: "~/.openclaw/guardrails/audit.jsonl",
  policies: DEFAULT_POLICIES,
  contexts: {
    senders: {
      allow: ["*"],
      deny: [],
    },
    channels: {
      allow: ["*"],
      deny: [],
    },
    agents: {
      allow: ["*"],
      deny: [],
    },
    timeWindows: [],
  },
  resources: {
    filesystem: {
      readAllow: ["**"],
      readDeny: [],
      writeAllow: ["~/.openclaw/workspace/**"],
      writeDeny: ["~/.ssh/**", "~/.openclaw/credentials/**"],
    },
    network: {
      allow: ["*"],
      deny: [],
    },
    exec: {
      allow: ["git *", "npm *", "node *", "ls", "cat", "rg *"],
      deny: ["rm -rf *", "sudo *", "chmod 777 *", "curl * | bash"],
      cwdAllow: ["~/.openclaw/workspace/**"],
      cwdDeny: ["~/.ssh/**", "~/.openclaw/credentials/**"],
    },
    channels: {
      readAllow: ["*"],
      writeAllow: [],
      writeDeny: [],
    },
    database: {
      allowOperations: ["select"],
      denyOperations: ["drop", "truncate", "delete"],
    },
  },
  dangerousArgPatterns: [
    "\\b--force\\b",
    "\\b--no-verify\\b",
    "\\b--hard\\b",
    "\\b--delete\\b",
    "\\b--all\\b",
    "\\b-rf\\b",
  ],
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toAction(value: unknown, fallback: DecisionAction): DecisionAction {
  if (value === "allow" || value === "deny" || value === "require_approval") {
    return value;
  }
  return fallback;
}

function toPositiveInt(value: unknown, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fallback;
  }
  const rounded = Math.round(value);
  return rounded > 0 ? rounded : fallback;
}

function toStringArray(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) {
    return fallback;
  }
  const filtered = value.filter((entry): entry is string => typeof entry === "string");
  if (value.length > 0 && filtered.length === 0) {
    return fallback;
  }
  return filtered;
}

function mergePatternAllowDeny(input: unknown, fallback: PatternAllowDeny): PatternAllowDeny {
  if (!isRecord(input)) {
    return fallback;
  }
  return {
    allow: toStringArray(input.allow, fallback.allow),
    deny: toStringArray(input.deny, fallback.deny),
  };
}

function toResourcePatternArray(value: unknown, fallback: string[]): string[] {
  return toStringArray(value, fallback);
}

function toResourceKind(value: unknown): ResourceKind | undefined {
  switch (value) {
    case "filesystem_read":
    case "filesystem_write":
    case "network":
    case "database":
    case "channel_read":
    case "channel_write":
    case "exec":
    case "unknown":
      return value;
    default:
      return undefined;
  }
}

function sanitizePolicies(input: unknown, fallback: PolicyRule[]): PolicyRule[] {
  if (!Array.isArray(input)) {
    return fallback;
  }
  const policies: PolicyRule[] = [];
  for (const candidate of input) {
    if (!isRecord(candidate) || typeof candidate.id !== "string" || !isRecord(candidate.match)) {
      continue;
    }
    const action = toAction(candidate.action, "deny");
    const matchRecord = candidate.match as Record<string, unknown>;
    const resources = toStringArray(matchRecord.resources, []);
    const riskLevel = toStringArray(matchRecord.riskLevel, []).filter(
      (level): level is "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" =>
        level === "LOW" || level === "MEDIUM" || level === "HIGH" || level === "CRITICAL",
    );

    policies.push({
      id: candidate.id,
      description: typeof candidate.description === "string" ? candidate.description : undefined,
      action,
      reason: typeof candidate.reason === "string" ? candidate.reason : undefined,
      match: {
        tools: toStringArray(matchRecord.tools, []),
        commands: toStringArray(matchRecord.commands, []),
        resources,
        riskLevel,
        senders: toStringArray(matchRecord.senders, []),
        channels: toStringArray(matchRecord.channels, []),
        agents: toStringArray(matchRecord.agents, []),
      },
    });
  }
  return policies.length > 0 ? policies : fallback;
}

export function resolveGuardrailsConfig(rawConfig: unknown): GuardrailsConfig {
  if (!isRecord(rawConfig)) {
    return defaultGuardrailsConfig;
  }

  const contexts = isRecord(rawConfig.contexts) ? rawConfig.contexts : {};
  const resources = isRecord(rawConfig.resources) ? rawConfig.resources : {};
  const filesystem = isRecord(resources.filesystem) ? resources.filesystem : {};
  const network = isRecord(resources.network) ? resources.network : {};
  const exec = isRecord(resources.exec) ? resources.exec : {};
  const channels = isRecord(resources.channels) ? resources.channels : {};
  const database = isRecord(resources.database) ? resources.database : {};

  const merged: GuardrailsConfig = {
    defaultAction: toAction(rawConfig.defaultAction, defaultGuardrailsConfig.defaultAction),
    approvalTimeout: toPositiveInt(rawConfig.approvalTimeout, defaultGuardrailsConfig.approvalTimeout),
    approvalFallback: toAction(rawConfig.approvalFallback, defaultGuardrailsConfig.approvalFallback),
    approvalStorePath:
      typeof rawConfig.approvalStorePath === "string"
        ? rawConfig.approvalStorePath
        : defaultGuardrailsConfig.approvalStorePath,
    approvalNotifyChannel:
      typeof rawConfig.approvalNotifyChannel === "string" ? rawConfig.approvalNotifyChannel : undefined,
    auditLog: typeof rawConfig.auditLog === "boolean" ? rawConfig.auditLog : defaultGuardrailsConfig.auditLog,
    auditLogPath:
      typeof rawConfig.auditLogPath === "string"
        ? rawConfig.auditLogPath
        : defaultGuardrailsConfig.auditLogPath,
    policies: sanitizePolicies(rawConfig.policies, defaultGuardrailsConfig.policies),
    contexts: {
      senders: mergePatternAllowDeny(contexts.senders, defaultGuardrailsConfig.contexts.senders),
      channels: mergePatternAllowDeny(contexts.channels, defaultGuardrailsConfig.contexts.channels),
      agents: mergePatternAllowDeny(contexts.agents, defaultGuardrailsConfig.contexts.agents),
      timeWindows: Array.isArray(contexts.timeWindows)
        ? contexts.timeWindows
            .filter((window): window is Record<string, unknown> => isRecord(window))
            .filter(
              (window) => typeof window.start === "string" && typeof window.end === "string",
            )
            .map((window) => ({
              start: window.start as string,
              end: window.end as string,
              days: Array.isArray(window.days)
                ? window.days.filter(
                    (day): day is number => typeof day === "number" && day >= 0 && day <= 6,
                  )
                : undefined,
              timezone: typeof window.timezone === "string" ? window.timezone : undefined,
            }))
        : defaultGuardrailsConfig.contexts.timeWindows,
    },
    resources: {
      filesystem: {
        readAllow: toResourcePatternArray(filesystem.readAllow, defaultGuardrailsConfig.resources.filesystem.readAllow),
        readDeny: toResourcePatternArray(filesystem.readDeny, defaultGuardrailsConfig.resources.filesystem.readDeny),
        writeAllow: toResourcePatternArray(
          filesystem.writeAllow,
          defaultGuardrailsConfig.resources.filesystem.writeAllow,
        ),
        writeDeny: toResourcePatternArray(
          filesystem.writeDeny,
          defaultGuardrailsConfig.resources.filesystem.writeDeny,
        ),
      },
      network: {
        allow: toResourcePatternArray(network.allow, defaultGuardrailsConfig.resources.network.allow),
        deny: toResourcePatternArray(network.deny, defaultGuardrailsConfig.resources.network.deny),
      },
      exec: {
        allow: toResourcePatternArray(exec.allow, defaultGuardrailsConfig.resources.exec.allow),
        deny: toResourcePatternArray(exec.deny, defaultGuardrailsConfig.resources.exec.deny),
        cwdAllow: toResourcePatternArray(exec.cwdAllow, defaultGuardrailsConfig.resources.exec.cwdAllow),
        cwdDeny: toResourcePatternArray(exec.cwdDeny, defaultGuardrailsConfig.resources.exec.cwdDeny),
      },
      channels: {
        readAllow: toResourcePatternArray(channels.readAllow, defaultGuardrailsConfig.resources.channels.readAllow),
        writeAllow: toResourcePatternArray(channels.writeAllow, defaultGuardrailsConfig.resources.channels.writeAllow),
        writeDeny: toResourcePatternArray(channels.writeDeny, defaultGuardrailsConfig.resources.channels.writeDeny),
      },
      database: {
        allowOperations: toStringArray(
          database.allowOperations,
          defaultGuardrailsConfig.resources.database.allowOperations,
        ).map((value) => value.toLowerCase()),
        denyOperations: toStringArray(
          database.denyOperations,
          defaultGuardrailsConfig.resources.database.denyOperations,
        ).map((value) => value.toLowerCase()),
      },
    },
    dangerousArgPatterns: toStringArray(
      rawConfig.dangerousArgPatterns,
      defaultGuardrailsConfig.dangerousArgPatterns,
    ),
  };

  // Keep at least one policy and at least one agent allow rule.
  if (merged.policies.length === 0) {
    merged.policies = defaultGuardrailsConfig.policies;
  }
  if (merged.contexts.agents.allow.length === 0) {
    merged.contexts.agents.allow = defaultGuardrailsConfig.contexts.agents.allow;
  }
  return merged;
}

export function inferResourceKind(raw: string): ResourceKind | undefined {
  return toResourceKind(raw);
}
