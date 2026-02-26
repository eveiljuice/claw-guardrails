import { Static, Type } from "@sinclair/typebox";

const DecisionActionSchema = Type.Union(
  [Type.Literal("allow"), Type.Literal("deny"), Type.Literal("require_approval")],
  { default: "deny" },
);

const RiskLevelSchema = Type.Union([
  Type.Literal("LOW"),
  Type.Literal("MEDIUM"),
  Type.Literal("HIGH"),
  Type.Literal("CRITICAL"),
]);

const PatternAllowDenySchema = Type.Object(
  {
    allow: Type.Array(Type.String(), { default: ["*"] }),
    deny: Type.Array(Type.String(), { default: [] }),
  },
  { additionalProperties: false },
);

const ContextTimeWindowSchema = Type.Object(
  {
    start: Type.String(),
    end: Type.String(),
    days: Type.Optional(Type.Array(Type.Integer({ minimum: 0, maximum: 6 }))),
    timezone: Type.Optional(Type.String()),
  },
  { additionalProperties: false },
);

const PolicyRuleSchema = Type.Object(
  {
    id: Type.String({ minLength: 1 }),
    description: Type.Optional(Type.String()),
    match: Type.Object(
      {
        tools: Type.Optional(Type.Array(Type.String())),
        commands: Type.Optional(Type.Array(Type.String())),
        resources: Type.Optional(Type.Array(Type.String())),
        riskLevel: Type.Optional(Type.Array(RiskLevelSchema)),
        senders: Type.Optional(Type.Array(Type.String())),
        channels: Type.Optional(Type.Array(Type.String())),
        agents: Type.Optional(Type.Array(Type.String())),
      },
      { additionalProperties: false },
    ),
    action: DecisionActionSchema,
    reason: Type.Optional(Type.String()),
  },
  { additionalProperties: false },
);

const FilesystemSchema = Type.Object(
  {
    readAllow: Type.Array(Type.String(), { default: ["**"] }),
    readDeny: Type.Array(Type.String(), { default: [] }),
    writeAllow: Type.Array(Type.String(), { default: ["~/.openclaw/workspace/**"] }),
    writeDeny: Type.Array(Type.String(), {
      default: ["~/.ssh/**", "~/.openclaw/credentials/**"],
    }),
  },
  { additionalProperties: false },
);

const NetworkSchema = Type.Object(
  {
    allow: Type.Array(Type.String(), { default: ["*"] }),
    deny: Type.Array(Type.String(), { default: [] }),
  },
  { additionalProperties: false },
);

const ExecSchema = Type.Object(
  {
    allow: Type.Array(Type.String(), { default: ["git *", "npm *", "node *", "ls", "cat", "rg *"] }),
    deny: Type.Array(Type.String(), { default: ["rm -rf *", "sudo *", "chmod 777 *", "curl * | bash"] }),
    cwdAllow: Type.Array(Type.String(), { default: ["~/.openclaw/workspace/**"] }),
    cwdDeny: Type.Array(Type.String(), {
      default: ["~/.ssh/**", "~/.openclaw/credentials/**"],
    }),
  },
  { additionalProperties: false },
);

const ChannelsSchema = Type.Object(
  {
    readAllow: Type.Array(Type.String(), { default: ["*"] }),
    writeAllow: Type.Array(Type.String(), { default: [] }),
    writeDeny: Type.Array(Type.String(), { default: [] }),
  },
  { additionalProperties: false },
);

const DatabaseSchema = Type.Object(
  {
    allowOperations: Type.Array(Type.String(), { default: ["select"] }),
    denyOperations: Type.Array(Type.String(), { default: ["drop", "truncate", "delete"] }),
  },
  { additionalProperties: false },
);

export const GuardrailsConfigSchema = Type.Object(
  {
    defaultAction: DecisionActionSchema,
    approvalTimeout: Type.Integer({ minimum: 1, default: 300 }),
    approvalFallback: DecisionActionSchema,
    approvalStorePath: Type.String({ default: "~/.openclaw/guardrails/pending.json" }),
    approvalNotifyChannel: Type.Optional(Type.String()),
    auditLog: Type.Boolean({ default: true }),
    auditLogPath: Type.String({ default: "~/.openclaw/guardrails/audit.jsonl" }),
    policies: Type.Array(PolicyRuleSchema, { default: [] }),
    contexts: Type.Object(
      {
        senders: PatternAllowDenySchema,
        channels: PatternAllowDenySchema,
        agents: PatternAllowDenySchema,
        timeWindows: Type.Array(ContextTimeWindowSchema, { default: [] }),
      },
      { additionalProperties: false },
    ),
    resources: Type.Object(
      {
        filesystem: FilesystemSchema,
        network: NetworkSchema,
        exec: ExecSchema,
        channels: ChannelsSchema,
        database: DatabaseSchema,
      },
      { additionalProperties: false },
    ),
    dangerousArgPatterns: Type.Array(Type.String(), {
      default: ["\\b--force\\b", "\\b--no-verify\\b", "\\b--hard\\b"],
    }),
  },
  { additionalProperties: false },
);

export type GuardrailsPluginConfig = Static<typeof GuardrailsConfigSchema>;
