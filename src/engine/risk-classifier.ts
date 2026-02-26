import {
  PermissionRequest,
  RiskAssessment,
  RiskLevel,
  RiskPatternMatch,
} from "../types.js";

interface RiskPattern {
  source: RiskPatternMatch["source"];
  id: string;
  reason: string;
  level: RiskLevel;
  score: number;
  pattern: RegExp;
}

const RISK_SCORE_BY_LEVEL: Record<RiskLevel, number> = {
  LOW: 20,
  MEDIUM: 45,
  HIGH: 75,
  CRITICAL: 95,
};

const SHELL_PATTERNS: RiskPattern[] = [
  {
    source: "shell",
    id: "shell.rm-force",
    reason: "Potentially destructive recursive remove command",
    level: "CRITICAL",
    score: 98,
    pattern: /\brm\s+-[^\n]*r[^\n]*f\b/,
  },
  {
    source: "shell",
    id: "shell.sudo",
    reason: "Privilege escalation via sudo",
    level: "CRITICAL",
    score: 96,
    pattern: /\bsudo\b/,
  },
  {
    source: "shell",
    id: "shell.chmod-777",
    reason: "Overly broad file permissions change",
    level: "HIGH",
    score: 80,
    pattern: /\bchmod\s+777\b/,
  },
  {
    source: "shell",
    id: "shell.curl-pipe-bash",
    reason: "Remote script execution pipeline",
    level: "CRITICAL",
    score: 97,
    pattern: /\bcurl\b[^\n|]*\|\s*(bash|sh)\b/,
  },
  {
    source: "shell",
    id: "shell.shutdown",
    reason: "Host shutdown/reboot command",
    level: "CRITICAL",
    score: 99,
    pattern: /\b(shutdown|reboot|halt)\b/,
  },
  {
    source: "shell",
    id: "shell.move-delete",
    reason: "Potential destructive filesystem mutation",
    level: "HIGH",
    score: 74,
    pattern: /\b(mv|dd|mkfs|fdisk)\b/,
  },
];

const GIT_PATTERNS: RiskPattern[] = [
  {
    source: "git",
    id: "git.force-push",
    reason: "Force push can rewrite remote history",
    level: "HIGH",
    score: 78,
    pattern: /\bgit\s+push\b[^\n]*--force(?:-with-lease)?\b/,
  },
  {
    source: "git",
    id: "git.reset-hard",
    reason: "Hard reset can discard local changes",
    level: "HIGH",
    score: 76,
    pattern: /\bgit\s+reset\b[^\n]*--hard\b/,
  },
  {
    source: "git",
    id: "git.clean-force",
    reason: "Clean with force deletes untracked files",
    level: "HIGH",
    score: 80,
    pattern: /\bgit\s+clean\b[^\n]*\s-f\b/,
  },
  {
    source: "git",
    id: "git.commit",
    reason: "Commit mutates repository history",
    level: "MEDIUM",
    score: 50,
    pattern: /\bgit\s+commit\b/,
  },
];

const NPM_PATTERNS: RiskPattern[] = [
  {
    source: "npm",
    id: "npm.publish",
    reason: "Publishing package is externally visible",
    level: "HIGH",
    score: 82,
    pattern: /\b(npm|pnpm|yarn)\s+publish\b/,
  },
  {
    source: "npm",
    id: "npm.script-force",
    reason: "Forced package manager operation",
    level: "MEDIUM",
    score: 55,
    pattern: /\b(npm|pnpm|yarn)\b[^\n]*--force\b/,
  },
  {
    source: "npm",
    id: "npm.install",
    reason: "Dependency installation mutates lockfiles",
    level: "MEDIUM",
    score: 45,
    pattern: /\b(npm|pnpm|yarn)\s+(install|add|up|upgrade)\b/,
  },
];

const DOCKER_PATTERNS: RiskPattern[] = [
  {
    source: "docker",
    id: "docker.system-prune",
    reason: "Docker system prune can remove volumes/images",
    level: "HIGH",
    score: 85,
    pattern: /\bdocker\s+system\s+prune\b/,
  },
  {
    source: "docker",
    id: "docker.rm-force",
    reason: "Force remove container/image",
    level: "HIGH",
    score: 78,
    pattern: /\bdocker\s+(rm|rmi)\b[^\n]*\s-f\b/,
  },
  {
    source: "docker",
    id: "docker.exec-root",
    reason: "Executing shell with elevated container context",
    level: "MEDIUM",
    score: 60,
    pattern: /\bdocker\s+exec\b/,
  },
];

const EMAIL_PATTERNS: RiskPattern[] = [
  {
    source: "email",
    id: "email.delete",
    reason: "Email deletion can be irreversible",
    level: "CRITICAL",
    score: 99,
    pattern: /\b(gmail|email)\b[^\n]*(delete|trash|purge|remove)\b/,
  },
  {
    source: "email",
    id: "email.send",
    reason: "Email send is externally visible",
    level: "HIGH",
    score: 74,
    pattern: /\b(gmail|email)\b[^\n]*(send|reply|forward)\b/,
  },
];

const CHANNEL_PATTERNS: RiskPattern[] = [
  {
    source: "channel",
    id: "channel.post",
    reason: "Posting to channel is externally visible",
    level: "HIGH",
    score: 72,
    pattern: /\b(post|publish|send)\b[^\n]*(telegram|discord|slack|channel|group)\b|\b(telegram|discord|slack|channel|group)\b[^\n]*(post|publish|send)\b/,
  },
  {
    source: "channel",
    id: "channel.delete",
    reason: "Deleting/editing channel content can be destructive",
    level: "HIGH",
    score: 80,
    pattern: /\b(edit|delete|remove)\b[^\n]*(message|post|channel)\b/,
  },
];

const LOW_RISK_READ_ONLY_PATTERNS: RegExp[] = [
  /^\s*ls(?:\s|$)/,
  /^\s*pwd(?:\s|$)/,
  /^\s*cat(?:\s|$)/,
  /^\s*rg(?:\s|$)/,
  /^\s*grep(?:\s|$)/,
  /^\s*git\s+(status|diff|log)(?:\s|$)/,
  /^\s*head(?:\s|$)/,
  /^\s*tail(?:\s|$)/,
];

const ALL_PATTERN_GROUPS: RiskPattern[] = [
  ...SHELL_PATTERNS,
  ...GIT_PATTERNS,
  ...NPM_PATTERNS,
  ...DOCKER_PATTERNS,
  ...EMAIL_PATTERNS,
  ...CHANNEL_PATTERNS,
];

function levelRank(level: RiskLevel): number {
  switch (level) {
    case "LOW":
      return 1;
    case "MEDIUM":
      return 2;
    case "HIGH":
      return 3;
    case "CRITICAL":
      return 4;
  }
}

function scoreToLevel(score: number): RiskLevel {
  if (score >= 90) {
    return "CRITICAL";
  }
  if (score >= 70) {
    return "HIGH";
  }
  if (score >= 40) {
    return "MEDIUM";
  }
  return "LOW";
}

function buildSearchText(request: PermissionRequest): string {
  const commandText = [request.command ?? "", ...(request.args ?? [])].join(" ").trim();
  const payloadText =
    typeof request.payload === "string"
      ? request.payload
      : JSON.stringify(request.payload ?? {});
  const resourceText = (request.resources ?? [])
    .map((resource) => `${resource.kind}:${resource.value}:${resource.operation ?? ""}`)
    .join(" ");
  return [request.toolName, request.action ?? "", commandText, payloadText, resourceText]
    .join(" ")
    .toLowerCase();
}

function addResourceSignals(request: PermissionRequest, baseScore: number, reasons: string[]): number {
  let score = baseScore;
  for (const resource of request.resources ?? []) {
    if (resource.kind === "channel_write") {
      score = Math.max(score, 72);
      reasons.push("Channel write resource detected");
    } else if (resource.kind === "filesystem_write") {
      score = Math.max(score, 45);
      reasons.push("Filesystem write resource detected");
    } else if (resource.kind === "database") {
      const operation = (resource.operation ?? "").toLowerCase();
      if (operation.includes("drop") || operation.includes("truncate") || operation.includes("delete")) {
        score = Math.max(score, 96);
        reasons.push(`Destructive database operation: ${operation}`);
      } else if (operation.length > 0) {
        score = Math.max(score, 50);
        reasons.push(`Database operation: ${operation}`);
      }
    }
  }
  return score;
}

function fromPattern(pattern: RiskPattern): RiskPatternMatch {
  return {
    source: pattern.source,
    pattern: pattern.id,
    reason: pattern.reason,
    level: pattern.level,
    score: pattern.score,
  };
}

export function classifyRisk(request: PermissionRequest): RiskAssessment {
  const searchText = buildSearchText(request);
  const matchedPatterns: RiskPatternMatch[] = [];
  const reasons: string[] = [];

  let score = 0;
  for (const pattern of ALL_PATTERN_GROUPS) {
    if (pattern.pattern.test(searchText)) {
      matchedPatterns.push(fromPattern(pattern));
      reasons.push(pattern.reason);
      score = Math.max(score, pattern.score);
    }
  }

  if (request.toolName === "safe_send") {
    score = Math.max(score, RISK_SCORE_BY_LEVEL.HIGH);
    reasons.push("safe_send is externally visible by default");
  }

  if (request.toolName === "safe_action" && score < RISK_SCORE_BY_LEVEL.MEDIUM) {
    score = RISK_SCORE_BY_LEVEL.MEDIUM;
    reasons.push("safe_action uses generic mutation-capable payload");
  }

  if (request.toolName === "safe_exec") {
    const commandText = [request.command ?? "", ...(request.args ?? [])].join(" ").toLowerCase();
    if (commandText.length > 0 && LOW_RISK_READ_ONLY_PATTERNS.some((pattern) => pattern.test(commandText))) {
      score = Math.max(score, RISK_SCORE_BY_LEVEL.LOW);
      reasons.push("Read-only shell command pattern matched");
    } else if (commandText.length > 0 && score < RISK_SCORE_BY_LEVEL.MEDIUM) {
      score = RISK_SCORE_BY_LEVEL.MEDIUM;
      reasons.push("Unknown shell command treated as mutable operation");
    }
  }

  score = addResourceSignals(request, score, reasons);

  if (score === 0) {
    score = RISK_SCORE_BY_LEVEL.LOW;
    reasons.push("No destructive indicators were detected");
  }

  const inferredLevel = scoreToLevel(score);
  const strongestMatch = matchedPatterns
    .slice()
    .sort((a, b) => levelRank(b.level) - levelRank(a.level))[0];
  const level = strongestMatch ? strongestMatch.level : inferredLevel;
  const dedupedReasons = Array.from(new Set(reasons));

  return {
    level,
    score,
    reasons: dedupedReasons,
    matches: matchedPatterns,
  };
}
