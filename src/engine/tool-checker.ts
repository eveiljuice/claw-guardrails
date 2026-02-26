import os from "node:os";
import path from "node:path";

import { minimatch } from "minimatch";

import {
  GuardrailsConfig,
  PermissionDecision,
  PermissionRequest,
  createDecision,
} from "../types.js";

const BUILTIN_DANGEROUS_ARG_PATTERNS: RegExp[] = [
  /--force\b/i,
  /--no-verify\b/i,
  /--hard\b/i,
  /--delete\b/i,
  /--all\b/i,
  /\s-rf\b/i,
  /-rf\s/i,
];

function toPosix(value: string): string {
  return value.replace(/\\/g, "/");
}

function expandHome(rawPath: string): string {
  if (!rawPath.startsWith("~")) {
    return rawPath;
  }
  return path.join(os.homedir(), rawPath.slice(1));
}

function normalizeFsPath(rawPath: string): string {
  return toPosix(path.resolve(expandHome(rawPath)));
}

function matchesGlob(value: string, pattern: string): boolean {
  return minimatch(value, toPosix(expandHome(pattern)), {
    nocase: true,
    dot: true,
  });
}

function isPathAllowed(targetPath: string, allow: string[], deny: string[]): boolean {
  if (deny.length > 0 && deny.some((pattern) => matchesGlob(targetPath, pattern))) {
    return false;
  }
  if (allow.length === 0) {
    return true;
  }
  return allow.some((pattern) => matchesGlob(targetPath, pattern));
}

function compileDynamicDangerousPatterns(config: GuardrailsConfig): RegExp[] {
  const patterns: RegExp[] = [];
  for (const rawPattern of config.dangerousArgPatterns) {
    try {
      patterns.push(new RegExp(rawPattern, "i"));
    } catch {
      // Invalid user regex should not break resolver.
    }
  }
  return patterns;
}

export function checkToolPermission(
  request: PermissionRequest,
  config: GuardrailsConfig,
): PermissionDecision {
  if (request.toolName !== "safe_exec") {
    return createDecision(
      "tool-checker",
      "allow",
      "TOOL_ALLOW_NON_EXEC",
      "Non-exec wrapper tool accepted by tool checker",
    );
  }

  const commandText = [request.command ?? "", ...(request.args ?? [])].join(" ").trim();
  if (commandText.length === 0) {
    return createDecision(
      "tool-checker",
      "deny",
      "TOOL_EXEC_MISSING_COMMAND",
      "safe_exec requires a command",
    );
  }

  if (
    config.resources.exec.deny.length > 0 &&
    config.resources.exec.deny.some((pattern) =>
      minimatch(commandText, pattern, { nocase: true, dot: true }),
    )
  ) {
    return createDecision(
      "tool-checker",
      "deny",
      "TOOL_EXEC_DENYLIST_MATCH",
      "Command matches exec denylist policy",
      { metadata: { command: commandText } },
    );
  }

  if (
    config.resources.exec.allow.length > 0 &&
    !config.resources.exec.allow.some((pattern) =>
      minimatch(commandText, pattern, { nocase: true, dot: true }),
    )
  ) {
    return createDecision(
      "tool-checker",
      "require_approval",
      "TOOL_EXEC_ALLOWLIST_MISS",
      "Command is outside exec allowlist and requires human approval",
      { metadata: { command: commandText } },
    );
  }

  if (request.cwd) {
    const normalizedCwd = normalizeFsPath(request.cwd);
    const cwdAllowed = isPathAllowed(
      normalizedCwd,
      config.resources.exec.cwdAllow,
      config.resources.exec.cwdDeny,
    );
    if (!cwdAllowed) {
      return createDecision(
        "tool-checker",
        "deny",
        "TOOL_EXEC_CWD_SCOPE_DENY",
        "Command cwd is outside allowed scope",
        { metadata: { cwd: normalizedCwd } },
      );
    }
  }

  const dynamicPatterns = compileDynamicDangerousPatterns(config);
  const allDangerousArgPatterns = [...BUILTIN_DANGEROUS_ARG_PATTERNS, ...dynamicPatterns];
  const suspiciousArgPattern = allDangerousArgPatterns.find((pattern) => pattern.test(commandText));
  if (suspiciousArgPattern) {
    return createDecision(
      "tool-checker",
      "require_approval",
      "TOOL_EXEC_SUSPICIOUS_ARGS",
      "Dangerous flag pattern detected in command arguments",
      {
        metadata: {
          command: commandText,
          pattern: suspiciousArgPattern.source,
        },
      },
    );
  }

  return createDecision("tool-checker", "allow", "TOOL_ALLOW", "Tool checks passed", {
    metadata: { command: commandText, cwd: request.cwd },
  });
}
