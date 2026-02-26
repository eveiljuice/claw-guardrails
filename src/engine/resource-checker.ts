import os from "node:os";
import path from "node:path";

import { minimatch } from "minimatch";

import {
  GuardrailsConfig,
  PermissionDecision,
  PermissionRequest,
  PermissionResource,
  createDecision,
} from "../types.js";

function toPosix(value: string): string {
  return value.replace(/\\/g, "/");
}

function expandHome(rawValue: string): string {
  if (!rawValue.startsWith("~")) {
    return rawValue;
  }
  return path.join(os.homedir(), rawValue.slice(1));
}

function normalizePath(rawPath: string): string {
  return toPosix(path.resolve(expandHome(rawPath)));
}

function matchPattern(value: string, pattern: string): boolean {
  const normalizedPattern = toPosix(expandHome(pattern));
  return minimatch(value, normalizedPattern, { nocase: true, dot: true });
}

function parseHost(value: string): string {
  try {
    const parsed = new URL(value);
    return parsed.host.toLowerCase();
  } catch {
    return value.toLowerCase();
  }
}

function checkFilesystemResource(
  resource: PermissionResource,
  config: GuardrailsConfig,
): PermissionDecision | undefined {
  const targetPath = normalizePath(resource.value);
  const fsConfig = config.resources.filesystem;

  if (resource.kind === "filesystem_read") {
    if (fsConfig.readDeny.some((pattern) => matchPattern(targetPath, pattern))) {
      return createDecision(
        "resource-checker",
        "deny",
        "RESOURCE_FS_READ_DENY",
        "Filesystem read path is denylisted",
        { metadata: { path: targetPath } },
      );
    }
    if (
      fsConfig.readAllow.length > 0 &&
      !fsConfig.readAllow.some((pattern) => matchPattern(targetPath, pattern))
    ) {
      return createDecision(
        "resource-checker",
        "deny",
        "RESOURCE_FS_READ_NOT_ALLOWED",
        "Filesystem read path is outside allowlist",
        { metadata: { path: targetPath } },
      );
    }
    return undefined;
  }

  if (resource.kind === "filesystem_write") {
    if (fsConfig.writeDeny.some((pattern) => matchPattern(targetPath, pattern))) {
      return createDecision(
        "resource-checker",
        "deny",
        "RESOURCE_FS_WRITE_DENY",
        "Filesystem write path is denylisted",
        { metadata: { path: targetPath } },
      );
    }
    if (
      fsConfig.writeAllow.length > 0 &&
      !fsConfig.writeAllow.some((pattern) => matchPattern(targetPath, pattern))
    ) {
      return createDecision(
        "resource-checker",
        "require_approval",
        "RESOURCE_FS_WRITE_NEEDS_APPROVAL",
        "Filesystem write path is outside allowlist",
        { metadata: { path: targetPath } },
      );
    }
  }

  return undefined;
}

function checkNetworkResource(
  resource: PermissionResource,
  config: GuardrailsConfig,
): PermissionDecision | undefined {
  if (resource.kind !== "network") {
    return undefined;
  }
  const host = parseHost(resource.value);

  if (config.resources.network.deny.some((pattern) => minimatch(host, pattern, { nocase: true }))) {
    return createDecision(
      "resource-checker",
      "deny",
      "RESOURCE_NETWORK_DENY",
      "Network host is denylisted",
      { metadata: { host } },
    );
  }

  if (
    config.resources.network.allow.length > 0 &&
    !config.resources.network.allow.some((pattern) => minimatch(host, pattern, { nocase: true }))
  ) {
    return createDecision(
      "resource-checker",
      "require_approval",
      "RESOURCE_NETWORK_NEEDS_APPROVAL",
      "Network host is outside allowlist",
      { metadata: { host } },
    );
  }

  return undefined;
}

function checkDatabaseResource(
  resource: PermissionResource,
  config: GuardrailsConfig,
): PermissionDecision | undefined {
  if (resource.kind !== "database") {
    return undefined;
  }
  const operation = (resource.operation ?? "").toLowerCase();
  if (operation.length === 0) {
    return createDecision(
      "resource-checker",
      "require_approval",
      "RESOURCE_DB_UNKNOWN_OPERATION",
      "Database operation is missing and requires approval",
    );
  }

  if (config.resources.database.denyOperations.includes(operation)) {
    return createDecision(
      "resource-checker",
      "deny",
      "RESOURCE_DB_DENY_OPERATION",
      `Database operation '${operation}' is denylisted`,
      { metadata: { operation } },
    );
  }

  if (
    config.resources.database.allowOperations.length > 0 &&
    !config.resources.database.allowOperations.includes(operation)
  ) {
    return createDecision(
      "resource-checker",
      "require_approval",
      "RESOURCE_DB_NEEDS_APPROVAL",
      `Database operation '${operation}' is outside allowlist`,
      { metadata: { operation } },
    );
  }

  return undefined;
}

function checkChannelResource(
  resource: PermissionResource,
  config: GuardrailsConfig,
): PermissionDecision | undefined {
  const channelsConfig = config.resources.channels;
  if (resource.kind === "channel_read") {
    if (
      channelsConfig.readAllow.length > 0 &&
      !channelsConfig.readAllow.some((pattern) => minimatch(resource.value, pattern, { nocase: true }))
    ) {
      return createDecision(
        "resource-checker",
        "deny",
        "RESOURCE_CHANNEL_READ_NOT_ALLOWED",
        "Channel is outside read allowlist",
        { metadata: { channel: resource.value } },
      );
    }
    return undefined;
  }

  if (resource.kind === "channel_write") {
    if (channelsConfig.writeDeny.some((pattern) => minimatch(resource.value, pattern, { nocase: true }))) {
      return createDecision(
        "resource-checker",
        "deny",
        "RESOURCE_CHANNEL_WRITE_DENY",
        "Channel write target is denylisted",
        { metadata: { channel: resource.value } },
      );
    }
    if (
      channelsConfig.writeAllow.length > 0 &&
      !channelsConfig.writeAllow.some((pattern) => minimatch(resource.value, pattern, { nocase: true }))
    ) {
      return createDecision(
        "resource-checker",
        "require_approval",
        "RESOURCE_CHANNEL_WRITE_NEEDS_APPROVAL",
        "Channel write target is outside allowlist",
        { metadata: { channel: resource.value } },
      );
    }
  }

  return undefined;
}

function implicitResources(request: PermissionRequest): PermissionResource[] {
  if (request.toolName !== "safe_send") {
    return [];
  }
  const channel = request.context.channelId ?? "unknown-channel";
  return [
    {
      kind: "channel_write",
      value: channel,
    },
  ];
}

export function checkResourcePermission(
  request: PermissionRequest,
  config: GuardrailsConfig,
): PermissionDecision {
  const resources = [...(request.resources ?? []), ...implicitResources(request)];
  for (const resource of resources) {
    const fsDecision = checkFilesystemResource(resource, config);
    if (fsDecision) {
      return fsDecision;
    }

    const networkDecision = checkNetworkResource(resource, config);
    if (networkDecision) {
      return networkDecision;
    }

    const dbDecision = checkDatabaseResource(resource, config);
    if (dbDecision) {
      return dbDecision;
    }

    const channelDecision = checkChannelResource(resource, config);
    if (channelDecision) {
      return channelDecision;
    }
  }

  return createDecision(
    "resource-checker",
    "allow",
    "RESOURCE_ALLOW",
    "Resource checks passed",
    {
      metadata: {
        checkedResources: resources.length,
      },
    },
  );
}
