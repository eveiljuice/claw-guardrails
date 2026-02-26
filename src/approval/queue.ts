import { randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";

import { ApprovalEntry, PermissionDecision, PermissionRequest } from "../types.js";

interface QueueStoreFile {
  version: number;
  entries: ApprovalEntry[];
}

export interface ApprovalQueueOptions {
  storePath: string;
  timeoutSeconds: number;
}

function expandHome(rawPath: string): string {
  if (!rawPath.startsWith("~")) {
    return rawPath;
  }
  return path.join(os.homedir(), rawPath.slice(1));
}

function cloneEntry(entry: ApprovalEntry): ApprovalEntry {
  return JSON.parse(JSON.stringify(entry)) as ApprovalEntry;
}

export class ApprovalQueue {
  private readonly options: ApprovalQueueOptions;
  private readonly entries = new Map<string, ApprovalEntry>();
  private initialized = false;

  constructor(options: ApprovalQueueOptions) {
    this.options = options;
  }

  public async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }
    await this.loadFromDisk();
    this.initialized = true;
  }

  private async ensureInitialized(): Promise<void> {
    if (this.initialized) {
      return;
    }
    await this.initialize();
  }

  private get storePath(): string {
    return path.resolve(expandHome(this.options.storePath));
  }

  private async loadFromDisk(): Promise<void> {
    const filePath = this.storePath;
    try {
      const raw = await readFile(filePath, "utf-8");
      const parsed = JSON.parse(raw) as QueueStoreFile;
      if (!parsed || !Array.isArray(parsed.entries)) {
        return;
      }
      for (const entry of parsed.entries) {
        if (!entry || typeof entry.id !== "string") {
          continue;
        }
        this.entries.set(entry.id, entry);
      }
    } catch {
      // No queue file yet is expected on first run.
    }
  }

  private async persist(): Promise<void> {
    const filePath = this.storePath;
    await mkdir(path.dirname(filePath), { recursive: true });
    const payload: QueueStoreFile = {
      version: 1,
      entries: this.listAll(),
    };
    await writeFile(filePath, JSON.stringify(payload, null, 2), "utf-8");
  }

  public listAll(): ApprovalEntry[] {
    return Array.from(this.entries.values())
      .sort((a, b) => (a.createdAt > b.createdAt ? -1 : 1))
      .map(cloneEntry);
  }

  public listPending(): ApprovalEntry[] {
    return this.listAll().filter((entry) => entry.status === "pending");
  }

  public async get(id: string): Promise<ApprovalEntry | undefined> {
    await this.ensureInitialized();
    const entry = this.entries.get(id);
    return entry ? cloneEntry(entry) : undefined;
  }

  public async enqueue(
    request: PermissionRequest,
    decisionSnapshot: PermissionDecision,
  ): Promise<ApprovalEntry> {
    await this.ensureInitialized();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.options.timeoutSeconds * 1000);

    const entry: ApprovalEntry = {
      id: randomUUID(),
      status: "pending",
      request: JSON.parse(JSON.stringify(request)) as PermissionRequest,
      decisionSnapshot: JSON.parse(JSON.stringify(decisionSnapshot)) as PermissionDecision,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };
    this.entries.set(entry.id, entry);
    await this.persist();
    return cloneEntry(entry);
  }

  private async resolve(
    id: string,
    status: "approved" | "denied" | "expired",
    resolvedBy?: string,
    note?: string,
  ): Promise<ApprovalEntry | undefined> {
    await this.ensureInitialized();
    const entry = this.entries.get(id);
    if (!entry || entry.status !== "pending") {
      return undefined;
    }
    entry.status = status;
    entry.resolvedAt = new Date().toISOString();
    entry.resolvedBy = resolvedBy;
    entry.note = note;
    this.entries.set(id, entry);
    await this.persist();
    return cloneEntry(entry);
  }

  public async approve(id: string, resolvedBy?: string, note?: string): Promise<ApprovalEntry | undefined> {
    return this.resolve(id, "approved", resolvedBy, note);
  }

  public async deny(id: string, resolvedBy?: string, note?: string): Promise<ApprovalEntry | undefined> {
    return this.resolve(id, "denied", resolvedBy, note);
  }

  public async expirePending(now: Date = new Date()): Promise<ApprovalEntry[]> {
    await this.ensureInitialized();
    const expired: ApprovalEntry[] = [];
    for (const entry of this.entries.values()) {
      if (entry.status !== "pending") {
        continue;
      }
      const expiry = new Date(entry.expiresAt);
      if (Number.isNaN(expiry.getTime())) {
        continue;
      }
      if (expiry <= now) {
        entry.status = "expired";
        entry.resolvedAt = now.toISOString();
        entry.resolvedBy = "system:timeout";
        entry.note = "Approval timed out";
        this.entries.set(entry.id, entry);
        expired.push(cloneEntry(entry));
      }
    }
    if (expired.length > 0) {
      await this.persist();
    }
    return expired;
  }
}
