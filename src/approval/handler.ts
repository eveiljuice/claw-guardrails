import { ApprovalQueue } from "./queue.js";

import { ApprovalEntry, ApprovalResolutionResult } from "../types.js";

export interface ApprovalQueueSummary {
  pending: number;
  approved: number;
  denied: number;
  expired: number;
  total: number;
}

function summarize(entries: ApprovalEntry[]): ApprovalQueueSummary {
  return entries.reduce<ApprovalQueueSummary>(
    (acc, entry) => {
      acc.total += 1;
      if (entry.status === "pending") {
        acc.pending += 1;
      } else if (entry.status === "approved") {
        acc.approved += 1;
      } else if (entry.status === "denied") {
        acc.denied += 1;
      } else if (entry.status === "expired") {
        acc.expired += 1;
      }
      return acc;
    },
    {
      pending: 0,
      approved: 0,
      denied: 0,
      expired: 0,
      total: 0,
    },
  );
}

export class ApprovalHandler {
  private readonly queue: ApprovalQueue;

  constructor(queue: ApprovalQueue) {
    this.queue = queue;
  }

  public async listPending(): Promise<ApprovalEntry[]> {
    await this.queue.initialize();
    return this.queue.listPending();
  }

  public async listAll(): Promise<ApprovalEntry[]> {
    await this.queue.initialize();
    return this.queue.listAll();
  }

  public async queueSummary(): Promise<ApprovalQueueSummary> {
    const entries = await this.listAll();
    return summarize(entries);
  }

  public async approve(id: string, resolvedBy?: string, note?: string): Promise<ApprovalResolutionResult> {
    const entry = await this.queue.approve(id, resolvedBy, note);
    if (!entry) {
      return {
        ok: false,
        error: `Approval request '${id}' was not found or already resolved`,
      };
    }
    return { ok: true, entry };
  }

  public async deny(id: string, resolvedBy?: string, note?: string): Promise<ApprovalResolutionResult> {
    const entry = await this.queue.deny(id, resolvedBy, note);
    if (!entry) {
      return {
        ok: false,
        error: `Approval request '${id}' was not found or already resolved`,
      };
    }
    return { ok: true, entry };
  }

  public async expirePending(): Promise<ApprovalEntry[]> {
    return this.queue.expirePending();
  }
}
