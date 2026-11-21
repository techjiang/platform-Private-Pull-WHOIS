import { monitorEventLoopDelay } from 'node:perf_hooks';
import { metrics } from './metrics.js';

/**
 * 智能后台调度
 *
 * 在进程内按固定节奏检查到期任务，并且只在请求空闲、事件循环延迟较低时执行，
 * 避免与线上查询争抢 CPU 与网络资源。任务状态会暴露给后台管理页面。
 */

export interface SchedulerPolicy {
  enabled: boolean;
  idleOnly: boolean;
}

export const DEFAULT_SCHEDULER_POLICY: SchedulerPolicy = {
  enabled: true,
  idleOnly: true,
};

export function normalizeSchedulerPolicy(raw: Partial<SchedulerPolicy> | undefined): SchedulerPolicy {
  return {
    enabled: typeof raw?.enabled === 'boolean' ? raw.enabled : DEFAULT_SCHEDULER_POLICY.enabled,
    idleOnly: typeof raw?.idleOnly === 'boolean' ? raw.idleOnly : DEFAULT_SCHEDULER_POLICY.idleOnly,
  };
}

export interface SchedulerRunResult {
  summary: string;
}

export interface SchedulerJobDefinition {
  key: string;
  label: string;
  description: string;
  intervalMs: number;
  /** 关键任务：即使持续有请求，超期后也要择机执行，避免缓存长期不清理 */
  critical?: boolean;
  run: () => Promise<SchedulerRunResult | void>;
}

export interface SchedulerJobSnapshot {
  key: string;
  label: string;
  description: string;
  intervalSec: number;
  lastRunAt: string | null;
  lastDurationMs: number | null;
  lastStatus: 'ok' | 'error' | 'never';
  lastError: string | null;
  lastSummary: string | null;
  nextRunAt: string | null;
  runCount: number;
  failCount: number;
  skippedCount: number;
  consecutiveFailures: number;
  backoffUntil: string | null;
  due: boolean;
  running: boolean;
}

export interface SchedulerSnapshot {
  policy: SchedulerPolicy;
  running: boolean;
  loopLagMs: number;
  inflight: number;
  startedAt: string | null;
  jobs: SchedulerJobSnapshot[];
}

interface JobState {
  definition: SchedulerJobDefinition;
  nextRunAt: number;
  lastRunAt: number | null;
  lastDurationMs: number | null;
  lastStatus: 'ok' | 'error' | 'never';
  lastError: string | null;
  lastSummary: string | null;
  runCount: number;
  failCount: number;
  skippedCount: number;
  consecutiveFailures: number;
  backoffUntil: number | null;
  running: boolean;
}

const TICK_MS = 20_000;
const MAX_LAG_MS = 80;
const MAX_BACKOFF_MS = 6 * 60 * 60 * 1000;
/** 关键任务最多可被繁忙流量推迟的时间 */
const CRITICAL_GRACE_MS = 5 * 60 * 1000;

export class Scheduler {
  private readonly jobs = new Map<string, JobState>();
  private timer: NodeJS.Timeout | null = null;
  private readonly histogram = monitorEventLoopDelay({ resolution: 20 });
  private startedAt: string | null = null;
  private running = false;

  constructor(private readonly getPolicy: () => SchedulerPolicy) {}

  register(definition: SchedulerJobDefinition): void {
    const index = this.jobs.size;
    this.jobs.set(definition.key, {
      definition,
      // 启动后错峰执行，避免所有任务同时唤醒
      nextRunAt: Date.now() + 60_000 + index * 25_000 + Math.floor(Math.random() * 15_000),
      lastRunAt: null,
      lastDurationMs: null,
      lastStatus: 'never',
      lastError: null,
      lastSummary: null,
      runCount: 0,
      failCount: 0,
      skippedCount: 0,
      consecutiveFailures: 0,
      backoffUntil: null,
      running: false,
    });
  }

  start(): void {
    if (this.timer) return;
    this.startedAt = new Date().toISOString();
    this.histogram.enable();
    this.timer = setInterval(() => void this.tick(), TICK_MS);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.histogram.disable();
    this.startedAt = null;
  }

  private peekLoopLagMs(): number {
    const mean = this.histogram.mean;
    return Number.isFinite(mean) ? Math.round((mean / 1e6) * 10) / 10 : 0;
  }

  private loopLagMs(): number {
    const lag = this.peekLoopLagMs();
    this.histogram.reset();
    return lag;
  }

  private async tick(): Promise<void> {
    if (this.running) return;
    const policy = this.getPolicy();
    if (!policy.enabled) {
      this.histogram.reset();
      return;
    }

    const now = Date.now();
    const due = [...this.jobs.values()]
      .filter((job) => !job.running && job.nextRunAt <= now)
      .sort((a, b) => a.nextRunAt - b.nextRunAt);

    if (due.length === 0) {
      this.histogram.reset();
      return;
    }

    let job = due[0] as JobState;
    if (policy.idleOnly) {
      const lag = this.loopLagMs();
      const overdueCritical = due.find(
        (item) => item.definition.critical && now - item.nextRunAt >= CRITICAL_GRACE_MS,
      );
      if (lag > MAX_LAG_MS || (!overdueCritical && metrics.inflight > 0)) {
        for (const item of due) item.skippedCount += 1;
        return;
      }
      if (overdueCritical) job = overdueCritical;
    } else {
      this.histogram.reset();
    }

    await this.execute(job);
  }

  private async execute(job: JobState): Promise<void> {
    this.running = true;
    job.running = true;
    const startedAt = Date.now();
    try {
      const outcome = await job.definition.run();
      job.lastStatus = 'ok';
      job.lastError = null;
      job.lastSummary = outcome?.summary ?? null;
      job.consecutiveFailures = 0;
      job.backoffUntil = null;
    } catch (error) {
      job.lastStatus = 'error';
      job.lastError = error instanceof Error ? error.message.slice(0, 200) : String(error);
      job.lastSummary = null;
      job.failCount += 1;
      job.consecutiveFailures += 1;
      // 连续失败时指数退避，最多退到 6 小时，避免对故障上游持续施压
      const factor = Math.min(2 ** job.consecutiveFailures, MAX_BACKOFF_MS / job.definition.intervalMs);
      job.backoffUntil = Date.now() + Math.min(job.definition.intervalMs * factor, MAX_BACKOFF_MS);
    } finally {
      job.running = false;
      job.runCount += 1;
      job.lastRunAt = startedAt;
      job.lastDurationMs = Date.now() - startedAt;
      // 成功时加入 ±5% 抖动，避免多实例或多次启动后任务再次同步
      const jitter = 0.95 + Math.random() * 0.1;
      job.nextRunAt = job.backoffUntil ?? Date.now() + Math.round(job.definition.intervalMs * jitter);
      this.running = false;
    }
  }

  /** 立即执行指定任务（后台手动触发时不受空闲策略限制） */
  async runNow(key: string): Promise<SchedulerJobSnapshot> {
    const job = this.jobs.get(key);
    if (!job) throw new Error(`未知的调度任务：${key}`);
    if (job.running) return this.jobSnapshot(job);
    await this.execute(job);
    return this.jobSnapshot(job);
  }

  /** 立即依次执行全部任务，返回执行后的快照 */
  async runAll(): Promise<SchedulerJobSnapshot[]> {
    for (const job of this.jobs.values()) {
      if (!job.running) await this.execute(job);
    }
    return [...this.jobs.values()].map((job) => this.jobSnapshot(job));
  }

  private jobSnapshot(job: JobState): SchedulerJobSnapshot {
    return {
      key: job.definition.key,
      label: job.definition.label,
      description: job.definition.description,
      intervalSec: Math.round(job.definition.intervalMs / 1000),
      lastRunAt: job.lastRunAt === null ? null : new Date(job.lastRunAt).toISOString(),
      lastDurationMs: job.lastDurationMs,
      lastStatus: job.lastStatus,
      lastError: job.lastError,
      lastSummary: job.lastSummary,
      nextRunAt: new Date(job.nextRunAt).toISOString(),
      runCount: job.runCount,
      failCount: job.failCount,
      skippedCount: job.skippedCount,
      consecutiveFailures: job.consecutiveFailures,
      backoffUntil: job.backoffUntil === null ? null : new Date(job.backoffUntil).toISOString(),
      due: job.nextRunAt <= Date.now(),
      running: job.running,
    };
  }

  snapshot(): SchedulerSnapshot {
    return {
      policy: this.getPolicy(),
      running: this.running,
      loopLagMs: this.peekLoopLagMs(),
      inflight: metrics.inflight,
      startedAt: this.startedAt,
      jobs: [...this.jobs.values()].map((job) => this.jobSnapshot(job)),
    };
  }
}
