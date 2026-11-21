export interface RecentQuery {
  tool: string;
  target: string;
  cached: boolean;
  at: string;
}

export interface MetricsSnapshot {
  startedAt: string;
  uptimeSec: number;
  requests: Record<string, number>;
  cache: Record<string, { hits: number; misses: number }>;
  recent: RecentQuery[];
  topTargets: Array<{ target: string; count: number }>;
  totalRequests: number;
  inflight: number;
  memory: NodeJS.MemoryUsage;
  node: string;
}

const RECENT_LIMIT = 40;
const TOP_LIMIT = 600;

/** 极轻量的进程内指标，固定内存占用 */
class Metrics {
  private readonly startedAt = Date.now();
  private readonly requests = new Map<string, number>();
  private readonly cache = new Map<string, { hits: number; misses: number }>();
  private readonly recent: RecentQuery[] = [];
  private readonly targets = new Map<string, number>();
  private active = 0;

  /** 进入请求时计数，用于智能调度判断当前是否繁忙 */
  enter(): void {
    this.active += 1;
  }

  leave(): void {
    if (this.active > 0) this.active -= 1;
  }

  get inflight(): number {
    return this.active;
  }

  recordRequest(tool: string): void {
    this.requests.set(tool, (this.requests.get(tool) ?? 0) + 1);
  }

  recordCache(tool: string, hit: boolean): void {
    const entry = this.cache.get(tool) ?? { hits: 0, misses: 0 };
    if (hit) entry.hits += 1;
    else entry.misses += 1;
    this.cache.set(tool, entry);
  }

  recordQuery(tool: string, target: string, cached: boolean): void {
    const value = String(target ?? '').slice(0, 120);
    if (!value) return;

    if (this.targets.size >= TOP_LIMIT && !this.targets.has(value)) {
      const oldest = this.targets.keys().next();
      if (!oldest.done) this.targets.delete(oldest.value);
    }
    this.targets.set(value, (this.targets.get(value) ?? 0) + 1);

    this.recent.unshift({ tool, target: value, cached, at: new Date().toISOString() });
    if (this.recent.length > RECENT_LIMIT) this.recent.length = RECENT_LIMIT;
  }

  snapshot(): MetricsSnapshot {
    const requests: Record<string, number> = {};
    let totalRequests = 0;
    for (const [tool, count] of this.requests) {
      requests[tool] = count;
      totalRequests += count;
    }

    const cache: Record<string, { hits: number; misses: number }> = {};
    for (const [tool, entry] of this.cache) cache[tool] = { ...entry };

    const topTargets = [...this.targets.entries()]
      .map(([target, count]) => ({ target, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return {
      startedAt: new Date(this.startedAt).toISOString(),
      uptimeSec: Math.round(process.uptime()),
      requests,
      cache,
      recent: [...this.recent],
      topTargets,
      totalRequests,
      inflight: this.active,
      memory: process.memoryUsage(),
      node: process.version,
    };
  }
}

export const metrics = new Metrics();
