import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

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

  /** 启动时恢复上次持久化的调用次数，请求路径只做内存计数 */
  restore(saved: Record<string, number>): void {
    for (const [tool, count] of Object.entries(saved)) {
      if (Number.isFinite(count) && count > 0) {
        this.requests.set(tool, Math.trunc(count));
      }
    }
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

const DEFAULT_METRICS_FILE = fileURLToPath(new URL('../../data/metrics.json', import.meta.url));

interface PersistedMetrics {
  version: 1;
  savedAt: string;
  totalRequests: number;
  requests: Record<string, number>;
  cache: Record<string, { hits: number; misses: number }>;
  topTargets: Array<{ target: string; count: number }>;
}

/** 启动时读取历史调用统计，文件不存在或损坏时忽略 */
export async function initMetrics(filePath: string = DEFAULT_METRICS_FILE): Promise<void> {
  try {
    const parsed = JSON.parse(await readFile(filePath, 'utf8')) as Partial<PersistedMetrics>;
    if (parsed && parsed.requests && typeof parsed.requests === 'object') {
      metrics.restore(parsed.requests as Record<string, number>);
    }
  } catch {
    /* 首次启动或文件损坏时从 0 开始 */
  }
}

/**
 * 智能调度周期性调用：把调用次数聚合后一次性写盘。
 * 高并发时请求路径只累加内存计数，不做任何磁盘 IO。
 */
export async function persistMetrics(
  filePath: string = DEFAULT_METRICS_FILE,
): Promise<{ totalRequests: number; tools: number }> {
  const snapshot = metrics.snapshot();
  const payload: PersistedMetrics = {
    version: 1,
    savedAt: new Date().toISOString(),
    totalRequests: snapshot.totalRequests,
    requests: snapshot.requests,
    cache: snapshot.cache,
    topTargets: snapshot.topTargets,
  };
  await mkdir(dirname(filePath), { recursive: true });
  const temp = `${filePath}.tmp`;
  await writeFile(temp, JSON.stringify(payload), 'utf8');
  await rename(temp, filePath);
  return { totalRequests: snapshot.totalRequests, tools: Object.keys(snapshot.requests).length };
}
