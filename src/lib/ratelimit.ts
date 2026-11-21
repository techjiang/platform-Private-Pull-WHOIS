export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetMs: number;
  retryAfterSec: number;
}

interface Bucket {
  count: number;
  resetAt: number;
}

/** 固定窗口限流器（单实例内存实现，可平滑替换为 Redis） */
export class FixedWindowRateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly timer: NodeJS.Timeout;

  constructor(
    private readonly windowMs: number,
    private readonly maxBuckets = 50_000,
  ) {
    this.timer = setInterval(() => this.sweep(), Math.max(windowMs, 10_000));
    this.timer.unref();
  }

  hit(key: string, limit: number): RateLimitResult {
    const now = Date.now();
    let bucket = this.buckets.get(key);

    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + this.windowMs };
      this.buckets.set(key, bucket);
    }

    bucket.count += 1;
    const remaining = Math.max(0, limit - bucket.count);
    const resetMs = Math.max(0, bucket.resetAt - now);

    return {
      allowed: bucket.count <= limit,
      limit,
      remaining,
      resetMs,
      retryAfterSec: Math.max(1, Math.ceil(resetMs / 1000)),
    };
  }

  private sweep(): void {
    const now = Date.now();
    for (const [key, bucket] of this.buckets) {
      if (bucket.resetAt <= now) this.buckets.delete(key);
    }
    // 极端情况下兜底，避免内存无上限增长
    if (this.buckets.size > this.maxBuckets) {
      const excess = this.buckets.size - this.maxBuckets;
      let removed = 0;
      for (const key of this.buckets.keys()) {
        if (removed >= excess) break;
        this.buckets.delete(key);
        removed += 1;
      }
    }
  }
}
