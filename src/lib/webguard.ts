/**
 * 网页端访问策略：固定窗口限速 + 每日额度 + 违规临时封禁。
 *
 * 全部为进程内轻量状态，重启后归零；后台修改策略立即生效。
 * 仅用于无需 API Key 的 /web/v1/* 查询，API 密钥策略独立。
 */

export interface WebPolicy {
  /** 每个 IP 在窗口内的请求上限，0 表示不限 */
  rateLimit: number;
  /** 限流窗口（秒） */
  rateWindowSec: number;
  /** 每个 IP 每日查询额度，0 表示不限 */
  dailyQuota: number;
  /** 累计多少次限流/超额后临时封禁，0 表示不封禁 */
  blockAfter: number;
  /** 封禁时长（秒），0 表示不封禁 */
  blockSec: number;
}

export const DEFAULT_WEB_POLICY: WebPolicy = {
  rateLimit: 120,
  rateWindowSec: 60,
  dailyQuota: 0,
  blockAfter: 10,
  blockSec: 300,
};

export type WebDenyReason = 'blocked' | 'rate' | 'quota';

export interface WebVerdict {
  allowed: boolean;
  reason: WebDenyReason | null;
  /** 当前窗口的请求上限，0 表示不限 */
  limit: number;
  remaining: number;
  /** 窗口剩余秒数 */
  resetSec: number;
  retryAfterSec: number;
  /** 每日额度，0 表示不限 */
  quota: number;
  quotaRemaining: number;
}

interface RateBucket {
  count: number;
  resetAt: number;
}

interface DayBucket {
  day: number;
  count: number;
}

interface GuardState {
  violations: number;
  lastViolation: number;
  blockedUntil: number;
}

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_TRACKED = 20_000;

export class WebGuard {
  private readonly rates = new Map<string, RateBucket>();
  private readonly days = new Map<string, DayBucket>();
  private readonly guards = new Map<string, GuardState>();
  private currentDay = 0;
  private lastPruneAt = 0;

  check(ip: string, policy: WebPolicy): WebVerdict {
    const now = Date.now();
    const day = Math.floor(now / DAY_MS);
    if (day !== this.currentDay) {
      this.currentDay = day;
      this.days.clear();
    }

    this.prune(now);
    const guard = this.guardFor(ip);

    if (guard.blockedUntil > now) {
      const retryAfterSec = Math.max(1, Math.ceil((guard.blockedUntil - now) / 1000));
      return this.verdict(false, 'blocked', policy, 0, retryAfterSec, 0);
    }
    guard.blockedUntil = 0;

    const rateLimit = Math.max(0, Math.trunc(policy.rateLimit));
    let remaining = 0;
    let resetSec = 0;

    if (rateLimit > 0) {
      const windowMs = Math.max(1, Math.trunc(policy.rateWindowSec)) * 1000;
      let bucket = this.rates.get(ip);
      if (!bucket || bucket.resetAt <= now) {
        bucket = { count: 0, resetAt: now + windowMs };
        this.rates.set(ip, bucket);
      }
      bucket.count += 1;
      resetSec = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
      remaining = Math.max(0, rateLimit - bucket.count);
      if (bucket.count > rateLimit) {
        const blockSec = this.registerViolation(guard, now, policy);
        return this.verdict(false, 'rate', policy, 0, blockSec || resetSec, 0);
      }
    }

    const dailyQuota = Math.max(0, Math.trunc(policy.dailyQuota));
    let quotaRemaining = 0;
    if (dailyQuota > 0) {
      let bucket = this.days.get(ip);
      if (!bucket || bucket.day !== day) {
        bucket = { day, count: 0 };
        this.days.set(ip, bucket);
      }
      bucket.count += 1;
      quotaRemaining = Math.max(0, dailyQuota - bucket.count);
      if (bucket.count > dailyQuota) {
        const untilNextDay = Math.max(1, Math.ceil(((day + 1) * DAY_MS - now) / 1000));
        const blockSec = this.registerViolation(guard, now, policy);
        return this.verdict(false, 'quota', policy, 0, blockSec || untilNextDay, quotaRemaining);
      }
    }

    return this.verdict(true, null, policy, remaining, resetSec, quotaRemaining);
  }

  /** 运行指标：用于后台展示当前风控状态 */
  snapshot(): { trackedIps: number; blockedIps: number; dailyRequests: number } {
    const now = Date.now();
    let blockedIps = 0;
    for (const guard of this.guards.values()) {
      if (guard.blockedUntil > now) blockedIps += 1;
    }
    let dailyRequests = 0;
    for (const bucket of this.days.values()) dailyRequests += bucket.count;
    return { trackedIps: this.rates.size, blockedIps, dailyRequests };
  }

  reset(): void {
    this.rates.clear();
    this.days.clear();
    this.guards.clear();
  }

  private guardFor(ip: string): GuardState {
    let guard = this.guards.get(ip);
    if (!guard) {
      guard = { violations: 0, lastViolation: 0, blockedUntil: 0 };
      this.guards.set(ip, guard);
    }
    return guard;
  }

  private registerViolation(guard: GuardState, now: number, policy: WebPolicy): number {
    const blockAfter = Math.max(0, Math.trunc(policy.blockAfter));
    const blockSec = Math.max(0, Math.trunc(policy.blockSec));
    if (blockAfter <= 0 || blockSec <= 0) return 0;

    const cooldownMs = Math.max(60_000, Math.trunc(policy.rateWindowSec) * 2000);
    if (guard.lastViolation && now - guard.lastViolation > cooldownMs) guard.violations = 0;

    guard.violations += 1;
    guard.lastViolation = now;
    if (guard.violations < blockAfter) return 0;

    guard.violations = 0;
    guard.blockedUntil = now + blockSec * 1000;
    return blockSec;
  }

  private verdict(
    allowed: boolean,
    reason: WebDenyReason | null,
    policy: WebPolicy,
    remaining: number,
    retryAfterSec: number,
    quotaRemaining: number,
  ): WebVerdict {
    return {
      allowed,
      reason,
      limit: Math.max(0, Math.trunc(policy.rateLimit)),
      remaining,
      resetSec: allowed ? retryAfterSec : Math.max(1, retryAfterSec),
      retryAfterSec: Math.max(1, retryAfterSec),
      quota: Math.max(0, Math.trunc(policy.dailyQuota)),
      quotaRemaining,
    };
  }

  /**
   * 低频清理过期状态，避免大量不同来源 IP 长期占用内存。
   * 每分钟最多扫描一次，正常情况下不会带来可感知的 CPU 开销。
   */
  private prune(now: number): void {
    if (now - this.lastPruneAt < 60_000) return;
    this.lastPruneAt = now;

    if (this.rates.size > MAX_TRACKED) {
      for (const [key, bucket] of this.rates) {
        if (bucket.resetAt <= now) this.rates.delete(key);
      }
    }

    if (this.guards.size > MAX_TRACKED) {
      for (const [key, guard] of this.guards) {
        if (guard.blockedUntil <= now && now - guard.lastViolation > DAY_MS) {
          this.guards.delete(key);
        }
      }
    }

    // 仍然超额时整体重置，作为最后的内存保护
    if (this.rates.size > MAX_TRACKED || this.guards.size > MAX_TRACKED) {
      this.rates.clear();
      this.days.clear();
      this.guards.clear();
    }
  }
}
