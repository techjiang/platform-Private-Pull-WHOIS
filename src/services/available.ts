import { config } from '../config.js';
import { TtlCache } from '../lib/cache.js';
import { ApiError } from '../lib/errors.js';
import { parseDomain } from '../lib/domain.js';
import { metrics } from '../lib/metrics.js';
import { rdapLookup } from '../whois/rdap.js';
import { whoisLookup } from '../whois/whois.js';

/**
 * 域名批量可注册性检测
 *
 * 对每个域名优先走注册局 RDAP，未覆盖时回退 WHOIS 43，逐个判断是否可注册，
 * 并返回注册商与关键日期。结果带缓存，避免重复请求上游。
 */

export type AvailabilityStatus = 'available' | 'registered' | 'unknown';

export interface AvailabilityItem {
  domain: string;
  status: AvailabilityStatus;
  registrar: string | null;
  expires: string | null;
  created: string | null;
  source: 'rdap' | 'whois' | null;
  durationMs: number;
  error: string | null;
}

export interface AvailabilityResult {
  total: number;
  available: number;
  registered: number;
  unknown: number;
  truncated: number;
  items: AvailabilityItem[];
  durationMs: number;
  note: string;
  checkedAt: string;
  cached: boolean;
  ttlMs: number;
}

interface CachedAvailability {
  status: AvailabilityStatus;
  registrar: string | null;
  expires: string | null;
  created: string | null;
  source: 'rdap' | 'whois' | null;
  error: string | null;
}

const cache = new TtlCache<CachedAvailability>(config.availability.maxEntries);

export const AVAILABILITY_NOTE =
  '可注册性由本站直接查询注册局 RDAP 或 WHOIS 判断，仅代表查询时刻的注册状态，最终能否注册请以注册商下单结果为准。';

/** 拆分并规范化域名列表（纯函数，便于测试） */
export function normalizeDomainList(
  input: string | string[],
  max = config.availability.maxDomains,
): { domains: string[]; truncated: number } {
  const raw = Array.isArray(input) ? input : String(input ?? '').split(/[\s,;，；]+/);
  const seen = new Set<string>();
  const domains: string[] = [];
  for (const item of raw) {
    const value = String(item ?? '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    domains.push(value);
  }
  if (domains.length > max) {
    return { domains: domains.slice(0, max), truncated: domains.length - max };
  }
  return { domains, truncated: 0 };
}

async function queryOne(input: string): Promise<{ item: AvailabilityItem; cached: boolean }> {
  const startedAt = Date.now();
  let parsed: ReturnType<typeof parseDomain>;
  try {
    parsed = parseDomain(input);
  } catch (error) {
    return {
      cached: false,
      item: {
        domain: String(input).trim(),
        status: 'unknown',
        registrar: null,
        expires: null,
        created: null,
        source: null,
        durationMs: Date.now() - startedAt,
        error: error instanceof Error ? error.message : '域名格式不正确',
      },
    };
  }

  const hit = cache.get(parsed.ascii);
  if (hit) {
    return {
      cached: true,
      item: {
        domain: parsed.ascii,
        status: hit.value.status,
        registrar: hit.value.registrar,
        expires: hit.value.expires,
        created: hit.value.created,
        source: hit.value.source,
        durationMs: Date.now() - startedAt,
        error: hit.value.error,
      },
    };
  }

  let status: AvailabilityStatus = 'unknown';
  let registrar: string | null = null;
  let expires: string | null = null;
  let created: string | null = null;
  let source: 'rdap' | 'whois' | null = null;
  let error: string | null = null;

  try {
    const rdap = await rdapLookup(parsed.ascii, parsed.tld, config.upstream.rdapTimeoutMs);
    let parsedRecord = rdap.result?.parsed ?? null;
    if (rdap.result) source = 'rdap';

    if (!parsedRecord) {
      try {
        const whois = await whoisLookup(
          parsed,
          config.upstream.whoisTimeoutMs,
          config.upstream.followReferral,
        );
        if (whois) {
          parsedRecord = whois.parsed;
          source = 'whois';
        }
      } catch (fallbackError) {
        error =
          fallbackError instanceof Error ? fallbackError.message.slice(0, 160) : 'WHOIS 查询失败';
      }
    }

    if (parsedRecord) {
      status = parsedRecord.available ? 'available' : 'registered';
      registrar = parsedRecord.registrar?.name ?? null;
      expires = parsedRecord.dates.expires;
      created = parsedRecord.dates.created;
    } else if (!error) {
      error = '没有可用的 RDAP 或 WHOIS 数据源';
    }
  } catch (queryError) {
    error = queryError instanceof Error ? queryError.message.slice(0, 160) : '查询失败';
  }

  const ttl =
    status === 'available'
      ? 3 * 60 * 1000
      : status === 'registered'
        ? config.availability.cacheTtlMs
        : 2 * 60 * 1000;

  cache.set(
    parsed.ascii,
    { status, registrar, expires, created, source, error },
    ttl,
  );

  return {
    cached: false,
    item: {
      domain: parsed.ascii,
      status,
      registrar,
      expires,
      created,
      source,
      durationMs: Date.now() - startedAt,
      error,
    },
  };
}

/** 控制并发地批量检测可注册性 */
async function runPool<T>(items: string[], limit: number, task: (item: string) => Promise<T>): Promise<T[]> {
  const results: T[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      results[index] = await task(items[index] as string);
    }
  });
  await Promise.all(workers);
  return results;
}

/** 批量检测域名是否可注册 */
export async function checkAvailability(input: string | string[]): Promise<AvailabilityResult> {
  const { domains, truncated } = normalizeDomainList(input);
  if (domains.length === 0) throw ApiError.badRequest('请至少提供一个域名');

  metrics.recordCache('available', false);
  const startedAt = Date.now();
  const settled = await runPool(domains, config.availability.concurrency, (domain) => queryOne(domain));

  const items = settled.map((entry) => entry.item);
  const available = items.filter((item) => item.status === 'available').length;
  const registered = items.filter((item) => item.status === 'registered').length;
  const unknown = items.filter((item) => item.status === 'unknown').length;

  return {
    total: items.length,
    available,
    registered,
    unknown,
    truncated,
    items,
    durationMs: Date.now() - startedAt,
    note: AVAILABILITY_NOTE,
    checkedAt: new Date().toISOString(),
    cached: settled.some((entry) => entry.cached),
    ttlMs: config.availability.cacheTtlMs,
  };
}

export function clearAvailabilityCache(): void {
  cache.clear();
}

export function availabilityCacheSize(): number {
  return cache.size;
}
