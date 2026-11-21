import { Resolver } from 'node:dns/promises';
import { config } from '../config.js';
import { TtlCache } from '../lib/cache.js';
import { ApiError } from '../lib/errors.js';
import { parseDomain } from '../lib/domain.js';
import { metrics } from '../lib/metrics.js';

/**
 * DNS 多解析器传播对比
 *
 * 由本站同时向多个公共递归解析器发起标准 DNS 查询，比较解析结果是否一致，
 * 用于判断域名解析是否已经传播完成。查询与对比逻辑均在本地完成。
 */

export const PROP_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'CAA'] as const;
export type PropType = (typeof PROP_TYPES)[number];

export const PROP_RESOLVERS = [
  { id: 'alidns', name: '阿里 DNS', address: '223.5.5.5' },
  { id: 'dnspod', name: 'DNSPod', address: '119.29.29.29' },
  { id: 'cloudflare', name: 'Cloudflare', address: '1.1.1.1' },
  { id: 'google', name: 'Google DNS', address: '8.8.8.8' },
] as const;

export interface PropResolverResult {
  id: string;
  name: string;
  address: string;
  status: 'ok' | 'error' | 'timeout';
  records: string[];
  durationMs: number;
  error: string | null;
}

export interface DnsPropResult {
  domain: string;
  type: PropType;
  consistent: boolean;
  successful: number;
  failed: number;
  resolvers: PropResolverResult[];
  groups: Array<{ records: string[]; resolvers: string[] }>;
  differences: Array<{ records: string[]; resolvers: string[] }>;
  note: string;
  checkedAt: string;
  cached: boolean;
  ttlMs: number;
}

interface CachedProp {
  domain: string;
  type: PropType;
  consistent: boolean;
  successful: number;
  failed: number;
  resolvers: PropResolverResult[];
  groups: Array<{ records: string[]; resolvers: string[] }>;
  differences: Array<{ records: string[]; resolvers: string[] }>;
  checkedAt: string;
}

const cache = new TtlCache<CachedProp>(config.dnsProp.maxEntries);

export const DNS_PROP_NOTE =
  '对比结果由本站直接向多个公共递归 DNS 发起查询后计算，不同解析器可能因缓存尚未过期而短暂不一致，通常等待 TTL 后会自动收敛。';

export function normalizePropType(value: unknown): PropType {
  const upper = String(value ?? 'A').trim().toUpperCase() || 'A';
  if (!(PROP_TYPES as readonly string[]).includes(upper)) {
    throw ApiError.badRequest(`type 仅支持 ${PROP_TYPES.join('、')}`);
  }
  return upper as PropType;
}

function formatCaa(record: {
  critical?: number;
  issue?: string;
  issuewild?: string;
  iodef?: string;
  contactemail?: string;
  contactphone?: string;
}): string {
  const parts: string[] = [];
  if (record.issue) parts.push(`issue "${record.issue}"`);
  if (record.issuewild) parts.push(`issuewild "${record.issuewild}"`);
  if (record.iodef) parts.push(`iodef "${record.iodef}"`);
  if (record.contactemail) parts.push(`contactemail "${record.contactemail}"`);
  if (record.contactphone) parts.push(`contactphone "${record.contactphone}"`);
  return `${record.critical ?? 0} ${parts.join('; ')}`.trim();
}

async function queryOne(address: string, domain: string, type: PropType): Promise<string[]> {
  const resolver = new Resolver({ timeout: config.dnsProp.timeoutMs, tries: 1 });
  resolver.setServers([address]);
  try {
    switch (type) {
      case 'A':
        return (await resolver.resolve4(domain)).map((item) => item.toLowerCase()).sort();
      case 'AAAA':
        return (await resolver.resolve6(domain)).map((item) => item.toLowerCase()).sort();
      case 'MX':
        return (await resolver.resolveMx(domain))
          .sort((a, b) => a.priority - b.priority)
          .map((item) => `${item.priority} ${item.exchange.toLowerCase()}`);
      case 'TXT':
        return (await resolver.resolveTxt(domain))
          .map((chunks) => chunks.join(''))
          .filter(Boolean)
          .sort();
      case 'NS':
        return (await resolver.resolveNs(domain)).map((item) => item.toLowerCase()).sort();
      case 'CNAME':
        return (await resolver.resolveCname(domain)).map((item) => item.toLowerCase()).sort();
      case 'CAA':
        return (await resolver.resolveCaa(domain)).map(formatCaa).sort();
    }
    throw new Error('不支持的记录类型');
  } finally {
    try {
      resolver.cancel();
    } catch {
      /* 忽略取消失败 */
    }
  }
}

function withTimeout<T>(task: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('查询超时')), timeoutMs + 400);
    timer.unref();
    task.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

/** 对比各解析器的记录集合（纯函数，便于测试） */
export function compareResolverRecords(
  results: Array<{ id: string; name: string; records: string[]; status: string }>,
): {
  consistent: boolean;
  groups: Array<{ records: string[]; resolvers: string[] }>;
  differences: Array<{ records: string[]; resolvers: string[] }>;
} {
  const groups = new Map<string, { records: string[]; resolvers: string[] }>();
  for (const item of results) {
    if (item.status !== 'ok') continue;
    const key = item.records
      .map((record) => record.trim().toLowerCase().replace(/\s+/g, ' '))
      .filter(Boolean)
      .sort()
      .join('|');
    const group = groups.get(key);
    if (group) group.resolvers.push(item.name);
    else {
      groups.set(key, {
        records: [...item.records].sort(),
        resolvers: [item.name],
      });
    }
  }

  const list = [...groups.values()];
  return {
    consistent: list.length <= 1,
    groups: list,
    differences: list.length > 1 ? list : [],
  };
}

/** 查询域名在多个公共解析器上的结果并比较 */
export async function checkDnsPropagation(
  input: string,
  rawType?: unknown,
): Promise<DnsPropResult> {
  const domain = parseDomain(input).ascii;
  const type = normalizePropType(rawType);
  const key = `${domain}:${type}`;
  const hit = cache.get(key);
  if (hit) {
    metrics.recordCache('dnsprop', true);
    return { ...hit.value, note: DNS_PROP_NOTE, cached: true, ttlMs: Math.round(hit.ttlMs) };
  }

  metrics.recordCache('dnsprop', false);

  const resolvers = await Promise.all(
    PROP_RESOLVERS.map(async (item): Promise<PropResolverResult> => {
      const queryStarted = Date.now();
      try {
        const records = await withTimeout(
          queryOne(item.address, domain, type),
          config.dnsProp.timeoutMs,
        );
        return {
          id: item.id,
          name: item.name,
          address: item.address,
          status: 'ok',
          records,
          durationMs: Date.now() - queryStarted,
          error: null,
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const timeout = /超时|timeout/i.test(message);
        return {
          id: item.id,
          name: item.name,
          address: item.address,
          status: timeout ? 'timeout' : 'error',
          records: [],
          durationMs: Date.now() - queryStarted,
          error: timeout ? '解析器响应超时' : message.slice(0, 120),
        };
      }
    }),
  );

  const successful = resolvers.filter((item) => item.status === 'ok').length;
  const failed = resolvers.length - successful;
  const compared = compareResolverRecords(resolvers);

  const result: CachedProp = {
    domain,
    type,
    consistent: compared.consistent,
    successful,
    failed,
    resolvers,
    groups: compared.groups,
    differences: compared.differences,
    checkedAt: new Date().toISOString(),
  };

  if (successful > 0) {
    cache.set(key, result, config.dnsProp.cacheTtlMs);
  }

  return { ...result, note: DNS_PROP_NOTE, cached: false, ttlMs: config.dnsProp.cacheTtlMs };
}

export function clearDnsPropCache(): void {
  cache.clear();
}

export function dnsPropCacheSize(): number {
  return cache.size;
}
