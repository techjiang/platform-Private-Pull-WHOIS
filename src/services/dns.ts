import { Resolver } from 'node:dns/promises';
import { config } from '../config.js';
import { TtlCache } from '../lib/cache.js';
import { ApiError } from '../lib/errors.js';
import { metrics } from '../lib/metrics.js';

export const DNS_TYPES = [
  'A',
  'AAAA',
  'MX',
  'TXT',
  'NS',
  'CNAME',
  'SOA',
  'SRV',
  'CAA',
] as const;

export type DnsRecordType = (typeof DNS_TYPES)[number];
export type DnsQueryType = DnsRecordType | 'ANY';

export interface DnsRecord {
  type: DnsRecordType;
  value: unknown;
}

export interface DnsLookupResult {
  domain: string;
  type: DnsQueryType;
  status: 'ok' | 'nodata' | 'nxdomain';
  records: DnsRecord[];
  durationMs: number;
  cached: boolean;
  ttlMs: number;
}

interface CachedDns {
  status: DnsLookupResult['status'];
  records: DnsRecord[];
  durationMs: number;
}

const cache = new TtlCache<CachedDns>(config.dns.maxEntries);

export function isDnsType(value: unknown): value is DnsQueryType {
  const upper = String(value ?? '').toUpperCase();
  return upper === 'ANY' || (DNS_TYPES as readonly string[]).includes(upper);
}

/** 解析 A,AAAA,MX 形式的多记录类型，最多 6 个；存在非法类型时返回空数组 */
export function normalizeDnsTypes(input: unknown): DnsQueryType[] {
  const parts = String(input ?? '')
    .toUpperCase()
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  const unique = [...new Set(parts)];
  if (unique.length === 0 || unique.length > 6) return [];
  if (!unique.every((item) => isDnsType(item))) return [];
  return unique;
}

function timeoutRun<T>(resolver: Resolver, timeoutMs: number, task: () => Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      try {
        resolver.cancel();
      } catch {
        /* 忽略取消失败 */
      }
      reject(ApiError.timeout('DNS 查询超时'));
    }, timeoutMs);
    timer.unref();

    task()
      .then(resolve, reject)
      .finally(() => clearTimeout(timer));
  });
}

function errorCode(error: unknown): string {
  return String((error as NodeJS.ErrnoException)?.code ?? '');
}

async function resolveOne(
  resolver: Resolver,
  domain: string,
  type: DnsRecordType,
): Promise<{ records: DnsRecord[]; missing: boolean }> {
  try {
    switch (type) {
      case 'A':
      case 'AAAA':
      case 'NS':
      case 'CNAME': {
        const values =
          type === 'A'
            ? await resolver.resolve4(domain)
            : type === 'AAAA'
              ? await resolver.resolve6(domain)
              : type === 'NS'
                ? await resolver.resolveNs(domain)
                : await resolver.resolveCname(domain);
        return { records: values.map((value) => ({ type, value })), missing: false };
      }
      case 'MX': {
        const values = await resolver.resolveMx(domain);
        return {
          records: values.map((value) => ({
            type,
            value: { priority: value.priority, exchange: value.exchange },
          })),
          missing: false,
        };
      }
      case 'TXT': {
        const values = await resolver.resolveTxt(domain);
        return {
          records: values.map((chunks) => ({
            type,
            value: { text: chunks.join(''), chunks },
          })),
          missing: false,
        };
      }
      case 'SOA': {
        const value = await resolver.resolveSoa(domain);
        return { records: [{ type, value }], missing: false };
      }
      case 'SRV': {
        const values = await resolver.resolveSrv(domain);
        return { records: values.map((value) => ({ type, value })), missing: false };
      }
      case 'CAA': {
        const values = await resolver.resolveCaa(domain);
        return { records: values.map((value) => ({ type, value })), missing: false };
      }
      default:
        return { records: [], missing: true };
    }
  } catch (error) {
    const code = errorCode(error);
    if (code === 'ENODATA' || code === 'ENOTFOUND' || code === 'ENONAME' || code === 'NOTFOUND') {
      return { records: [], missing: true };
    }
    throw error;
  }
}

/** 查询 DNS 记录，带短 TTL 缓存与超时保护 */
export async function lookupDns(
  domain: string,
  type: DnsQueryType = 'A',
): Promise<DnsLookupResult> {
  const key = `${domain}:${type}`;
  const hit = cache.get(key);
  if (hit) {
    metrics.recordCache('dns', true);
    return {
      domain,
      type,
      status: hit.value.status,
      records: hit.value.records,
      durationMs: hit.value.durationMs,
      cached: true,
      ttlMs: Math.round(hit.ttlMs),
    };
  }

  metrics.recordCache('dns', false);
  const startedAt = Date.now();
  const resolver = new Resolver();

  const types: DnsRecordType[] = type === 'ANY' ? [...DNS_TYPES] : [type];
  let settled;
  try {
    settled = await timeoutRun(resolver, config.dns.timeoutMs, () =>
      Promise.all(types.map((item) => resolveOne(resolver, domain, item))),
    );
  } catch (error) {
    if (error instanceof ApiError) throw error;
    const code = errorCode(error) || 'UNKNOWN';
    throw ApiError.upstream(`DNS 查询失败（${code}）`);
  }

  const records = settled.flatMap((item) => item.records);
  const allMissing = settled.every((item) => item.missing);
  const status: DnsLookupResult['status'] = allMissing ? 'nodata' : 'ok';
  const durationMs = Date.now() - startedAt;

  cache.set(key, { status, records, durationMs }, config.dns.ttlMs);

  return {
    domain,
    type,
    status,
    records,
    durationMs,
    cached: false,
    ttlMs: config.dns.ttlMs,
  };
}

export function clearDnsCache(): void {
  cache.clear();
}

export function dnsCacheSize(): number {
  return cache.size;
}
