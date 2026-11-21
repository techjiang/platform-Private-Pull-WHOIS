import { config } from '../config.js';
import { TtlCache } from '../lib/cache.js';
import { ApiError } from '../lib/errors.js';
import type { ParsedDomain } from '../lib/domain.js';
import { rdapLookup } from './rdap.js';
import { whoisLookup } from './whois.js';
import type {
  LookupOptions,
  LookupRecord,
  ParsedRecord,
  SourceAttempt,
  WhoisData,
} from './types.js';

export interface LookupResult {
  record: LookupRecord;
  cached: boolean;
  ttlMs: number;
}

const MAX_RAW_LENGTH = 100_000;

const cache = new TtlCache<LookupRecord>(config.cache.maxEntries);
const inflight = new Map<string, Promise<{ record: LookupRecord; ttlMs: number }>>();

export function buildData(domain: ParsedDomain, parsed: ParsedRecord, raw: string): WhoisData {
  const available = parsed.available;
  const trimmedRaw = raw.length > MAX_RAW_LENGTH ? `${raw.slice(0, MAX_RAW_LENGTH)}\n… (已截断)` : raw;

  return {
    domain: domain.ascii,
    unicodeDomain: domain.unicode,
    tld: domain.tld,
    sld: domain.sld,
    idn: domain.idn,
    available,
    registered: !available,
    registrar: available ? null : parsed.registrar,
    registrant: available ? null : parsed.registrant,
    dates: available
      ? { created: null, updated: null, expires: null }
      : parsed.dates,
    statuses: available ? [] : parsed.statuses,
    nameservers: available ? [] : parsed.nameservers,
    dnssec: available ? 'unknown' : parsed.dnssec,
    registryDomainId: available ? null : parsed.registryDomainId,
    raw: trimmedRaw,
  };
}

/**
 * 查询域名信息：RDAP 优先，失败或未覆盖时回退 WHOIS 43。
 * 内置 TTL+LRU 缓存、并发去重与可用性短缓存。
 */
export async function lookupDomain(
  domain: ParsedDomain,
  options: LookupOptions = {},
): Promise<LookupResult> {
  const key = domain.ascii;

  if (!options.forceRefresh) {
    const hit = cache.get(key);
    if (hit) {
      return { record: hit.value, cached: true, ttlMs: Math.round(hit.ttlMs) };
    }
  }

  const pending = inflight.get(key);
  if (pending) {
    const shared = await pending;
    return { record: shared.record, cached: false, ttlMs: shared.ttlMs };
  }

  const task = (async (): Promise<{ record: LookupRecord; ttlMs: number }> => {
    const startedAt = Date.now();
    const attempts: SourceAttempt[] = [];
    let record: LookupRecord | null = null;

    const rdap = await rdapLookup(domain.ascii, domain.tld, config.upstream.rdapTimeoutMs);
    attempts.push(...rdap.attempts);

    if (rdap.result) {
      record = {
        data: buildData(domain, rdap.result.parsed, rdap.result.raw),
        source: 'rdap',
        server: rdap.result.server,
        durationMs: Date.now() - startedAt,
        queriedAt: new Date().toISOString(),
      };
    } else {
      try {
        const whois = await whoisLookup(
          domain,
          config.upstream.whoisTimeoutMs,
          config.upstream.followReferral,
        );
        if (whois) {
          attempts.push({
            source: 'whois',
            server: whois.server,
            ok: true,
            durationMs: whois.durationMs,
          });
          record = {
            data: buildData(domain, whois.parsed, whois.raw),
            source: 'whois',
            server: whois.server,
            durationMs: Date.now() - startedAt,
            queriedAt: new Date().toISOString(),
          };
        } else {
          attempts.push({
            source: 'whois',
            server: 'whois.iana.org',
            ok: false,
            error: '未找到该后缀的 WHOIS 服务器',
            durationMs: 0,
          });
        }
      } catch (error) {
        attempts.push({
          source: 'whois',
          server: 'unknown',
          ok: false,
          error: error instanceof Error ? error.message : String(error),
          durationMs: 0,
        });
      }
    }

    if (!record) {
      throw ApiError.upstream('RDAP 与 WHOIS 均未能返回该域名信息', { attempts });
    }

    const ttlMs = record.data.available
      ? config.cache.availableTtlMs
      : config.cache.ttlMs;
    cache.set(key, record, ttlMs);

    return { record, ttlMs };
  })();

  inflight.set(key, task);

  try {
    const result = await task;
    return { record: result.record, cached: false, ttlMs: result.ttlMs };
  } finally {
    inflight.delete(key);
  }
}

export function clearLookupCache(): void {
  cache.clear();
  inflight.clear();
}

export function lookupCacheSize(): number {
  return cache.size;
}
