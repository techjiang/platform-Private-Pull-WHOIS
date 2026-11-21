import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { config } from '../config.js';
import { TtlCache } from '../lib/cache.js';
import { parseDomain } from '../lib/domain.js';
import { ApiError } from '../lib/errors.js';
import { metrics } from '../lib/metrics.js';
import { historyStore } from '../services/history.js';
import { domainIndex, INDEX_NOTE } from '../services/index.js';
import { isDnsType, lookupDns, normalizeDnsTypes, type DnsQueryType } from '../services/dns.js';
import { checkAvailability, AVAILABILITY_NOTE } from '../services/available.js';
import { fetchCertificateChain, CERT_CHAIN_NOTE } from '../services/certchain.js';
import { checkDnsPropagation, DNS_PROP_NOTE } from '../services/dnsprop.js';
import { checkDomainHealth, HEALTH_NOTE } from '../services/health.js';
import { checkHttp, HTTP_NOTE } from '../services/httpcheck.js';
import { lookupIp } from '../services/ip.js';
import { ICP_NOTE, lookupIcp } from '../services/icp.js';
import { checkMailAuth, MAIL_NOTE } from '../services/mail.js';
import { registrarNote, registrarRegistry, type RegistrarStatus } from '../services/registrars.js';
import { checkTls } from '../services/tls.js';
import { checkUptime } from '../services/uptime.js';
import { rdapLookup, type RdapOutcome } from '../whois/rdap.js';
import { buildData, lookupDomain } from '../whois/lookup.js';
import type { SourceAttempt, WhoisData } from '../whois/types.js';

export interface ToolRouteOptions {
  basePath: string;
}

interface DomainParams {
  domain: string;
}

interface IpParams {
  ip: string;
}

interface HostParams {
  host: string;
}

interface TargetParams {
  target: string;
}

interface DomainQuery {
  domain?: string;
  raw?: boolean | string;
  refresh?: boolean | string;
}

interface HealthQuery extends DomainQuery {
  dimensions?: string;
}

interface DnsQuery {
  domain?: string;
  type?: string;
}

interface IpQuery {
  ip?: string;
  raw?: boolean | string;
}

interface UptimeQuery {
  target?: string;
}

interface NameserverQuery {
  host?: string;
  limit?: number | string;
  offset?: number | string;
}

interface RegistrarQuery {
  q?: string;
  page?: number | string;
  limit?: number | string;
  country?: string;
  status?: string;
}

interface RegistrarParams {
  id: string;
}

interface RegistrarDetailQuery {
  limit?: number | string;
  offset?: number | string;
}

interface TlsQuery {
  host?: string;
  port?: number | string;
}

interface MailQuery {
  domain?: string;
  selector?: string;
}

interface HttpQuery {
  target?: string;
  refresh?: boolean | string;
}

interface DnsPropQuery {
  domain?: string;
  type?: string;
}

interface AvailabilityQuery {
  domains?: string;
}

interface CertChainQuery {
  host?: string;
  port?: number | string;
  format?: string;
}

interface CertChainParams {
  host: string;
  port?: number | string;
}

const flagSchema = {
  anyOf: [{ type: 'boolean' }, { type: 'string', enum: ['true', 'false', '1', '0'] }],
} as const;

const domainParamSchema = {
  type: 'object',
  required: ['domain'],
  properties: { domain: { type: 'string', minLength: 1, maxLength: 512 } },
} as const;

const domainQuerySchema = {
  type: 'object',
  properties: {
    domain: { type: 'string', minLength: 1, maxLength: 512 },
    raw: { ...flagSchema, default: false },
    refresh: { ...flagSchema, default: false },
  },
} as const;

const healthQuerySchema = {
  type: 'object',
  properties: {
    domain: { type: 'string', minLength: 1, maxLength: 512 },
    refresh: { ...flagSchema, default: false },
    dimensions: { type: 'string', maxLength: 80 },
  },
} as const;

const dnsQuerySchema = {
  type: 'object',
  properties: {
    domain: { type: 'string', minLength: 1, maxLength: 512 },
    type: { type: 'string', minLength: 1, maxLength: 64, default: 'A' },
  },
} as const;

const ipParamSchema = {
  type: 'object',
  required: ['ip'],
  properties: { ip: { type: 'string', minLength: 2, maxLength: 64 } },
} as const;

const ipQuerySchema = {
  type: 'object',
  properties: {
    ip: { type: 'string', minLength: 2, maxLength: 64 },
    raw: { ...flagSchema, default: false },
  },
} as const;

const targetParamSchema = {
  type: 'object',
  required: ['target'],
  properties: { target: { type: 'string', minLength: 3, maxLength: 512 } },
} as const;

const uptimeQuerySchema = {
  type: 'object',
  properties: { target: { type: 'string', minLength: 3, maxLength: 2048 } },
} as const;

const hostParamSchema = {
  type: 'object',
  required: ['host'],
  properties: { host: { type: 'string', minLength: 3, maxLength: 253 } },
} as const;

const nameserverQuerySchema = {
  type: 'object',
  properties: {
    host: { type: 'string', minLength: 3, maxLength: 253 },
    limit: { type: 'integer', minimum: 1, maximum: 200, default: 100 },
    offset: { type: 'integer', minimum: 0, maximum: 100_000, default: 0 },
  },
} as const;

const registrarQuerySchema = {
  type: 'object',
  properties: {
    q: { type: 'string', maxLength: 120, default: '' },
    page: { type: 'integer', minimum: 1, maximum: 2000, default: 1 },
    limit: { type: 'integer', minimum: 1, maximum: 100, default: 24 },
    country: { type: 'string', maxLength: 80, default: '' },
    status: {
      type: 'string',
      enum: ['', 'all', 'accredited', 'terminated', 'reserved', 'unknown'],
      default: '',
    },
  },
} as const;

const registrarParamsSchema = {
  type: 'object',
  required: ['id'],
  properties: { id: { type: 'string', minLength: 1, maxLength: 120 } },
} as const;

const registrarDetailQuerySchema = {
  type: 'object',
  properties: {
    limit: { type: 'integer', minimum: 1, maximum: 200, default: 40 },
    offset: { type: 'integer', minimum: 0, maximum: 100_000, default: 0 },
  },
} as const;

const tlsQuerySchema = {
  type: 'object',
  properties: {
    host: { type: 'string', minLength: 3, maxLength: 2048 },
    port: { type: 'integer', minimum: 1, maximum: 65535, default: 443 },
  },
} as const;

const mailQuerySchema = {
  type: 'object',
  properties: {
    domain: { type: 'string', minLength: 1, maxLength: 512 },
    selector: { type: 'string', maxLength: 400 },
  },
} as const;

const httpQuerySchema = {
  type: 'object',
  properties: {
    target: { type: 'string', minLength: 3, maxLength: 2048 },
    refresh: { ...flagSchema, default: false },
  },
} as const;

const dnsPropQuerySchema = {
  type: 'object',
  properties: {
    domain: { type: 'string', minLength: 1, maxLength: 512 },
    type: { type: 'string', minLength: 1, maxLength: 8, default: 'A' },
  },
} as const;

const availabilityQuerySchema = {
  type: 'object',
  properties: {
    domains: { type: 'string', minLength: 1, maxLength: 4096 },
  },
} as const;

const certChainQuerySchema = {
  type: 'object',
  properties: {
    host: { type: 'string', minLength: 3, maxLength: 2048 },
    port: { type: 'integer', minimum: 1, maximum: 65535, default: 443 },
    format: { type: 'string', enum: ['json', 'pem'], default: 'json' },
  },
} as const;

function asFlag(value: unknown): boolean {
  return value === true || value === 1 || value === '1' || value === 'true';
}

function meta(request: FastifyRequest, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    requestId: request.id,
    ...(request.rateLimitInfo
      ? {
          rateLimit: {
            limit: request.rateLimitInfo.limit,
            remaining: request.rateLimitInfo.remaining,
            reset: Math.max(1, Math.ceil(request.rateLimitInfo.resetMs / 1000)),
          },
        }
      : {}),
    ...extra,
  };
}

function cacheHeaders(reply: FastifyReply, cached: boolean, ttlMs: number): void {
  reply.header('x-cache', cached ? 'HIT' : 'MISS');
  reply.header('cache-control', `public, max-age=${Math.min(120, Math.max(1, Math.round(ttlMs / 1000)))}`);
}

function remember(data: WhoisData): void {
  historyStore.record(data);
  domainIndex.record(data);
}

/* -------------------------------- RDAP -------------------------------- */

interface CachedRdap {
  data: WhoisData;
  server: string;
  durationMs: number;
  queriedAt: string;
  attempts: SourceAttempt[];
}

const rdapCache = new TtlCache<CachedRdap>(config.cache.maxEntries);
const rdapInflight = new Map<string, Promise<CachedRdap>>();

async function rdapQuery(
  domain: ReturnType<typeof parseDomain>,
): Promise<{ entry: CachedRdap; cached: boolean }> {
  const hit = rdapCache.get(domain.ascii);
  if (hit) return { entry: hit.value, cached: true };

  const pending = rdapInflight.get(domain.ascii);
  if (pending) return { entry: await pending, cached: false };

  const task = (async (): Promise<CachedRdap> => {
    const startedAt = Date.now();
    const outcome: RdapOutcome = await rdapLookup(
      domain.ascii,
      domain.tld,
      config.upstream.rdapTimeoutMs,
    );
    if (!outcome.result) {
      throw ApiError.upstream('RDAP 未覆盖该域名或暂时不可用', {
        attempts: outcome.attempts,
      });
    }

    const entry: CachedRdap = {
      data: buildData(domain, outcome.result.parsed, outcome.result.raw),
      server: outcome.result.server,
      durationMs: Date.now() - startedAt,
      queriedAt: new Date().toISOString(),
      attempts: outcome.attempts,
    };
    rdapCache.set(domain.ascii, entry, config.cache.ttlMs);
    return entry;
  })();

  rdapInflight.set(domain.ascii, task);
  try {
    return { entry: await task, cached: false };
  } finally {
    rdapInflight.delete(domain.ascii);
  }
}

export function clearRdapCache(): void {
  rdapCache.clear();
  rdapInflight.clear();
}

export function rdapCacheSize(): number {
  return rdapCache.size;
}

/* ----------------------------- registrar ------------------------------ */

interface DirectoryEntry {
  id: string;
  ianaId: string | null;
  name: string;
  website: string | null;
  country: string | null;
  contact: string | null;
  status: RegistrarStatus;
  rdapServer: string | null;
  updated: string | null;
  aliases: string[];
  source: 'iana' | 'iana+icann' | 'icann' | 'curated' | 'local';
  indexedDomains: number;
  lastSeen: string | null;
}

/** 合并 IANA/ICANN 目录与本站本地索引统计 */
let directoryCache: { at: number; entries: DirectoryEntry[] } | null = null;
const DIRECTORY_CACHE_MS = 15_000;

function buildDirectory(): DirectoryEntry[] {
  if (directoryCache && Date.now() - directoryCache.at < DIRECTORY_CACHE_MS) {
    return directoryCache.entries;
  }

  const usage = domainIndex.registrarUsage();
  const used = new Set<string>();

  const findUsage = (ianaId: string | null, name: string) =>
    usage.find((item) => {
      if (ianaId && item.ianaId === ianaId) return true;
      return item.name.toLowerCase() === name.toLowerCase();
    });

  const entries: DirectoryEntry[] = registrarRegistry.all().map((record) => {
    const match = findUsage(record.ianaId, record.name);
    if (match) used.add(match.key);
    return {
      id: record.ianaId ?? record.name.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      ianaId: record.ianaId,
      name: record.name,
      website: record.website,
      country: record.country,
      contact: record.contact,
      status: record.status,
      rdapServer: record.rdapServer,
      updated: record.updated,
      aliases: record.aliases,
      source: record.origin,
      indexedDomains: match?.count ?? 0,
      lastSeen: match?.lastSeen ?? null,
    };
  });

  for (const item of usage) {
    if (used.has(item.key)) continue;
    entries.push({
      id: item.key,
      ianaId: item.ianaId,
      name: item.name,
      website: null,
      country: null,
      contact: null,
      status: 'unknown',
      rdapServer: null,
      updated: null,
      aliases: [],
      source: 'local',
      indexedDomains: item.count,
      lastSeen: item.lastSeen,
    });
  }

  entries.sort((a, b) => {
    if (b.indexedDomains !== a.indexedDomains) return b.indexedDomains - a.indexedDomains;
    return a.name.localeCompare(b.name);
  });

  directoryCache = { at: Date.now(), entries };
  return entries;
}

function findDirectoryEntry(directory: DirectoryEntry[], id: string): DirectoryEntry | null {
  const value = id.trim().toLowerCase();
  return (
    directory.find((item) => item.id === value || item.ianaId === value) ??
    directory.find((item) => item.name.toLowerCase() === value) ??
    directory.find((item) => item.aliases.some((alias) => alias.toLowerCase() === value)) ??
    null
  );
}

/* -------------------------------- routes ------------------------------- */

export async function toolRoutes(
  app: FastifyInstance,
  options: ToolRouteOptions,
): Promise<void> {
  const base = options.basePath.replace(/\/$/, '');

  /* RDAP */
  const rdapHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    rawDomain: string,
    includeRaw: boolean,
  ) => {
    const domain = parseDomain(rawDomain);
    const { entry, cached } = await rdapQuery(domain);
    cacheHeaders(reply, cached, config.cache.ttlMs);
    metrics.recordQuery('rdap', domain.ascii, cached);
    if (!entry.data.available) remember(entry.data);

    const { raw, ...rest } = entry.data;
    return {
      success: true,
      data: includeRaw ? entry.data : rest,
      meta: meta(request, {
        source: 'rdap',
        server: entry.server,
        durationMs: entry.durationMs,
        queriedAt: entry.queriedAt,
        cached,
        attempts: entry.attempts,
      }),
    };
  };

  app.get<{ Params: DomainParams; Querystring: DomainQuery }>(
    `${base}/rdap/:domain`,
    { schema: { params: domainParamSchema, querystring: domainQuerySchema } },
    async (request, reply) =>
      rdapHandler(request, reply, request.params.domain, asFlag(request.query.raw)),
  );

  app.get<{ Querystring: DomainQuery }>(
    `${base}/rdap`,
    { schema: { querystring: domainQuerySchema } },
    async (request, reply) => {
      if (!request.query.domain) throw ApiError.badRequest('缺少 domain 查询参数');
      return rdapHandler(request, reply, request.query.domain, asFlag(request.query.raw));
    },
  );

  /* DNS */
  const dnsHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    rawDomain: string,
    rawType: string | undefined,
  ) => {
    const domain = parseDomain(rawDomain);
    const raw = String(rawType ?? 'A').toUpperCase();

    if (raw.includes(',')) {
      const types = normalizeDnsTypes(raw);
      if (types.length < 2) {
        throw ApiError.badRequest(
          `多类型查询最多 6 个，可选：${['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'CAA', 'ANY'].join(', ')}`,
        );
      }
      const results = await Promise.all(types.map((item) => lookupDns(domain.ascii, item)));
      const cached = results.every((item) => item.cached);
      cacheHeaders(reply, cached, Math.min(...results.map((item) => item.ttlMs)));
      metrics.recordQuery('dns', `${domain.ascii} ${types.join(',')}`, cached);
      return {
        success: true,
        data: {
          domain: domain.ascii,
          tld: domain.tld,
          sld: domain.sld,
          idn: domain.idn,
          unicodeDomain: domain.unicode,
          types,
          results,
        },
        meta: meta(request, {
          source: 'dns',
          resolver: 'system',
          cached,
          durationMs: Math.max(...results.map((item) => item.durationMs)),
        }),
      };
    }

    const type = raw;
    if (!isDnsType(type)) {
      throw ApiError.badRequest(`不支持的记录类型，可选：${['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'CAA', 'ANY'].join(', ')}`);
    }

    const result = await lookupDns(domain.ascii, type as DnsQueryType);
    cacheHeaders(reply, result.cached, result.ttlMs);
    metrics.recordQuery('dns', `${domain.ascii} ${type}`, result.cached);

    return {
      success: true,
      data: {
        ...result,
        tld: domain.tld,
        sld: domain.sld,
        idn: domain.idn,
        unicodeDomain: domain.unicode,
      },
      meta: meta(request, {
        source: 'dns',
        resolver: 'system',
        cached: result.cached,
        durationMs: result.durationMs,
      }),
    };
  };

  app.get<{ Params: DomainParams; Querystring: DnsQuery }>(
    `${base}/dns/:domain`,
    { schema: { params: domainParamSchema, querystring: dnsQuerySchema } },
    async (request, reply) =>
      dnsHandler(request, reply, request.params.domain, request.query.type),
  );

  app.get<{ Querystring: DnsQuery }>(
    `${base}/dns`,
    { schema: { querystring: dnsQuerySchema } },
    async (request, reply) => {
      if (!request.query.domain) throw ApiError.badRequest('缺少 domain 查询参数');
      return dnsHandler(request, reply, request.query.domain, request.query.type);
    },
  );

  /* IP */
  const ipHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    rawIp: string,
    includeRaw: boolean,
  ) => {
    let result;
    try {
      result = await lookupIp(rawIp, includeRaw);
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw ApiError.badRequest(error instanceof Error ? error.message : 'IP 地址不合法');
    }

    cacheHeaders(reply, result.cached, result.ttlMs);
    metrics.recordQuery('ip', result.ip, result.cached);

    return {
      success: true,
      data: result,
      meta: meta(request, {
        source: 'ip-rdap',
        cached: result.cached,
        durationMs: result.durationMs,
        server: result.server,
      }),
    };
  };

  app.get<{ Params: IpParams; Querystring: IpQuery }>(
    `${base}/ip/:ip`,
    { schema: { params: ipParamSchema, querystring: ipQuerySchema } },
    async (request, reply) =>
      ipHandler(request, reply, request.params.ip, asFlag(request.query.raw)),
  );

  app.get<{ Querystring: IpQuery }>(
    `${base}/ip`,
    { schema: { querystring: ipQuerySchema } },
    async (request, reply) => {
      if (!request.query.ip) throw ApiError.badRequest('缺少 ip 查询参数');
      return ipHandler(request, reply, request.query.ip, asFlag(request.query.raw));
    },
  );

  /* Uptime */
  const uptimeHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    target: string,
  ) => {
    const result = await checkUptime(target);
    reply.header('x-cache', result.cached ? 'HIT' : 'MISS');
    reply.header('cache-control', 'no-store');
    metrics.recordQuery('uptime', result.target, result.cached);

    return {
      success: true,
      data: result,
      meta: meta(request, {
        source: 'uptime',
        cached: result.cached,
        durationMs: result.latencyMs,
      }),
    };
  };

  app.get<{ Querystring: UptimeQuery }>(
    `${base}/uptime`,
    { schema: { querystring: uptimeQuerySchema } },
    async (request, reply) => {
      if (!request.query.target) throw ApiError.badRequest('缺少 target 查询参数');
      return uptimeHandler(request, reply, request.query.target);
    },
  );

  app.get<{ Params: TargetParams }>(
    `${base}/uptime/:target`,
    { schema: { params: targetParamSchema } },
    async (request, reply) => uptimeHandler(request, reply, request.params.target),
  );

  /* History */
  const historyHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    rawDomain: string,
    refresh: boolean,
  ) => {
    const domain = parseDomain(rawDomain);
    let history = historyStore.get(domain.ascii);
    let note: string | undefined;

    if (history.snapshots.length === 0 || refresh) {
      try {
        const result = await lookupDomain(domain, { forceRefresh: refresh });
        historyStore.record(result.record.data);
        domainIndex.record(result.record.data);
        history = historyStore.get(domain.ascii);
      } catch (error) {
        note = error instanceof ApiError
          ? error.message
          : '实时快照获取失败，以下为已保存的历史记录';
      }
    }

    reply.header('cache-control', 'no-store');
    metrics.recordQuery('history', domain.ascii, false);

    return {
      success: true,
      data: { ...history, note: note ? `${history.note} ${note}` : history.note },
      meta: meta(request, {
        source: 'history',
        snapshots: history.snapshots.length,
        changes: history.changes.length,
      }),
    };
  };

  app.get<{ Params: DomainParams; Querystring: DomainQuery }>(
    `${base}/history/:domain`,
    { schema: { params: domainParamSchema, querystring: domainQuerySchema } },
    async (request, reply) =>
      historyHandler(request, reply, request.params.domain, asFlag(request.query.refresh)),
  );

  app.get<{ Querystring: DomainQuery }>(
    `${base}/history`,
    { schema: { querystring: domainQuerySchema } },
    async (request, reply) => {
      if (!request.query.domain) throw ApiError.badRequest('缺少 domain 查询参数');
      return historyHandler(request, reply, request.query.domain, asFlag(request.query.refresh));
    },
  );

  /* Nameserver reverse */
  const nameserverHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    rawHost: string,
    limit: number,
    offset: number,
  ) => {
    let host: string;
    try {
      host = parseDomain(rawHost).ascii;
    } catch {
      throw ApiError.badRequest('请输入合法的名称服务器主机名，例如 ns1.example.com');
    }

    const result = domainIndex.reverseNameserver(host, limit, offset);
    reply.header('cache-control', 'no-store');
    metrics.recordQuery('nameservers', host, false);

    return {
      success: true,
      data: { ...result, note: INDEX_NOTE },
      meta: meta(request, {
        source: 'local-index',
        total: result.total,
        limit,
        offset,
      }),
    };
  };

  app.get<{ Params: HostParams; Querystring: NameserverQuery }>(
    `${base}/nameservers/:host`,
    { schema: { params: hostParamSchema, querystring: nameserverQuerySchema } },
    async (request, reply) =>
      nameserverHandler(
        request,
        reply,
        request.params.host,
        Number(request.query.limit ?? 100),
        Number(request.query.offset ?? 0),
      ),
  );

  app.get<{ Querystring: NameserverQuery }>(
    `${base}/nameservers`,
    { schema: { querystring: nameserverQuerySchema } },
    async (request, reply) => {
      if (!request.query.host) throw ApiError.badRequest('缺少 host 查询参数');
      return nameserverHandler(
        request,
        reply,
        request.query.host,
        Number(request.query.limit ?? 100),
        Number(request.query.offset ?? 0),
      );
    },
  );

  /* TLS 证书 */
  const tlsHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    host: string,
    port: number | string | undefined,
  ) => {
    const startedAt = Date.now();
    const result = await checkTls(host, port);
    cacheHeaders(reply, result.cached, result.ttlMs);
    metrics.recordQuery('tls', `${result.host}:${result.port}`, result.cached);

    return {
      success: true,
      data: result,
      meta: meta(request, {
        source: 'tls',
        cached: result.cached,
        durationMs: result.cached ? 0 : Date.now() - startedAt,
        checkedAt: result.checkedAt,
      }),
    };
  };

  app.get<{ Params: HostParams; Querystring: TlsQuery }>(
    `${base}/tls/:host`,
    { schema: { params: hostParamSchema, querystring: tlsQuerySchema } },
    async (request, reply) =>
      tlsHandler(request, reply, request.params.host, request.query.port),
  );

  app.get<{ Querystring: TlsQuery }>(
    `${base}/tls`,
    { schema: { querystring: tlsQuerySchema } },
    async (request, reply) => {
      if (!request.query.host) throw ApiError.badRequest('缺少 host 查询参数');
      return tlsHandler(request, reply, request.query.host, request.query.port);
    },
  );

  /* 邮件安全 */
  const mailHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    rawDomain: string,
    selector: string | undefined,
  ) => {
    const domain = parseDomain(rawDomain);
    const result = await checkMailAuth(domain.ascii, selector);
    cacheHeaders(reply, result.cached, result.ttlMs);
    metrics.recordQuery('mail', domain.ascii, result.cached);

    return {
      success: true,
      data: { ...result, tld: domain.tld, unicodeDomain: domain.unicode },
      meta: meta(request, {
        source: 'mail-dns',
        cached: result.cached,
        selectors: result.dkim.map((item) => item.selector),
        note: MAIL_NOTE,
      }),
    };
  };

  app.get<{ Params: DomainParams; Querystring: MailQuery }>(
    `${base}/mail/:domain`,
    { schema: { params: domainParamSchema, querystring: mailQuerySchema } },
    async (request, reply) =>
      mailHandler(request, reply, request.params.domain, request.query.selector),
  );

  app.get<{ Querystring: MailQuery }>(
    `${base}/mail`,
    { schema: { querystring: mailQuerySchema } },
    async (request, reply) => {
      if (!request.query.domain) throw ApiError.badRequest('缺少 domain 查询参数');
      return mailHandler(request, reply, request.query.domain, request.query.selector);
    },
  );

  /* HTTP 安全体检 */
  const httpHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    target: string,
    refresh: boolean,
  ) => {
    const result = await checkHttp(target, { refresh });
    cacheHeaders(reply, result.cached, result.ttlMs);
    metrics.recordQuery('http', result.host, result.cached);

    return {
      success: true,
      data: result,
      meta: meta(request, {
        source: 'http-probe',
        cached: result.cached,
        durationMs: result.latencyMs,
        note: HTTP_NOTE,
      }),
    };
  };

  app.get<{ Params: TargetParams; Querystring: HttpQuery }>(
    `${base}/http/:target`,
    { schema: { params: targetParamSchema, querystring: httpQuerySchema } },
    async (request, reply) =>
      httpHandler(request, reply, request.params.target, asFlag(request.query.refresh)),
  );

  app.get<{ Querystring: HttpQuery }>(
    `${base}/http`,
    { schema: { querystring: httpQuerySchema } },
    async (request, reply) => {
      if (!request.query.target) throw ApiError.badRequest('缺少 target 查询参数');
      return httpHandler(request, reply, request.query.target, asFlag(request.query.refresh));
    },
  );

  /* DNS 传播对比 */
  const dnsPropHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    rawDomain: string,
    type: string | undefined,
  ) => {
    const result = await checkDnsPropagation(rawDomain, type);
    cacheHeaders(reply, result.cached, result.ttlMs);
    metrics.recordQuery('dnsprop', `${result.domain} ${result.type}`, result.cached);

    return {
      success: true,
      data: result,
      meta: meta(request, {
        source: 'dns-propagation',
        cached: result.cached,
        resolvers: result.resolvers.map((item) => item.name),
        note: DNS_PROP_NOTE,
      }),
    };
  };

  app.get<{ Params: DomainParams; Querystring: DnsPropQuery }>(
    `${base}/dnsprop/:domain`,
    { schema: { params: domainParamSchema, querystring: dnsPropQuerySchema } },
    async (request, reply) =>
      dnsPropHandler(request, reply, request.params.domain, request.query.type),
  );

  app.get<{ Querystring: DnsPropQuery }>(
    `${base}/dnsprop`,
    { schema: { querystring: dnsPropQuerySchema } },
    async (request, reply) => {
      if (!request.query.domain) throw ApiError.badRequest('缺少 domain 查询参数');
      return dnsPropHandler(request, reply, request.query.domain, request.query.type);
    },
  );

  /* 域名健康评分 */
  const healthHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    rawDomain: string,
    refresh: boolean,
    dimensions?: string,
  ) => {
    const result = await checkDomainHealth(rawDomain, { refresh, dimensions });
    cacheHeaders(reply, result.cached, result.ttlMs);
    metrics.recordQuery('health', result.domain, result.cached);

    return {
      success: true,
      data: result,
      meta: meta(request, {
        source: 'health-score',
        cached: result.cached,
        score: result.score,
        grade: result.grade,
        note: HEALTH_NOTE,
      }),
    };
  };

  app.get<{ Params: DomainParams; Querystring: HealthQuery }>(
    `${base}/health/:domain`,
    { schema: { params: domainParamSchema, querystring: healthQuerySchema } },
    async (request, reply) =>
      healthHandler(
        request,
        reply,
        request.params.domain,
        asFlag(request.query.refresh),
        request.query.dimensions,
      ),
  );

  app.get<{ Querystring: HealthQuery }>(
    `${base}/health`,
    { schema: { querystring: healthQuerySchema } },
    async (request, reply) => {
      if (!request.query.domain) throw ApiError.badRequest('缺少 domain 查询参数');
      return healthHandler(
        request,
        reply,
        request.query.domain,
        asFlag(request.query.refresh),
        request.query.dimensions,
      );
    },
  );

  /* 批量可注册查询 */
  const availabilityHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    domains: string,
  ) => {
    const result = await checkAvailability(domains);
    reply.header('x-cache', result.cached ? 'HIT' : 'MISS');
    reply.header('cache-control', 'no-store');
    metrics.recordQuery('available', `${result.total} domains`, result.cached);

    return {
      success: true,
      data: result,
      meta: meta(request, {
        source: 'availability',
        total: result.total,
        available: result.available,
        note: AVAILABILITY_NOTE,
      }),
    };
  };

  app.get<{ Params: { domains: string }; Querystring: AvailabilityQuery }>(
    `${base}/available/:domains`,
    { schema: { params: { type: 'object', required: ['domains'], properties: { domains: { type: 'string', minLength: 1, maxLength: 4096 } } } } },
    async (request, reply) => availabilityHandler(request, reply, request.params.domains),
  );

  app.get<{ Querystring: AvailabilityQuery }>(
    `${base}/available`,
    { schema: { querystring: availabilityQuerySchema } },
    async (request, reply) => {
      if (!request.query.domains) throw ApiError.badRequest('缺少 domains 查询参数');
      return availabilityHandler(request, reply, request.query.domains);
    },
  );

  /* 证书链导出 */
  const certChainHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    host: string,
    port: number | string | undefined,
    format: string | undefined,
  ) => {
    const result = await fetchCertificateChain(host, port);
    cacheHeaders(reply, result.cached, result.ttlMs);
    metrics.recordQuery('certchain', `${result.host}:${result.port}`, result.cached);

    if (String(format ?? 'json').toLowerCase() === 'pem') {
      reply.type('application/x-pem-file');
      reply.header('content-disposition', `inline; filename="${result.host}.pem"`);
      return reply.send(result.pem);
    }

    return {
      success: true,
      data: result,
      meta: meta(request, {
        source: 'cert-chain',
        cached: result.cached,
        count: result.count,
        note: CERT_CHAIN_NOTE,
      }),
    };
  };

  app.get<{ Params: HostParams; Querystring: CertChainQuery }>(
    `${base}/tls/:host/chain`,
    { schema: { params: hostParamSchema, querystring: certChainQuerySchema } },
    async (request, reply) =>
      certChainHandler(
        request,
        reply,
        request.params.host,
        request.query.port,
        request.query.format,
      ),
  );

  app.get<{ Params: CertChainParams; Querystring: CertChainQuery }>(
    `${base}/certchain/:host`,
    {
      schema: {
        params: { type: 'object', required: ['host'], properties: { host: { type: 'string', minLength: 3, maxLength: 2048 } } },
        querystring: certChainQuerySchema,
      },
    },
    async (request, reply) =>
      certChainHandler(
        request,
        reply,
        request.params.host,
        request.query.port,
        request.query.format,
      ),
  );

  app.get<{ Querystring: CertChainQuery }>(
    `${base}/certchain`,
    { schema: { querystring: certChainQuerySchema } },
    async (request, reply) => {
      if (!request.query.host) throw ApiError.badRequest('缺少 host 查询参数');
      return certChainHandler(
        request,
        reply,
        request.query.host,
        request.query.port,
        request.query.format,
      );
    },
  );

  /* ICP 备案 */
  const icpHandler = async (
    request: FastifyRequest,
    reply: FastifyReply,
    rawDomain: string,
    refresh: boolean,
  ) => {
    const domain = parseDomain(rawDomain);
    const { result, cached, durationMs } = await lookupIcp(domain.ascii, { refresh });

    cacheHeaders(reply, cached, config.icp.cacheTtlMs);
    metrics.recordQuery('icp', domain.ascii, cached);

    return {
      success: true,
      data: result,
      meta: meta(request, {
        source: 'icp',
        cached,
        durationMs,
        note: ICP_NOTE,
      }),
    };
  };

  app.get<{ Params: DomainParams; Querystring: DomainQuery }>(
    `${base}/icp/:domain`,
    { schema: { params: domainParamSchema, querystring: domainQuerySchema } },
    async (request, reply) => icpHandler(request, reply, request.params.domain, asFlag(request.query.refresh)),
  );

  app.get<{ Querystring: DomainQuery }>(
    `${base}/icp`,
    { schema: { querystring: domainQuerySchema } },
    async (request, reply) => {
      if (!request.query.domain) throw ApiError.badRequest('缺少 domain 查询参数');
      return icpHandler(request, reply, request.query.domain, asFlag(request.query.refresh));
    },
  );

  /* Registrars */
  app.get<{ Querystring: RegistrarQuery }>(
    `${base}/registrars`,
    { schema: { querystring: registrarQuerySchema } },
    async (request) => {
      const q = String(request.query.q ?? '').trim().toLowerCase();
      const country = String(request.query.country ?? '').trim().toLowerCase();
      const status = String(request.query.status ?? '').trim().toLowerCase();
      const page = Number(request.query.page ?? 1);
      const limit = Number(request.query.limit ?? 24);

      let entries = buildDirectory();
      if (status === 'all') {
        // 保留全部状态
      } else if (status) {
        entries = entries.filter((entry) => entry.status === status);
      } else {
        // 默认不展示已终止/保留的注册商
        entries = entries.filter(
          (entry) => entry.status !== 'terminated' && entry.status !== 'reserved',
        );
      }
      if (country) {
        entries = entries.filter((entry) => (entry.country ?? '').toLowerCase() === country);
      }
      if (q) {
        entries = entries.filter((entry) =>
          [entry.name, entry.ianaId, entry.id, entry.country, entry.website, entry.contact, ...entry.aliases]
            .filter(Boolean)
            .join(' ')
            .toLowerCase()
            .includes(q),
        );
      }

      const total = entries.length;
      const items = entries.slice((page - 1) * limit, page * limit);
      metrics.recordQuery('registrars', q || '*', false);

      const sync = registrarRegistry.status();
      return {
        success: true,
        data: {
          total,
          page,
          limit,
          totalPages: Math.max(1, Math.ceil(total / limit)),
          items,
          stats: registrarRegistry.stats(),
          sync: {
            syncedAt: sync.syncedAt,
            ianaUpdated: sync.ianaUpdated,
            sources: sync.sources,
            refreshing: sync.refreshing,
            total: sync.total,
          },
          note: registrarNote(sync.syncedAt),
        },
        meta: meta(request, { source: 'registrar-directory' }),
      };
    },
  );

  app.get<{ Params: RegistrarParams; Querystring: RegistrarDetailQuery }>(
    `${base}/registrars/:id`,
    { schema: { params: registrarParamsSchema, querystring: registrarDetailQuerySchema } },
    async (request) => {
      const id = request.params.id;
      const limit = Number(request.query.limit ?? 40);
      const offset = Number(request.query.offset ?? 0);

      const directory = buildDirectory();
      const entry = findDirectoryEntry(directory, id);
      if (!entry) throw ApiError.notFound('未找到该注册商');

      const domains = domainIndex.registrarDomains(
        { ianaId: entry.ianaId, name: entry.name },
        limit,
        offset,
      );
      metrics.recordQuery('registrars', entry.name, false);
      const sync = registrarRegistry.status();

      return {
        success: true,
        data: {
          registrar: entry,
          domains: {
            total: domains.total,
            offset,
            limit,
            items: domains.domains,
          },
          sync: { syncedAt: sync.syncedAt, sources: sync.sources, total: sync.total },
          note: registrarNote(sync.syncedAt),
        },
        meta: meta(request, { source: 'registrar-directory' }),
      };
    },
  );

  app.get<{ Params: RegistrarParams; Querystring: RegistrarDetailQuery }>(
    `${base}/registrars/:id/domains`,
    { schema: { params: registrarParamsSchema, querystring: registrarDetailQuerySchema } },
    async (request) => {
      const id = request.params.id;
      const limit = Number(request.query.limit ?? 40);
      const offset = Number(request.query.offset ?? 0);

      const entry = findDirectoryEntry(buildDirectory(), id);
      if (!entry) throw ApiError.notFound('未找到该注册商');

      const domains = domainIndex.registrarDomains(
        { ianaId: entry.ianaId, name: entry.name },
        limit,
        offset,
      );
      metrics.recordQuery('registrars', entry.name, false);

      return {
        success: true,
        data: {
          registrar: { id: entry.id, ianaId: entry.ianaId, name: entry.name },
          total: domains.total,
          offset,
          limit,
          items: domains.domains,
          note: INDEX_NOTE,
        },
        meta: meta(request, { source: 'local-index' }),
      };
    },
  );
}
