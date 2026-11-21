import type { FastifyInstance, FastifyRequest } from 'fastify';
import { config } from '../config.js';
import { mapWithConcurrency } from '../lib/concurrency.js';
import { parseDomain } from '../lib/domain.js';
import { ApiError } from '../lib/errors.js';
import { metrics } from '../lib/metrics.js';
import { historyStore } from '../services/history.js';
import { domainIndex } from '../services/index.js';
import { lookupDomain } from '../whois/lookup.js';
import type { LookupRecord } from '../whois/types.js';

interface LookupQuery {
  domain?: string;
  raw?: boolean | string;
  refresh?: boolean | string;
}

interface DomainParams {
  domain: string;
}

interface BatchBody {
  domains: string[];
  raw?: boolean;
  refresh?: boolean;
}

const booleanFlagSchema = {
  anyOf: [
    { type: 'boolean' },
    { type: 'string', enum: ['true', 'false', '1', '0'] },
  ],
} as const;

const lookupQuerySchema = {
  type: 'object',
  properties: {
    domain: { type: 'string', minLength: 1, maxLength: 512 },
    raw: { ...booleanFlagSchema, default: false },
    refresh: { ...booleanFlagSchema, default: false },
  },
} as const;

const domainParamsSchema = {
  type: 'object',
  required: ['domain'],
  properties: {
    domain: { type: 'string', minLength: 1, maxLength: 512 },
  },
} as const;

const batchSchema = {
  type: 'object',
  required: ['domains'],
  properties: {
    domains: {
      type: 'array',
      minItems: 1,
      maxItems: config.upstream.batchMaxDomains,
      items: { type: 'string', minLength: 1, maxLength: 512 },
    },
    raw: { type: 'boolean', default: false },
    refresh: { type: 'boolean', default: false },
  },
} as const;

function metaOf(
  request: FastifyRequest,
  record: LookupRecord,
  cached: boolean,
  ttlMs: number,
): Record<string, unknown> {
  return {
    source: record.source,
    server: record.server,
    durationMs: record.durationMs,
    cached,
    cacheTtlMs: Math.round(ttlMs),
    queriedAt: record.queriedAt,
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
  };
}

function payloadOf(
  request: FastifyRequest,
  record: LookupRecord,
  cached: boolean,
  ttlMs: number,
  includeRaw: boolean,
): Record<string, unknown> {
  const { raw, ...rest } = record.data;
  return {
    success: true,
    data: includeRaw ? record.data : rest,
    meta: metaOf(request, record, cached, ttlMs),
  };
}

function asFlag(value: unknown): boolean {
  return value === true || value === 1 || value === '1' || value === 'true';
}

async function performLookup(
  request: FastifyRequest,
  reply: import('fastify').FastifyReply,
  rawDomain: string,
  options: { raw?: boolean | string; refresh?: boolean | string },
): Promise<Record<string, unknown>> {
  const domain = parseDomain(rawDomain);
  const includeRaw = asFlag(options.raw);
  const refresh = asFlag(options.refresh);

  const result = await lookupDomain(domain, { forceRefresh: refresh, includeRaw });

  metrics.recordCache('whois', result.cached);
  metrics.recordQuery('whois', domain.ascii, result.cached);
  if (!result.cached) {
    historyStore.record(result.record.data);
    domainIndex.record(result.record.data);
  }

  reply.header('x-cache', result.cached ? 'HIT' : 'MISS');
  const edgeTtl = Math.min(30, Math.max(1, Math.round(result.ttlMs / 1000)));
  reply.header(
    'cache-control',
    refresh
      ? 'no-store'
      : `public, max-age=${Math.min(60, Math.max(1, Math.round(result.ttlMs / 1000)))}, s-maxage=${edgeTtl}, stale-while-revalidate=30`,
  );

  return payloadOf(request, result.record, result.cached, result.ttlMs, includeRaw);
}

export interface WhoisRouteOptions {
  /** 路由前缀：`/v1`（API）或 `/web/v1`（网页端，策略独立） */
  basePath: string;
}

export async function whoisRoutes(
  app: FastifyInstance,
  options: WhoisRouteOptions,
): Promise<void> {
  const base = options.basePath.replace(/\/$/, '');

  app.get<{ Params: DomainParams; Querystring: LookupQuery }>(
    `${base}/whois/:domain`,
    { schema: { params: domainParamsSchema, querystring: lookupQuerySchema } },
    async (request, reply) => {
      const { domain } = request.params;
      return performLookup(request, reply, domain, request.query);
    },
  );

  app.get<{ Querystring: LookupQuery }>(
    `${base}/whois`,
    { schema: { querystring: lookupQuerySchema } },
    async (request, reply) => {
      const domain = request.query.domain;
      if (!domain) {
        throw ApiError.badRequest('缺少 domain 查询参数');
      }
      return performLookup(request, reply, domain, request.query);
    },
  );

  app.post<{ Body: BatchBody }>(
    `${base}/whois/batch`,
    { schema: { body: batchSchema } },
    async (request, reply) => {
      const startedAt = Date.now();
      const { domains, raw = false, refresh = false } = request.body;

      const uniqueDomains = [...new Set(domains.map((domain) => domain.trim()).filter(Boolean))];
      if (uniqueDomains.length === 0) {
        throw ApiError.badRequest('domains 不能为空');
      }

      const results = await mapWithConcurrency(
        uniqueDomains,
        config.upstream.batchConcurrency,
        async (rawDomain) => {
          try {
            const domain = parseDomain(rawDomain);
            const result = await lookupDomain(domain, { forceRefresh: refresh, includeRaw: raw });
            metrics.recordCache('whois', result.cached);
            metrics.recordQuery('whois', domain.ascii, result.cached);
            if (!result.cached) {
              historyStore.record(result.record.data);
              domainIndex.record(result.record.data);
            }
            return payloadOf(request, result.record, result.cached, result.ttlMs, raw);
          } catch (error) {
            if (error instanceof ApiError) {
              return error.toJSON();
            }
            request.log.warn({ err: error, domain: rawDomain }, 'batch lookup failed');
            return {
              success: false,
              error: { code: 'INTERNAL', message: '查询失败，请稍后重试' },
            };
          }
        },
      );

      reply.header('x-cache', 'MISS');
      reply.header('cache-control', 'no-store');

      return {
        success: true,
        results,
        meta: {
          count: results.length,
          durationMs: Date.now() - startedAt,
          requestId: request.id,
        },
      };
    },
  );
}
