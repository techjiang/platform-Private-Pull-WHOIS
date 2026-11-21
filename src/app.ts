import { timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import compress from '@fastify/compress';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import Fastify, { LogController, type FastifyInstance, type FastifyRequest } from 'fastify';
import { config } from './config.js';
import { AdminSessions } from './admin/sessions.js';
import { AdminStore } from './admin/store.js';
import { ApiError } from './lib/errors.js';
import { FEATURE_LABELS, toolOfPath } from './lib/features.js';
import { initMetrics, metrics, persistMetrics } from './lib/metrics.js';
import { pruneAllCaches } from './lib/cache.js';
import { Scheduler } from './lib/scheduler.js';
import { FixedWindowRateLimiter } from './lib/ratelimit.js';
import { WebGuard } from './lib/webguard.js';
import { adminRoutes } from './routes/admin.js';
import { toolRoutes } from './routes/tools.js';
import { whoisRoutes } from './routes/whois.js';
import { systemRoutes } from './routes/system.js';
import { historyStore } from './services/history.js';
import { domainIndex } from './services/index.js';
import { registrarRegistry } from './services/registrars.js';
import { pruneIcpLocalCache } from './services/icp.js';
import { prewarmRdapBootstrap } from './whois/rdap.js';

const PUBLIC_DIR = fileURLToPath(new URL('../public', import.meta.url));

const SECURITY_HEADERS: Record<string, string> = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'geolocation=(), microphone=(), camera=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-site',
  'x-dns-prefetch-control': 'off',
  'x-permitted-cross-domain-policies': 'none',
  'content-security-policy':
    "default-src 'self'; base-uri 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
};

function extractApiKey(request: FastifyRequest): string | null {
  const header = request.headers['x-api-key'];
  if (typeof header === 'string' && header.trim()) return header.trim();

  const authorization = request.headers.authorization;
  if (authorization) {
    const match = /^Bearer\s+(.+)$/i.exec(authorization);
    if (match?.[1]) return match[1].trim();
  }
  return null;
}

function isValidApiKey(candidate: string | null): boolean {
  if (!candidate || config.apiKeys.size === 0) return false;
  const candidateBuffer = Buffer.from(candidate);
  let valid = false;
  for (const key of config.apiKeys) {
    const keyBuffer = Buffer.from(key);
    if (keyBuffer.length === candidateBuffer.length && timingSafeEqual(keyBuffer, candidateBuffer)) {
      valid = true;
    }
  }
  return valid;
}

function isClientError(error: unknown): error is { statusCode: number; message?: string } {
  const statusCode = (error as { statusCode?: unknown }).statusCode;
  return typeof statusCode === 'number' && statusCode >= 400 && statusCode < 500;
}

function errorMeta(request: FastifyRequest): Record<string, unknown> {
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
  };
}

export async function buildApp(): Promise<FastifyInstance> {
  const adminStore = new AdminStore(config.admin.dataFile || undefined, {
    requireKey: config.requireKeyDefault,
    webEnabled: config.admin.webEnabledDefault,
    username: config.admin.username,
    password: config.admin.password,
  });
  await adminStore.init();
  const adminSessions = new AdminSessions(config.admin.sessionTtlMs);
  await Promise.all([historyStore.init(), domainIndex.init(), registrarRegistry.init(), initMetrics()]);

  const app = Fastify({
    logger: { level: config.logLevel },
    // 逐请求日志会带来持续磁盘写入与序列化开销，错误仍由错误处理器记录。
    logController: new LogController({ disableRequestLogging: true }),
    trustProxy: config.trustProxy,
    bodyLimit: 64 * 1024,
    requestIdHeader: 'x-request-id',
    // 限制空闲连接与单请求时长，降低慢速连接长期占用资源的风险
    connectionTimeout: 15_000,
    keepAliveTimeout: 72_000,
    requestTimeout: 60_000,
  });

  app.decorate('adminStore', adminStore);

  // 必须在注册路由之前设置，确保子上下文继承统一的错误处理器。
  app.setErrorHandler((error, request, reply) => {
    if (reply.sent) return;

    let apiError: ApiError;
    const validation = (error as { validation?: unknown }).validation;

    if (error instanceof ApiError) {
      apiError = error;
    } else if (validation) {
      apiError = ApiError.badRequest('请求参数不合法', validation);
    } else if ((error as { statusCode?: number }).statusCode === 404) {
      apiError = ApiError.notFound();
    } else if ((error as { statusCode?: number }).statusCode === 413) {
      apiError = ApiError.badRequest('请求体过大');
    } else if ((error as { statusCode?: number }).statusCode === 415) {
      apiError = new ApiError(415, 'UNSUPPORTED_MEDIA_TYPE', '不支持的 Content-Type');
    } else if (isClientError(error)) {
      apiError = new ApiError(
        (error as { statusCode: number }).statusCode,
        'BAD_REQUEST',
        error.message || '请求不合法',
      );
    } else {
      request.log.error({ err: error }, 'unhandled request error');
      apiError = ApiError.internal();
    }

    reply.status(apiError.statusCode).send({
      ...apiError.toJSON(),
      meta: errorMeta(request),
    });
  });

  app.setNotFoundHandler((request, reply) => {
    reply.status(404).send({
      success: false,
      error: { code: 'NOT_FOUND', message: '接口或资源不存在' },
      meta: { requestId: request.id },
    });
  });

  await app.register(cors, {
    origin: config.corsOrigin,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['content-type', 'x-api-key', 'authorization'],
    exposedHeaders: [
      'x-request-id',
      'x-cache',
      'x-key-quota-limit',
      'x-key-quota-remaining',
      'x-key-expires-at',
      'ratelimit-limit',
      'ratelimit-remaining',
      'ratelimit-reset',
      'x-web-quota-limit',
      'x-web-quota-remaining',
      'retry-after',
    ],
    maxAge: 86400,
  });

  // 动态 JSON 以 gzip 为主：压缩速度明显快于 brotli，降低响应延迟与 CPU 占用
  await app.register(compress, { global: true, threshold: 1024, encodings: ['gzip', 'deflate'] });

  await app.register(fastifyStatic, {
    root: PUBLIC_DIR,
    prefix: '/',
    index: ['index.html'],
    cacheControl: false,
    setHeaders(res, filePath) {
      // 首页与文档允许 CDN 短暂缓存，命中边缘节点时无需回源；后台页面禁止缓存
      if (/admin\.html?$/i.test(filePath)) {
        res.setHeader('cache-control', 'no-store');
      } else if (/\.html?$/i.test(filePath)) {
        res.setHeader('cache-control', 'public, max-age=0, s-maxage=60, stale-while-revalidate=60');
      } else if (/\.(css|js|mjs|svg|ico|png|jpe?g|webp|woff2?)$/i.test(filePath)) {
        res.setHeader('cache-control', 'public, max-age=2592000, immutable');
      } else {
        res.setHeader('cache-control', 'public, max-age=3600');
      }
    },
  });

  const limiter = new FixedWindowRateLimiter(config.rateLimit.windowMs);
  const webGuard = new WebGuard();
  const scheduler = new Scheduler(() => adminStore.schedulerPolicy);

  scheduler.register({
    key: 'cache',
    label: '缓存整理',
    description: '清理各查询缓存中已过期的条目，释放内存',
    intervalMs: 10 * 60 * 1000,
    critical: true,
    run: async () => {
      const result = pruneAllCaches();
      return { summary: `清理 ${result.removed} 条过期缓存，当前 ${result.entries} 条` };
    },
  });

  scheduler.register({
    key: 'warm',
    label: '上游数据预热',
    description: '提前拉取 RDAP 引导数据，减少首次查询 RDAP 域名的等待时间',
    intervalMs: 6 * 60 * 60 * 1000,
    run: async () => {
      const tlds = await prewarmRdapBootstrap();
      return { summary: `RDAP 引导覆盖 ${tlds} 个 TLD` };
    },
  });

  scheduler.register({
    key: 'icp',
    label: '备案缓存压缩',
    description: '清理本地持久化的过期备案缓存，控制数据文件体积',
    intervalMs: 24 * 60 * 60 * 1000,
    run: async () => {
      const result = await pruneIcpLocalCache();
      return { summary: `清理 ${result.removed} 条，保留 ${result.remaining} 条` };
    },
  });

  scheduler.register({
    key: 'persist',
    label: '本地数据落盘',
    description: '在低峰期把历史快照与域名索引写入磁盘，降低突发写入压力',
    intervalMs: 15 * 60 * 1000,
    run: async () => {
      await Promise.all([historyStore.flush(), domainIndex.flush()]);
      return { summary: '历史记录与域名索引已落盘' };
    },
  });

  scheduler.register({
    key: 'guard',
    label: '风控状态清理',
    description: '主动清理过期的限流、每日额度与临时封禁状态，避免来源 IP 记录堆积',
    intervalMs: 5 * 60 * 1000,
    run: async () => {
      const result = webGuard.pruneExpired();
      return { summary: `当前跟踪 ${result.trackedIps} 个 IP，封禁 ${result.blockedIps} 个` };
    },
  });

  scheduler.register({
    key: 'metrics',
    label: '调用统计落盘',
    description: '各接口调用次数先在内存中累计，再由调度器聚合批量写盘，避免高并发时逐条记录',
    intervalMs: 5 * 60 * 1000,
    run: async () => {
      const result = await persistMetrics();
      return { summary: `累计 ${result.totalRequests} 次调用，覆盖 ${result.tools} 个接口` };
    },
  });

  app.addHook('onRequest', async (request, reply) => {
    metrics.enter();
    reply.header('x-request-id', request.id);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      reply.header(name, value);
    }
    if (request.url.startsWith('/admin')) {
      reply.header('x-robots-tag', 'noindex, nofollow');
    }
    if (request.protocol === 'https') {
      reply.header('strict-transport-security', 'max-age=31536000; includeSubDomains');
    }

    const isApi = request.url.startsWith('/v1/');
    const isWeb = request.url.startsWith('/web/v1/');
    if (!isApi && !isWeb) return;

    // 网页端查询与 API 鉴权策略相互独立
    if (isWeb && !adminStore.webEnabled) {
      throw ApiError.webDisabled();
    }

    const tool = toolOfPath(request.url);

    // 网页端：限速 + 每日额度 + 违规临时封禁，均由后台策略驱动
    if (isWeb) {
      const verdict = webGuard.check(request.ip, adminStore.webPolicy);
      request.rateLimitInfo = {
        limit: verdict.limit,
        remaining: verdict.remaining,
        resetMs: verdict.resetSec * 1000,
      };
      reply.header('ratelimit-limit', String(verdict.limit));
      reply.header('ratelimit-remaining', String(verdict.remaining));
      reply.header('ratelimit-reset', String(Math.max(1, verdict.resetSec)));
      if (verdict.quota > 0) {
        reply.header('x-web-quota-limit', String(verdict.quota));
        reply.header('x-web-quota-remaining', String(verdict.quotaRemaining));
      }

      if (!verdict.allowed) {
        reply.header('retry-after', String(verdict.retryAfterSec));
        if (verdict.reason === 'quota') {
          throw new ApiError(
            429,
            'WEB_QUOTA_EXCEEDED',
            '网页端今日查询额度已用完，请明日再试或使用 API Key',
            { retryAfterSec: verdict.retryAfterSec },
          );
        }
        if (verdict.reason === 'blocked') {
          throw new ApiError(
            429,
            'RATE_LIMITED',
            '访问过于频繁，已临时限制，请稍后重试',
            { retryAfterSec: verdict.retryAfterSec },
          );
        }
        throw ApiError.rateLimited(verdict.retryAfterSec);
      }

      metrics.recordRequest(tool ?? 'system');
      if (tool && !adminStore.featureEnabled(tool)) {
        throw ApiError.featureDisabled(FEATURE_LABELS[tool]);
      }
      return;
    }

    const candidate = isApi ? extractApiKey(request) : null;
    const envKeyValid = isValidApiKey(candidate);
    const managedKey = candidate && !envKeyValid ? adminStore.findByToken(candidate) : null;
    const keyIssue = managedKey ? adminStore.evaluateKey(managedKey, tool, request.ip) : null;
    const keyValid = envKeyValid || Boolean(managedKey && !keyIssue);

    const limit = keyValid
      ? (managedKey?.rateLimit ?? config.rateLimit.keyMax)
      : config.rateLimit.max;
    const identity = managedKey
      ? `key:${managedKey.id}`
      : envKeyValid && candidate
        ? `envkey:${candidate}`
        : `ip:${request.ip}`;
    const rateLimit = limiter.hit(identity, limit);

    request.rateLimitInfo = {
      limit: rateLimit.limit,
      remaining: rateLimit.remaining,
      resetMs: rateLimit.resetMs,
    };
    reply.header('ratelimit-limit', String(rateLimit.limit));
    reply.header('ratelimit-remaining', String(rateLimit.remaining));
    reply.header('ratelimit-reset', String(Math.max(1, Math.ceil(rateLimit.resetMs / 1000))));

    if (!rateLimit.allowed) {
      reply.header('retry-after', String(rateLimit.retryAfterSec));
      throw ApiError.rateLimited(rateLimit.retryAfterSec);
    }

    metrics.recordRequest(tool ?? 'system');
    if (tool && !adminStore.featureEnabled(tool)) {
      throw ApiError.featureDisabled(FEATURE_LABELS[tool]);
    }

    if (!isApi) return;

    if (candidate && !keyValid) {
      if (managedKey && keyIssue) throw ApiError.keyIssue(keyIssue, tool);
      throw ApiError.unauthorized('API Key 无效或已停用');
    }

    if (adminStore.requireKey && !keyValid) {
      throw ApiError.unauthorized(
        '该接口需要 API Key，请在 x-api-key 或 Authorization: Bearer 中携带',
      );
    }

    if (managedKey) {
      request.apiKey = managedKey.prefix;
      reply.header('x-key-quota-used', String(managedKey.requestCount + 1));
      if (managedKey.quota !== null) {
        reply.header('x-key-quota-limit', String(managedKey.quota));
        reply.header(
          'x-key-quota-remaining',
          String(Math.max(0, managedKey.quota - managedKey.requestCount - 1)),
        );
      }
      if (managedKey.expiresAt) {
        reply.header('x-key-expires-at', managedKey.expiresAt);
      }
      adminStore.touch(managedKey.id, request.ip);
    } else if (keyValid && candidate) {
      request.apiKey = candidate;
    }
  });

  app.addHook('onResponse', async () => {
    metrics.leave();
  });

  // 客户端中断连接时不会触发 onResponse，单独回收并发计数，避免长期累积
  app.addHook('onRequestAbort', async (_request) => {
    metrics.leave();
  });

  app.get('/docs', async (_request, reply) => {
    reply.header('cache-control', 'public, max-age=0, s-maxage=60, stale-while-revalidate=60');
    return reply.sendFile('docs.html');
  });

  await app.register(adminRoutes, {
    store: adminStore,
    sessions: adminSessions,
    webGuard,
    scheduler,
  });
  // API 与网页端共用同一套查询逻辑，但鉴权策略完全独立
  await app.register(whoisRoutes, { basePath: '/v1' });
  await app.register(whoisRoutes, { basePath: '/web/v1' });
  await app.register(toolRoutes, { basePath: '/v1' });
  await app.register(toolRoutes, { basePath: '/web/v1' });
  await app.register(systemRoutes);

  scheduler.start();

  app.addHook('onClose', async () => {
    scheduler.stop();
    await Promise.all([
      historyStore.flush(),
      domainIndex.flush(),
      persistMetrics().catch(() => undefined),
    ]);
  });

  return app;
}
