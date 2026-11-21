import type { FastifyInstance, FastifyRequest } from 'fastify';
import { config } from '../config.js';
import { ApiError } from '../lib/errors.js';
import { FixedWindowRateLimiter } from '../lib/ratelimit.js';
import { AdminSessions, ADMIN_COOKIE, clearedSessionCookie, parseCookie, sessionCookie } from '../admin/sessions.js';
import { toPublicKey, validateCredentials, type AdminStore, type KeyOptions, type KeyPatch } from '../admin/store.js';
import { FEATURE_KEYS, FEATURE_LABELS, type FeatureFlags, type FeatureKey } from '../lib/features.js';
import { normalizeIpRule } from '../lib/netmatch.js';
import { metrics } from '../lib/metrics.js';
import { clearLookupCache, lookupCacheSize } from '../whois/lookup.js';
import { clearDnsCache, dnsCacheSize } from '../services/dns.js';
import { clearIpCache, ipCacheSize } from '../services/ip.js';
import { clearUptimeCache, uptimeCacheSize } from '../services/uptime.js';
import { clearRdapCache, rdapCacheSize } from '../routes/tools.js';
import { historyStore } from '../services/history.js';
import { domainIndex } from '../services/index.js';
import { registrarRegistry } from '../services/registrars.js';
import { clearIcpCache, icpCacheSize } from '../services/icp.js';
import { clearTlsCache, tlsCacheSize } from '../services/tls.js';
import { clearMailCache, mailCacheSize } from '../services/mail.js';
import { clearHttpCache, httpCacheSize } from '../services/httpcheck.js';
import { clearDnsPropCache, dnsPropCacheSize } from '../services/dnsprop.js';
import { clearHealthCache, healthCacheSize } from '../services/health.js';
import { clearAvailabilityCache, availabilityCacheSize } from '../services/available.js';
import { clearCertChainCache, certChainCacheSize } from '../services/certchain.js';
import type { WebGuard, WebPolicy } from '../lib/webguard.js';
import type { Scheduler, SchedulerPolicy } from '../lib/scheduler.js';

interface AdminRouteOptions {
  store: AdminStore;
  sessions: AdminSessions;
  webGuard: WebGuard;
  scheduler: Scheduler;
}

interface LoginBody {
  username: string;
  password: string;
}

interface KeyPolicyBody {
  expiresInDays?: number | null;
  quota?: number | null;
  rateLimit?: number | null;
  scopes?: FeatureKey[] | null;
  allowedIps?: string[];
  note?: string | null;
}

interface CreateKeyBody extends KeyPolicyBody {
  name?: string;
}

interface UpdateKeyBody extends KeyPolicyBody {
  name?: string;
  enabled?: boolean;
}

interface KeyParams {
  id: string;
}

interface SettingsBody {
  requireKey?: boolean;
  webEnabled?: boolean;
  webPolicy?: Partial<WebPolicy>;
  schedulerPolicy?: Partial<SchedulerPolicy>;
}

interface SchedulerRunBody {
  job?: string;
}

interface CredentialsBody {
  currentPassword: string;
  username: string;
  password: string;
}

interface FeaturesBody extends Partial<FeatureFlags> {}

const loginLimiter = new FixedWindowRateLimiter(5 * 60 * 1000);

const loginSchema = {
  type: 'object',
  required: ['username', 'password'],
  properties: {
    username: { type: 'string', minLength: 1, maxLength: 64 },
    password: { type: 'string', minLength: 1, maxLength: 256 },
  },
} as const;

const keyPolicyProperties = {
  expiresInDays: { type: ['integer', 'null'], minimum: 1, maximum: 3650 },
  quota: { type: ['integer', 'null'], minimum: 1, maximum: 1_000_000_000 },
  rateLimit: { type: ['integer', 'null'], minimum: 1, maximum: 1_000_000 },
  scopes: {
    type: ['array', 'null'],
    minItems: 1,
    maxItems: FEATURE_KEYS.length,
    uniqueItems: true,
    items: { type: 'string', enum: [...FEATURE_KEYS] },
  },
  allowedIps: {
    type: 'array',
    maxItems: 20,
    items: { type: 'string', minLength: 1, maxLength: 64 },
  },
  note: { type: ['string', 'null'], maxLength: 200 },
} as const;

const createKeySchema = {
  type: 'object',
  properties: {
    name: { type: 'string', maxLength: 64 },
    ...keyPolicyProperties,
  },
} as const;

const updateKeySchema = {
  type: 'object',
  minProperties: 1,
  properties: {
    name: { type: 'string', maxLength: 64 },
    enabled: { type: 'boolean' },
    ...keyPolicyProperties,
  },
} as const;

function assertAllowedIps(value: string[] | undefined): void {
  if (!value) return;
  for (const rule of value) {
    if (!normalizeIpRule(rule)) {
      throw ApiError.badRequest(`IP 白名单格式不正确：${rule}`, { rule });
    }
  }
}

function policyOf(body: KeyPolicyBody): KeyOptions {
  return {
    expiresInDays: body.expiresInDays,
    quota: body.quota,
    rateLimit: body.rateLimit,
    scopes: body.scopes,
    allowedIps: body.allowedIps,
    note: body.note,
  };
}

const settingsSchema = {
  type: 'object',
  minProperties: 1,
  properties: {
    requireKey: { type: 'boolean' },
    webEnabled: { type: 'boolean' },
    webPolicy: {
      type: 'object',
      minProperties: 1,
      additionalProperties: false,
      properties: {
        rateLimit: { type: 'integer', minimum: 0, maximum: 10_000 },
        rateWindowSec: { type: 'integer', minimum: 5, maximum: 86_400 },
        dailyQuota: { type: 'integer', minimum: 0, maximum: 1_000_000 },
        blockAfter: { type: 'integer', minimum: 0, maximum: 1_000 },
        blockSec: { type: 'integer', minimum: 0, maximum: 86_400 },
      },
    },
    schedulerPolicy: {
      type: 'object',
      minProperties: 1,
      additionalProperties: false,
      properties: {
        enabled: { type: 'boolean' },
        idleOnly: { type: 'boolean' },
      },
    },
  },
} as const;

const schedulerRunSchema = {
  type: 'object',
  properties: {
    job: { type: 'string', minLength: 1, maxLength: 64 },
  },
} as const;

const credentialsSchema = {
  type: 'object',
  required: ['currentPassword', 'username', 'password'],
  properties: {
    currentPassword: { type: 'string', minLength: 1, maxLength: 256 },
    username: { type: 'string', minLength: 3, maxLength: 32 },
    password: { type: 'string', minLength: 8, maxLength: 128 },
  },
} as const;

const featuresSchema = {
  type: 'object',
  minProperties: 1,
  additionalProperties: false,
  properties: Object.fromEntries(FEATURE_KEYS.map((key) => [key, { type: 'boolean' }])),
} as const;

const keyParamsSchema = {
  type: 'object',
  required: ['id'],
  properties: {
    id: { type: 'string', minLength: 1, maxLength: 100 },
  },
} as const;

function requireSession(
  request: FastifyRequest,
  sessions: AdminSessions,
): string {
  const token = parseCookie(request.headers.cookie, ADMIN_COOKIE);
  if (!sessions.has(token)) {
    throw ApiError.unauthorized('管理会话已失效，请重新登录');
  }
  return token as string;
}

function assertCsrf(request: FastifyRequest): void {
  if (request.headers['x-admin-csrf'] !== '1') {
    throw ApiError.badRequest('缺少管理请求校验头');
  }
}

export async function adminRoutes(
  app: FastifyInstance,
  options: AdminRouteOptions,
): Promise<void> {
  const { store, sessions, webGuard, scheduler } = options;

  app.addHook('onRequest', async (request, reply) => {
    if (request.url.startsWith('/admin/api/')) {
      reply.header('cache-control', 'no-store');
    }
  });

  app.get('/admin', async (_request, reply) => {
    reply.header('cache-control', 'no-cache');
    return reply.sendFile('admin.html');
  });

  app.post<{ Body: LoginBody }>(
    '/admin/api/login',
    { schema: { body: loginSchema } },
    async (request, reply) => {
      if (!store.hasCredentials) throw ApiError.adminDisabled();

      const rate = loginLimiter.hit(`admin-login:${request.ip}`, 10);
      if (!rate.allowed) {
        reply.header('retry-after', String(rate.retryAfterSec));
        throw ApiError.rateLimited(rate.retryAfterSec);
      }

      const ok = await store.verifyCredentials(request.body.username, request.body.password);
      if (!ok) {
        throw ApiError.unauthorized('账号或密码不正确');
      }

      const token = sessions.create();
      reply.header(
        'set-cookie',
        sessionCookie(token, sessions.ttlSeconds, request.protocol === 'https'),
      );

      return {
        success: true,
        data: { authenticated: true, expiresInSec: sessions.ttlSeconds },
      };
    },
  );

  app.post('/admin/api/logout', async (request, reply) => {
    const token = parseCookie(request.headers.cookie, ADMIN_COOKIE);
    sessions.destroy(token);
    reply.header('set-cookie', clearedSessionCookie(request.protocol === 'https'));
    return { success: true, data: { authenticated: false } };
  });

  app.get('/admin/api/session', async (request) => {
    const token = parseCookie(request.headers.cookie, ADMIN_COOKIE);
    const authenticated = sessions.has(token);

    return {
      success: true,
      data: {
        authenticated,
        username: store.username,
        adminEnabled: store.hasCredentials,
        requireKey: store.requireKey,
        webEnabled: store.webEnabled,
        webPolicy: store.webPolicy,
        schedulerPolicy: store.schedulerPolicy,
        features: store.features,
        keyCount: store.keyCount,
        activeKeyCount: store.activeKeyCount,
        keySummary: store.keySummary(),
        envKeyCount: config.apiKeys.size,
        sessionTtlSec: sessions.ttlSeconds,
      },
    };
  });

  app.get('/admin/api/keys', async (request) => {
    requireSession(request, sessions);

    return {
      success: true,
      data: {
        keys: store.listKeys(),
        summary: store.keySummary(),
        requireKey: store.requireKey,
        webEnabled: store.webEnabled,
        webPolicy: store.webPolicy,
        schedulerPolicy: store.schedulerPolicy,
        envKeyCount: config.apiKeys.size,
      },
    };
  });

  app.post<{ Body: CreateKeyBody }>(
    '/admin/api/keys',
    { schema: { body: createKeySchema } },
    async (request, reply) => {
      requireSession(request, sessions);
      assertCsrf(request);
      assertAllowedIps(request.body.allowedIps);

      const created = await store.createKey(request.body.name, policyOf(request.body));
      reply.status(201);

      return {
        success: true,
        data: {
          key: toPublicKey(created.record),
          // 明文密钥仅在此刻返回一次
          token: created.token,
        },
      };
    },
  );

  app.patch<{ Params: KeyParams; Body: UpdateKeyBody }>(
    '/admin/api/keys/:id',
    { schema: { params: keyParamsSchema, body: updateKeySchema } },
    async (request) => {
      requireSession(request, sessions);
      assertCsrf(request);
      assertAllowedIps(request.body.allowedIps);

      const patch: KeyPatch = { ...policyOf(request.body) };
      if (request.body.name !== undefined) patch.name = request.body.name;
      if (request.body.enabled !== undefined) patch.enabled = request.body.enabled;

      const updated = await store.updateKey(request.params.id, patch);
      if (!updated) throw ApiError.notFound('密钥不存在');

      return { success: true, data: { key: updated } };
    },
  );

  app.post<{ Params: KeyParams }>(
    '/admin/api/keys/:id/reset',
    { schema: { params: keyParamsSchema } },
    async (request) => {
      requireSession(request, sessions);
      assertCsrf(request);

      const updated = await store.resetKeyUsage(request.params.id);
      if (!updated) throw ApiError.notFound('密钥不存在');

      return { success: true, data: { key: updated, reset: true } };
    },
  );

  app.delete<{ Params: KeyParams }>(
    '/admin/api/keys/:id',
    { schema: { params: keyParamsSchema } },
    async (request) => {
      requireSession(request, sessions);
      assertCsrf(request);

      const deleted = await store.deleteKey(request.params.id);
      if (!deleted) throw ApiError.notFound('密钥不存在');

      return { success: true, data: { deleted: true, id: request.params.id } };
    },
  );

  app.patch<{ Body: SettingsBody }>(
    '/admin/api/settings',
    { schema: { body: settingsSchema } },
    async (request) => {
      requireSession(request, sessions);
      assertCsrf(request);

      const { requireKey, webEnabled, webPolicy, schedulerPolicy } = request.body;
      if (requireKey !== undefined) await store.setRequireKey(requireKey);
      if (webEnabled !== undefined) await store.setWebEnabled(webEnabled);
      if (webPolicy) await store.setWebPolicy(webPolicy);
      if (schedulerPolicy) await store.setSchedulerPolicy(schedulerPolicy);

      return {
        success: true,
        data: {
          requireKey: store.requireKey,
          webEnabled: store.webEnabled,
          webPolicy: store.webPolicy,
          schedulerPolicy: store.schedulerPolicy,
        },
      };
    },
  );

  app.post<{ Body: CredentialsBody }>(
    '/admin/api/credentials',
    { schema: { body: credentialsSchema } },
    async (request, reply) => {
      requireSession(request, sessions);
      assertCsrf(request);

      const { currentPassword, username, password } = request.body;
      const ok = await store.verifyCredentials(store.username, currentPassword);
      if (!ok) {
        throw ApiError.unauthorized('当前密码不正确');
      }

      const invalid = validateCredentials(username, password);
      if (invalid) throw ApiError.badRequest(invalid);

      await store.setCredentials(username, password);
      // 修改凭据后让所有旧会话立即失效
      sessions.destroyAll();
      reply.header('set-cookie', clearedSessionCookie(request.protocol === 'https'));

      return { success: true, data: { updated: true, username: store.username } };
    },
  );

  /* --------------------------- 功能开关 --------------------------- */

  app.get('/admin/api/features', async (request) => {
    requireSession(request, sessions);
    return {
      success: true,
      data: { features: store.features, labels: FEATURE_LABELS },
    };
  });

  app.patch<{ Body: FeaturesBody }>(
    '/admin/api/features',
    { schema: { body: featuresSchema } },
    async (request) => {
      requireSession(request, sessions);
      assertCsrf(request);

      const features = await store.setFeatures(request.body);
      return { success: true, data: { features } };
    },
  );

  /* --------------------------- 运行指标 --------------------------- */

  app.get('/admin/api/stats', async (request) => {
    requireSession(request, sessions);
    return {
      success: true,
      data: {
        features: store.features,
        metrics: metrics.snapshot(),
        cache: {
          whois: lookupCacheSize(),
          dns: dnsCacheSize(),
          ip: ipCacheSize(),
          uptime: uptimeCacheSize(),
          rdap: rdapCacheSize(),
          icp: icpCacheSize(),
          tls: tlsCacheSize(),
          mail: mailCacheSize(),
          http: httpCacheSize(),
          dnsprop: dnsPropCacheSize(),
          health: healthCacheSize(),
          available: availabilityCacheSize(),
          certchain: certChainCacheSize(),
        },
        webPolicy: store.webPolicy,
        webGuard: webGuard.snapshot(),
        scheduler: scheduler.snapshot(),
        history: historyStore.stats(),
        index: domainIndex.stats(),
        registrars: registrarRegistry.stats(),
        keys: store.keySummary(),
      },
    };
  });

  app.post('/admin/api/cache/clear', async (request) => {
    requireSession(request, sessions);
    assertCsrf(request);

    clearLookupCache();
    clearDnsCache();
    clearIpCache();
    clearUptimeCache();
    clearRdapCache();
    clearIcpCache();
    clearTlsCache();
    clearMailCache();
    clearHttpCache();
    clearDnsPropCache();
    clearHealthCache();
    clearAvailabilityCache();
    clearCertChainCache();

    return {
      success: true,
      data: {
        cleared: true,
        cache: {
          whois: 0,
          dns: 0,
          ip: 0,
          uptime: 0,
          rdap: 0,
          icp: 0,
          tls: 0,
          mail: 0,
          http: 0,
          dnsprop: 0,
          health: 0,
          available: 0,
          certchain: 0,
        },
      },
    };
  });

  /* --------------------------- 智能调度 --------------------------- */

  app.get('/admin/api/scheduler', async (request) => {
    requireSession(request, sessions);
    return {
      success: true,
      data: {
        ...scheduler.snapshot(),
        policy: store.schedulerPolicy,
      },
    };
  });

  app.patch<{ Body: { enabled?: boolean; idleOnly?: boolean } }>(
    '/admin/api/scheduler',
    {
      schema: {
        body: {
          type: 'object',
          minProperties: 1,
          additionalProperties: false,
          properties: { enabled: { type: 'boolean' }, idleOnly: { type: 'boolean' } },
        },
      },
    },
    async (request) => {
      requireSession(request, sessions);
      assertCsrf(request);
      const policy = await store.setSchedulerPolicy(request.body);
      return {
        success: true,
        data: { ...scheduler.snapshot(), policy },
      };
    },
  );

  app.post<{ Body: SchedulerRunBody }>(
    '/admin/api/scheduler/run',
    { schema: { body: schedulerRunSchema } },
    async (request) => {
      requireSession(request, sessions);
      assertCsrf(request);

      if (request.body.job) {
        try {
          const job = await scheduler.runNow(request.body.job);
          return { success: true, data: { job, ...scheduler.snapshot() } };
        } catch (error) {
          throw ApiError.badRequest(error instanceof Error ? error.message : '调度任务执行失败');
        }
      }

      const jobs = await scheduler.runAll();
      return { success: true, data: { ranJobs: jobs, ...scheduler.snapshot() } };
    },
  );

  /* --------------------------- 历史数据 --------------------------- */

  app.get('/admin/api/history', async (request) => {
    requireSession(request, sessions);
    return {
      success: true,
      data: { history: historyStore.stats(), index: domainIndex.stats() },
    };
  });

  app.delete('/admin/api/history', async (request) => {
    requireSession(request, sessions);
    assertCsrf(request);

    await historyStore.clear();
    return { success: true, data: { cleared: true, history: historyStore.stats() } };
  });

  app.delete('/admin/api/index', async (request) => {
    requireSession(request, sessions);
    assertCsrf(request);

    await domainIndex.clear();
    return { success: true, data: { cleared: true, index: domainIndex.stats() } };
  });

  /* --------------------------- 注册商目录 --------------------------- */

  app.get('/admin/api/registrars', async (request) => {
    requireSession(request, sessions);
    return {
      success: true,
      data: {
        status: registrarRegistry.status(),
        stats: registrarRegistry.stats(),
      },
    };
  });

  app.post('/admin/api/registrars/refresh', async (request) => {
    requireSession(request, sessions);
    assertCsrf(request);

    await registrarRegistry.refresh();
    return {
      success: true,
      data: {
        status: registrarRegistry.status(),
        stats: registrarRegistry.stats(),
      },
    };
  });

  /* --------------------------- 会话管理 --------------------------- */

  app.post('/admin/api/sessions/revoke', async (request, reply) => {
    requireSession(request, sessions);
    assertCsrf(request);

    sessions.destroyAll();
    reply.header('set-cookie', clearedSessionCookie(request.protocol === 'https'));
    return { success: true, data: { revoked: true } };
  });
}
