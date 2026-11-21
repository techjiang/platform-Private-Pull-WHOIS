import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/* 本地开发时自动加载 .env，生产环境直接使用进程环境变量 */
const envPath = fileURLToPath(new URL('../.env', import.meta.url));
if (existsSync(envPath)) {
  try {
    process.loadEnvFile(envPath);
  } catch {
    /* 忽略无法解析的 .env */
  }
}

function num(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function bool(value: string | undefined, fallback = false): boolean {
  if (value === undefined || value === '') return fallback;
  return /^(1|true|yes|on)$/i.test(value);
}

function list(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

const apiKeys = list(process.env.API_KEYS);
const corsOrigins = list(process.env.CORS_ORIGIN);

export const config = {
  version: '1.1.2',
  nodeEnv: process.env.NODE_ENV ?? 'development',
  isProduction: process.env.NODE_ENV === 'production',
  host: process.env.HOST ?? '0.0.0.0',
  port: num(process.env.PORT, 3000),
  trustProxy: bool(process.env.TRUST_PROXY),
  logLevel: process.env.LOG_LEVEL ?? 'info',
  corsOrigin:
    corsOrigins.length === 0 || corsOrigins.includes('*') ? true : corsOrigins,
  apiKeys: new Set(apiKeys),
  cache: {
    ttlMs: num(process.env.CACHE_TTL_MS, 10 * 60 * 1000),
    availableTtlMs: num(process.env.CACHE_AVAILABLE_TTL_MS, 60 * 1000),
    maxEntries: num(process.env.CACHE_MAX_ENTRIES, 2000),
  },
  rateLimit: {
    windowMs: num(process.env.RATE_LIMIT_WINDOW_MS, 60 * 1000),
    max: num(process.env.RATE_LIMIT_MAX, 120),
    keyMax: num(process.env.RATE_LIMIT_KEY_MAX, 600),
  },
  upstream: {
    rdapTimeoutMs: num(process.env.RDAP_TIMEOUT_MS, 8000),
    whoisTimeoutMs: num(process.env.WHOIS_TIMEOUT_MS, 8000),
    followReferral: bool(process.env.WHOIS_FOLLOW_REFERRAL, true),
    batchMaxDomains: num(process.env.BATCH_MAX_DOMAINS, 20),
    batchConcurrency: 5,
  },
  dns: {
    ttlMs: num(process.env.DNS_CACHE_TTL_MS, 5 * 60 * 1000),
    maxEntries: num(process.env.DNS_CACHE_MAX_ENTRIES, 1500),
    timeoutMs: num(process.env.DNS_TIMEOUT_MS, 5000),
  },
  ip: {
    // RDAP 仅作为补充信息，超时后回退到 ASN DNS 数据，避免拖慢整体响应
    rdapTimeoutMs: num(process.env.IP_RDAP_TIMEOUT_MS, 6000),
    asnTimeoutMs: num(process.env.IP_ASN_TIMEOUT_MS, 3000),
  },
  uptime: {
    timeoutMs: num(process.env.UPTIME_TIMEOUT_MS, 8000),
    cacheTtlMs: num(process.env.UPTIME_CACHE_TTL_MS, 60 * 1000),
  },
  history: {
    dataFile: process.env.HISTORY_DATA_FILE ?? '',
    maxDomains: num(process.env.HISTORY_MAX_DOMAINS, 2000),
    maxSnapshots: num(process.env.HISTORY_MAX_SNAPSHOTS, 24),
    minIntervalMs: num(process.env.HISTORY_MIN_INTERVAL_MS, 6 * 60 * 60 * 1000),
  },
  index: {
    dataFile: process.env.INDEX_DATA_FILE ?? '',
    maxDomains: num(process.env.INDEX_MAX_DOMAINS, 20000),
  },
  registrars: {
    dataFile: process.env.REGISTRARS_DATA_FILE ?? '',
    /** IANA / ICANN 注册商目录同步间隔 */
    syncTtlMs: num(process.env.REGISTRARS_SYNC_TTL_MS, 24 * 60 * 60 * 1000),
    timeoutMs: num(process.env.REGISTRARS_SYNC_TIMEOUT_MS, 30000),
  },
  icp: {
    /** 备案数据源账号，不配置时使用公共账号，公共账号有全局调用间隔 */
    apiId: process.env.ICP_API_ID ?? '88888888',
    apiKey: process.env.ICP_API_KEY ?? '88888888',
    timeoutMs: num(process.env.ICP_TIMEOUT_MS, 8000),
    /** 已备案结果缓存 12 小时 */
    cacheTtlMs: num(process.env.ICP_CACHE_TTL_MS, 12 * 60 * 60 * 1000),
    /** 未备案结果缓存 30 分钟 */
    missTtlMs: num(process.env.ICP_MISS_TTL_MS, 30 * 60 * 1000),
    /** 公共账号全局最小调用间隔（默认 15 秒） */
    cooldownMs: num(process.env.ICP_COOLDOWN_MS, 15000),
    maxEntries: num(process.env.ICP_CACHE_MAX_ENTRIES, 800),
    /** 本地持久化缓存文件，默认 data/icp.json */
    dataFile: process.env.ICP_DATA_FILE ?? '',
    /** 本地缓存可直接返回的有效期（默认 7 天） */
    localTtlMs: num(process.env.ICP_LOCAL_TTL_MS, 7 * 24 * 60 * 60 * 1000),
    /** 本地缓存保留上限，超过后仅在上游失败时兜底（默认 30 天） */
    localMaxAgeMs: num(process.env.ICP_LOCAL_MAX_AGE_MS, 30 * 24 * 60 * 60 * 1000),
  },
  tls: {
    timeoutMs: num(process.env.TLS_TIMEOUT_MS, 6000),
    cacheTtlMs: num(process.env.TLS_CACHE_TTL_MS, 30 * 60 * 1000),
    maxEntries: num(process.env.TLS_CACHE_MAX_ENTRIES, 500),
  },
  certChain: {
    cacheTtlMs: num(process.env.CERT_CHAIN_CACHE_TTL_MS, 30 * 60 * 1000),
    maxEntries: num(process.env.CERT_CHAIN_CACHE_MAX_ENTRIES, 120),
  },
  httpProbe: {
    timeoutMs: num(process.env.HTTP_CHECK_TIMEOUT_MS, 8000),
    cacheTtlMs: num(process.env.HTTP_CHECK_CACHE_TTL_MS, 5 * 60 * 1000),
    maxEntries: num(process.env.HTTP_CHECK_CACHE_MAX_ENTRIES, 180),
  },
  dnsProp: {
    timeoutMs: num(process.env.DNS_PROP_TIMEOUT_MS, 2500),
    cacheTtlMs: num(process.env.DNS_PROP_CACHE_TTL_MS, 60 * 1000),
    maxEntries: num(process.env.DNS_PROP_CACHE_MAX_ENTRIES, 300),
  },
  health: {
    cacheTtlMs: num(process.env.HEALTH_CACHE_TTL_MS, 10 * 60 * 1000),
    maxEntries: num(process.env.HEALTH_CACHE_MAX_ENTRIES, 200),
    upstreamTimeoutMs: num(process.env.HEALTH_UPSTREAM_TIMEOUT_MS, 12_000),
  },
  availability: {
    maxDomains: num(process.env.AVAILABILITY_MAX_DOMAINS, 10),
    concurrency: 3,
    cacheTtlMs: num(process.env.AVAILABILITY_CACHE_TTL_MS, 10 * 60 * 1000),
    maxEntries: num(process.env.AVAILABILITY_CACHE_MAX_ENTRIES, 300),
  },
  mail: {
    cacheTtlMs: num(process.env.MAIL_CACHE_TTL_MS, 10 * 60 * 1000),
    maxEntries: num(process.env.MAIL_CACHE_MAX_ENTRIES, 500),
    /** 默认探测的 DKIM 选择器；DKIM 选择器无法通过 DNS 枚举 */
    dkimSelectors: list(process.env.MAIL_DKIM_SELECTORS).length
      ? list(process.env.MAIL_DKIM_SELECTORS)
      : ['default', 'google', 'selector1', 'selector2'],
  },
  admin: {
    username: process.env.ADMIN_USERNAME ?? 'admin',
    password: process.env.ADMIN_PASSWORD ?? '',
    sessionTtlMs: num(process.env.ADMIN_SESSION_TTL_MS, 12 * 60 * 60 * 1000),
    // 未配置时使用 src/admin/store.ts 中的默认路径
    dataFile: process.env.ADMIN_DATA_FILE ?? '',
    // 网页端查询开关（与 API 是否需要 Key 相互独立）
    webEnabledDefault: process.env.WEB_QUERY_ENABLED === undefined
      ? true
      : bool(process.env.WEB_QUERY_ENABLED, true),
  },
  /** 首次启动（尚无管理数据）时是否默认要求 API Key */
  requireKeyDefault:
    process.env.API_REQUIRE_KEY === undefined
      ? apiKeys.length > 0
      : bool(process.env.API_REQUIRE_KEY),
} as const;

export type AppConfig = typeof config;
