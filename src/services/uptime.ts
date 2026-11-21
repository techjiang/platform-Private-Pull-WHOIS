import { lookup } from 'node:dns/promises';
import { config } from '../config.js';
import { TtlCache } from '../lib/cache.js';
import { ApiError } from '../lib/errors.js';
import { metrics } from '../lib/metrics.js';
import { isPrivateAddress } from './ip.js';

export interface UptimeResult {
  target: string;
  finalUrl: string;
  reachable: boolean;
  ok: boolean;
  status: number | null;
  statusText: string | null;
  method: 'HEAD' | 'GET' | null;
  latencyMs: number;
  redirected: boolean;
  error: string | null;
  checkedAt: string;
  cached: boolean;
  ttlMs: number;
}

interface CachedUptime {
  target: string;
  finalUrl: string;
  reachable: boolean;
  ok: boolean;
  status: number | null;
  statusText: string | null;
  method: 'HEAD' | 'GET' | null;
  latencyMs: number;
  redirected: boolean;
  error: string | null;
  checkedAt: string;
}

const cache = new TtlCache<CachedUptime>(500);
const MAX_REDIRECTS = 5;

/** 接受域名或完整 URL，补全协议并校验 */
export function normalizeTarget(input: string): URL {
  const value = input.trim();
  if (!value) throw ApiError.badRequest('请输入域名或网址');
  if (value.length > 2048) throw ApiError.badRequest('输入内容过长');

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`;

  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw ApiError.badRequest('网址格式不正确');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw ApiError.badRequest('仅支持 http 与 https 协议');
  }
  if (url.username || url.password) {
    throw ApiError.badRequest('网址不能包含账号密码');
  }
  if (!url.hostname) throw ApiError.badRequest('网址缺少主机名');

  return url;
}

export async function assertPublicHost(hostname: string): Promise<void> {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    throw ApiError.badRequest('不允许检查内网地址');
  }

  let addresses: Array<{ address: string }>;
  try {
    addresses = await lookup(host, { all: true, verbatim: true });
  } catch {
    throw ApiError.badRequest('无法解析该主机名');
  }

  if (addresses.length === 0) throw ApiError.badRequest('无法解析该主机名');
  if (addresses.some((item) => isPrivateAddress(item.address))) {
    throw ApiError.badRequest('不允许检查内网或保留地址');
  }
}

async function probe(url: URL, method: 'HEAD' | 'GET', timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      method,
      redirect: 'manual',
      signal: controller.signal,
      headers: {
        'user-agent': 'PullWhois-Uptime/1.0 (+https://pull-whois.asoe.cn)',
        accept: '*/*',
        ...(method === 'GET' ? { range: 'bytes=0-0' } : {}),
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

/** 检查站点可访问性，带 SSRF 防护、超时与短缓存 */
export async function checkUptime(input: string): Promise<UptimeResult> {
  const url = normalizeTarget(input);
  const key = url.href;
  const hit = cache.get(key);
  if (hit) {
    metrics.recordCache('uptime', true);
    return { ...hit.value, cached: true, ttlMs: Math.round(hit.ttlMs) };
  }

  metrics.recordCache('uptime', false);
  await assertPublicHost(url.hostname);

  // 手动跟随重定向，以便统计跳转次数并逐跳做地址校验
  let current = url;
  let redirects = 0;
  const startedAt = Date.now();
  let usedMethod: 'HEAD' | 'GET' = 'HEAD';
  let response: Response | null = null;
  let error: string | null = null;

  const deadline = startedAt + config.uptime.timeoutMs;

  try {
    while (true) {
      const remaining = Math.max(500, deadline - Date.now());
      try {
        response = await probe(current, 'HEAD', remaining);
        if (response.status === 405 || response.status === 501 || response.status === 403) {
          response = await probe(current, 'GET', Math.max(500, deadline - Date.now()));
          usedMethod = 'GET';
        }
      } catch {
        // HEAD 失败时回退 GET（例如部分 CDN 直接断开 HEAD）
        response = await probe(current, 'GET', Math.max(500, deadline - Date.now()));
        usedMethod = 'GET';
      }

      // 不读取正文，避免占用带宽与内存
      await response.body?.cancel().catch(() => undefined);

      const location = response.headers.get('location');
      if (response.status >= 300 && response.status < 400 && location && redirects < MAX_REDIRECTS) {
        current = new URL(location, current);
        if (current.protocol !== 'http:' && current.protocol !== 'https:') {
          throw new Error('重定向到了不支持的协议');
        }
        await assertPublicHost(current.hostname);
        redirects += 1;
        continue;
      }
      break;
    }
  } catch (err) {
    error =
      err instanceof Error && err.name === 'AbortError'
        ? '请求超时'
        : err instanceof Error
          ? err.message
          : String(err);
    response = null;
  }

  const latencyMs = Date.now() - startedAt;
  const status = response?.status ?? null;
  const result: CachedUptime = {
    target: url.href,
    finalUrl: response?.url || current.href,
    reachable: status !== null,
    ok: status !== null && status >= 200 && status < 400,
    status,
    statusText: response?.statusText || null,
    method: response ? usedMethod : null,
    latencyMs,
    redirected: redirects > 0 || (response?.url ? response.url !== url.href : false),
    error,
    checkedAt: new Date().toISOString(),
  };

  cache.set(key, result, config.uptime.cacheTtlMs);
  return { ...result, cached: false, ttlMs: config.uptime.cacheTtlMs };
}

export function clearUptimeCache(): void {
  cache.clear();
}

export function uptimeCacheSize(): number {
  return cache.size;
}
