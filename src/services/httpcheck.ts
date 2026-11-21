import { config } from '../config.js';
import { TtlCache } from '../lib/cache.js';
import { ApiError } from '../lib/errors.js';
import { metrics } from '../lib/metrics.js';
import { assertPublicHost } from './uptime.js';

/**
 * HTTP 安全响应头体检
 *
 * 直接向目标站点发起一次轻量请求（不加载页面资源、不执行脚本），
 * 读取响应头后在本站完成分析，不依赖任何第三方检测服务。
 */

export type HttpCheckStatus = 'pass' | 'warn' | 'fail' | 'info';

export interface HttpSecurityCheck {
  id: string;
  label: string;
  status: HttpCheckStatus;
  weight: number;
  value: string | null;
  detail: string;
}

export interface HttpCookieFlag {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
}

export interface HttpCheckIssue {
  id: string;
  label: string;
  severity: 'high' | 'medium' | 'low';
  detail: string;
}

export interface HttpCheckResult {
  target: string;
  finalUrl: string;
  host: string;
  https: boolean;
  reachable: boolean;
  status: number | null;
  statusText: string | null;
  latencyMs: number;
  redirects: Array<{ from: string; to: string; status: number }>;
  server: string | null;
  poweredBy: string | null;
  contentType: string | null;
  contentEncoding: string | null;
  cacheControl: string | null;
  via: string | null;
  headers: Record<string, string>;
  security: HttpSecurityCheck[];
  cookies: HttpCookieFlag[];
  score: number | null;
  grade: string;
  issues: HttpCheckIssue[];
  summary: string;
  error: string | null;
  checkedAt: string;
  cached: boolean;
  ttlMs: number;
  note: string;
}

interface CachedHttpCheck {
  target: string;
  finalUrl: string;
  host: string;
  https: boolean;
  reachable: boolean;
  status: number | null;
  statusText: string | null;
  latencyMs: number;
  redirects: Array<{ from: string; to: string; status: number }>;
  server: string | null;
  poweredBy: string | null;
  contentType: string | null;
  contentEncoding: string | null;
  cacheControl: string | null;
  via: string | null;
  headers: Record<string, string>;
  security: HttpSecurityCheck[];
  cookies: HttpCookieFlag[];
  score: number | null;
  grade: string;
  issues: HttpCheckIssue[];
  summary: string;
  error: string | null;
  checkedAt: string;
}

const cache = new TtlCache<CachedHttpCheck>(config.httpProbe.maxEntries);
const MAX_REDIRECTS = 5;
const MAX_HEADERS = 48;

export const HTTP_NOTE =
  '响应头由本站直接请求目标站点获取并分析，只读取响应头、不下载页面正文、不执行脚本，也不经过任何第三方检测服务。';

/** 接受域名或完整 URL，补全协议并校验基础格式 */
export function normalizeHttpTarget(input: string): URL {
  const value = String(input ?? '').trim();
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
  if (url.username || url.password) throw ApiError.badRequest('网址不能包含账号密码');
  if (!url.hostname) throw ApiError.badRequest('网址缺少主机名');
  return url;
}

function readHeader(headers: Headers, name: string): string | null {
  const value = headers.get(name);
  if (!value) return null;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, 600) : null;
}

function parseMaxAge(hsts: string): number | null {
  const match = hsts.match(/max-age\s*=\s*"?(\d+)"?/i);
  if (!match) return null;
  const value = Number(match[1]);
  return Number.isFinite(value) ? value : null;
}

function parseCookies(raw: string[]): HttpCookieFlag[] {
  return raw.slice(0, 12).map((item) => {
    const [pair] = item.split(';');
    const name = (pair?.split('=')[0] ?? '').trim() || '未知';
    const sameSite = item.match(/samesite\s*=\s*([a-z]+)/i)?.[1]?.toLowerCase() ?? null;
    return {
      name,
      secure: /;\s*secure\b/i.test(item),
      httpOnly: /;\s*httponly\b/i.test(item),
      sameSite,
    };
  });
}

function headerMap(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  let count = 0;
  headers.forEach((value, key) => {
    if (count >= MAX_HEADERS) return;
    const lower = key.toLowerCase();
    if (lower === 'set-cookie') return;
    out[lower] = value.length > 400 ? `${value.slice(0, 400)}…` : value;
    count += 1;
  });
  return out;
}

/** 根据响应头计算安全项、评分与问题列表（纯函数，便于测试） */
export function analyzeHttpHeaders(
  headers: Record<string, string>,
  options: { https: boolean; cookies: HttpCookieFlag[] },
): {
  security: HttpSecurityCheck[];
  score: number;
  grade: string;
  issues: HttpCheckIssue[];
  summary: string;
} {
  const get = (name: string): string | null => {
    const value = headers[name.toLowerCase()];
    return value && value.trim() ? value.trim() : null;
  };
  const security: HttpSecurityCheck[] = [];

  const hsts = get('strict-transport-security');
  const hstsMaxAge = hsts ? parseMaxAge(hsts) : null;
  if (!options.https) {
    security.push({
      id: 'hsts',
      label: 'HSTS 强制 HTTPS',
      status: 'fail',
      weight: 14,
      value: null,
      detail: '站点未使用 HTTPS，HSTS 无法生效',
    });
  } else if (!hsts) {
    security.push({
      id: 'hsts',
      label: 'HSTS 强制 HTTPS',
      status: 'fail',
      weight: 14,
      value: null,
      detail: '未设置 Strict-Transport-Security，浏览器可能被降级到 HTTP',
    });
  } else if (hstsMaxAge !== null && hstsMaxAge < 15_552_000) {
    security.push({
      id: 'hsts',
      label: 'HSTS 强制 HTTPS',
      status: 'warn',
      weight: 14,
      value: hsts,
      detail: 'max-age 小于 180 天，建议提升到 31536000 秒',
    });
  } else {
    security.push({
      id: 'hsts',
      label: 'HSTS 强制 HTTPS',
      status: 'pass',
      weight: 14,
      value: hsts,
      detail: '已开启 HSTS，浏览器会强制使用 HTTPS',
    });
  }

  const csp = get('content-security-policy');
  if (!csp) {
    security.push({
      id: 'csp',
      label: '内容安全策略 CSP',
      status: 'fail',
      weight: 12,
      value: null,
      detail: '未设置 CSP，页面注入脚本的防护较弱',
    });
  } else if (/unsafe-inline|unsafe-eval/i.test(csp)) {
    security.push({
      id: 'csp',
      label: '内容安全策略 CSP',
      status: 'warn',
      weight: 12,
      value: csp,
      detail: 'CSP 中包含 unsafe-inline 或 unsafe-eval，防护效果被削弱',
    });
  } else {
    security.push({
      id: 'csp',
      label: '内容安全策略 CSP',
      status: 'pass',
      weight: 12,
      value: csp,
      detail: '已设置 CSP，可限制脚本与资源来源',
    });
  }

  const frame = get('x-frame-options');
  const frameAncestors = csp ? /frame-ancestors/i.test(csp) : false;
  if (frame || frameAncestors) {
    security.push({
      id: 'frame',
      label: '点击劫持防护',
      status: 'pass',
      weight: 10,
      value: frame ?? 'CSP frame-ancestors',
      detail: '已限制页面被第三方站点嵌套',
    });
  } else {
    security.push({
      id: 'frame',
      label: '点击劫持防护',
      status: 'fail',
      weight: 10,
      value: null,
      detail: '缺少 X-Frame-Options 或 CSP frame-ancestors',
    });
  }

  const nosniff = get('x-content-type-options');
  if (nosniff && /nosniff/i.test(nosniff)) {
    security.push({
      id: 'nosniff',
      label: 'MIME 类型嗅探防护',
      status: 'pass',
      weight: 8,
      value: nosniff,
      detail: '已禁止浏览器猜解资源类型',
    });
  } else {
    security.push({
      id: 'nosniff',
      label: 'MIME 类型嗅探防护',
      status: 'fail',
      weight: 8,
      value: nosniff,
      detail: '缺少 X-Content-Type-Options: nosniff',
    });
  }

  const referrer = get('referrer-policy');
  security.push({
    id: 'referrer',
    label: 'Referrer 策略',
    status: referrer ? 'pass' : 'warn',
    weight: 6,
    value: referrer,
    detail: referrer ? '已声明来源信息传递策略' : '未设置 Referrer-Policy，跨站请求可能泄露来源地址',
  });

  const permissions = get('permissions-policy') ?? get('feature-policy');
  security.push({
    id: 'permissions',
    label: '浏览器权限策略',
    status: permissions ? 'pass' : 'info',
    weight: 4,
    value: permissions,
    detail: permissions ? '已限制可选浏览器能力' : '未设置 Permissions-Policy，建议按需关闭摄像头、定位等能力',
  });

  const coop = get('cross-origin-opener-policy');
  security.push({
    id: 'coop',
    label: '跨源窗口隔离',
    status: coop ? 'pass' : 'info',
    weight: 4,
    value: coop,
    detail: coop ? '已开启 COOP，降低跨源窗口攻击面' : '未设置 Cross-Origin-Opener-Policy',
  });

  const poweredBy = get('x-powered-by');
  if (poweredBy) {
    security.push({
      id: 'banner',
      label: '技术栈信息隐藏',
      status: 'warn',
      weight: 3,
      value: poweredBy,
      detail: '响应头暴露了后端框架信息，建议移除 X-Powered-By',
    });
  }

  if (options.cookies.length > 0) {
    const weak = options.cookies.filter(
      (item) => !item.secure || !item.httpOnly || (!item.sameSite && item.sameSite !== 'none'),
    );
    security.push({
      id: 'cookies',
      label: 'Cookie 安全属性',
      status: weak.length === 0 ? 'pass' : 'warn',
      weight: 8,
      value: `${options.cookies.length} 个 Cookie`,
      detail:
        weak.length === 0
          ? 'Cookie 均带有 Secure、HttpOnly 与 SameSite'
          : `有 ${weak.length} 个 Cookie 缺少 Secure、HttpOnly 或 SameSite`,
    });
  } else {
    security.push({
      id: 'cookies',
      label: 'Cookie 安全属性',
      status: 'info',
      weight: 0,
      value: null,
      detail: '响应未设置 Cookie',
    });
  }

  const issues: HttpCheckIssue[] = [];
  let score = 100;
  for (const item of security) {
    if (item.status === 'fail') {
      score -= item.weight;
      issues.push({
        id: item.id,
        label: item.label,
        severity: item.weight >= 10 ? 'high' : item.weight >= 6 ? 'medium' : 'low',
        detail: item.detail,
      });
    } else if (item.status === 'warn') {
      score -= Math.ceil(item.weight / 2);
      issues.push({
        id: item.id,
        label: item.label,
        severity: item.weight >= 10 ? 'medium' : 'low',
        detail: item.detail,
      });
    }
  }
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 50 ? 'D' : 'E';
  const summary =
    score >= 90
      ? '安全响应头配置良好'
      : score >= 70
        ? '基础配置可用，仍有可加固项'
        : '缺少多项关键安全响应头';

  return { security, score, grade, issues, summary };
}

async function requestHop(url: URL, timeoutMs: number, method: 'HEAD' | 'GET'): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      method,
      redirect: 'manual',
      signal: controller.signal,
      headers: {
        'user-agent': 'PullWhois-HTTPCheck/1.0 (+https://pull-whois.asoe.cn)',
        accept: 'text/html,application/xhtml+xml,*/*',
        'accept-encoding': 'identity',
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

/** 体检站点 HTTP 响应头与安全配置 */
export async function checkHttp(
  input: string,
  options: { refresh?: boolean } = {},
): Promise<HttpCheckResult> {
  const url = normalizeHttpTarget(input);
  const key = url.href;
  const hit = options.refresh ? null : cache.get(key);
  if (hit) {
    metrics.recordCache('http', true);
    return { ...hit.value, note: HTTP_NOTE, cached: true, ttlMs: Math.round(hit.ttlMs) };
  }

  metrics.recordCache('http', false);
  await assertPublicHost(url.hostname);

  const startedAt = Date.now();
  const deadline = startedAt + config.httpProbe.timeoutMs;
  const redirects: Array<{ from: string; to: string; status: number }> = [];
  let current = url;
  let response: Response | null = null;
  let error: string | null = null;

  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
      const remaining = Math.max(800, deadline - Date.now());
      response = await requestHop(current, remaining, 'HEAD');
      // 少数站点禁用 HEAD，回退到 GET 并立即取消正文，仍只读取响应头
      if (response.status === 405 || response.status === 501) {
        await response.body?.cancel().catch(() => undefined);
        response = await requestHop(current, Math.max(800, deadline - Date.now()), 'GET');
      }
      await response.body?.cancel().catch(() => undefined);

      const location = response.headers.get('location');
      if (response.status >= 300 && response.status < 400 && location && hop < MAX_REDIRECTS) {
        const next = new URL(location, current);
        if (next.protocol !== 'http:' && next.protocol !== 'https:') {
          throw new Error('重定向到了不支持的协议');
        }
        await assertPublicHost(next.hostname);
        redirects.push({ from: current.href, to: next.href, status: response.status });
        current = next;
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
  const headers = response ? headerMap(response.headers) : {};
  const rawCookies = response?.headers.getSetCookie?.() ?? [];
  const cookies = parseCookies(rawCookies);
  const analyzed = analyzeHttpHeaders(headers, {
    https: current.protocol === 'https:',
    cookies,
  });

  const status = response?.status ?? null;
  const result: CachedHttpCheck = {
    target: url.href,
    finalUrl: current.href,
    host: current.hostname,
    https: current.protocol === 'https:',
    reachable: status !== null,
    status,
    statusText: response?.statusText || null,
    latencyMs,
    redirects,
    server: headers['server'] ?? null,
    poweredBy: headers['x-powered-by'] ?? null,
    contentType: headers['content-type'] ?? null,
    contentEncoding: headers['content-encoding'] ?? null,
    cacheControl: headers['cache-control'] ?? null,
    via: headers['via'] ?? headers['cf-ray'] ?? null,
    headers,
    security: analyzed.security,
    cookies,
    score: error ? null : analyzed.score,
    grade: error ? 'N/A' : analyzed.grade,
    issues: analyzed.issues,
    summary: error ? '目标不可访问，无法完成体检' : analyzed.summary,
    error,
    checkedAt: new Date().toISOString(),
  };

  if (!error) {
    cache.set(key, result, config.httpProbe.cacheTtlMs);
  }

  return { ...result, note: HTTP_NOTE, cached: false, ttlMs: config.httpProbe.cacheTtlMs };
}

export function clearHttpCache(): void {
  cache.clear();
}

export function httpCacheSize(): number {
  return cache.size;
}
