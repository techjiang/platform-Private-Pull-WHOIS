import { config } from '../config.js';
import { TtlCache } from '../lib/cache.js';
import { parseDomain } from '../lib/domain.js';
import { metrics } from '../lib/metrics.js';
import { lookupDomain } from '../whois/lookup.js';
import type { DnsLookupResult } from './dns.js';
import { lookupDns } from './dns.js';
import { checkMailAuth } from './mail.js';
import { checkTls } from './tls.js';

/**
 * 域名健康评分
 *
 * 把注册信息、DNS、TLS 证书、邮件安全四个维度的自建检测结果汇总为 0-100 分，
 * 并给出可执行的改进建议，帮助用户快速判断域名的整体可用性与安全状况。
 */

export type HealthStatus = 'pass' | 'warn' | 'fail' | 'info';
export type HealthDimensionKey = 'registration' | 'dns' | 'tls' | 'mail';

export const HEALTH_DIMENSION_KEYS: HealthDimensionKey[] = ['registration', 'dns', 'tls', 'mail'];

/** 解析 ?dimensions=dns,tls 形式的维度过滤；非法或为空时返回全部维度 */
export function normalizeHealthDimensions(input?: string | string[]): HealthDimensionKey[] {
  const raw = Array.isArray(input) ? input.join(',') : (input ?? '');
  const picked = raw
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter((item): item is HealthDimensionKey =>
      (HEALTH_DIMENSION_KEYS as string[]).includes(item),
    );
  const unique = [...new Set(picked)];
  return unique.length > 0 ? unique : [...HEALTH_DIMENSION_KEYS];
}

function gradeOf(score: number): string {
  return score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 60 ? 'C' : score >= 45 ? 'D' : 'E';
}

function summaryOf(score: number): string {
  return score >= 90
    ? '域名整体状况优秀'
    : score >= 80
      ? '域名整体状况良好'
      : score >= 70
        ? '域名可用，但仍有改进空间'
        : score >= 60
          ? '存在多项待优化配置'
          : '存在较明显风险，建议尽快处理';
}

export interface HealthCheckItem {
  id: string;
  label: string;
  status: HealthStatus;
  detail: string;
}

export interface HealthDimension {
  key: HealthDimensionKey;
  label: string;
  score: number;
  max: number;
  status: HealthStatus;
  checks: HealthCheckItem[];
}

export interface DomainHealthResult {
  domain: string;
  score: number;
  grade: string;
  summary: string;
  dimensions: HealthDimension[];
  issues: Array<{ dimension: HealthDimensionKey; label: string; status: HealthStatus; detail: string }>;
  checkedAt: string;
  cached: boolean;
  ttlMs: number;
  note: string;
}

export interface HealthInput {
  whois:
    | {
        available: boolean;
        registrar: string | null;
        expires: string | null;
        dnssec: 'signed' | 'unsigned' | 'unknown';
      }
    | null;
  whoisError?: string | null;
  dns: {
    ns: string[];
    a: string[];
    aaaa: string[];
    soa: boolean;
  };
  tls:
    | {
        reachable: boolean;
        authorized: boolean;
        protocol: string | null;
        daysRemaining: number | null;
      }
    | null;
  mail:
    | {
        mx: boolean;
        spf: 'pass' | 'warn' | 'fail';
        dmarc: 'pass' | 'warn' | 'fail';
        dkim: 'pass' | 'warn' | 'fail';
      }
    | null;
  now?: number;
}

interface CachedHealth {
  domain: string;
  score: number;
  grade: string;
  summary: string;
  dimensions: HealthDimension[];
  issues: Array<{ dimension: HealthDimensionKey; label: string; status: HealthStatus; detail: string }>;
  checkedAt: string;
}

const cache = new TtlCache<CachedHealth>(config.health.maxEntries);

export const HEALTH_NOTE =
  '健康评分由本站自建的注册信息、DNS、TLS 与邮件安全检测结果综合计算，仅用于快速评估域名状态，不替代人工安全审计。';

function weightedDimension(
  key: HealthDimensionKey,
  label: string,
  checks: Array<HealthCheckItem & { points: number }>,
  max: number,
): HealthDimension {
  const score = Math.max(
    0,
    Math.min(
      max,
      checks.reduce((sum, item) => sum + (item.status === 'info' ? 0 : item.points), 0),
    ),
  );
  const ratio = max > 0 ? score / max : 0;
  const status: HealthStatus = ratio >= 0.8 ? 'pass' : ratio >= 0.5 ? 'warn' : 'fail';
  return {
    key,
    label,
    score,
    max,
    status,
    checks: checks.map(({ points: _points, ...item }) => item),
  };
}

function expiryDays(expires: string | null, now: number): number | null {
  if (!expires) return null;
  const time = Date.parse(expires);
  if (Number.isNaN(time)) return null;
  return Math.floor((time - now) / (24 * 60 * 60 * 1000));
}

function tlsProtocolOk(protocol: string | null): boolean {
  return protocol === 'TLSv1.2' || protocol === 'TLSv1.3';
}

/** 根据各维度输入计算总分与等级（纯函数，便于测试） */
export function scoreHealth(input: HealthInput): {
  score: number;
  grade: string;
  summary: string;
  dimensions: HealthDimension[];
  issues: Array<{ dimension: HealthDimensionKey; label: string; status: HealthStatus; detail: string }>;
} {
  const now = input.now ?? Date.now();
  const dimensions: HealthDimension[] = [];

  const registrationChecks: Array<HealthCheckItem & { points: number }> = [];
  if (!input.whois) {
    registrationChecks.push({
      id: 'whois',
      label: '注册信息',
      status: 'fail',
      points: 0,
      detail: input.whoisError ? `注册信息获取失败：${input.whoisError}` : '未获取到注册信息',
    });
  } else if (input.whois.available) {
    registrationChecks.push({
      id: 'whois',
      label: '注册信息',
      status: 'fail',
      points: 0,
      detail: '域名当前未注册，无法参与健康评分',
    });
  } else {
    registrationChecks.push({
      id: 'registered',
      label: '注册状态',
      status: 'pass',
      points: 10,
      detail: '域名已注册且注册信息可读取',
    });
    const days = expiryDays(input.whois.expires, now);
    if (days === null) {
      registrationChecks.push({
        id: 'expiry',
        label: '到期时间',
        status: 'warn',
        points: 4,
        detail: '注册信息未提供到期时间，建议在注册商后台确认',
      });
    } else if (days < 0) {
      registrationChecks.push({
        id: 'expiry',
        label: '到期时间',
        status: 'fail',
        points: 0,
        detail: '域名已过期，请立即续费',
      });
    } else if (days < 30) {
      registrationChecks.push({
        id: 'expiry',
        label: '到期时间',
        status: 'fail',
        points: 3,
        detail: `域名将在 ${days} 天后到期，请尽快续费`,
      });
    } else if (days < 90) {
      registrationChecks.push({
        id: 'expiry',
        label: '到期时间',
        status: 'warn',
        points: 6,
        detail: `域名剩余 ${days} 天，建议提前安排续费`,
      });
    } else {
      registrationChecks.push({
        id: 'expiry',
        label: '到期时间',
        status: 'pass',
        points: 8,
        detail: `域名剩余 ${days} 天`,
      });
    }
    registrationChecks.push({
      id: 'registrar',
      label: '注册商信息',
      status: input.whois.registrar ? 'pass' : 'warn',
      points: input.whois.registrar ? 3 : 1,
      detail: input.whois.registrar ? `注册商：${input.whois.registrar}` : '未解析到注册商名称',
    });
    registrationChecks.push({
      id: 'dnssec',
      label: 'DNSSEC',
      status: input.whois.dnssec === 'signed' ? 'pass' : input.whois.dnssec === 'unsigned' ? 'warn' : 'info',
      points: input.whois.dnssec === 'signed' ? 4 : input.whois.dnssec === 'unsigned' ? 2 : 0,
      detail:
        input.whois.dnssec === 'signed'
          ? '域名已启用 DNSSEC 签名'
          : input.whois.dnssec === 'unsigned'
            ? '未启用 DNSSEC，可考虑开启以防御 DNS 劫持'
            : '注册信息未提供 DNSSEC 状态',
    });
  }
  dimensions.push(weightedDimension('registration', '注册与所有权', registrationChecks, 25));

  const dnsChecks: Array<HealthCheckItem & { points: number }> = [];
  const ns = input.dns.ns;
  dnsChecks.push({
    id: 'ns',
    label: 'NS 记录',
    status: ns.length >= 2 ? 'pass' : ns.length === 1 ? 'warn' : 'fail',
    points: ns.length >= 2 ? 9 : ns.length === 1 ? 4 : 0,
    detail:
      ns.length >= 2
        ? `已配置 ${ns.length} 个 NS 服务器`
        : ns.length === 1
          ? '只配置了 1 个 NS，建议至少 2 个实现冗余'
          : '未查询到 NS 记录，域名可能未配置解析',
  });
  const addressCount = input.dns.a.length + input.dns.aaaa.length;
  dnsChecks.push({
    id: 'address',
    label: '地址记录',
    status: addressCount > 0 ? 'pass' : 'fail',
    points: addressCount > 0 ? 8 : 0,
    detail:
      addressCount > 0
        ? `A ${input.dns.a.length} 条 · AAAA ${input.dns.aaaa.length} 条`
        : '未查询到 A 或 AAAA 记录，网站可能无法访问',
  });
  dnsChecks.push({
    id: 'soa',
    label: 'SOA 记录',
    status: input.dns.soa ? 'pass' : 'warn',
    points: input.dns.soa ? 4 : 0,
    detail: input.dns.soa ? '区域 SOA 记录正常' : '未查询到 SOA 记录',
  });
  const uniqueNs = new Set(ns.map((item) => item.toLowerCase().replace(/\.$/, '')));
  dnsChecks.push({
    id: 'ns-diversity',
    label: 'NS 唯一性',
    status: uniqueNs.size >= 2 ? 'pass' : uniqueNs.size === 1 ? 'warn' : 'info',
    points: uniqueNs.size >= 2 ? 4 : 0,
    detail:
      uniqueNs.size >= 2
        ? `${uniqueNs.size} 个不同 NS 域名`
        : 'NS 记录重复或缺失，冗余能力不足',
  });
  dimensions.push(weightedDimension('dns', 'DNS 解析', dnsChecks, 25));

  const tlsChecks: Array<HealthCheckItem & { points: number }> = [];
  if (!input.tls || !input.tls.reachable) {
    tlsChecks.push({
      id: 'tls',
      label: 'TLS 连接',
      status: 'fail',
      points: 0,
      detail: '无法完成 443 端口 TLS 握手，可能未启用 HTTPS',
    });
  } else {
    tlsChecks.push({
      id: 'tls',
      label: 'TLS 连接',
      status: 'pass',
      points: 4,
      detail: '已成功建立 TLS 连接',
    });
    tlsChecks.push({
      id: 'authorized',
      label: '证书信任',
      status: input.tls.authorized ? 'pass' : 'fail',
      points: input.tls.authorized ? 10 : 0,
      detail: input.tls.authorized ? '证书链校验通过' : '证书链校验未通过，浏览器可能提示不安全',
    });
    const days = input.tls.daysRemaining;
    if (days === null) {
      tlsChecks.push({
        id: 'cert-expiry',
        label: '证书有效期',
        status: 'warn',
        points: 2,
        detail: '未读取到证书到期时间',
      });
    } else if (days < 0) {
      tlsChecks.push({
        id: 'cert-expiry',
        label: '证书有效期',
        status: 'fail',
        points: 0,
        detail: '证书已过期',
      });
    } else if (days < 14) {
      tlsChecks.push({
        id: 'cert-expiry',
        label: '证书有效期',
        status: 'fail',
        points: 2,
        detail: `证书将在 ${days} 天后过期，请尽快续签`,
      });
    } else if (days < 30) {
      tlsChecks.push({
        id: 'cert-expiry',
        label: '证书有效期',
        status: 'warn',
        points: 4,
        detail: `证书剩余 ${days} 天`,
      });
    } else {
      tlsChecks.push({
        id: 'cert-expiry',
        label: '证书有效期',
        status: 'pass',
        points: 6,
        detail: `证书剩余 ${days} 天`,
      });
    }
    tlsChecks.push({
      id: 'protocol',
      label: 'TLS 协议版本',
      status: tlsProtocolOk(input.tls.protocol) ? 'pass' : 'warn',
      points: tlsProtocolOk(input.tls.protocol) ? 5 : 0,
      detail: input.tls.protocol ? `当前协议：${input.tls.protocol}` : '未协商出可识别的协议版本',
    });
  }
  dimensions.push(weightedDimension('tls', 'HTTPS 证书', tlsChecks, 25));

  const mailChecks: Array<HealthCheckItem & { points: number }> = [];
  if (!input.mail) {
    mailChecks.push({
      id: 'mail',
      label: '邮件安全',
      status: 'warn',
      points: 0,
      detail: '未能完成邮件安全检测',
    });
  } else {
    mailChecks.push({
      id: 'mx',
      label: 'MX 记录',
      status: input.mail.mx ? 'pass' : 'fail',
      points: input.mail.mx ? 6 : 0,
      detail: input.mail.mx ? '已配置收信 MX 记录' : '未配置 MX 记录，无法接收邮件',
    });
    const spfPoints = input.mail.spf === 'pass' ? 6 : input.mail.spf === 'warn' ? 3 : 0;
    mailChecks.push({
      id: 'spf',
      label: 'SPF',
      status: input.mail.spf,
      points: spfPoints,
      detail:
        input.mail.spf === 'pass'
          ? 'SPF 配置有效并包含收紧的 all 策略'
          : input.mail.spf === 'warn'
            ? 'SPF 存在但策略偏宽松'
            : 'SPF 缺失或存在错误',
    });
    const dmarcPoints = input.mail.dmarc === 'pass' ? 7 : input.mail.dmarc === 'warn' ? 3 : 0;
    mailChecks.push({
      id: 'dmarc',
      label: 'DMARC',
      status: input.mail.dmarc,
      points: dmarcPoints,
      detail:
        input.mail.dmarc === 'pass'
          ? 'DMARC 策略有效'
          : input.mail.dmarc === 'warn'
            ? 'DMARC 已配置但策略较宽松'
            : 'DMARC 缺失，域外伪造邮件难以拦截',
    });
    const dkimPoints = input.mail.dkim === 'pass' ? 6 : input.mail.dkim === 'warn' ? 3 : 0;
    mailChecks.push({
      id: 'dkim',
      label: 'DKIM',
      status: input.mail.dkim,
      points: dkimPoints,
      detail:
        input.mail.dkim === 'pass'
          ? '已探测到可用的 DKIM 公钥'
          : input.mail.dkim === 'warn'
            ? 'DKIM 公钥存在异常'
            : '常用选择器未探测到 DKIM 公钥',
    });
  }
  dimensions.push(weightedDimension('mail', '邮件安全', mailChecks, 25));

  const score = dimensions.reduce((sum, item) => sum + item.score, 0);
  const grade = gradeOf(score);
  const summary = summaryOf(score);

  const issues = dimensions.flatMap((item) =>
    item.checks
      .filter((check) => check.status === 'fail' || check.status === 'warn')
      .map((check) => ({
        dimension: item.key,
        label: check.label,
        status: check.status,
        detail: check.detail,
      })),
  );

  return { score, grade, summary, dimensions, issues };
}

function valuesOf(result: DnsLookupResult): string[] {
  return result.records
    .map((record) => (typeof record.value === 'string' ? record.value : ''))
    .filter(Boolean);
}

/** 给上游检测加超时上限，超时后按该维度失败降级，避免慢上游拖垮整个评分接口 */
function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const guard = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} 超时`)), ms);
  });
  return Promise.race([promise, guard]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function mailStatus(
  checks: Array<{ id: string; status: 'pass' | 'warn' | 'fail' }>,
  id: string,
): 'pass' | 'warn' | 'fail' {
  const found = checks.find((item) => item.id === id);
  return found ? found.status : 'fail';
}

/** 聚合多维度检测并给出域名健康评分；dimensions 可只评估部分维度以减少上游压力 */
export async function checkDomainHealth(
  input: string,
  options: { refresh?: boolean; dimensions?: string | string[] } = {},
): Promise<DomainHealthResult> {
  const parsed = parseDomain(input);
  const domain = parsed.ascii;
  const selected = normalizeHealthDimensions(options.dimensions);
  const wants = new Set(selected);
  const cacheKey = `${domain}|${selected.join(',')}`;
  const hit = options.refresh ? null : cache.get(cacheKey);
  if (hit) {
    metrics.recordCache('health', true);
    return { ...hit.value, note: HEALTH_NOTE, cached: true, ttlMs: Math.round(hit.ttlMs) };
  }

  metrics.recordCache('health', false);

  const upstreamMs = config.health.upstreamTimeoutMs;
  const skip = Promise.resolve(null);
  const [nsResult, aResult, aaaaResult, soaResult, tlsResult, mailResult, whoisResult] =
    await Promise.allSettled([
      wants.has('dns') ? lookupDns(domain, 'NS') : skip,
      wants.has('dns') ? lookupDns(domain, 'A') : skip,
      wants.has('dns') ? lookupDns(domain, 'AAAA') : skip,
      wants.has('dns') ? lookupDns(domain, 'SOA') : skip,
      wants.has('tls') ? withTimeout(checkTls(domain), upstreamMs, 'TLS 检测') : skip,
      wants.has('mail')
        ? withTimeout(checkMailAuth(domain, 'default,google'), upstreamMs, '邮件安全检测')
        : skip,
      wants.has('registration') ? withTimeout(lookupDomain(parsed), upstreamMs, '注册信息查询') : skip,
    ]);

  const ns = nsResult.status === 'fulfilled' && nsResult.value ? valuesOf(nsResult.value) : [];
  const a = aResult.status === 'fulfilled' && aResult.value ? valuesOf(aResult.value) : [];
  const aaaa = aaaaResult.status === 'fulfilled' && aaaaResult.value ? valuesOf(aaaaResult.value) : [];
  const soa = Boolean(
    soaResult.status === 'fulfilled' && soaResult.value && soaResult.value.records.length > 0,
  );

  let tls: HealthInput['tls'] = null;
  if (tlsResult.status === 'fulfilled' && tlsResult.value) {
    tls = {
      reachable: tlsResult.value.reachable,
      authorized: tlsResult.value.authorized,
      protocol: tlsResult.value.protocol,
      daysRemaining: tlsResult.value.certificate?.daysRemaining ?? null,
    };
  }

  let mail: HealthInput['mail'] = null;
  if (mailResult.status === 'fulfilled' && mailResult.value) {
    const value = mailResult.value;
    mail = {
      mx: value.mx.length > 0 || value.aFallback.length > 0,
      spf: mailStatus(value.checks, 'spf'),
      dmarc: mailStatus(value.checks, 'dmarc'),
      dkim: mailStatus(value.checks, 'dkim'),
    };
  }

  let whois: HealthInput['whois'] = null;
  let whoisError: string | null = null;
  if (whoisResult.status === 'fulfilled' && whoisResult.value) {
    const data = whoisResult.value.record.data;
    whois = {
      available: data.available,
      registrar: data.registrar?.name ?? null,
      expires: data.dates.expires,
      dnssec: data.dnssec,
    };
  } else if (whoisResult.status === 'rejected') {
    whoisError = whoisResult.reason instanceof Error ? whoisResult.reason.message : '注册信息获取失败';
  }

  const scored = scoreHealth({
    whois,
    whoisError,
    dns: { ns, a, aaaa, soa },
    tls,
    mail,
  });

  const dimensions = scored.dimensions.filter((item) => wants.has(item.key));
  const rawScore = dimensions.reduce((sum, item) => sum + item.score, 0);
  const fullScore = dimensions.length > 0 ? (rawScore / (dimensions.length * 25)) * 100 : 0;
  const score = Math.round(fullScore);

  const result: CachedHealth = {
    domain,
    score,
    grade: gradeOf(score),
    summary: summaryOf(score),
    dimensions,
    issues: scored.issues.filter((item) => wants.has(item.dimension)),
    checkedAt: new Date().toISOString(),
  };

  cache.set(cacheKey, result, config.health.cacheTtlMs);
  return { ...result, note: HEALTH_NOTE, cached: false, ttlMs: config.health.cacheTtlMs };
}

export function clearHealthCache(): void {
  cache.clear();
}

export function healthCacheSize(): number {
  return cache.size;
}
