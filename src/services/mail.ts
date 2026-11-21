import { config } from '../config.js';
import { TtlCache } from '../lib/cache.js';
import { ApiError } from '../lib/errors.js';
import { metrics } from '../lib/metrics.js';
import { lookupDns, type DnsRecord } from './dns.js';

/**
 * 邮件安全记录检查
 *
 * 全部通过本站 DNS 查询与本地解析完成（SPF / DMARC / DKIM / MX），
 * 不调用任何第三方邮件安全检测接口。
 */

export interface SpfInfo {
  raw: string;
  version: boolean;
  mechanisms: string[];
  all: string | null;
  allQualifier: string | null;
  includes: string[];
  ip4: string[];
  ip6: string[];
  redirect: string | null;
  lookupCount: number;
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export interface DmarcInfo {
  raw: string;
  version: boolean;
  policy: string | null;
  subdomainPolicy: string | null;
  pct: number;
  rua: string[];
  ruf: string[];
  alignment: { dkim: string; spf: string };
  tags: Record<string, string>;
  valid: boolean;
  errors: string[];
}

export interface DkimInfo {
  raw: string;
  version: string | null;
  keyType: string;
  keyPresent: boolean;
  revoked: boolean;
  hashAlgorithms: string[];
  flags: string[];
  valid: boolean;
  errors: string[];
}

export interface MailCheck {
  id: 'spf' | 'dmarc' | 'dkim' | 'mx';
  label: string;
  status: 'pass' | 'warn' | 'fail';
  detail: string;
}

export interface MailAuthResult {
  domain: string;
  mx: Array<{ priority: number; exchange: string }>;
  aFallback: string[];
  spf: SpfInfo | null;
  dmarc: DmarcInfo | null;
  dkim: Array<{ selector: string; found: boolean; info: DkimInfo | null }>;
  checks: MailCheck[];
  summary: '良好' | '需改进' | '缺少关键配置';
  note: string;
  cached: boolean;
  ttlMs: number;
}

export const MAIL_NOTE =
  'SPF、DMARC、DKIM 与 MX 均由本站直接查询 DNS 后解析，不依赖第三方检测服务。DKIM 选择器无法通过 DNS 枚举，默认只探测常见选择器。';

const cache = new TtlCache<Omit<MailAuthResult, 'cached' | 'ttlMs'>>(config.mail.maxEntries);
const inflight = new Map<string, Promise<Omit<MailAuthResult, 'cached' | 'ttlMs'>>>();

function txtRecords(records: DnsRecord[]): string[] {
  return records
    .filter((record) => record.type === 'TXT')
    .map((record) => {
      const value = record.value as { text?: unknown; chunks?: unknown };
      if (typeof value?.text === 'string') return value.text;
      if (Array.isArray(value?.chunks)) return value.chunks.map((item) => String(item)).join('');
      return '';
    })
    .filter(Boolean);
}

function firstSpf(records: string[]): { raw: string; multiple: boolean } | null {
  const matches = records.filter((text) => /^v=spf1(\s|$)/i.test(text.trim()));
  const raw = matches[0];
  if (!raw) return null;
  return { raw, multiple: matches.length > 1 };
}

/** 解析单条 SPF 记录 */
export function parseSpf(raw: string): SpfInfo {
  const tokens = raw.trim().split(/\s+/).filter(Boolean);
  const version = (tokens[0] ?? '').toLowerCase() === 'v=spf1';
  const mechanisms = tokens.slice(1);
  const stripped = mechanisms.map((item) => item.replace(/^[+\-~?]/, ''));
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!version) errors.push('缺少 v=spf1 版本标识');

  const allToken = mechanisms.find((item) => /^[+\-~?]?all$/i.test(item));
  const all = allToken ? 'all' : null;
  const allQualifier = allToken
    ? (allToken.match(/^[+\-~?]/)?.[0] ?? '+')
    : null;
  if (!allToken) {
    warnings.push('缺少 all 机制，未匹配的邮件默认按中性处理');
  } else if (allQualifier === '+') {
    warnings.push('+all 允许所有来源发信，存在伪造风险');
  }

  const includes = mechanisms
    .filter((item) => /^[+\-~?]?include:/i.test(item))
    .map((item) => item.replace(/^[+\-~?]/, '').slice('include:'.length))
    .filter(Boolean);
  const ip4 = mechanisms
    .filter((item) => /^[+\-~?]?ip4:/i.test(item))
    .map((item) => item.replace(/^[+\-~?]/, '').slice('ip4:'.length))
    .filter(Boolean);
  const ip6 = mechanisms
    .filter((item) => /^[+\-~?]?ip6:/i.test(item))
    .map((item) => item.replace(/^[+\-~?]/, '').slice('ip6:'.length))
    .filter(Boolean);
  const redirectToken = mechanisms.find((item) => /^[+\-~?]?redirect=/i.test(item));
  const redirect = redirectToken ? redirectToken.split('=')[1]?.trim() || null : null;

  const lookupCount = stripped.filter(
    (item) =>
      /^(include:|a(\/|:|$)|mx(\/|:|$)|ptr(\/|:|$)|exists:|redirect=)/i.test(item),
  ).length;
  if (lookupCount > 10) {
    errors.push(`SPF DNS 查询机制 ${lookupCount} 个，超过 RFC 规定的 10 次上限`);
  }

  return {
    raw,
    version,
    mechanisms,
    all,
    allQualifier,
    includes,
    ip4,
    ip6,
    redirect,
    lookupCount,
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

function parseTags(raw: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of raw.split(';')) {
    const item = part.trim();
    if (!item) continue;
    const index = item.indexOf('=');
    if (index <= 0) continue;
    const key = item.slice(0, index).trim().toLowerCase();
    const value = item.slice(index + 1).trim();
    if (key && tags[key] === undefined) tags[key] = value;
  }
  return tags;
}

/** 解析单条 DMARC 记录 */
export function parseDmarc(raw: string): DmarcInfo {
  const tags = parseTags(raw);
  const version = (tags.v ?? '').toUpperCase() === 'DMARC1';
  const policy = tags.p?.toLowerCase() ?? null;
  const errors: string[] = [];

  if (!version) errors.push('缺少 v=DMARC1 版本标识');
  if (!policy) errors.push('缺少 p= 策略');
  else if (!['none', 'quarantine', 'reject'].includes(policy)) {
    errors.push(`p=${policy} 不是有效策略`);
  }

  const rawPct = Number(tags.pct ?? '100');
  const pct = Number.isFinite(rawPct) ? Math.min(100, Math.max(0, Math.trunc(rawPct))) : 100;
  const splitList = (value: string | undefined) =>
    (value ?? '')
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean);

  const dkimAlignment = (tags.adkim ?? 'r').toLowerCase();
  const spfAlignment = (tags.aspf ?? 'r').toLowerCase();

  return {
    raw,
    version,
    policy,
    subdomainPolicy: tags.sp?.toLowerCase() ?? null,
    pct,
    rua: splitList(tags.rua),
    ruf: splitList(tags.ruf),
    alignment: {
      dkim: dkimAlignment === 's' ? 's' : 'r',
      spf: spfAlignment === 's' ? 's' : 'r',
    },
    tags,
    valid: errors.length === 0,
    errors,
  };
}

/** 解析单条 DKIM 公钥记录 */
export function parseDkim(raw: string): DkimInfo {
  const tags = parseTags(raw);
  const version = tags.v ?? null;
  const keyType = (tags.k ?? 'rsa').toLowerCase();
  const keyPresent = typeof tags.p === 'string';
  const revoked = keyPresent && tags.p === '';
  const errors: string[] = [];

  if (version && version.toUpperCase() !== 'DKIM1') errors.push(`v=${version} 不是 DKIM1`);
  if (!keyPresent) errors.push('缺少 p= 公钥');
  if (revoked) errors.push('公钥为空，该选择器已被撤销');

  return {
    raw,
    version,
    keyType,
    keyPresent: keyPresent && !revoked,
    revoked,
    hashAlgorithms: (tags.h ?? '').split(':').map((item) => item.trim()).filter(Boolean),
    flags: (tags.t ?? '').split(':').map((item) => item.trim()).filter(Boolean),
    valid: errors.length === 0,
    errors,
  };
}

/** 解析并校验 DKIM 选择器（默认使用配置中的常见选择器） */
export function normalizeSelectors(input?: string): string[] {
  if (!input || !input.trim()) return config.mail.dkimSelectors.slice(0, 6);
  const selectors = [
    ...new Set(
      input
        .split(',')
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean),
    ),
  ];
  if (selectors.length === 0) throw ApiError.badRequest('DKIM 选择器不能为空');
  if (selectors.length > 6) throw ApiError.badRequest('最多同时查询 6 个 DKIM 选择器');
  if (selectors.some((item) => !/^[a-z0-9._-]{1,63}$/.test(item))) {
    throw ApiError.badRequest('DKIM 选择器格式不正确，例如 selector1');
  }
  return selectors;
}

function buildChecks(
  mx: MailAuthResult['mx'],
  aFallback: string[],
  spf: SpfInfo | null,
  dmarc: DmarcInfo | null,
  dkim: MailAuthResult['dkim'],
): MailCheck[] {
  const checks: MailCheck[] = [];

  checks.push({
    id: 'mx',
    label: 'MX 邮件交换记录',
    status: mx.length > 0 ? 'pass' : 'warn',
    detail:
      mx.length > 0
        ? `${mx.length} 条 MX 记录`
        : aFallback.length > 0
          ? `未配置 MX，按 RFC 回退到 A 记录（${aFallback.join(', ')}）`
          : '未配置 MX，可能无法接收邮件',
  });

  checks.push({
    id: 'spf',
    label: 'SPF 发信来源',
    status: !spf ? 'fail' : spf.valid ? (spf.warnings.length ? 'warn' : 'pass') : 'warn',
    detail: !spf
      ? '未找到 v=spf1 记录'
      : spf.errors.length
        ? spf.errors.join('；')
        : spf.warnings.length
          ? spf.warnings.join('；')
          : `包含 ${spf.mechanisms.length} 个机制，all=${spf.allQualifier ?? '?'}${spf.all ?? ''}`,
  });

  checks.push({
    id: 'dmarc',
    label: 'DMARC 策略',
    status: !dmarc ? 'fail' : dmarc.valid ? (dmarc.policy === 'none' ? 'warn' : 'pass') : 'warn',
    detail: !dmarc
      ? '未找到 _dmarc 记录'
      : dmarc.errors.length
        ? dmarc.errors.join('；')
        : dmarc.policy === 'none'
          ? 'p=none 仅监控，未实际拦截伪造邮件'
          : `p=${dmarc.policy}${dmarc.pct < 100 ? `，pct=${dmarc.pct}%` : ''}`,
  });

  const found = dkim.filter((item) => item.found);
  const usable = dkim.filter((item) => item.info?.valid);
  checks.push({
    id: 'dkim',
    label: 'DKIM 签名公钥',
    status: usable.length > 0 ? 'pass' : 'warn',
    detail:
      usable.length > 0
        ? `可用选择器：${usable.map((item) => item.selector).join(', ')}`
        : found.length > 0
          ? `发现 ${found.length} 个选择器记录，但公钥无效或已撤销`
          : '常见选择器下未找到 DKIM 公钥（业务可能使用其他选择器）',
  });

  return checks;
}

async function queryMail(domain: string, selectors: string[]): Promise<Omit<MailAuthResult, 'cached' | 'ttlMs'>> {
  const [mxResult, txtResult, dmarcResult] = await Promise.all([
    lookupDns(domain, 'MX'),
    lookupDns(domain, 'TXT'),
    lookupDns(`_dmarc.${domain}`, 'TXT'),
  ]);

  const mx = mxResult.records
    .filter((record) => record.type === 'MX')
    .map((record) => record.value as { priority: number; exchange: string })
    .filter((record) => typeof record?.exchange === 'string' && record.exchange)
    .map((record) => ({ priority: Number(record.priority) || 0, exchange: record.exchange }))
    .sort((a, b) => a.priority - b.priority);

  let aFallback: string[] = [];
  if (mx.length === 0) {
    try {
      const aResult = await lookupDns(domain, 'A');
      aFallback = aResult.records
        .filter((record) => record.type === 'A')
        .map((record) => String(record.value));
    } catch {
      aFallback = [];
    }
  }

  const spfRecord = firstSpf(txtRecords(txtResult.records));
  const spf = spfRecord ? parseSpf(spfRecord.raw) : null;
  if (spf && spfRecord?.multiple) {
    spf.errors.push('存在多条 SPF 记录，收信方可能判定为无效');
    spf.valid = false;
  }

  const dmarcRecord = txtRecords(dmarcResult.records).find((text) => /^v=DMARC1(\s|;|$)/i.test(text.trim()));
  const dmarc = dmarcRecord ? parseDmarc(dmarcRecord) : null;

  const dkim = await Promise.all(
    selectors.map(async (selector) => {
      try {
        const result = await lookupDns(`${selector}._domainkey.${domain}`, 'TXT');
        const records = txtRecords(result.records);
        const key = records.find((text) => /(^|;)\s*p\s*=/i.test(text)) ?? records[0];
        return { selector, found: Boolean(key), info: key ? parseDkim(key) : null };
      } catch {
        return { selector, found: false, info: null };
      }
    }),
  );

  const checks = buildChecks(mx, aFallback, spf, dmarc, dkim);
  const fails = checks.filter((item) => item.status === 'fail').length;
  const warns = checks.filter((item) => item.status === 'warn').length;

  return {
    domain,
    mx,
    aFallback,
    spf,
    dmarc,
    dkim,
    checks,
    summary: fails > 0 ? '缺少关键配置' : warns > 0 ? '需改进' : '良好',
    note: MAIL_NOTE,
  };
}

/** 检查域名邮件安全记录（带缓存与单飞） */
export async function checkMailAuth(domain: string, selectorInput?: string): Promise<MailAuthResult> {
  const selectors = normalizeSelectors(selectorInput);
  const key = `${domain}|${selectors.join(',')}`;
  const hit = cache.get(key);
  if (hit) {
    metrics.recordCache('mail', true);
    return { ...hit.value, cached: true, ttlMs: Math.round(hit.ttlMs) };
  }

  const pending = inflight.get(key);
  if (pending) {
    return { ...(await pending), cached: true, ttlMs: Math.round(config.mail.cacheTtlMs) };
  }

  metrics.recordCache('mail', false);

  const task = queryMail(domain, selectors);
  inflight.set(key, task);
  try {
    const result = await task;
    cache.set(key, result, config.mail.cacheTtlMs);
    return { ...result, cached: false, ttlMs: config.mail.cacheTtlMs };
  } finally {
    inflight.delete(key);
  }
}

export function clearMailCache(): void {
  cache.clear();
  inflight.clear();
}

export function mailCacheSize(): number {
  return cache.size;
}
