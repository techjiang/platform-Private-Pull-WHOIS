import type { DnssecStatus, ParsedRecord, RegistrarInfo, RegistrantInfo } from './types.js';

const EMPTY_REGISTRAR: RegistrarInfo = {
  name: null,
  ianaId: null,
  url: null,
  abuseEmail: null,
  abusePhone: null,
};

const EMPTY_RECORD: ParsedRecord = {
  available: false,
  registrar: null,
  registrant: null,
  dates: { created: null, updated: null, expires: null },
  statuses: [],
  nameservers: [],
  dnssec: 'unknown',
  registryDomainId: null,
};

export function emptyParsedRecord(available = false): ParsedRecord {
  return {
    ...EMPTY_RECORD,
    available,
    dates: { ...EMPTY_RECORD.dates },
    statuses: [],
    nameservers: [],
  };
}

const EPP_STATUSES: Record<string, string> = {
  ok: 'ok',
  active: 'active',
  inactive: 'inactive',
  connect: 'connect',
  free: 'free',
  reserved: 'reserved',
  blocked: 'blocked',
  clienttransferprohibited: 'clientTransferProhibited',
  clientdeleteprohibited: 'clientDeleteProhibited',
  clientupdateprohibited: 'clientUpdateProhibited',
  clientrenewprohibited: 'clientRenewProhibited',
  clienthold: 'clientHold',
  servertransferprohibited: 'serverTransferProhibited',
  serverdeleteprohibited: 'serverDeleteProhibited',
  serverupdateprohibited: 'serverUpdateProhibited',
  serverrenewprohibited: 'serverRenewProhibited',
  serverhold: 'serverHold',
  pendingcreate: 'pendingCreate',
  pendingdelete: 'pendingDelete',
  pendingrenew: 'pendingRenew',
  pendingtransfer: 'pendingTransfer',
  pendingupdate: 'pendingUpdate',
  pendingrestore: 'pendingRestore',
  redemptionperiod: 'redemptionPeriod',
  autorenewperiod: 'autoRenewPeriod',
  addperiod: 'addPeriod',
  renewperiod: 'renewPeriod',
  transferperiod: 'transferPeriod',
  restoreperiod: 'restorePeriod',
  registereduntilexpirydate: 'active',
};

const REDACTION_RE =
  /redacted|not disclosed|withheld|gdpr|data protected|statutory masking|non-public|anonymous|masked|no data|not available/i;

/** 将注册局/注册商的多种状态写法统一为 EPP 风格 */
export function normalizeStatus(raw: string): string | null {
  let value = raw
    .replace(/https?:\/\/\S+/gi, ' ')
    .replace(/[()]/g, ' ')
    .replace(/^status\s*:\s*/i, '')
    .replace(/\s+/g, ' ')
    .replace(/[.;,\s]+$/, '')
    .trim();

  if (!value) return null;

  const compact = value.toLowerCase().replace(/[\s_-]/g, '');
  const known = EPP_STATUSES[compact];
  if (known) return known;

  return value;
}

/**
 * 解析 WHOIS 中常见的日期格式，统一输出 ISO 8601（UTC）。
 * 无法确定时返回 null，绝不猜测非法值。
 */
export function parseWhoisDate(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let value = raw.trim();
  if (!value) return null;
  if (/^(before|after|unknown|n\/?a|none|null)/i.test(value)) return null;

  value = value
    .replace(/\s*\([^)]*\)\s*$/, '')
    .replace(/\s*(UTC|GMT)\s*$/i, '')
    .trim();

  let year: number | undefined;
  let month: number | undefined;
  let day: number | undefined;
  let hour = 0;
  let minute = 0;
  let second = 0;

  // 2024-01-02T03:04:05Z / 2024-01-02 03:04:05 / 2024.01.02
  let m = /^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[T\s](\d{1,2}):(\d{2})(?::(\d{2}))?)?/.exec(value);
  if (m) {
    year = Number(m[1]);
    month = Number(m[2]);
    day = Number(m[3]);
    hour = Number(m[4] ?? 0);
    minute = Number(m[5] ?? 0);
    second = Number(m[6] ?? 0);
  }

  // 20240102（部分 ccTLD 使用紧凑日期）
  if (year === undefined) {
    m = /^(\d{4})(\d{2})(\d{2})$/.exec(value);
    if (m) {
      year = Number(m[1]);
      month = Number(m[2]);
      day = Number(m[3]);
    }
  }

  // 02-Jan-2024 / 2 January 2024
  if (year === undefined) {
    m = /^(\d{1,2})[-\s]([A-Za-z]{3,9})[-\s](\d{4})(?:[T\s](\d{1,2}):(\d{2})(?::(\d{2}))?)?/.exec(value);
    if (m) {
      const monthIndex = monthFromName(m[2] as string);
      if (monthIndex === null) return null;
      day = Number(m[1]);
      month = monthIndex;
      year = Number(m[3]);
      hour = Number(m[4] ?? 0);
      minute = Number(m[5] ?? 0);
      second = Number(m[6] ?? 0);
    }
  }

  // Jan 2, 2024 / January 2 2024
  if (year === undefined) {
    m = /^([A-Za-z]{3,9})\s+(\d{1,2}),?\s+(\d{4})/.exec(value);
    if (m) {
      const monthIndex = monthFromName(m[1] as string);
      if (monthIndex === null) return null;
      month = monthIndex;
      day = Number(m[2]);
      year = Number(m[3]);
    }
  }

  // 02.01.2024 / 02/01/2024 / 02-01-2024（点号与短横线优先按 DMY，斜杠优先按 MDY）
  if (year === undefined) {
    m = /^(\d{1,2})([./-])(\d{1,2})\2(\d{4})(?:[T\s](\d{1,2}):(\d{2})(?::(\d{2}))?)?/.exec(value);
    if (m) {
      const first = Number(m[1]);
      const secondPart = Number(m[3]);
      const sep = m[2];
      const dayFirst = sep === '.' || sep === '-' || first > 12;
      day = dayFirst ? first : secondPart;
      month = dayFirst ? secondPart : first;
      year = Number(m[4]);
      hour = Number(m[5] ?? 0);
      minute = Number(m[6] ?? 0);
      second = Number(m[7] ?? 0);
    }
  }

  // 2024年1月2日
  if (year === undefined) {
    m = /^(\d{4})年(\d{1,2})月(\d{1,2})日/.exec(value);
    if (m) {
      year = Number(m[1]);
      month = Number(m[2]);
      day = Number(m[3]);
    }
  }

  if (year === undefined || month === undefined || day === undefined) return null;
  if (year < 1980 || year > 2100) return null;
  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;

  const timestamp = Date.UTC(year, month - 1, day, hour, minute, second);
  const date = new Date(timestamp);
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return null;
  }
  return date.toISOString();
}

function monthFromName(name: string): number | null {
  const months = [
    'january',
    'february',
    'march',
    'april',
    'may',
    'june',
    'july',
    'august',
    'september',
    'october',
    'november',
    'december',
  ];
  const key = name.toLowerCase();
  const index = months.findIndex((month) => month.startsWith(key.slice(0, 3)));
  return index === -1 ? null : index + 1;
}

/** 从 WHOIS 文本中提取域名服务器（支持带 IP、逗号分隔、多行） */
export function extractNameservers(values: readonly string[]): string[] {
  const result = new Set<string>();

  for (const value of values) {
    const tokens = value.split(/[\s,;]+/);
    for (const token of tokens) {
      const host = token
        .replace(/[()[\]]/g, '')
        .replace(/\.$/, '')
        .toLowerCase();
      if (!host || host.length > 253) continue;
      if (!host.includes('.')) continue;
      if (IPV4_RE.test(host)) continue;
      if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(host)) {
        continue;
      }
      result.add(host);
    }
  }

  return [...result];
}

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

export function normalizeDnssec(values: readonly string[]): DnssecStatus {
  for (const raw of values) {
    const value = raw.trim().toLowerCase();
    if (!value) continue;
    if (/^(signed|yes|true|signeddelegation|signed delegation)/.test(value)) return 'signed';
    if (/^(unsigned|no|false|unsigned delegation|unsigneddelegation)/.test(value)) return 'unsigned';
  }
  return 'unknown';
}

export function detectRedaction(text: string, registrant: RegistrantInfo | null): boolean {
  if (registrant) {
    const values = [registrant.name, registrant.organization, registrant.email, registrant.country];
    if (values.some((value) => value && REDACTION_RE.test(value))) return true;
  }
  return /\b(redacted for privacy|data protected|gdpr masked|statutory masking|not disclosed|withheld for privacy)\b/i.test(
    text,
  );
}

export function createRegistrar(partial: Partial<RegistrarInfo>): RegistrarInfo | null {
  const registrar: RegistrarInfo = {
    name: cleanValue(partial.name),
    ianaId: cleanValue(partial.ianaId),
    url: cleanValue(partial.url),
    abuseEmail: cleanValue(partial.abuseEmail),
    abusePhone: cleanValue(partial.abusePhone),
  };
  const hasData = Object.values(registrar).some((value) => value !== null);
  return hasData ? registrar : null;
}

export function createRegistrant(partial: Partial<RegistrantInfo>, text: string): RegistrantInfo | null {
  const name = sanitizeRegistrantValue(partial.name);
  const organization = sanitizeRegistrantValue(partial.organization);
  const email = sanitizeRegistrantValue(partial.email);
  const country = sanitizeRegistrantValue(partial.country);

  const fieldRedacted =
    name.redacted || organization.redacted || email.redacted || country.redacted;
  const hasData = Boolean(name.value || organization.value || email.value || country.value);

  const registrant: RegistrantInfo = {
    name: name.value,
    organization: organization.value,
    email: email.value,
    country: country.value,
    // 只有注册人字段本身被隐藏，或完全没有数据但声明了隐私保护时才标记
    redacted: fieldRedacted || (!hasData && detectRedaction(text, null)),
  };
  return hasData || registrant.redacted ? registrant : null;
}

function sanitizeRegistrantValue(value: string | null | undefined): {
  value: string | null;
  redacted: boolean;
} {
  const cleaned = cleanValue(value);
  if (cleaned && REDACTION_RE.test(cleaned)) return { value: null, redacted: true };
  return { value: cleaned, redacted: false };
}

/** 合并两个来源（注册局 + 注册商）的解析结果，主来源优先 */
export function mergeParsed(primary: ParsedRecord, secondary: ParsedRecord): ParsedRecord {
  if (primary.available || secondary.available) return primary;

  return {
    available: false,
    registrar: mergeObject(primary.registrar, secondary.registrar, EMPTY_REGISTRAR),
    registrant: mergeObject(primary.registrant, secondary.registrant, {
      name: null,
      organization: null,
      email: null,
      country: null,
      redacted: false,
    }),
    dates: {
      created: primary.dates.created ?? secondary.dates.created,
      updated: primary.dates.updated ?? secondary.dates.updated,
      expires: primary.dates.expires ?? secondary.dates.expires,
    },
    statuses: uniqueStrings([...primary.statuses, ...secondary.statuses]),
    nameservers: uniqueStrings([...primary.nameservers, ...secondary.nameservers]),
    dnssec: primary.dnssec !== 'unknown' ? primary.dnssec : secondary.dnssec,
    registryDomainId: primary.registryDomainId ?? secondary.registryDomainId,
  };
}

function mergeObject<T extends object>(
  primary: T | null,
  secondary: T | null,
  fallback: T,
): T | null {
  if (!primary && !secondary) return null;
  const result = { ...fallback };
  for (const key of Object.keys(fallback) as Array<keyof T>) {
    const primaryValue = primary?.[key];
    const secondaryValue = secondary?.[key];
    (result as Record<string, unknown>)[key as string] =
      primaryValue ?? secondaryValue ?? fallback[key];
  }
  return result;
}

function cleanValue(value: string | null | undefined): string | null {
  if (!value) return null;
  const trimmed = value.replace(/\s+/g, ' ').trim();
  if (!trimmed) return null;
  if (/^(n\/?a|none|null|unknown|not applicable|not available|-+)$/i.test(trimmed)) return null;
  return trimmed;
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values)];
}
