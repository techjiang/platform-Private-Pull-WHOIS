import { emptyParsedRecord, extractNameservers, normalizeDnssec, normalizeStatus, parseWhoisDate, createRegistrar, createRegistrant } from './parsers.js';
import type { ParsedRecord } from './types.js';

interface Entry {
  key: string;
  value: string;
}

const IGNORED_LINE_RE = /^(>>>|%|#|--|<\?)/;

function toEntries(text: string): Entry[] {
  const entries: Entry[] = [];
  let last: Entry | null = null;

  for (const rawLine of text.replace(/\r/g, '').split('\n')) {
    const line = rawLine.replace(/\s+$/, '');
    if (!line.trim()) continue;
    if (IGNORED_LINE_RE.test(line.trim())) continue;

    // JPRS 等注册局使用 “[Key] value” 形式
    const bracketMatch = /^\s*\[([^\]\n]{1,60})\]\s*(.*)$/.exec(line);
    if (bracketMatch) {
      last = {
        key: normalizeKey(bracketMatch[1] as string),
        value: (bracketMatch[2] ?? '').trim(),
      };
      entries.push(last);
      continue;
    }

    const match = /^\s*([^:\n]{1,60}?)\s*:\s*(.*)$/.exec(line);
    if (match) {
      last = { key: normalizeKey(match[1] as string), value: (match[2] ?? '').trim() };
      entries.push(last);
    } else if (last) {
      last.value = `${last.value} ${line.trim()}`.trim();
    }
  }

  return entries;
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/\s+/g, ' ').trim();
}

function toMap(entries: readonly Entry[]): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const entry of entries) {
    if (!entry.key) continue;
    const existing = map.get(entry.key);
    if (existing) {
      if (entry.value) existing.push(entry.value);
    } else {
      map.set(entry.key, entry.value ? [entry.value] : []);
    }
  }
  return map;
}

function getAll(map: Map<string, string[]>, keys: readonly string[]): string[] {
  const values: string[] = [];
  for (const key of keys) {
    const found = map.get(key);
    if (found) values.push(...found);
  }
  return values;
}

function getFirst(map: Map<string, string[]>, keys: readonly string[]): string | null {
  for (const key of keys) {
    const found = map.get(key);
    if (found) {
      for (const value of found) {
        if (value.trim()) return value.trim();
      }
    }
  }
  return null;
}

function firstDate(map: Map<string, string[]>, keys: readonly string[]): string | null {
  for (const key of keys) {
    const found = map.get(key);
    if (!found) continue;
    for (const value of found) {
      const parsed = parseWhoisDate(value);
      if (parsed) return parsed;
    }
  }
  return null;
}

const AVAILABILITY_PATTERNS: RegExp[] = [
  /no match for/,
  /no data found/,
  /no entries found/,
  /no object found/,
  /not found/,
  /not registered/,
  /no such domain/,
  /domain (name )?not found/,
  /is available for (registration|purchase)/,
  /available for registration/,
  /has not been registered/,
  /not been registered/,
  /the queried object does not exist/,
  /object does not exist/,
  /no information available/,
  /status:\s*free\b/,
  /domain is free/,
  /does not exist in (the )?(database|registry)/,
];

const UPSTREAM_ERROR_RE =
  /(rate limit|quota exceeded|too many requests|try again later|connection refused|query limit)/i;

/** 判断 WHOIS 文本是否表示“域名可注册” */
export function isAvailableText(text: string): boolean {
  const normalized = text.toLowerCase();
  if (!normalized.trim()) return false;
  if (UPSTREAM_ERROR_RE.test(normalized)) return false;

  const hasRegistrationData =
    /(creation date|created on|created:|registered on|registrar:|domain name:|registry expiry|expiry date)/.test(
      normalized,
    );
  if (hasRegistrationData) {
    return /no match|not found|no entries|available/.test(normalized) && !/registrar:/.test(normalized);
  }

  return AVAILABILITY_PATTERNS.some((pattern) => pattern.test(normalized));
}

/** 把原始 WHOIS 文本解析为统一结构 */
export function parseWhois(text: string): ParsedRecord {
  if (isAvailableText(text)) {
    return emptyParsedRecord(true);
  }

  const map = toMap(toEntries(text));
  const available = false;

  const registrar = createRegistrar({
    name: getFirst(map, [
      'registrar',
      'registrar name',
      'sponsoring registrar',
      'registrar organization',
      'registrar company name',
      'registrar handle',
    ]),
    ianaId: getFirst(map, ['registrar iana id', 'iana id', 'registrar id', 'iana registrar id']),
    url: getFirst(map, ['registrar url', 'registrar website', 'registrar homepage', 'url']),
    abuseEmail: getFirst(map, [
      'registrar abuse contact email',
      'registrar abuse email',
      'abuse email',
      'abuse contact email',
    ]),
    abusePhone: getFirst(map, [
      'registrar abuse contact phone',
      'registrar abuse phone',
      'abuse phone',
      'abuse contact phone',
    ]),
  });

  const registrantName = getFirst(map, [
    'registrant name',
    'registrant contact name',
    'registrant person',
    'registrant',
    'holder name',
    'holder',
    'owner name',
    'owner',
    '登録者名',
  ]);
  const registrantOrg = getFirst(map, [
    'registrant organization',
    'registrant organisation',
    'registrant org',
    'registrant company',
    'holder organization',
    'owner organization',
  ]);
  const explicitEmail = getFirst(map, [
    'registrant email',
    'registrant contact email',
    'registrant e-mail',
    'holder email',
    'owner email',
  ]);
  const fallbackEmail =
    registrantName || registrantOrg ? getFirst(map, ['email', 'e-mail']) : null;

  const registrant = createRegistrant(
    {
      name: registrantName,
      organization: registrantOrg,
      email: explicitEmail ?? fallbackEmail,
      country: getFirst(map, [
        'registrant country',
        'registrant country/economy',
        'registrant country code',
        'holder country',
        'owner country',
      ]),
    },
    text,
  );

  const statuses = [
    ...new Set(
      getAll(map, [
        'domain status',
        'domain status codes',
        'domain status code',
        'status',
        'registration status',
        'state',
        '状態',
      ])
        .map(normalizeStatus)
        .filter((status): status is string => Boolean(status)),
    ),
  ];

  const registryDomainId = getFirst(map, ['registry domain id', 'domain id', 'roid', 'registry id']);
  const cleanedRegistryDomainId =
    registryDomainId && !/redacted|not disclosed|withheld|privacy/i.test(registryDomainId)
      ? registryDomainId
      : null;

  return {
    available,
    registrar,
    registrant,
    dates: {
      created: firstDate(map, [
        'creation date',
        'created on',
        'created',
        'registration time',
        'registration date',
        'registered on',
        'registered date',
        'registered',
        'domain registration date',
        'commencement date',
        'activation date',
        'created date',
        '登録年月日',
        '注册时间',
        '注册日期',
      ]),
      updated: firstDate(map, [
        'updated date',
        'last updated on',
        'last updated',
        'last update',
        'last-modified',
        'last modified',
        'changed',
        'modified',
        'update date',
        'last update date',
        '最終更新',
      ]),
      expires: firstDate(map, [
        'registry expiry date',
        'expiration date',
        'expiry date',
        'expires on',
        'expires',
        'expiration time',
        'registrar registration expiration date',
        'paid-till',
        'valid until',
        'validity',
        'renewal date',
        'expire date',
        'expiration',
        'date of expiry',
        '有効期限',
        '到期时间',
      ]),
    },
    statuses,
    nameservers: extractNameservers(
      getAll(map, [
        'name server',
        'name servers',
        'nameserver',
        'nameservers',
        'nserver',
        'dns server',
        'dns servers',
        'name server information',
        'ネームサーバ',
      ]),
    ),
    dnssec: normalizeDnssec(getAll(map, ['dnssec', 'dnssec status', 'dnssec signed', 'dnssec delegation signed'])),
    registryDomainId: cleanedRegistryDomainId,
  };
}
