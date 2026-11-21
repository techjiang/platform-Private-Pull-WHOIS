import { httpGet, parseJson } from '../lib/http.js';
import {
  createRegistrar,
  createRegistrant,
  emptyParsedRecord,
  extractNameservers,
  normalizeDnssec,
  normalizeStatus,
  parseWhoisDate,
} from './parsers.js';
import type { ParsedRecord, SourceAttempt } from './types.js';

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}

interface RdapPublicId {
  type?: string;
  identifier?: string;
}

interface RdapLink {
  href?: string;
  rel?: string;
  type?: string;
}

interface RdapVcardProperty extends Array<unknown> {
  0?: string;
  3?: unknown;
}

export interface RdapEntity {
  handle?: string;
  roles?: string[];
  vcardArray?: unknown;
  entities?: RdapEntity[];
  publicIds?: RdapPublicId[];
  links?: RdapLink[];
}

interface RdapDomain {
  objectClassName?: string;
  handle?: string;
  ldhName?: string;
  unicodeName?: string;
  status?: string[];
  events?: RdapEvent[];
  nameservers?: Array<{ ldhName?: string }>;
  entities?: RdapEntity[];
  secureDNS?: { delegationSigned?: boolean; zoneSigned?: boolean };
}

interface IanaBootstrap {
  services?: Array<[string[], string[]]>;
}

export interface RdapQueryResult {
  parsed: ParsedRecord;
  server: string;
  raw: string;
  durationMs: number;
}

export interface RdapOutcome {
  result: RdapQueryResult | null;
  attempts: SourceAttempt[];
}

const FALLBACK_RDAP: Record<string, string[]> = {
  com: ['https://rdap.verisign.com/com/v1/'],
  net: ['https://rdap.verisign.com/net/v1/'],
  org: ['https://rdap.publicinterestregistry.org/rdap/'],
  info: ['https://rdap.identitydigital.services/rdap/'],
  xyz: ['https://rdap.centralnic.com/xyz/'],
  io: ['https://rdap.identitydigital.services/rdap/'],
};

const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;

let bootstrapCache: { map: Map<string, string[]>; expiresAt: number } | null = null;
let bootstrapPromise: Promise<Map<string, string[]>> | null = null;

async function loadBootstrap(): Promise<Map<string, string[]>> {
  const now = Date.now();
  if (bootstrapCache && bootstrapCache.expiresAt > now) return bootstrapCache.map;
  if (bootstrapPromise) return bootstrapPromise;

  bootstrapPromise = (async () => {
    try {
      const response = await httpGet(BOOTSTRAP_URL, { timeoutMs: 10_000, maxBytes: 4 * 1024 * 1024 });
      const body = parseJson<IanaBootstrap>(response.text);
      const map = new Map<string, string[]>();

      for (const service of body?.services ?? []) {
        const tlds = service[0];
        const urls = (service[1] ?? []).filter((url) => url.startsWith('https://'));
        if (!Array.isArray(tlds) || urls.length === 0) continue;
        for (const tld of tlds) {
          map.set(tld.toLowerCase(), urls);
        }
      }

      if (map.size === 0) throw new Error('empty bootstrap');
      bootstrapCache = { map, expiresAt: Date.now() + BOOTSTRAP_TTL_MS };
      return map;
    } catch {
      // 引导文件不可用时使用内置兜底，缩短缓存时间以便尽快恢复
      const map = new Map(Object.entries(FALLBACK_RDAP));
      bootstrapCache = { map, expiresAt: Date.now() + 5 * 60 * 1000 };
      return map;
    } finally {
      bootstrapPromise = null;
    }
  })();

  return bootstrapPromise;
}

/** 供调度任务预热 RDAP 引导数据，减少首个查询的等待时间 */
export async function prewarmRdapBootstrap(): Promise<number> {
  const map = await loadBootstrap();
  return map.size;
}

export function entityVcard(entity: RdapEntity | undefined): Record<string, string | null> {
  const result: Record<string, string | null> = {
    fn: null,
    org: null,
    email: null,
    tel: null,
    country: null,
    url: null,
  };
  if (!entity) return result;

  const properties = Array.isArray(entity.vcardArray) ? entity.vcardArray[1] : null;
  if (Array.isArray(properties)) {
    for (const property of properties as RdapVcardProperty[]) {
      if (!Array.isArray(property)) continue;
      const name = String(property[0] ?? '').toLowerCase();
      const value = property[3];
      if (value === undefined || value === null) continue;

      if (name === 'fn' && typeof value === 'string') result.fn = value;
      else if (name === 'org') {
        result.org = Array.isArray(value) ? value.filter(Boolean).join(', ') : String(value);
      } else if (name === 'email' && typeof value === 'string') {
        result.email = value;
      } else if (name === 'tel') {
        const rawTel = Array.isArray(value) ? String(value[0] ?? '') : String(value);
        result.tel = rawTel.replace(/^(tel|fax):/i, '').trim() || null;
      } else if (name === 'adr' && Array.isArray(value)) {
        const parts = value.map((part) => (typeof part === 'string' ? part.trim() : ''));
        result.country = parts.filter(Boolean).pop() ?? null;
      } else if (name === 'url' && typeof value === 'string') {
        result.url = value;
      }
    }
  }

  if (!result.url) {
    const link = entity.links?.find(
      (item) => item.href && (!item.type || /html/i.test(item.type)),
    );
    result.url = link?.href ?? null;
  }

  return result;
}

export function findEntityByRole(
  entities: readonly RdapEntity[] | undefined,
  role: string,
): RdapEntity | null {
  if (!entities) return null;
  for (const entity of entities) {
    if (entity.roles?.some((item) => item.toLowerCase() === role)) return entity;
    const nested = findEntityByRole(entity.entities, role);
    if (nested) return nested;
  }
  return null;
}

function rdapDate(value: string | undefined): string | null {
  const parsed = parseWhoisDate(value);
  return parsed;
}

export function parseRdapDomain(rdap: RdapDomain): ParsedRecord {
  if (!rdap || (rdap.objectClassName && rdap.objectClassName !== 'domain') || !rdap.ldhName) {
    return emptyParsedRecord(false);
  }

  const statuses = [
    ...new Set(
      (rdap.status ?? [])
        .map(normalizeStatus)
        .filter((status): status is string => Boolean(status)),
    ),
  ];

  const events = new Map<string, string>();
  for (const event of rdap.events ?? []) {
    if (!event.eventAction || !event.eventDate) continue;
    events.set(event.eventAction.toLowerCase(), event.eventDate);
  }

  const registrarEntity = findEntityByRole(rdap.entities, 'registrar');
  const registrarCard = entityVcard(registrarEntity ?? undefined);
  const ianaId =
    registrarEntity?.publicIds?.find((item) => /iana/i.test(item.type ?? ''))?.identifier ?? null;
  const abuseEntity =
    findEntityByRole(registrarEntity?.entities, 'abuse') ?? findEntityByRole(rdap.entities, 'abuse');
  const abuseCard = entityVcard(abuseEntity ?? undefined);

  const registrar = createRegistrar({
    name: registrarCard.fn ?? registrarCard.org ?? registrarEntity?.handle ?? null,
    ianaId,
    url: registrarCard.url,
    abuseEmail: abuseCard.email,
    abusePhone: abuseCard.tel,
  });

  const registrantEntity = findEntityByRole(rdap.entities, 'registrant');
  const registrantCard = entityVcard(registrantEntity ?? undefined);
  const registrant = registrantEntity
    ? createRegistrant(
        {
          name: registrantCard.fn,
          organization: registrantCard.org,
          email: registrantCard.email,
          country: registrantCard.country,
        },
        JSON.stringify(registrantEntity),
      )
    : null;

  const delegationSigned = rdap.secureDNS?.delegationSigned;

  return {
    available: false,
    registrar,
    registrant,
    dates: {
      created: rdapDate(events.get('registration')),
      updated:
        rdapDate(events.get('last changed')) ?? rdapDate(events.get('last update of rdap database')),
      expires: rdapDate(events.get('expiration')),
    },
    statuses,
    nameservers: extractNameservers(
      (rdap.nameservers ?? []).map((server) => server.ldhName ?? '').filter(Boolean),
    ),
    dnssec:
      delegationSigned === true
        ? 'signed'
        : delegationSigned === false
          ? 'unsigned'
          : 'unknown',
    registryDomainId: rdap.handle ?? null,
  };
}

/** 优先使用注册局 RDAP；不支持或失败时返回 null 交给 WHOIS 兜底 */
export async function rdapLookup(
  domain: string,
  tld: string,
  timeoutMs: number,
): Promise<RdapOutcome> {
  const startedAt = Date.now();
  const attempts: SourceAttempt[] = [];
  let bases: string[];

  try {
    const map = await loadBootstrap();
    bases = map.get(tld) ?? [];
  } catch {
    bases = [];
  }

  if (bases.length === 0) return { result: null, attempts };

  for (const base of bases.slice(0, 2)) {
    const url = `${base.replace(/\/+$/, '')}/domain/${encodeURIComponent(domain)}`;
    const server = new URL(url).host;
    const attemptStarted = Date.now();

    try {
      const response = await httpGet(url, {
        timeoutMs,
        headers: { accept: 'application/rdap+json, application/json' },
        maxBytes: 2 * 1024 * 1024,
      });

      if (response.status === 200) {
        const body = parseJson<RdapDomain>(response.text);
        if (!body) throw new Error('RDAP 返回了非 JSON 内容');

        attempts.push({
          source: 'rdap',
          server,
          ok: true,
          durationMs: Date.now() - attemptStarted,
        });

        return {
          result: {
            parsed: parseRdapDomain(body),
            server,
            raw: JSON.stringify(body, null, 2),
            durationMs: Date.now() - startedAt,
          },
          attempts,
        };
      }

      if (response.status === 404) {
        attempts.push({
          source: 'rdap',
          server,
          ok: true,
          error: '域名未注册（RDAP 404）',
          durationMs: Date.now() - attemptStarted,
        });
        return {
          result: {
            parsed: emptyParsedRecord(true),
            server,
            raw: response.text.slice(0, 4096),
            durationMs: Date.now() - startedAt,
          },
          attempts,
        };
      }

      attempts.push({
        source: 'rdap',
        server,
        ok: false,
        error: `HTTP ${response.status}`,
        durationMs: Date.now() - attemptStarted,
      });
    } catch (error) {
      attempts.push({
        source: 'rdap',
        server,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
        durationMs: Date.now() - attemptStarted,
      });
    }
  }

  return { result: null, attempts };
}
