import { Resolver, reverse } from 'node:dns/promises';
import { isIP } from 'node:net';
import { config } from '../config.js';
import { TtlCache } from '../lib/cache.js';
import { httpGet, parseJson } from '../lib/http.js';
import { metrics } from '../lib/metrics.js';
import {
  entityVcard,
  findEntityByRole,
  type RdapEntity,
} from '../whois/rdap.js';

interface RdapIpResponse {
  handle?: string;
  name?: string;
  startAddress?: string;
  endAddress?: string;
  ipVersion?: string;
  country?: string;
  type?: string;
  parentHandle?: string;
  events?: Array<{ eventAction?: string; eventDate?: string }>;
  entities?: RdapEntity[];
  status?: string[];
}

interface BootstrapFile {
  services?: Array<[string[], string[]]>;
}

interface PrefixEntry {
  network: bigint;
  prefix: number;
  base: string;
}

export interface IpNetworkInfo {
  handle: string | null;
  name: string | null;
  range: { start: string | null; end: string | null };
  ipVersion: string | null;
  country: string | null;
  type: string | null;
  parentHandle: string | null;
  organization: string | null;
  registered: string | null;
  updated: string | null;
  statuses: string[];
}

/** 来自 Team Cymru DNS（origin.asn.cymru.com）的自治系统信息，毫秒级返回 */
export interface IpAsnInfo {
  asn: number | null;
  name: string | null;
  prefix: string | null;
  country: string | null;
  registry: string | null;
  allocated: string | null;
}

export interface IpLookupResult {
  ip: string;
  version: 4 | 6;
  ptr: string[];
  network: IpNetworkInfo | null;
  asn: IpAsnInfo | null;
  server: string | null;
  note?: string;
  raw?: string;
  cached: boolean;
  ttlMs: number;
  durationMs: number;
}

interface CachedIp {
  ip: string;
  version: 4 | 6;
  ptr: string[];
  network: IpNetworkInfo | null;
  asn: IpAsnInfo | null;
  server: string | null;
  note?: string;
  raw?: string;
  durationMs: number;
}

const cache = new TtlCache<CachedIp>(800);
const bootstrap = new Map<4 | 6, { entries: PrefixEntry[]; expiresAt: number }>();
const bootstrapPending = new Map<4 | 6, Promise<PrefixEntry[]>>();
const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;

function ipv4ToBigInt(value: string): bigint | null {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  let result = 0n;
  for (const part of parts) {
    const num = Number(part);
    if (!Number.isInteger(num) || num < 0 || num > 255) return null;
    result = (result << 8n) + BigInt(num);
  }
  return result;
}

function ipv6ToBigInt(value: string): bigint | null {
  let input = value.toLowerCase();
  const zone = input.indexOf('%');
  if (zone !== -1) input = input.slice(0, zone);

  if (input.includes('.')) {
    const lastColon = input.lastIndexOf(':');
    const v4 = input.slice(lastColon + 1);
    const parsed = ipv4ToBigInt(v4);
    if (parsed === null) return null;
    const high = (parsed >> 16n) & 0xffffn;
    const low = parsed & 0xffffn;
    input = `${input.slice(0, lastColon + 1)}${high.toString(16)}:${low.toString(16)}`;
  }

  const halves = input.split('::');
  if (halves.length > 2) return null;

  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = 8 - left.length - right.length;
  if (halves.length === 2) {
    if (fill < 1) return null;
  } else if (fill !== 0) {
    return null;
  }

  const groups = [...left, ...Array.from({ length: Math.max(0, fill) }, () => '0'), ...right];
  if (groups.length !== 8) return null;

  let result = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    result = (result << 16n) + BigInt(parseInt(group, 16));
  }
  return result;
}

function ipToBigInt(ip: string, version: 4 | 6): bigint | null {
  return version === 4 ? ipv4ToBigInt(ip) : ipv6ToBigInt(ip);
}

function maskFor(prefix: number, bits: number): bigint {
  if (prefix <= 0) return 0n;
  const all = (1n << BigInt(bits)) - 1n;
  return all ^ ((1n << BigInt(bits - prefix)) - 1n);
}

function parseCidr(cidr: string): { network: bigint; prefix: number; bits: number } | null {
  const [address, prefixText] = cidr.split('/');
  if (!address || prefixText === undefined) return null;
  const version = isIP(address);
  if (version !== 4 && version !== 6) return null;
  const prefix = Number(prefixText);
  const bits = version === 4 ? 32 : 128;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return null;
  const value = ipToBigInt(address, version);
  if (value === null) return null;
  return { network: value & maskFor(prefix, bits), prefix, bits };
}

function parseBootstrap(text: string, version: 4 | 6): PrefixEntry[] {
  const body = parseJson<BootstrapFile>(text);
  const entries: PrefixEntry[] = [];

  for (const service of body?.services ?? []) {
    const cidrs = service[0];
    const urls = (service[1] ?? []).filter((url) => url.startsWith('https://'));
    if (!Array.isArray(cidrs) || urls.length === 0) continue;
    const base = urls[0] as string;
    for (const cidr of cidrs) {
      const parsed = parseCidr(cidr);
      if (!parsed) continue;
      if ((version === 4 && parsed.bits !== 32) || (version === 6 && parsed.bits !== 128)) continue;
      entries.push({ network: parsed.network, prefix: parsed.prefix, base });
    }
  }

  entries.sort((a, b) => b.prefix - a.prefix);
  return entries;
}

async function loadBootstrap(version: 4 | 6): Promise<PrefixEntry[]> {
  const cached = bootstrap.get(version);
  if (cached && cached.expiresAt > Date.now()) return cached.entries;

  const pending = bootstrapPending.get(version);
  if (pending) return pending;

  const task = (async () => {
    const file = version === 4 ? 'ipv4.json' : 'ipv6.json';
    try {
      const response = await httpGet(`https://data.iana.org/rdap/${file}`, {
        timeoutMs: 10_000,
        maxBytes: 4 * 1024 * 1024,
      });
      const entries = parseBootstrap(response.text, version);
      if (entries.length === 0) throw new Error('empty bootstrap');
      bootstrap.set(version, { entries, expiresAt: Date.now() + BOOTSTRAP_TTL_MS });
      return entries;
    } catch {
      const fallback: PrefixEntry[] = [
        { network: 0n, prefix: 0, base: 'https://rdap.arin.net/registry/' },
      ];
      bootstrap.set(version, { entries: fallback, expiresAt: Date.now() + 5 * 60 * 1000 });
      return fallback;
    } finally {
      bootstrapPending.delete(version);
    }
  })();

  bootstrapPending.set(version, task);
  return task;
}

function buildNetwork(body: RdapIpResponse): IpNetworkInfo {
  const entity =
    findEntityByRole(body.entities, 'registrant') ??
    findEntityByRole(body.entities, 'administrative') ??
    findEntityByRole(body.entities, 'technical');
  const card = entityVcard(entity ?? undefined);

  const events = new Map<string, string>();
  for (const event of body.events ?? []) {
    if (event.eventAction && event.eventDate) {
      events.set(event.eventAction.toLowerCase(), event.eventDate);
    }
  }

  return {
    handle: body.handle ?? null,
    name: body.name ?? null,
    range: { start: body.startAddress ?? null, end: body.endAddress ?? null },
    ipVersion: body.ipVersion ?? null,
    country: body.country ?? null,
    type: body.type ?? null,
    parentHandle: body.parentHandle ?? null,
    organization: card.org ?? card.fn ?? null,
    registered: events.get('registration') ?? null,
    updated: events.get('last changed') ?? null,
    statuses: body.status ?? [],
  };
}

async function lookupPtr(ip: string): Promise<string[]> {
  try {
    const names = await reverse(ip);
    return names.slice(0, 20);
  } catch {
    return [];
  }
}

/* ------------------------- ASN / 网络（DNS） ------------------------- */

function expandIpv6(ip: string): string | null {
  const value = ipv6ToBigInt(ip);
  if (value === null) return null;
  const hex = value.toString(16).padStart(32, '0');
  return hex.match(/.{4}/g)?.join(':') ?? null;
}

function cymruName(ip: string, version: 4 | 6): string | null {
  if (version === 4) {
    return `${ip.split('.').reverse().join('.')}.origin.asn.cymru.com`;
  }
  const expanded = expandIpv6(ip);
  if (!expanded) return null;
  const nibbles = expanded.replace(/:/g, '').split('').reverse().join('.');
  return `${nibbles}.origin6.asn.cymru.com`;
}

async function resolveTxtOnce(name: string, timeoutMs: number): Promise<string[]> {
  const resolver = new Resolver({ timeout: timeoutMs, tries: 1 });
  return new Promise<string[]>((resolve) => {
    const timer = setTimeout(() => {
      try {
        resolver.cancel();
      } catch {
        /* 忽略取消失败 */
      }
      resolve([]);
    }, timeoutMs);
    timer.unref();

    resolver
      .resolveTxt(name)
      .then((chunks) => resolve(chunks.map((parts) => parts.join('')).filter(Boolean)))
      .catch(() => resolve([]))
      .finally(() => clearTimeout(timer));
  });
}

/** Cymru DNS 偶发 SERVFAIL，失败后短暂重试一次 */
async function resolveTxtRows(name: string, timeoutMs: number): Promise<string[]> {
  const first = await resolveTxtOnce(name, timeoutMs);
  if (first.length > 0) return first;
  return resolveTxtOnce(name, Math.min(timeoutMs, 1200));
}

/** 通过 Team Cymru DNS 接口获取 ASN / 前缀 / 注册机构，失败时返回 null */
async function lookupAsn(ip: string, version: 4 | 6): Promise<IpAsnInfo | null> {
  const name = cymruName(ip, version);
  if (!name) return null;

  const rows = await resolveTxtRows(name, config.ip.asnTimeoutMs);
  const parts = rows[0]?.split('|').map((item) => item.trim());
  if (!parts || parts.length < 2) return null;

  const asnValue = Number(parts[0]);
  const info: IpAsnInfo = {
    asn: Number.isFinite(asnValue) && asnValue > 0 ? asnValue : null,
    prefix: parts[1] && parts[1] !== 'NA' ? parts[1] : null,
    country: parts[2] && parts[2] !== 'NA' ? parts[2] : null,
    registry: parts[3] && parts[3] !== 'NA' ? parts[3] : null,
    allocated: parts[4] && parts[4] !== 'NA' ? parts[4] : null,
    name: null,
  };

  if (!info.asn) return info;

  const nameRows = await resolveTxtRows(`AS${info.asn}.asn.cymru.com`, config.ip.asnTimeoutMs);
  const nameParts = nameRows[0]?.split('|').map((item) => item.trim());
  if (nameParts && nameParts.length >= 5 && nameParts[4]) {
    info.name = nameParts[4];
  }
  return info;
}

async function queryRdap(
  ip: string,
  version: 4 | 6,
): Promise<{ network: IpNetworkInfo | null; server: string | null; note?: string; raw?: string }> {
  const value = ipToBigInt(ip, version);
  if (value === null) return { network: null, server: null, note: 'IP 地址格式无法解析' };

  const entries = await loadBootstrap(version);
  const bits = version === 4 ? 32 : 128;
  const match = entries.find(
    (entry) => (value & maskFor(entry.prefix, bits)) === entry.network,
  );
  const base = match?.base ?? (version === 4
    ? 'https://rdap.arin.net/registry/'
    : 'https://rdap.arin.net/registry/');

  const url = `${base.replace(/\/+$/, '')}/ip/${encodeURIComponent(ip)}`;
  const server = new URL(url).host;

  try {
    const response = await httpGet(url, {
      timeoutMs: config.ip.rdapTimeoutMs,
      headers: { accept: 'application/rdap+json, application/json' },
      maxBytes: 2 * 1024 * 1024,
    });

    if (response.status !== 200) {
      return { network: null, server, note: `RDAP 返回 HTTP ${response.status}` };
    }

    const body = parseJson<RdapIpResponse>(response.text);
    if (!body) return { network: null, server, note: 'RDAP 返回了非 JSON 内容' };

    return {
      network: buildNetwork(body),
      server,
      raw: JSON.stringify(body, null, 2).slice(0, 100_000),
    };
  } catch (error) {
    return {
      network: null,
      server,
      note: error instanceof Error ? error.message : String(error),
    };
  }
}

export function normalizeIp(input: string): { ip: string; version: 4 | 6 } {
  const value = input.trim().replace(/^\[|\]$/g, '');
  const version = isIP(value);
  if (version !== 4 && version !== 6) {
    throw new Error('请输入合法的 IPv4 或 IPv6 地址');
  }
  return { ip: value, version };
}

/** 查询 IP 的 PTR 与 RDAP 网络归属，短缓存 */
export async function lookupIp(input: string, includeRaw = false): Promise<IpLookupResult> {
  const { ip, version } = normalizeIp(input);
  const hit = cache.get(ip);
  if (hit) {
    metrics.recordCache('ip', true);
    return {
      ...hit.value,
      raw: includeRaw ? hit.value.raw : undefined,
      cached: true,
      ttlMs: Math.round(hit.ttlMs),
    };
  }

  metrics.recordCache('ip', false);
  const startedAt = Date.now();
  const [ptr, asn, rdap] = await Promise.all([
    lookupPtr(ip),
    lookupAsn(ip, version),
    queryRdap(ip, version),
  ]);
  const result: CachedIp = {
    ip,
    version,
    ptr,
    network: rdap.network,
    asn,
    server: rdap.server,
    note:
      rdap.note && asn
        ? `${rdap.note}（已回退到 ASN DNS 数据）`
        : rdap.note,
    raw: rdap.raw,
    durationMs: Date.now() - startedAt,
  };
  cache.set(ip, result, config.cache.ttlMs);

  return {
    ...result,
    raw: includeRaw ? result.raw : undefined,
    cached: false,
    ttlMs: config.cache.ttlMs,
  };
}

/* ------------------------------------------------------------------ */
/* 内网 / 保留地址判断（供可用性检查做 SSRF 防护）                      */
/* ------------------------------------------------------------------ */

const V4_BLOCKED: Array<[string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

const V6_BLOCKED: Array<[string, number]> = [
  ['::', 128],
  ['::1', 128],
  ['64:ff9b::', 96],
  ['2001:db8::', 32],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
];

function inRange(value: bigint, network: bigint, prefix: number, bits: number): boolean {
  return (value & maskFor(prefix, bits)) === network;
}

export function isPrivateAddress(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) {
    const value = ipv4ToBigInt(ip);
    if (value === null) return true;
    return V4_BLOCKED.some(([network, prefix]) => {
      const parsed = ipv4ToBigInt(network);
      return parsed !== null && inRange(value, parsed, prefix, 32);
    });
  }

  if (version === 6) {
    const value = ipv6ToBigInt(ip);
    if (value === null) return true;
    // IPv4-mapped（::ffff:0:0/96）与 IPv4-compatible（::/96）地址取出内嵌 IPv4 再判断
    const top96 = value >> 32n;
    if (top96 === 0xffffn || top96 === 0n) {
      const embedded = value & 0xffffffffn;
      const v4 = `${embedded >> 24n}.${(embedded >> 16n) & 255n}.${(embedded >> 8n) & 255n}.${embedded & 255n}`;
      if (isPrivateAddress(v4)) return true;
    }
    return V6_BLOCKED.some(([network, prefix]) => {
      const parsed = ipv6ToBigInt(network);
      return parsed !== null && inRange(value, parsed, prefix, 128);
    });
  }

  return true;
}

export function clearIpCache(): void {
  cache.clear();
}

export function ipCacheSize(): number {
  return cache.size;
}

/** 仅供测试使用 */
export const _internal = { ipv4ToBigInt, ipv6ToBigInt, parseCidr };
