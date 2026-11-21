import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from '../config.js';
import { REGISTRARS as CURATED, type RegistrarRecord } from '../data/registrars.js';
import { httpGet } from '../lib/http.js';

export type RegistrarStatus = 'accredited' | 'terminated' | 'reserved' | 'unknown';

export interface RegistrarBase {
  ianaId: string | null;
  name: string;
  country: string | null;
  website: string | null;
  contact: string | null;
  status: RegistrarStatus;
  rdapServer: string | null;
  updated: string | null;
  aliases: string[];
  origin: 'iana+icann' | 'iana' | 'icann' | 'curated';
}

export interface RegistrarSnapshot {
  version: 1;
  syncedAt: string | null;
  ianaUpdated: string | null;
  sources: { iana: 'ok' | 'failed'; icann: 'ok' | 'failed' };
  lastError: string | null;
  entries: RegistrarBase[];
}

export const IANA_REGISTRAR_URL =
  'https://www.iana.org/assignments/registrar-ids/registrar-ids.xml';
export const ICANN_REGISTRAR_CSV_URL =
  'https://www.icann.org/en/contracted-parties/accredited-registrars/list-of-accredited-registrars/csvdownload';

const DEFAULT_DATA_FILE = fileURLToPath(new URL('../../data/registrars.json', import.meta.url));
const STATUS_VALUES: RegistrarStatus[] = ['accredited', 'terminated', 'reserved', 'unknown'];

function decodeEntities(text: string): string {
  return text
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(x?[0-9a-f]+);/gi, (_match, code: string) => {
      const value = code.startsWith('x') || code.startsWith('X')
        ? Number.parseInt(code.slice(1), 16)
        : Number.parseInt(code, 10);
      return Number.isFinite(value) ? String.fromCodePoint(value) : '';
    })
    .replace(/&amp;/g, '&');
}

function xmlTag(body: string, tag: string): string | null {
  const match = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, 'i').exec(body);
  if (!match?.[1]) return null;
  const value = decodeEntities(match[1].replace(/<[^>]+>/g, '').trim());
  return value || null;
}

function normalizeStatus(value: string | null): RegistrarStatus {
  const status = (value ?? '').trim().toLowerCase();
  return STATUS_VALUES.includes(status as RegistrarStatus)
    ? (status as RegistrarStatus)
    : 'unknown';
}

export function normalizeWebsite(value: string | null): string | null {
  const text = (value ?? '').trim();
  if (!text) return null;
  const withScheme = /^https?:\/\//i.test(text) ? text : `https://${text}`;
  try {
    const url = new URL(withScheme);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

/** 解析 IANA registrar-ids.xml（Accredited / Terminated / Reserved） */
export function parseIanaXml(text: string): { entries: RegistrarBase[]; updated: string | null } {
  const entries: RegistrarBase[] = [];
  const updatedMatch = /<updated>([^<]+)<\/updated>/i.exec(text);

  const recordPattern = /<record\b([^>]*)>([\s\S]*?)<\/record>/gi;
  let match: RegExpExecArray | null;
  while ((match = recordPattern.exec(text)) !== null) {
    const attributes = match[1] ?? '';
    const body = match[2] ?? '';
    const ianaId = xmlTag(body, 'value');
    const name = xmlTag(body, 'name');
    if (!ianaId || !/^\d+$/.test(ianaId) || !name) continue;

    const updatedAttr = /\bupdated="([^"]+)"/i.exec(attributes)?.[1] ?? null;
    entries.push({
      ianaId,
      name: name.slice(0, 200),
      country: null,
      website: null,
      contact: null,
      status: normalizeStatus(xmlTag(body, 'status')),
      rdapServer: xmlTag(body, 'server'),
      updated: updatedAttr,
      aliases: [],
      origin: 'iana',
    });
  }

  return {
    entries,
    updated: updatedMatch?.[1]?.trim() ?? null,
  };
}

/** 解析带引号与转义的 CSV */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"') {
        if (text[index + 1] === '"') {
          field += '"';
          index += 1;
        } else {
          quoted = false;
        }
      } else {
        field += char;
      }
      continue;
    }

    if (char === '"') {
      quoted = true;
    } else if (char === ',') {
      row.push(field);
      field = '';
    } else if (char === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (char !== '\r') {
      field += char;
    }
  }

  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/** 解析 ICANN 认证注册商 CSV，提供国家/地区、官网与公开联系方式 */
export function parseIcannCsv(text: string): RegistrarBase[] {
  const rows = parseCsv(text.replace(/^\uFEFF/, ''));
  if (rows.length === 0) return [];

  const header = (rows[0] ?? []).map((cell) => cell.trim().toLowerCase());
  const indexOf = (needle: string, fallback: number): number => {
    const found = header.findIndex((cell) => cell.includes(needle));
    return found === -1 ? fallback : found;
  };

  const nameIndex = indexOf('registrar name', 0);
  const ianaIndex = indexOf('iana number', 1);
  const countryIndex = indexOf('country', 2);
  const contactIndex = indexOf('public contact', 3);
  const linkIndex = indexOf('link', 4);

  const entries: RegistrarBase[] = [];
  for (let index = 1; index < rows.length; index += 1) {
    const row = rows[index] ?? [];
    const name = (row[nameIndex] ?? '').trim();
    const ianaId = (row[ianaIndex] ?? '').trim();
    if (!name || !/^\d+$/.test(ianaId)) continue;

    const country = (row[countryIndex] ?? '').trim();
    const contact = (row[contactIndex] ?? '').trim();
    entries.push({
      ianaId,
      name: name.slice(0, 200),
      country: country && country.toLowerCase() !== 'not available' ? country : null,
      website: normalizeWebsite(row[linkIndex] ?? null),
      contact: contact || null,
      status: 'accredited',
      rdapServer: null,
      updated: null,
      aliases: [],
      origin: 'icann',
    });
  }
  return entries;
}

function curatedToBase(record: RegistrarRecord): RegistrarBase {
  return {
    ianaId: record.ianaId,
    name: record.name,
    country: record.country,
    website: record.website,
    contact: null,
    status: 'accredited',
    rdapServer: null,
    updated: null,
    aliases: record.aliases ? [...record.aliases] : [],
    origin: 'curated',
  };
}

/** 合并 IANA（状态/RDAP）与 ICANN（国家/官网/联系方式）数据，并补充精选别名 */
export function mergeRegistrars(
  iana: RegistrarBase[],
  icann: RegistrarBase[],
  curated: RegistrarRecord[] = CURATED,
): RegistrarBase[] {
  const byId = new Map<string, RegistrarBase>();

  for (const entry of iana) {
    if (!entry.ianaId) continue;
    byId.set(entry.ianaId, { ...entry, aliases: [...entry.aliases] });
  }

  for (const entry of icann) {
    if (!entry.ianaId) continue;
    const existing = byId.get(entry.ianaId);
    if (!existing) {
      byId.set(entry.ianaId, { ...entry, aliases: [...entry.aliases] });
      continue;
    }
    existing.country = existing.country ?? entry.country;
    existing.website = existing.website ?? entry.website;
    existing.contact = existing.contact ?? entry.contact;
    if (existing.status === 'unknown') existing.status = 'accredited';
    existing.origin = 'iana+icann';
  }

  for (const record of curated) {
    if (!record.ianaId) continue;
    const existing = byId.get(record.ianaId);
    if (!existing) {
      byId.set(record.ianaId, curatedToBase(record));
      continue;
    }
    existing.website = existing.website ?? record.website;
    existing.country = existing.country ?? record.country;
    for (const alias of record.aliases ?? []) {
      if (!existing.aliases.includes(alias)) existing.aliases.push(alias);
    }
  }

  return [...byId.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export function registrarNote(syncedAt: string | null): string {
  const sync = syncedAt ? `最近同步 ${syncedAt.slice(0, 10)}` : '等待首次同步';
  return `注册商目录来自 IANA Registrar IDs 与 ICANN 认证注册商列表（${sync}）；域名数量统计仅来自本站本地索引，不代表注册商真实业务规模。`;
}

function isRegistrarBase(value: unknown): value is RegistrarBase {
  const item = value as Partial<RegistrarBase> | null;
  return Boolean(
    item &&
      typeof item.name === 'string' &&
      (item.ianaId === null || typeof item.ianaId === 'string') &&
      typeof item.status === 'string' &&
      STATUS_VALUES.includes(item.status as RegistrarStatus),
  );
}

/** 注册商目录：本地快照 + 定时同步 IANA / ICANN */
export class RegistrarRegistry {
  private entries: RegistrarBase[] = CURATED.map(curatedToBase);
  private syncedAt: string | null = null;
  private ianaUpdated: string | null = null;
  private sources: RegistrarSnapshot['sources'] = { iana: 'failed', icann: 'failed' };
  private lastError: string | null = null;
  private refreshing: Promise<void> | null = null;
  private loaded = false;
  private timer: NodeJS.Timeout | null = null;

  constructor(private readonly filePath: string = config.registrars.dataFile || DEFAULT_DATA_FILE) {}

  async init(): Promise<void> {
    if (this.loaded) return;

    try {
      const text = await readFile(this.filePath, 'utf8');
      const snapshot = JSON.parse(text) as Partial<RegistrarSnapshot>;
      if (snapshot && snapshot.version === 1 && Array.isArray(snapshot.entries)) {
        const entries = snapshot.entries.filter(isRegistrarBase);
        if (entries.length > 0) {
          this.entries = entries;
          this.syncedAt = typeof snapshot.syncedAt === 'string' ? snapshot.syncedAt : null;
          this.ianaUpdated = typeof snapshot.ianaUpdated === 'string' ? snapshot.ianaUpdated : null;
          if (snapshot.sources) this.sources = snapshot.sources;
        }
      }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT') {
        console.error('[registrars] 读取注册商快照失败，使用内置精选目录:', error);
      }
    }

    this.loaded = true;
    this.schedule();
    void this.refreshIfStale();
  }

  /** 首次启动（快照不存在或过期）时后台同步，不阻塞服务启动 */
  private async refreshIfStale(): Promise<void> {
    if (this.syncedAt) {
      const age = Date.now() - Date.parse(this.syncedAt);
      if (Number.isFinite(age) && age < config.registrars.syncTtlMs) return;
    }
    try {
      await this.refresh();
    } catch (error) {
      this.lastError = error instanceof Error ? error.message : String(error);
    }
  }

  private schedule(): void {
    if (this.timer) return;
    const interval = Math.max(10 * 60 * 1000, Math.min(config.registrars.syncTtlMs, 6 * 60 * 60 * 1000));
    this.timer = setInterval(() => {
      void this.refreshIfStale();
    }, interval);
    this.timer.unref();
  }

  /** 手动或定时同步；重复调用会复用同一个任务 */
  async refresh(): Promise<void> {
    if (this.refreshing) return this.refreshing;

    this.refreshing = (async () => {
      const task = async (url: string, accept: string) =>
        httpGet(url, {
          timeoutMs: config.registrars.timeoutMs,
          headers: { accept },
          maxBytes: 8 * 1024 * 1024,
        });

      const [ianaResult, icannResult] = await Promise.allSettled([
        task(IANA_REGISTRAR_URL, 'application/xml, text/xml, */*'),
        task(ICANN_REGISTRAR_CSV_URL, 'text/csv, text/plain, */*'),
      ]);

      let iana: RegistrarBase[] = [];
      let ianaUpdated: string | null = null;
      let icann: RegistrarBase[] = [];
      let ianaOk = false;
      let icannOk = false;

      if (ianaResult.status === 'fulfilled' && ianaResult.value.status === 200) {
        const parsed = parseIanaXml(ianaResult.value.text);
        if (parsed.entries.length >= 100) {
          iana = parsed.entries;
          ianaUpdated = parsed.updated;
          ianaOk = true;
        }
      }
      if (icannResult.status === 'fulfilled' && icannResult.value.status === 200) {
        icann = parseIcannCsv(icannResult.value.text);
        if (icann.length >= 100) {
          icannOk = true;
        } else {
          icann = [];
        }
      }

      if (!ianaOk && !icannOk) {
        this.sources = { iana: 'failed', icann: 'failed' };
        this.lastError = 'IANA 与 ICANN 注册商数据同步均失败';
        return;
      }

      // 单一来源失败时，用已有条目补齐，避免目录数量骤降
      if (!ianaOk) {
        iana = this.entries
          .filter((entry) => entry.ianaId && entry.status !== 'unknown')
          .map((entry) => ({ ...entry, origin: 'iana' }));
      }
      if (!icannOk) {
        icann = this.entries
          .filter((entry) => entry.ianaId && (entry.country || entry.website || entry.contact))
          .map((entry) => ({ ...entry, origin: 'icann' }));
      }

      this.entries = mergeRegistrars(iana, icann);
      this.syncedAt = new Date().toISOString();
      this.ianaUpdated = ianaUpdated ?? this.ianaUpdated;
      this.sources = {
        iana: ianaOk ? 'ok' : 'failed',
        icann: icannOk ? 'ok' : 'failed',
      };
      this.lastError = null;
      await this.save();
    })();

    try {
      await this.refreshing;
    } finally {
      this.refreshing = null;
    }
  }

  private async save(): Promise<void> {
    const snapshot: RegistrarSnapshot = {
      version: 1,
      syncedAt: this.syncedAt,
      ianaUpdated: this.ianaUpdated,
      sources: this.sources,
      lastError: this.lastError,
      entries: this.entries,
    };
    const target = this.filePath;
    const temp = `${target}.tmp`;
    await mkdir(dirname(target), { recursive: true });
    await writeFile(temp, JSON.stringify(snapshot), { encoding: 'utf8', mode: 0o644 });
    await rename(temp, target);
  }

  get size(): number {
    return this.entries.length;
  }

  all(): RegistrarBase[] {
    return this.entries;
  }

  status(): {
    total: number;
    syncedAt: string | null;
    ianaUpdated: string | null;
    sources: RegistrarSnapshot['sources'];
    refreshing: boolean;
    lastError: string | null;
  } {
    return {
      total: this.entries.length,
      syncedAt: this.syncedAt,
      ianaUpdated: this.ianaUpdated,
      sources: this.sources,
      refreshing: Boolean(this.refreshing),
      lastError: this.lastError,
    };
  }

  stats(): { total: number; accredited: number; countries: number } {
    const countries = new Set<string>();
    let accredited = 0;
    for (const entry of this.entries) {
      if (entry.status === 'accredited') accredited += 1;
      if (entry.country) countries.add(entry.country);
    }
    return { total: this.entries.length, accredited, countries: countries.size };
  }

  find(idOrName: string): RegistrarBase | null {
    const value = idOrName.trim().toLowerCase();
    if (!value) return null;

    return (
      this.entries.find((entry) => entry.ianaId === value) ??
      this.entries.find((entry) => entry.name.toLowerCase() === value) ??
      this.entries.find((entry) =>
        entry.aliases.some((alias) => alias.toLowerCase() === value),
      ) ??
      null
    );
  }

  search(query: string): RegistrarBase[] {
    const value = query.trim().toLowerCase();
    if (!value) return this.entries;
    return this.entries.filter((entry) =>
      [entry.name, entry.ianaId, entry.country, entry.website, ...entry.aliases]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
        .includes(value),
    );
  }
}

export const registrarRegistry = new RegistrarRegistry();
