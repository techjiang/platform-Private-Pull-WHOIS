import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from '../config.js';
import type { WhoisData } from '../whois/types.js';

export interface IndexEntry {
  domain: string;
  registrar: string | null;
  registrarIanaId: string | null;
  nameservers: string[];
  firstSeen: string;
  lastSeen: string;
}

export interface RegistrarUsage {
  key: string;
  ianaId: string | null;
  name: string;
  count: number;
  lastSeen: string | null;
}

interface IndexState {
  version: 1;
  domains: Record<string, IndexEntry>;
}

const DEFAULT_FILE = fileURLToPath(new URL('../../data/index.json', import.meta.url));

export const INDEX_NOTE =
  '本地索引仅包含本站成功查询过的域名，不构成全网注册商或名称服务器数据；可接入外部数据源扩展。';

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.+$/, '');
}

/** 有界的 domain → 注册商 / DNS 索引，支撑名称服务器反查与注册商统计 */
export class DomainIndex {
  private state: IndexState = { version: 1, domains: {} };
  private loaded = false;
  private saveTimer: NodeJS.Timeout | null = null;
  private saveChain: Promise<void> = Promise.resolve();

  constructor(private readonly filePath: string = DEFAULT_FILE) {}

  async init(): Promise<void> {
    if (this.loaded) return;
    try {
      const text = await readFile(this.filePath, 'utf8');
      const parsed = JSON.parse(text) as Partial<IndexState>;
      if (parsed && parsed.version === 1 && parsed.domains && typeof parsed.domains === 'object') {
        const domains: Record<string, IndexEntry> = {};
        for (const [domain, entry] of Object.entries(parsed.domains)) {
          if (!entry || typeof entry !== 'object') continue;
          if (typeof entry.domain !== 'string') continue;
          domains[domain] = {
            domain: entry.domain,
            registrar: typeof entry.registrar === 'string' ? entry.registrar : null,
            registrarIanaId:
              typeof entry.registrarIanaId === 'string' ? entry.registrarIanaId : null,
            nameservers: Array.isArray(entry.nameservers)
              ? entry.nameservers.filter((item): item is string => typeof item === 'string')
              : [],
            firstSeen: typeof entry.firstSeen === 'string' ? entry.firstSeen : '',
            lastSeen: typeof entry.lastSeen === 'string' ? entry.lastSeen : '',
          };
        }
        this.state = { version: 1, domains };
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        console.error('[index] 读取索引失败:', error);
      }
    }
    this.loaded = true;
  }

  get domainCount(): number {
    return Object.keys(this.state.domains).length;
  }

  record(data: WhoisData): void {
    if (!data?.domain || data.available) return;
    const now = new Date().toISOString();
    const existing = this.state.domains[data.domain];

    this.state.domains[data.domain] = {
      domain: data.domain,
      registrar: data.registrar?.name ?? existing?.registrar ?? null,
      registrarIanaId: data.registrar?.ianaId ?? existing?.registrarIanaId ?? null,
      nameservers: [...data.nameservers],
      firstSeen: existing?.firstSeen || now,
      lastSeen: now,
    };

    const total = Object.keys(this.state.domains).length;
    if (total > config.index.maxDomains) {
      const oldest = Object.values(this.state.domains)
        .sort((a, b) => a.lastSeen.localeCompare(b.lastSeen))
        .slice(0, total - config.index.maxDomains);
      for (const entry of oldest) delete this.state.domains[entry.domain];
    }

    this.scheduleSave();
  }

  reverseNameserver(
    host: string,
    limit = 100,
    offset = 0,
  ): { host: string; total: number; domains: IndexEntry[]; note: string } {
    const target = normalizeHost(host);
    const matches = Object.values(this.state.domains)
      .filter((entry) => entry.nameservers.some((server) => normalizeHost(server) === target))
      .sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));

    return {
      host: target,
      total: matches.length,
      domains: matches.slice(offset, offset + limit),
      note: INDEX_NOTE,
    };
  }

  registrarUsage(): RegistrarUsage[] {
    const usage = new Map<string, RegistrarUsage>();

    for (const entry of Object.values(this.state.domains)) {
      if (!entry.registrar) continue;
      const key = entry.registrarIanaId
        ? `iana:${entry.registrarIanaId}`
        : `name:${entry.registrar.toLowerCase()}`;
      const existing = usage.get(key);
      if (existing) {
        existing.count += 1;
        if (entry.lastSeen > (existing.lastSeen ?? '')) existing.lastSeen = entry.lastSeen;
      } else {
        usage.set(key, {
          key,
          ianaId: entry.registrarIanaId,
          name: entry.registrar,
          count: 1,
          lastSeen: entry.lastSeen,
        });
      }
    }

    return [...usage.values()].sort((a, b) => b.count - a.count);
  }

  registrarDomains(
    match: { ianaId?: string | null; name?: string | null },
    limit = 100,
    offset = 0,
  ): { total: number; domains: IndexEntry[] } {
    const iana = match.ianaId?.trim();
    const name = match.name?.trim().toLowerCase();

    const matches = Object.values(this.state.domains)
      .filter((entry) => {
        if (iana && entry.registrarIanaId === iana) return true;
        if (name && entry.registrar?.toLowerCase() === name) return true;
        return false;
      })
      .sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));

    return { total: matches.length, domains: matches.slice(offset, offset + limit) };
  }

  stats(): { domainCount: number; registrarCount: number; nameserverCount: number; maxDomains: number } {
    const registrars = new Set<string>();
    const nameservers = new Set<string>();
    for (const entry of Object.values(this.state.domains)) {
      if (entry.registrar) registrars.add(entry.registrar.toLowerCase());
      for (const server of entry.nameservers) nameservers.add(normalizeHost(server));
    }
    return {
      domainCount: this.domainCount,
      registrarCount: registrars.size,
      nameserverCount: nameservers.size,
      maxDomains: config.index.maxDomains,
    };
  }

  async clear(): Promise<void> {
    this.state = { version: 1, domains: {} };
    await this.saveNow();
  }

  async flush(): Promise<void> {
    if (this.saveTimer) {
      clearTimeout(this.saveTimer);
      this.saveTimer = null;
      await this.saveNow();
    } else {
      await this.saveChain;
    }
  }

  private scheduleSave(): void {
    if (this.saveTimer) return;
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null;
      void this.saveNow().catch((error) => console.error('[index] 保存失败:', error));
    }, 4000);
    this.saveTimer.unref();
  }

  private async saveNow(): Promise<void> {
    const payload = JSON.stringify(this.state);
    const target = this.filePath;

    this.saveChain = this.saveChain.then(async () => {
      await mkdir(dirname(target), { recursive: true });
      const temp = `${target}.tmp`;
      await writeFile(temp, payload, { encoding: 'utf8', mode: 0o600 });
      await rename(temp, target);
    });

    await this.saveChain;
  }
}

export const domainIndex = new DomainIndex(config.index.dataFile || undefined);
