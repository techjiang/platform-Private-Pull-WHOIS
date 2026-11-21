import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from '../config.js';
import type { WhoisData } from '../whois/types.js';

export interface HistorySnapshot {
  at: string;
  available: boolean;
  registrar: string | null;
  registrarIanaId: string | null;
  registrantName: string | null;
  registrantOrg: string | null;
  registrantCountry: string | null;
  nameservers: string[];
  statuses: string[];
  created: string | null;
  updated: string | null;
  expires: string | null;
}

export interface HistoryChange {
  at: string;
  field: string;
  label: string;
  from: unknown;
  to: unknown;
}

export interface DomainHistory {
  domain: string;
  snapshots: HistorySnapshot[];
  changes: HistoryChange[];
  note: string;
}

interface HistoryState {
  version: 1;
  domains: Record<string, HistorySnapshot[]>;
}

const HISTORY_NOTE =
  '历史记录来自本站成功查询时保存的快照（自功能启用后开始积累），无法回溯 2007 年的全网历史；如需更早数据可接入第三方历史数据源。';

const DEFAULT_FILE = fileURLToPath(new URL('../../data/history.json', import.meta.url));

export function snapshotOf(data: WhoisData, at = new Date().toISOString()): HistorySnapshot {
  return {
    at,
    available: data.available,
    registrar: data.registrar?.name ?? null,
    registrarIanaId: data.registrar?.ianaId ?? null,
    registrantName: data.registrant?.name ?? null,
    registrantOrg: data.registrant?.organization ?? null,
    registrantCountry: data.registrant?.country ?? null,
    nameservers: [...data.nameservers].sort(),
    statuses: [...data.statuses].sort(),
    created: data.dates.created,
    updated: data.dates.updated,
    expires: data.dates.expires,
  };
}

function signature(snapshot: HistorySnapshot): string {
  return JSON.stringify([
    snapshot.available,
    snapshot.registrar,
    snapshot.registrarIanaId,
    snapshot.registrantName,
    snapshot.registrantOrg,
    snapshot.registrantCountry,
    snapshot.nameservers,
    snapshot.statuses,
    snapshot.created,
    snapshot.updated,
    snapshot.expires,
  ]);
}

const FIELDS: Array<{ field: string; label: string; value: (s: HistorySnapshot) => unknown }> = [
  { field: 'available', label: '可注册状态', value: (s) => s.available },
  { field: 'registrar', label: '注册商', value: (s) => s.registrar },
  { field: 'registrarIanaId', label: '注册商 IANA ID', value: (s) => s.registrarIanaId },
  { field: 'registrantName', label: '注册人姓名', value: (s) => s.registrantName },
  { field: 'registrantOrg', label: '注册人组织', value: (s) => s.registrantOrg },
  { field: 'registrantCountry', label: '注册人国家/地区', value: (s) => s.registrantCountry },
  { field: 'nameservers', label: 'DNS 服务器', value: (s) => s.nameservers },
  { field: 'statuses', label: '域名状态', value: (s) => s.statuses },
  { field: 'updated', label: '更新时间', value: (s) => s.updated },
  { field: 'expires', label: '到期时间', value: (s) => s.expires },
];

export function diffSnapshots(snapshots: HistorySnapshot[]): HistoryChange[] {
  const changes: HistoryChange[] = [];
  for (let index = 1; index < snapshots.length; index += 1) {
    const previous = snapshots[index - 1] as HistorySnapshot;
    const current = snapshots[index] as HistorySnapshot;
    for (const { field, label, value } of FIELDS) {
      const before = value(previous);
      const after = value(current);
      if (JSON.stringify(before) === JSON.stringify(after)) continue;
      changes.unshift({
        at: current.at,
        field,
        label,
        from: before,
        to: after,
      });
    }
  }
  return changes.slice(0, 100);
}

/** 有界的域名快照历史，落盘为单个 JSON 文件 */
export class HistoryStore {
  private state: HistoryState = { version: 1, domains: {} };
  private loaded = false;
  private saveTimer: NodeJS.Timeout | null = null;
  private saveChain: Promise<void> = Promise.resolve();

  constructor(private readonly filePath: string = DEFAULT_FILE) {}

  async init(): Promise<void> {
    if (this.loaded) return;
    try {
      const text = await readFile(this.filePath, 'utf8');
      const parsed = JSON.parse(text) as Partial<HistoryState>;
      if (parsed && parsed.version === 1 && parsed.domains && typeof parsed.domains === 'object') {
        const domains: Record<string, HistorySnapshot[]> = {};
        for (const [domain, list] of Object.entries(parsed.domains)) {
          if (!Array.isArray(list)) continue;
          domains[domain] = list
            .filter((item): item is HistorySnapshot => Boolean(item && typeof item.at === 'string'))
            .slice(-config.history.maxSnapshots);
        }
        this.state = { version: 1, domains };
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        console.error('[history] 读取历史数据失败:', error);
      }
    }
    this.loaded = true;
  }

  get domainCount(): number {
    return Object.keys(this.state.domains).length;
  }

  get snapshotCount(): number {
    return Object.values(this.state.domains).reduce((sum, list) => sum + list.length, 0);
  }

  record(data: WhoisData): void {
    if (!data?.domain) return;
    const domain = data.domain;
    const list = this.state.domains[domain] ?? [];
    const snapshot = snapshotOf(data);
    const last = list[list.length - 1];

    if (last) {
      const sig = signature(last);
      if (sig === signature(snapshot)) return;

      const elapsed = Date.now() - new Date(last.at).getTime();
      const significant = last.available !== snapshot.available
        || last.registrar !== snapshot.registrar
        || JSON.stringify(last.nameservers) !== JSON.stringify(snapshot.nameservers);
      if (!significant && elapsed < config.history.minIntervalMs) return;
    }

    list.push(snapshot);
    if (list.length > config.history.maxSnapshots) {
      list.splice(0, list.length - config.history.maxSnapshots);
    }
    this.state.domains[domain] = list;

    const domains = Object.keys(this.state.domains);
    if (domains.length > config.history.maxDomains) {
      const oldest = domains
        .map((key) => {
          const snapshots = this.state.domains[key] ?? [];
          return { key, at: snapshots[snapshots.length - 1]?.at ?? '' };
        })
        .sort((a, b) => a.at.localeCompare(b.at))
        .slice(0, domains.length - config.history.maxDomains);
      for (const item of oldest) delete this.state.domains[item.key];
    }

    this.scheduleSave();
  }

  get(domain: string): DomainHistory {
    const snapshots = this.state.domains[domain] ?? [];
    return {
      domain,
      snapshots,
      changes: diffSnapshots(snapshots),
      note: HISTORY_NOTE,
    };
  }

  stats(): { domainCount: number; snapshotCount: number; maxDomains: number; maxSnapshots: number } {
    return {
      domainCount: this.domainCount,
      snapshotCount: this.snapshotCount,
      maxDomains: config.history.maxDomains,
      maxSnapshots: config.history.maxSnapshots,
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
      void this.saveNow().catch((error) => console.error('[history] 保存失败:', error));
    }, 3000);
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

export const historyStore = new HistoryStore(config.history.dataFile || undefined);
