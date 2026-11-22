import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from '../config.js';
import { TtlCache } from '../lib/cache.js';
import { ApiError } from '../lib/errors.js';

/**
 * ICP 备案查询
 *
 * 数据流：内存缓存 → 本地持久化缓存 → 公开备案数据（实时库优先，离线库兜底）。
 * 本地缓存保存最近 30 天的成功结果，7 天内可直接返回；只有本地未命中
 * 或显式 refresh 时才会回源，因此回源接口只承担补充角色。
 *
 * 公共账号存在调用间隔限制，因此进程内做全局冷却 + TTL 缓存；
 * 配置 ICP_API_ID / ICP_API_KEY 后冷却自动关闭（付费账号频率更高）。
 * 所有结果均来自回源原始字段，不做任何推测补全。
 */

export type IcpSource = 'icp-realtime' | 'icp-offline';

export interface IcpResult {
  domain: string;
  /** 是否查询到 ICP 备案记录 */
  filed: boolean;
  /** 网站备案号，例如 粤B2-20090059-5 */
  icpCode: string | null;
  /** 主体备案号，例如 粤B2-20090059 */
  subjectCode: string | null;
  /** 主办单位名称 */
  unitName: string | null;
  /** 主办单位性质，例如 企业 / 个人 */
  unitType: string | null;
  /** 审核时间 */
  auditDate: string | null;
  /** 上游缓存/更新时间 */
  updatedAt: string | null;
  source: IcpSource;
  /** 是否为上游不可用时展示的历史缓存 */
  stale: boolean;
  note: string;
}

export type IcpParseOutcome =
  | { kind: 'ok'; result: IcpResult }
  | { kind: 'not_filed'; result: IcpResult }
  | { kind: 'rate_limited'; message: string; retryAfterSec: number }
  | { kind: 'error'; message: string };

type IcpRateLimited = Extract<IcpParseOutcome, { kind: 'rate_limited' }>;

const REALTIME_URL = 'https://cn.apihz.cn/api/wangzhan/syicpgx.php';
const OFFLINE_URL = 'https://cn.apihz.cn/api/wangzhan/icp.php';

export const ICP_NOTE =
  '备案结果由本站缓存并提供，仅在本地缓存未命中或显式刷新时回源公开备案数据；最终以工信部备案系统（beian.miit.gov.cn）为准。';

const PUBLIC_ID = '88888888';
const PUBLIC_KEY = '88888888';
const usingPublicAccount =
  config.icp.apiId === PUBLIC_ID && config.icp.apiKey === PUBLIC_KEY;

function clean(value: unknown): string | null {
  if (typeof value !== 'string' && typeof value !== 'number') return null;
  const text = String(value).trim();
  if (!text) return null;
  if (/^(null|undefined|无|暂无|未备案|-+)$/i.test(text)) return null;
  return text;
}

function isFiledCode(value: string | null): boolean {
  return Boolean(value && /\d/.test(value));
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
}

function buildResult(
  domain: string,
  source: IcpSource,
  fields: {
    icpCode: unknown;
    subjectCode: unknown;
    unitName: unknown;
    unitType: unknown;
    auditDate: unknown;
    updatedAt: unknown;
  },
): IcpResult {
  const icpCode = clean(fields.icpCode);
  const subjectCode = clean(fields.subjectCode);
  const filed = isFiledCode(icpCode) || isFiledCode(subjectCode);

  return {
    domain,
    filed,
    icpCode: filed ? icpCode : null,
    subjectCode: filed ? subjectCode : null,
    unitName: filed ? clean(fields.unitName) : null,
    unitType: filed ? clean(fields.unitType) : null,
    auditDate: filed ? clean(fields.auditDate) : null,
    updatedAt: filed ? clean(fields.updatedAt) : null,
    source,
    stale: false,
    note: filed
      ? ICP_NOTE
      : '未查询到该域名的 ICP 备案记录。境外域名或未备案域名通常没有记录；' + ICP_NOTE,
  };
}

function rateLimitFromMessage(message: string): IcpParseOutcome {
  const seconds = /(\d+)\s*秒/.exec(message);
  return {
    kind: 'rate_limited',
    message: '备案数据源公共配额受限，请稍后重试',
    retryAfterSec: seconds?.[1] ? Math.min(120, Math.max(1, Number(seconds[1]))) : 15,
  };
}

/**
 * 仅当上游明确表达“没有备案记录”时才判定为未备案。
 * 必须与“查询失败 / 参数错误 / 请求异常”等故障信息区分开，
 * 否则会把上游故障误报成“未备案”。
 */
function notFiledMessage(message: string): boolean {
  return /没有备案|未备案|无备案|无记录|未查询到|不存在备案|没有记录/.test(message);
}

/** 解析 apihz 实时库返回 */
export function parseRealtimeIcp(domain: string, payload: unknown): IcpParseOutcome {
  const body = asRecord(payload);
  const code = Number(body.code);

  if (code !== 200) {
    const message = clean(body.msg) ?? '备案接口返回异常';
    if (/15\s*秒|频率|限制|资源池|会员|收费/.test(message)) return rateLimitFromMessage(message);
    if (notFiledMessage(message)) {
      return { kind: 'not_filed', result: buildResult(domain, 'icp-realtime', {
        icpCode: null,
        subjectCode: null,
        unitName: null,
        unitType: null,
        auditDate: null,
        updatedAt: null,
      }) };
    }
    return { kind: 'error', message };
  }

  const result = buildResult(domain, 'icp-realtime', {
    icpCode: body.icpw,
    subjectCode: body.icp,
    unitName: body.mainname,
    unitType: body.maintype,
    auditDate: body.uptime,
    updatedAt: body.hctime,
  });

  return { kind: result.filed ? 'ok' : 'not_filed', result };
}

/** 解析 apihz 离线库返回 */
export function parseOfflineIcp(domain: string, payload: unknown): IcpParseOutcome {
  const body = asRecord(payload);
  const code = Number(body.code);
  const message = clean(body.msg) ?? '备案接口返回异常';

  if (code !== 200) {
    if (/15\s*秒|频率|限制|资源池|会员|收费/.test(message)) return rateLimitFromMessage(message);
    if (notFiledMessage(message)) {
      return { kind: 'not_filed', result: buildResult(domain, 'icp-offline', {
        icpCode: null,
        subjectCode: null,
        unitName: null,
        unitType: null,
        auditDate: null,
        updatedAt: null,
      }) };
    }
    return { kind: 'error', message };
  }

  const result = buildResult(domain, 'icp-offline', {
    icpCode: body.icp,
    subjectCode: body.icp,
    unitName: body.unit,
    unitType: body.type,
    auditDate: body.time,
    updatedAt: body.time,
  });

  return { kind: result.filed ? 'ok' : 'not_filed', result };
}

const cache = new TtlCache<IcpResult>(config.icp.maxEntries);
const inflight = new Map<string, Promise<IcpResult>>();
let lastRealtimeAt = 0;

/* ---------- 本地持久化缓存（回源接口只做补充） ---------- */

interface LocalEntry {
  result: IcpResult;
  savedAt: number;
}

interface LocalState {
  version: 1;
  entries: Record<string, LocalEntry>;
}

const DEFAULT_DATA_FILE = fileURLToPath(new URL('../../data/icp.json', import.meta.url));
const dataFile = config.icp.dataFile || DEFAULT_DATA_FILE;

let localState: LocalState | null = null;
let loadPromise: Promise<void> | null = null;
let saveTimer: NodeJS.Timeout | null = null;
let saveChain: Promise<void> = Promise.resolve();

async function loadLocal(): Promise<void> {
  if (localState) return;
  if (loadPromise) return loadPromise;
  loadPromise = (async () => {
    const state: LocalState = { version: 1, entries: {} };
    try {
      const raw = await readFile(dataFile, 'utf8');
      const parsed = JSON.parse(raw) as Partial<LocalState>;
      if (parsed && parsed.version === 1 && parsed.entries && typeof parsed.entries === 'object') {
        const now = Date.now();
        for (const [domain, value] of Object.entries(parsed.entries)) {
          if (!value || typeof value !== 'object') continue;
          const savedAt = Number((value as LocalEntry).savedAt);
          const result = (value as LocalEntry).result;
          if (!Number.isFinite(savedAt) || now - savedAt > config.icp.localMaxAgeMs) continue;
          if (!result || typeof result.domain !== 'string') continue;
          state.entries[domain] = { result, savedAt };
        }
      }
    } catch {
      /* 文件不存在或损坏时从空缓存开始 */
    }
    localState = state;
  })();
  return loadPromise;
}

function readLocal(domain: string, maxAgeMs: number): LocalEntry | null {
  const entry = localState?.entries[domain];
  if (!entry) return null;
  if (Date.now() - entry.savedAt > maxAgeMs) return null;
  return entry;
}

function saveLocalSoon(): void {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    void flushLocal();
  }, 1500);
  saveTimer.unref?.();
}

function flushLocal(): Promise<void> {
  saveChain = saveChain
    .then(async () => {
      if (!localState) return;
      const payload = JSON.stringify(localState);
      await mkdir(dirname(dataFile), { recursive: true });
      const tmpFile = `${dataFile}.tmp`;
      await writeFile(tmpFile, payload, { encoding: 'utf8', mode: 0o600 });
      await rename(tmpFile, dataFile);
    })
    .catch(() => {
      /* 落盘失败不影响查询结果 */
    });
  return saveChain;
}

function writeLocal(domain: string, result: IcpResult): void {
  if (!localState) return;
  const now = Date.now();
  localState.entries[domain] = { result, savedAt: now };

  const entries = localState.entries;
  for (const key of Object.keys(entries)) {
    const entry = entries[key];
    if (!entry || now - entry.savedAt > config.icp.localMaxAgeMs) delete entries[key];
  }

  const keys = Object.keys(entries);
  if (keys.length > config.icp.maxEntries) {
    keys.sort((a, b) => (entries[a]?.savedAt ?? 0) - (entries[b]?.savedAt ?? 0));
    for (const key of keys.slice(0, keys.length - config.icp.maxEntries)) delete entries[key];
  }

  saveLocalSoon();
}

function remember(domain: string, result: IcpResult, ttlMs: number): IcpResult {
  cache.set(domain, result, ttlMs);
  writeLocal(domain, result);
  return result;
}

function buildUrl(base: string, domain: string): string {
  const url = new URL(base);
  url.searchParams.set('id', config.icp.apiId);
  url.searchParams.set('key', config.icp.apiKey);
  url.searchParams.set('domain', domain);
  return url.toString();
}

async function requestJson(url: string): Promise<unknown> {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(config.icp.timeoutMs),
    headers: {
      accept: 'application/json',
      'user-agent': 'PullWhois/1.0 (+https://pull-whois.asoe.cn)',
    },
  });
  const text = await response.text();
  if (!text.trim()) throw new Error('备案接口返回空响应');
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`备案接口返回非 JSON 数据（HTTP ${response.status}）`);
  }
}

interface AttemptNote {
  source: string;
  ok: boolean;
  error?: string;
}

/**
 * 查询域名备案信息：内存缓存 → 本地持久化缓存 → 实时库 → 离线库。
 * 只有本地缓存未命中或显式 refresh 时才会回源。
 * @throws ApiError 回源全部失败且无本地兜底，或公共账号冷却中
 */
export async function lookupIcp(
  domain: string,
  options: { refresh?: boolean } = {},
): Promise<{ result: IcpResult; cached: boolean; durationMs: number }> {
  await loadLocal();

  if (!options.refresh) {
    const hit = cache.get(domain);
    if (hit) return { result: hit.value, cached: true, durationMs: 0 };

    const local = readLocal(domain, config.icp.localTtlMs);
    if (local) {
      cache.set(
        domain,
        local.result,
        local.result.filed ? config.icp.cacheTtlMs : config.icp.missTtlMs,
      );
      return { result: local.result, cached: true, durationMs: 0 };
    }

    const pending = inflight.get(domain);
    if (pending) {
      return { result: await pending, cached: true, durationMs: 0 };
    }
  }

  const startedAt = Date.now();
  const task = (async (): Promise<IcpResult> => {
    const attempts: AttemptNote[] = [];
    let rateLimited: IcpRateLimited | null = null;
    /** 实时库明确返回“无记录”，需等离线库复核后才可作为最终结论 */
    let realtimeMiss: IcpResult | null = null;

    const cooldownLeft = Math.ceil(
      (config.icp.cooldownMs - (Date.now() - lastRealtimeAt)) / 1000,
    );
    if (!usingPublicAccount || cooldownLeft <= 0) {
      lastRealtimeAt = Date.now();
      try {
        const payload = await requestJson(buildUrl(REALTIME_URL, domain));
        const parsed = parseRealtimeIcp(domain, payload);
        if (parsed.kind === 'ok') {
          return remember(domain, parsed.result, config.icp.cacheTtlMs);
        }
        if (parsed.kind === 'not_filed') realtimeMiss = parsed.result;
        if (parsed.kind === 'rate_limited') {
          rateLimited = parsed;
        }
        attempts.push({
          source: 'icp-realtime',
          ok: false,
          error: parsed.kind === 'not_filed' ? '实时库未查询到记录' : parsed.message,
        });
      } catch (error) {
        attempts.push({
          source: 'icp-realtime',
          ok: false,
          error: error instanceof Error ? error.message : '请求失败',
        });
      }
    } else {
      attempts.push({
        source: 'icp-realtime',
        ok: false,
        error: `公共账号冷却中（${cooldownLeft} 秒）`,
      });
    }

    try {
      const payload = await requestJson(buildUrl(OFFLINE_URL, domain));
      const parsed = parseOfflineIcp(domain, payload);
      if (parsed.kind === 'ok') {
        // 离线库命中说明实时库可能漏报或数据延迟，直接采用命中结果
        return remember(domain, parsed.result, config.icp.cacheTtlMs / 2);
      }
      if (parsed.kind === 'not_filed') {
        if (realtimeMiss) {
          // 两个数据源都明确无记录，才给出未备案结论
          return remember(domain, parsed.result, config.icp.missTtlMs);
        }
        // 实时库不可用（冷却或限流）时仅离线库可用，结论需明确标注来源
        return remember(
          domain,
          { ...parsed.result, note: `${parsed.result.note}（本次仅离线库可用）` },
          config.icp.missTtlMs,
        );
      }
      if (parsed.kind === 'rate_limited') rateLimited = parsed;
      attempts.push({
        source: 'icp-offline',
        ok: false,
        error: parsed.message,
      });
    } catch (error) {
      attempts.push({
        source: 'icp-offline',
        ok: false,
        error: error instanceof Error ? error.message : '请求失败',
      });
    }

    if (realtimeMiss) {
      // 实时库明确无记录、离线库不可用：保留未备案结论并标注来源
      return remember(
        domain,
        { ...realtimeMiss, note: `${realtimeMiss.note}（本次仅实时库可用）` },
        config.icp.missTtlMs,
      );
    }

    const local = readLocal(domain, config.icp.localMaxAgeMs);
    if (local) {
      const fallback: IcpResult = {
        ...local.result,
        stale: true,
        note: `${local.result.note}（回源暂不可用，展示本地缓存结果）`,
      };
      // 短暂缓存兜底结果，避免持续冲击回源接口
      cache.set(domain, fallback, Math.min(config.icp.missTtlMs, 5 * 60 * 1000));
      return fallback;
    }

    if (rateLimited) {
      throw new ApiError(429, 'RATE_LIMITED', rateLimited.message, {
        retryAfterSec: rateLimited.retryAfterSec,
        source: 'icp',
        attempts,
      });
    }

    throw ApiError.upstream('备案数据源暂时不可用，请稍后重试', { source: 'icp', attempts });
  })();

  inflight.set(domain, task);
  try {
    const result = await task;
    return { result, cached: false, durationMs: Date.now() - startedAt };
  } finally {
    if (inflight.get(domain) === task) inflight.delete(domain);
  }
}

/** 清理本地持久化缓存中超过保留期的记录（供后台调度使用） */
export async function pruneIcpLocalCache(): Promise<{ removed: number; remaining: number }> {
  await loadLocal();
  if (!localState) return { removed: 0, remaining: 0 };
  const now = Date.now();
  let removed = 0;
  for (const [key, entry] of Object.entries(localState.entries)) {
    if (!entry || now - entry.savedAt > config.icp.localMaxAgeMs) {
      delete localState.entries[key];
      removed += 1;
    }
  }
  if (removed > 0) await flushLocal();
  return { removed, remaining: Object.keys(localState.entries).length };
}

export function clearIcpCache(): void {
  cache.clear();
  inflight.clear();
  if (localState) {
    localState.entries = {};
    void flushLocal();
  }
}

export function icpCacheSize(): number {
  return cache.size + (localState ? Object.keys(localState.entries).length : 0);
}
