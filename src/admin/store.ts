import {
  createHash,
  randomBytes,
  randomUUID,
  scrypt as scryptCallback,
  timingSafeEqual,
  type ScryptOptions,
} from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_FEATURES,
  FEATURE_KEYS,
  isFeatureKey,
  type FeatureFlags,
  type FeatureKey,
} from '../lib/features.js';
import { DEFAULT_WEB_POLICY, type WebPolicy } from '../lib/webguard.js';
import {
  DEFAULT_SCHEDULER_POLICY,
  normalizeSchedulerPolicy,
  type SchedulerPolicy,
} from '../lib/scheduler.js';
import { matchIpRule, normalizeIpRule } from '../lib/netmatch.js';

export interface ManagedKey {
  id: string;
  name: string;
  /** 密钥前缀，仅用于界面识别 */
  prefix: string;
  /** SHA-256 摘要，不保存明文密钥 */
  hash: string;
  createdAt: string;
  lastUsedAt: string | null;
  /** 最近一次调用来源 IP，用于风控审计 */
  lastUsedIp: string | null;
  requestCount: number;
  enabled: boolean;
  /** 过期时间（ISO 8601），null 表示永久有效 */
  expiresAt: string | null;
  /** 总调用配额，null 表示不限 */
  quota: number | null;
  /** 每分钟限速，null 表示使用全局 Key 速率 */
  rateLimit: number | null;
  /** 允许访问的功能；null 表示全部功能 */
  scopes: FeatureKey[] | null;
  /** IP / CIDR 白名单，空数组表示不限制 */
  allowedIps: string[];
  note: string | null;
}

export type PublicKey = Omit<ManagedKey, 'hash'>;

export type KeyIssue =
  | 'KEY_DISABLED'
  | 'KEY_EXPIRED'
  | 'KEY_QUOTA_EXCEEDED'
  | 'KEY_SCOPE_DENIED'
  | 'KEY_IP_DENIED';

export interface KeyOptions {
  /** 有效天数，null / 省略表示永久 */
  expiresInDays?: number | null;
  quota?: number | null;
  rateLimit?: number | null;
  scopes?: FeatureKey[] | null;
  allowedIps?: string[];
  note?: string | null;
}

export interface KeyPatch extends KeyOptions {
  name?: string;
  enabled?: boolean;
}

export interface KeySummary {
  total: number;
  enabled: number;
  expired: number;
  exhausted: number;
  disabled: number;
}

/** scrypt 参数（内存硬 KDF，抗 GPU/ASIC 暴力破解） */
export interface PasswordHash {
  algo: 'scrypt';
  salt: string;
  hash: string;
  N: number;
  r: number;
  p: number;
  keylen: number;
}

interface AdminState {
  version: 6;
  username: string;
  password: PasswordHash | null;
  requireKey: boolean;
  webEnabled: boolean;
  webPolicy: WebPolicy;
  scheduler: SchedulerPolicy;
  features: FeatureFlags;
  keys: ManagedKey[];
}

export interface CreatedKey {
  record: ManagedKey;
  token: string;
}

export interface AdminStoreOptions {
  /** 首次启动（无数据文件）时是否要求 API Key */
  requireKey: boolean;
  /** 首次启动时是否允许网页端查询 */
  webEnabled?: boolean;
  /** 首次启动时写入的管理员账号 */
  username?: string;
  /** 首次启动时写入的管理员密码（仅用于生成摘要，不落盘明文） */
  password?: string;
}

const DEFAULT_DATA_FILE = fileURLToPath(new URL('../../data/admin.json', import.meta.url));
const SAVE_DEBOUNCE_MS = 3000;
const SCRYPT_PARAMS = { N: 32768, r: 8, p: 1, keylen: 32, saltBytes: 16 };
const SCRYPT_MAXMEM = 64 * 1024 * 1024;
const USERNAME_PATTERN = /^[A-Za-z0-9_.-]{3,32}$/;
const PASSWORD_MIN_LENGTH = 8;

function scryptAsync(
  password: string,
  salt: Buffer,
  keylen: number,
  options: ScryptOptions,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keylen, options, (error, derived) => {
      if (error) reject(error);
      else resolve(derived);
    });
  });
}

export function hashKey(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function toPublicKey(key: ManagedKey): PublicKey {
  const { hash: _hash, ...rest } = key;
  return rest;
}

async function derive(password: string, salt: Buffer, params: Omit<PasswordHash, 'algo' | 'salt' | 'hash'>): Promise<Buffer> {
  return scryptAsync(password, salt, params.keylen, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: SCRYPT_MAXMEM,
  });
}

export async function createPasswordHash(password: string): Promise<PasswordHash> {
  const salt = randomBytes(SCRYPT_PARAMS.saltBytes);
  const { N, r, p, keylen } = SCRYPT_PARAMS;
  const hash = await derive(password, salt, { N, r, p, keylen });
  return {
    algo: 'scrypt',
    salt: salt.toString('base64'),
    hash: hash.toString('base64'),
    N,
    r,
    p,
    keylen,
  };
}

export async function verifyPasswordHash(stored: PasswordHash, password: string): Promise<boolean> {
  const salt = Buffer.from(stored.salt, 'base64');
  const expected = Buffer.from(stored.hash, 'base64');
  const actual = await derive(password, salt, stored);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function safeEqualText(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/** 校验并归一化网页端访问策略，非法值回落到默认值 */
export function normalizeWebPolicy(raw: unknown): WebPolicy {
  const value = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const pick = (key: keyof WebPolicy, min: number, max: number): number => {
    const num = Number(value[key]);
    if (!Number.isFinite(num)) return DEFAULT_WEB_POLICY[key];
    return Math.min(max, Math.max(min, Math.trunc(num)));
  };
  return {
    rateLimit: pick('rateLimit', 0, 10_000),
    rateWindowSec: pick('rateWindowSec', 5, 86_400),
    dailyQuota: pick('dailyQuota', 0, 1_000_000),
    blockAfter: pick('blockAfter', 0, 1_000),
    blockSec: pick('blockSec', 0, 86_400),
  };
}

/** 可持久化的管理员凭据、API Key 与访问策略存储（单实例，JSON 文件） */
export class AdminStore {
  private state: AdminState = {
    version: 6,
    username: 'admin',
    password: null,
    requireKey: false,
    webEnabled: true,
    webPolicy: { ...DEFAULT_WEB_POLICY },
    scheduler: { ...DEFAULT_SCHEDULER_POLICY },
    features: { ...DEFAULT_FEATURES },
    keys: [],
  };
  private loaded = false;
  private saveTimer: NodeJS.Timeout | null = null;
  private saveChain: Promise<void> = Promise.resolve();

  constructor(
    private readonly filePath: string = DEFAULT_DATA_FILE,
    private readonly options: AdminStoreOptions = { requireKey: false },
  ) {}

  async init(): Promise<void> {
    if (this.loaded) return;

    let loaded = false;
    try {
      const text = await readFile(this.filePath, 'utf8');
      this.state = this.normalize(JSON.parse(text));
      loaded = true;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT') {
        console.error('[admin] 读取管理数据失败，使用默认配置:', error);
      }
    }

    if (!loaded) {
      this.state = {
        version: 6,
        username: normalizeUsername(this.options.username) || 'admin',
        password: null,
        requireKey: this.options.requireKey,
        webEnabled: this.options.webEnabled !== false,
        webPolicy: { ...DEFAULT_WEB_POLICY },
        scheduler: { ...DEFAULT_SCHEDULER_POLICY },
        features: { ...DEFAULT_FEATURES },
        keys: [],
      };
    }

    // 首次启动或数据文件中还没有管理员凭据时，使用环境变量初始化
    if (!this.state.password && this.options.password) {
      this.state.username = normalizeUsername(this.options.username) || this.state.username;
      this.state.password = await createPasswordHash(this.options.password);
      await this.saveNow();
    }

    this.loaded = true;
  }

  get requireKey(): boolean {
    return this.state.requireKey;
  }

  get webEnabled(): boolean {
    return this.state.webEnabled;
  }

  get webPolicy(): WebPolicy {
    return { ...this.state.webPolicy };
  }

  get schedulerPolicy(): SchedulerPolicy {
    return { ...this.state.scheduler };
  }

  get features(): FeatureFlags {
    return { ...this.state.features };
  }

  featureEnabled(feature: FeatureKey): boolean {
    return this.state.features[feature] !== false;
  }

  get username(): string {
    return this.state.username;
  }

  get hasCredentials(): boolean {
    return Boolean(this.state.password);
  }

  get keyCount(): number {
    return this.state.keys.length;
  }

  get activeKeyCount(): number {
    return this.state.keys.filter((key) => key.enabled).length;
  }

  keySummary(): KeySummary {
    const now = Date.now();
    let enabled = 0;
    let expired = 0;
    let exhausted = 0;
    let disabled = 0;
    for (const key of this.state.keys) {
      if (!key.enabled) disabled += 1;
      if (key.expiresAt && Date.parse(key.expiresAt) <= now) expired += 1;
      if (key.quota !== null && key.requestCount >= key.quota) exhausted += 1;
      if (key.enabled && !(key.expiresAt && Date.parse(key.expiresAt) <= now)) enabled += 1;
    }
    return { total: this.state.keys.length, enabled, expired, exhausted, disabled };
  }

  listKeys(): PublicKey[] {
    return this.state.keys.map(toPublicKey);
  }

  findById(id: string): PublicKey | null {
    const key = this.state.keys.find((item) => item.id === id);
    return key ? toPublicKey(key) : null;
  }

  /** 按明文密钥查找（包含停用/过期），用于精确风控提示 */
  findByToken(token: string): ManagedKey | null {
    if (!token || token.length > 256) return null;
    const hash = hashKey(token);
    return this.state.keys.find((item) => item.hash === hash) ?? null;
  }

  /** 校验明文密钥，停用或不存在时返回 null */
  verify(token: string): ManagedKey | null {
    const key = this.findByToken(token);
    return key && key.enabled ? key : null;
  }

  /** 评估密钥是否允许本次调用，返回具体风控原因 */
  evaluateKey(
    key: ManagedKey,
    tool: FeatureKey | null,
    ip: string,
  ): KeyIssue | null {
    if (!key.enabled) return 'KEY_DISABLED';
    if (key.expiresAt) {
      const expires = Date.parse(key.expiresAt);
      if (Number.isFinite(expires) && expires <= Date.now()) return 'KEY_EXPIRED';
    }
    if (key.quota !== null && key.requestCount >= key.quota) return 'KEY_QUOTA_EXCEEDED';
    if (tool && key.scopes && !key.scopes.includes(tool)) return 'KEY_SCOPE_DENIED';
    if (key.allowedIps.length > 0 && !key.allowedIps.some((rule) => matchIpRule(ip, rule))) {
      return 'KEY_IP_DENIED';
    }
    return null;
  }

  /** 校验管理员账号密码（恒定时间比较 + scrypt） */
  async verifyCredentials(username: string, password: string): Promise<boolean> {
    if (!this.state.password) return false;
    if (!safeEqualText(username, this.state.username)) return false;
    return verifyPasswordHash(this.state.password, password);
  }

  /** 更新管理员账号密码，重启后依然生效 */
  async setCredentials(username: string, password: string): Promise<void> {
    this.state.username = normalizeUsername(username);
    this.state.password = await createPasswordHash(password);
    await this.saveNow();
  }

  /** 记录使用情况（防抖写盘，避免每次请求都触发 IO） */
  touch(id: string, ip?: string): void {
    const key = this.state.keys.find((item) => item.id === id);
    if (!key) return;
    key.lastUsedAt = new Date().toISOString();
    key.requestCount += 1;
    if (ip) key.lastUsedIp = ip;
    this.scheduleSave();
  }

  async createKey(name?: string, options: KeyOptions = {}): Promise<CreatedKey> {
    const token = `pw_${randomBytes(24).toString('base64url')}`;
    const record: ManagedKey = {
      id: randomUUID(),
      name: normalizeName(name),
      prefix: token.slice(0, 10),
      hash: hashKey(token),
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
      lastUsedIp: null,
      requestCount: 0,
      enabled: true,
      expiresAt: expiresAtFromDays(options.expiresInDays),
      quota: normalizeQuota(options.quota),
      rateLimit: normalizeRate(options.rateLimit),
      scopes: normalizeScopes(options.scopes),
      allowedIps: normalizeIps(options.allowedIps),
      note: normalizeNote(options.note),
    };

    this.state.keys.unshift(record);
    await this.saveNow();
    return { record, token };
  }

  async updateKey(id: string, patch: KeyPatch): Promise<PublicKey | null> {
    const key = this.state.keys.find((item) => item.id === id);
    if (!key) return null;

    if (patch.name !== undefined) key.name = normalizeName(patch.name);
    if (patch.enabled !== undefined) key.enabled = patch.enabled;
    if (patch.expiresInDays !== undefined) {
      key.expiresAt = expiresAtFromDays(patch.expiresInDays);
    }
    if (patch.quota !== undefined) key.quota = normalizeQuota(patch.quota);
    if (patch.rateLimit !== undefined) key.rateLimit = normalizeRate(patch.rateLimit);
    if (patch.scopes !== undefined) key.scopes = normalizeScopes(patch.scopes);
    if (patch.allowedIps !== undefined) key.allowedIps = normalizeIps(patch.allowedIps);
    if (patch.note !== undefined) key.note = normalizeNote(patch.note);

    await this.saveNow();
    return toPublicKey(key);
  }

  /** 重置累计调用次数与最近使用记录，便于配额续期 */
  async resetKeyUsage(id: string): Promise<PublicKey | null> {
    const key = this.state.keys.find((item) => item.id === id);
    if (!key) return null;
    key.requestCount = 0;
    key.lastUsedAt = null;
    key.lastUsedIp = null;
    await this.saveNow();
    return toPublicKey(key);
  }

  async deleteKey(id: string): Promise<boolean> {
    const index = this.state.keys.findIndex((item) => item.id === id);
    if (index === -1) return false;

    this.state.keys.splice(index, 1);
    await this.saveNow();
    return true;
  }

  async setRequireKey(requireKey: boolean): Promise<void> {
    this.state.requireKey = requireKey;
    await this.saveNow();
  }

  async setWebEnabled(webEnabled: boolean): Promise<void> {
    this.state.webEnabled = webEnabled;
    await this.saveNow();
  }

  async setWebPolicy(patch: Partial<WebPolicy>): Promise<WebPolicy> {
    this.state.webPolicy = normalizeWebPolicy({ ...this.state.webPolicy, ...patch });
    await this.saveNow();
    return this.webPolicy;
  }

  async setSchedulerPolicy(patch: Partial<SchedulerPolicy>): Promise<SchedulerPolicy> {
    this.state.scheduler = normalizeSchedulerPolicy({ ...this.state.scheduler, ...patch });
    await this.saveNow();
    return this.schedulerPolicy;
  }

  async setFeatures(patch: Partial<FeatureFlags>): Promise<FeatureFlags> {
    for (const key of FEATURE_KEYS) {
      const value = patch[key];
      if (typeof value === 'boolean') this.state.features[key] = value;
    }
    await this.saveNow();
    return this.features;
  }

  /** 立即写入待保存的数据（优雅关闭时调用） */
  async flush(): Promise<void> {
    if (this.saveTimer) {
      clearTimeout(this.saveTimer);
      this.saveTimer = null;
      await this.saveNow();
    } else {
      await this.saveChain;
    }
  }

  private normalize(raw: unknown): AdminState {
    const value = raw as Partial<AdminState> & { version?: number; keys?: unknown };
    const version = (raw as { version?: unknown } | null)?.version;
    if (
      !value ||
      !Array.isArray(value.keys) ||
      (version !== 1 && version !== 2 && version !== 3 && version !== 4 && version !== 5 && version !== 6)
    ) {
      throw new Error('管理数据格式不正确');
    }

    const features: FeatureFlags = { ...DEFAULT_FEATURES };
    const rawFeatures = (raw as { features?: unknown } | null)?.features;
    if (rawFeatures && typeof rawFeatures === 'object') {
      for (const [key, enabled] of Object.entries(rawFeatures as Record<string, unknown>)) {
        if (isFeatureKey(key) && typeof enabled === 'boolean') features[key] = enabled;
      }
    }

    const keys = value.keys
      .map((item) => normalizeStoredKey(item))
      .filter((item): item is ManagedKey => item !== null);

    return {
      version: 6,
      username:
        typeof value.username === 'string' && USERNAME_PATTERN.test(value.username)
          ? value.username
          : 'admin',
      password: isPasswordHash(value.password) ? value.password : null,
      requireKey:
        typeof value.requireKey === 'boolean' ? value.requireKey : this.options.requireKey,
      webEnabled:
        typeof value.webEnabled === 'boolean'
          ? value.webEnabled
          : this.options.webEnabled !== false,
      webPolicy: normalizeWebPolicy(value.webPolicy),
      scheduler: normalizeSchedulerPolicy(value.scheduler),
      features,
      keys,
    };
  }

  private scheduleSave(): void {
    if (this.saveTimer) return;
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null;
      void this.saveNow().catch((error) => {
        console.error('[admin] 保存管理数据失败:', error);
      });
    }, SAVE_DEBOUNCE_MS);
    this.saveTimer.unref();
  }

  private async saveNow(): Promise<void> {
    const payload = JSON.stringify(this.state, null, 2);
    const target = this.filePath;
    const temp = `${target}.tmp`;

    this.saveChain = this.saveChain.then(async () => {
      await mkdir(dirname(target), { recursive: true });
      await writeFile(temp, payload, { encoding: 'utf8', mode: 0o600 });
      await rename(temp, target);
    });

    await this.saveChain;
  }
}

function isPasswordHash(value: unknown): value is PasswordHash {
  const item = value as Partial<PasswordHash> | null;
  return Boolean(
    item &&
      item.algo === 'scrypt' &&
      typeof item.salt === 'string' &&
      typeof item.hash === 'string' &&
      Number.isFinite(item.N) &&
      Number.isFinite(item.r) &&
      Number.isFinite(item.p) &&
      Number.isFinite(item.keylen),
  );
}

export function normalizeUsername(username: string | undefined): string {
  return (username ?? '').trim();
}

export function validateCredentials(username: string, password: string): string | null {
  if (!USERNAME_PATTERN.test(username)) {
    return '账号需为 3-32 位字母、数字、下划线、点或短横线';
  }
  if (password.length < PASSWORD_MIN_LENGTH) {
    return `密码至少 ${PASSWORD_MIN_LENGTH} 位`;
  }
  if (password.length > 128) {
    return '密码不能超过 128 位';
  }
  return null;
}

function normalizeName(name: string | undefined): string {
  const value = (name ?? '').replace(/\s+/g, ' ').trim().slice(0, 64);
  return value || '未命名密钥';
}

function normalizeQuota(value: number | null | undefined): number | null {
  if (value === null || value === undefined) return null;
  const quota = Number(value);
  return Number.isFinite(quota) && quota > 0 ? Math.min(Math.floor(quota), 1_000_000_000) : null;
}

function normalizeRate(value: number | null | undefined): number | null {
  if (value === null || value === undefined) return null;
  const rate = Number(value);
  return Number.isFinite(rate) && rate > 0 ? Math.min(Math.floor(rate), 1_000_000) : null;
}

function normalizeScopes(value: FeatureKey[] | null | undefined): FeatureKey[] | null {
  if (value === null || value === undefined) return null;
  const scopes = [...new Set(value.filter(isFeatureKey))];
  return scopes.length > 0 ? scopes : null;
}

function normalizeIps(value: string[] | null | undefined): string[] {
  if (!Array.isArray(value)) return [];
  const rules = value
    .map((item) => normalizeIpRule(String(item)))
    .filter((item): item is string => item !== null);
  return [...new Set(rules)].slice(0, 20);
}

function normalizeNote(value: string | null | undefined): string | null {
  const note = (value ?? '').replace(/\s+/g, ' ').trim().slice(0, 200);
  return note || null;
}

function expiresAtFromDays(days: number | null | undefined): string | null {
  if (days === null || days === undefined) return null;
  const value = Number(days);
  if (!Number.isFinite(value) || value <= 0) return null;
  return new Date(Date.now() + Math.min(value, 3650) * 24 * 60 * 60 * 1000).toISOString();
}

function normalizeStoredKey(item: unknown): ManagedKey | null {
  const key = item as Partial<ManagedKey> & Record<string, unknown>;
  if (
    !key ||
    typeof key !== 'object' ||
    typeof key.id !== 'string' ||
    typeof key.name !== 'string' ||
    typeof key.prefix !== 'string' ||
    typeof key.hash !== 'string' ||
    !/^[a-f0-9]{64}$/.test(key.hash) ||
    typeof key.createdAt !== 'string'
  ) {
    return null;
  }

  const expiresAt =
    typeof key.expiresAt === 'string' && Number.isFinite(Date.parse(key.expiresAt))
      ? key.expiresAt
      : null;

  return {
    id: key.id,
    name: key.name,
    prefix: key.prefix,
    hash: key.hash,
    createdAt: key.createdAt,
    lastUsedAt: typeof key.lastUsedAt === 'string' ? key.lastUsedAt : null,
    lastUsedIp: typeof key.lastUsedIp === 'string' ? key.lastUsedIp : null,
    requestCount: Number.isFinite(key.requestCount) ? Number(key.requestCount) : 0,
    enabled: key.enabled !== false,
    expiresAt,
    quota: normalizeQuota(key.quota as number | null | undefined),
    rateLimit: normalizeRate(key.rateLimit as number | null | undefined),
    scopes: normalizeScopes(key.scopes as FeatureKey[] | null | undefined),
    allowedIps: normalizeIps(key.allowedIps as string[] | undefined),
    note: normalizeNote(key.note as string | null | undefined),
  };
}
