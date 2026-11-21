import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { connect, type PeerCertificate } from 'node:tls';
import { config } from '../config.js';
import { TtlCache } from '../lib/cache.js';
import { ApiError } from '../lib/errors.js';
import { metrics } from '../lib/metrics.js';
import { isPrivateAddress } from './ip.js';

/**
 * TLS 证书检查
 *
 * 完全基于 Node.js 内置 tls 模块与 DNS 解析实现，不依赖任何第三方检测服务。
 * 只读取握手阶段的证书与协议信息，不发送 HTTP 请求。
 */

export interface TlsCertificateInfo {
  subject: { commonName: string | null; organization: string | null; country: string | null };
  issuer: { commonName: string | null; organization: string | null; country: string | null };
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  expired: boolean;
  notYetValid: boolean;
  serialNumber: string | null;
  fingerprint256: string | null;
  san: string[];
  keyBits: number | null;
  chainLength: number;
}

export interface TlsCheckResult {
  host: string;
  port: number;
  servername: string;
  address: string;
  family: number;
  reachable: boolean;
  authorized: boolean;
  authorizationError: string | null;
  protocol: string | null;
  cipher: { name: string; version: string } | null;
  alpn: string | null;
  certificate: TlsCertificateInfo | null;
  note: string;
  checkedAt: string;
  cached: boolean;
  ttlMs: number;
}

export const TLS_NOTE =
  '证书信息由本站直接与目标端口完成 TLS 握手获取，未经过任何第三方检测服务。校验结果仅供参考，请以浏览器实际提示为准。';

interface CachedTls {
  host: string;
  port: number;
  servername: string;
  address: string;
  family: number;
  reachable: boolean;
  authorized: boolean;
  authorizationError: string | null;
  protocol: string | null;
  cipher: { name: string; version: string } | null;
  alpn: string | null;
  certificate: TlsCertificateInfo | null;
  note: string;
  checkedAt: string;
}

export interface TlsTarget {
  host: string;
  port: number;
  servername: string;
}

const cache = new TtlCache<CachedTls>(config.tls.maxEntries);
const inflight = new Map<string, Promise<CachedTls>>();

const HOSTNAME_PATTERN =
  /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

/**
 * 解析主机 / URL 输入，返回连接目标。
 * 支持 example.com、example.com:8443、https://example.com/path。
 */
export function parseTlsTarget(input: string, rawPort?: number | string): TlsTarget {
  const value = String(input ?? '').trim();
  if (!value) throw ApiError.badRequest('请输入域名或网址');
  if (value.length > 2048) throw ApiError.badRequest('输入内容过长');

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw ApiError.badRequest('域名或网址格式不正确');
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw ApiError.badRequest('仅支持域名或 http(s) 网址');
  }
  if (url.username || url.password) throw ApiError.badRequest('网址不能包含账号密码');

  const host = url.hostname.replace(/\.$/, '').toLowerCase();
  if (!host) throw ApiError.badRequest('缺少主机名');
  if (isIP(host) || (host.startsWith('[') && host.endsWith(']'))) {
    throw ApiError.badRequest('请使用域名查询证书，IP 请使用 IP 查询工具');
  }
  if (!HOSTNAME_PATTERN.test(host)) {
    throw ApiError.badRequest('请输入合法的域名，例如 example.com');
  }

  const portValue = rawPort === undefined || rawPort === '' ? Number(url.port || 443) : Number(rawPort);
  const port = Number.isFinite(portValue) ? Math.trunc(portValue) : 443;
  if (port < 1 || port > 65535) throw ApiError.badRequest('端口必须在 1-65535 之间');

  return { host, port, servername: host };
}

function field(record: unknown, key: string): string | null {
  if (!record || typeof record !== 'object') return null;
  const value = (record as Record<string, unknown>)[key];
  if (Array.isArray(value)) {
    const text = value.map((item) => String(item)).join(', ').trim();
    return text || null;
  }
  if (typeof value === 'string') return value.trim() || null;
  return null;
}

function parseSan(subjectaltname: unknown): string[] {
  if (typeof subjectaltname !== 'string' || !subjectaltname.trim()) return [];
  return subjectaltname
    .split(/,\s*/)
    .map((item) => item.trim())
    .map((item) => (/^DNS:/i.test(item) ? item.slice(4) : item))
    .filter((item) => item && !/^IP Address:/i.test(item));
}

function chainLength(peer: PeerCertificate): number {
  let current: PeerCertificate | undefined = peer;
  let count = 0;
  const seen = new Set<string>();

  while (current && count < 10) {
    const id = current.fingerprint256 || current.fingerprint || '';
    if (id && seen.has(id)) break;
    if (id) seen.add(id);
    count += 1;
    const issuer: PeerCertificate | undefined = (
      current as PeerCertificate & { issuerCertificate?: PeerCertificate }
    ).issuerCertificate;
    current = issuer && issuer !== current ? issuer : undefined;
  }

  return count;
}

/** 将 Node 证书对象归一化为稳定结构（纯函数，便于测试） */
export function buildCertificateInfo(peer: PeerCertificate | null | undefined, now = Date.now()): TlsCertificateInfo | null {
  if (!peer) return null;

  const validFrom = peer.valid_from ? new Date(peer.valid_from) : null;
  const validTo = peer.valid_to ? new Date(peer.valid_to) : null;
  const fromTs = validFrom && !Number.isNaN(validFrom.getTime()) ? validFrom.getTime() : null;
  const toTs = validTo && !Number.isNaN(validTo.getTime()) ? validTo.getTime() : null;

  return {
    subject: {
      commonName: field(peer.subject, 'CN'),
      organization: field(peer.subject, 'O'),
      country: field(peer.subject, 'C'),
    },
    issuer: {
      commonName: field(peer.issuer, 'CN'),
      organization: field(peer.issuer, 'O'),
      country: field(peer.issuer, 'C'),
    },
    validFrom: fromTs === null ? null : new Date(fromTs).toISOString(),
    validTo: toTs === null ? null : new Date(toTs).toISOString(),
    daysRemaining: toTs === null ? null : Math.floor((toTs - now) / (24 * 60 * 60 * 1000)),
    expired: toTs !== null && toTs < now,
    notYetValid: fromTs !== null && fromTs > now,
    serialNumber: typeof peer.serialNumber === 'string' ? peer.serialNumber : null,
    fingerprint256: typeof peer.fingerprint256 === 'string' ? peer.fingerprint256 : null,
    san: parseSan(peer.subjectaltname),
    keyBits: typeof peer.bits === 'number' ? peer.bits : null,
    chainLength: chainLength(peer),
  };
}

export async function resolvePublicAddress(host: string): Promise<{ address: string; family: number }> {
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    throw ApiError.badRequest('不允许检查内网地址');
  }

  let addresses: Array<{ address: string; family: number }>;
  try {
    addresses = await lookup(host, { all: true, verbatim: true });
  } catch {
    throw ApiError.badRequest('无法解析该主机名');
  }

  if (addresses.length === 0) throw ApiError.badRequest('无法解析该主机名');
  if (addresses.some((item) => isPrivateAddress(item.address))) {
    throw ApiError.badRequest('不允许检查内网或保留地址');
  }

  return addresses.find((item) => item.family === 4) ?? addresses[0]!;
}

function handshake(target: TlsTarget, address: string): Promise<{
  authorized: boolean;
  authorizationError: string | null;
  protocol: string | null;
  cipher: { name: string; version: string } | null;
  alpn: string | null;
  certificate: PeerCertificate;
}> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = connect({
      host: address,
      port: target.port,
      servername: target.servername,
      rejectUnauthorized: false,
      ALPNProtocols: ['h2', 'http/1.1'],
      timeout: config.tls.timeoutMs,
    });

    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };

    socket.once('timeout', () => fail(new Error('TLS 握手超时')));
    socket.once('error', fail);
    socket.once('secureConnect', () => {
      if (settled) return;
      settled = true;
      const cipher = socket.getCipher();
      const authorizationError =
        socket.authorizationError === undefined || socket.authorizationError === null
          ? null
          : String(socket.authorizationError);
      resolve({
        authorized: socket.authorized,
        authorizationError,
        protocol: socket.getProtocol(),
        cipher: cipher ? { name: cipher.name, version: cipher.version } : null,
        alpn: typeof socket.alpnProtocol === 'string' ? socket.alpnProtocol : null,
        certificate: socket.getPeerCertificate(true),
      });
      socket.destroy();
    });
  });
}

function mapError(error: unknown, target: TlsTarget): never {
  const message = error instanceof Error ? error.message : String(error);
  const code = String((error as NodeJS.ErrnoException)?.code ?? '');
  if (code === 'ETIMEDOUT' || /timeout|超时/i.test(message)) {
    throw ApiError.timeout('TLS 握手超时，目标可能未开放该端口');
  }
  if (code === 'ECONNREFUSED') {
    throw ApiError.upstream(`目标端口 ${target.port} 拒绝连接`);
  }
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') {
    throw ApiError.badRequest('无法解析该主机名');
  }
  if (code === 'ECONNRESET') {
    throw ApiError.upstream('连接被目标重置，可能不是 TLS 服务');
  }
  throw ApiError.upstream(`TLS 连接失败：${message}`);
}

/** 检查域名 TLS 证书与握手信息（带缓存与单飞） */
export async function checkTls(
  input: string,
  rawPort?: number | string,
): Promise<TlsCheckResult> {
  const target = parseTlsTarget(input, rawPort);
  const key = `${target.host}:${target.port}`;
  const hit = cache.get(key);
  if (hit) {
    metrics.recordCache('tls', true);
    return { ...hit.value, cached: true, ttlMs: Math.round(hit.ttlMs) };
  }

  const pending = inflight.get(key);
  if (pending) {
    return { ...(await pending), cached: true, ttlMs: Math.round(config.tls.cacheTtlMs) };
  }

  metrics.recordCache('tls', false);

  const task = (async (): Promise<CachedTls> => {
    const resolved = await resolvePublicAddress(target.host);
    let handshakeResult;
    try {
      handshakeResult = await handshake(target, resolved.address);
    } catch (error) {
      throw mapError(error, target);
    }

    const result: CachedTls = {
      host: target.host,
      port: target.port,
      servername: target.servername,
      address: resolved.address,
      family: resolved.family,
      reachable: true,
      authorized: handshakeResult.authorized,
      authorizationError: handshakeResult.authorizationError,
      protocol: handshakeResult.protocol,
      cipher: handshakeResult.cipher,
      alpn: handshakeResult.alpn,
      certificate: buildCertificateInfo(handshakeResult.certificate),
      note: TLS_NOTE,
      checkedAt: new Date().toISOString(),
    };

    cache.set(key, result, config.tls.cacheTtlMs);
    return result;
  })();

  inflight.set(key, task);
  try {
    return { ...(await task), cached: false, ttlMs: config.tls.cacheTtlMs };
  } finally {
    inflight.delete(key);
  }
}

export function clearTlsCache(): void {
  cache.clear();
  inflight.clear();
}

export function tlsCacheSize(): number {
  return cache.size;
}
