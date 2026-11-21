import { connect, type PeerCertificate } from 'node:tls';
import { config } from '../config.js';
import { TtlCache } from '../lib/cache.js';
import { ApiError } from '../lib/errors.js';
import { metrics } from '../lib/metrics.js';
import { parseTlsTarget, resolvePublicAddress } from './tls.js';

/**
 * TLS 证书链导出
 *
 * 与目标端口完成一次 TLS 握手，按链顺序整理每张证书并输出标准 PEM，
 * 便于运维排查证书链缺失、顺序错误与交叉签名问题。整个过程不经过第三方服务。
 */

export interface ChainCertificate {
  index: number;
  subject: string | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  fingerprint256: string | null;
  selfSigned: boolean;
  pem: string;
}

export interface CertChainResult {
  host: string;
  port: number;
  address: string;
  count: number;
  chain: ChainCertificate[];
  pem: string;
  checkedAt: string;
  cached: boolean;
  ttlMs: number;
  note: string;
}

interface CachedChain {
  host: string;
  port: number;
  address: string;
  count: number;
  chain: ChainCertificate[];
  pem: string;
  checkedAt: string;
  note: string;
}

const cache = new TtlCache<CachedChain>(config.certChain.maxEntries);

export const CERT_CHAIN_NOTE =
  '证书链由本站直接与目标端口完成 TLS 握手后导出，PEM 内容与服务器实际返回的证书一致，可用于本地证书链排查。';

function text(record: unknown, key: string): string | null {
  if (!record || typeof record !== 'object') return null;
  const value = (record as Record<string, unknown>)[key];
  if (Array.isArray(value)) {
    const joined = value.map((item) => String(item)).join(', ').trim();
    return joined || null;
  }
  if (typeof value === 'string') return value.trim() || null;
  return null;
}

function toPem(raw: Buffer | undefined): string {
  if (!raw || raw.length === 0) return '';
  const base64 = raw.toString('base64').match(/.{1,64}/g)?.join('\n') ?? '';
  return `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----\n`;
}

function collectChain(peer: PeerCertificate): ChainCertificate[] {
  const chain: ChainCertificate[] = [];
  const seen = new Set<string>();
  let current: PeerCertificate | undefined = peer;

  while (current && chain.length < 10) {
    const fingerprint = current.fingerprint256 || current.fingerprint || '';
    if (fingerprint && seen.has(fingerprint)) break;
    if (fingerprint) seen.add(fingerprint);

    const subject = text(current.subject, 'CN');
    const issuer = text(current.issuer, 'CN');
    const pem = toPem(current.raw);
    if (pem) {
      chain.push({
        index: chain.length,
        subject,
        issuer,
        validFrom: current.valid_from ? new Date(current.valid_from).toISOString() : null,
        validTo: current.valid_to ? new Date(current.valid_to).toISOString() : null,
        fingerprint256: current.fingerprint256 ?? null,
        selfSigned: Boolean(subject && issuer && subject === issuer),
        pem,
      });
    }

    const issuerCert: PeerCertificate | undefined = (
      current as PeerCertificate & { issuerCertificate?: PeerCertificate }
    ).issuerCertificate;
    current = issuerCert && issuerCert !== current ? issuerCert : undefined;
  }

  return chain;
}

function fetchChain(host: string, port: number, address: string): Promise<PeerCertificate> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = connect({
      host: address,
      port,
      servername: host,
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
      const peer = socket.getPeerCertificate(true);
      socket.destroy();
      resolve(peer);
    });
  });
}

/** 导出目标域名指定端口的完整证书链 */
export async function fetchCertificateChain(
  input: string,
  rawPort?: number | string,
): Promise<CertChainResult> {
  const target = parseTlsTarget(input, rawPort);
  const key = `${target.host}:${target.port}`;
  const hit = cache.get(key);
  if (hit) {
    metrics.recordCache('certchain', true);
    return { ...hit.value, cached: true, ttlMs: Math.round(hit.ttlMs) };
  }

  metrics.recordCache('certchain', false);
  const resolved = await resolvePublicAddress(target.host);

  let peer: PeerCertificate;
  try {
    peer = await fetchChain(target.host, target.port, resolved.address);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (/timeout|超时/i.test(message)) {
      throw ApiError.timeout('TLS 握手超时，目标可能未开放该端口');
    }
    const code = String((error as NodeJS.ErrnoException)?.code ?? '');
    if (code === 'ECONNREFUSED') throw ApiError.upstream(`目标端口 ${target.port} 拒绝连接`);
    if (code === 'ENOTFOUND') throw ApiError.badRequest('无法解析该主机名');
    throw ApiError.upstream(`TLS 连接失败：${message}`);
  }

  const chain = collectChain(peer);
  if (chain.length === 0) throw ApiError.upstream('目标端口未返回可用证书');

  const result: CachedChain = {
    host: target.host,
    port: target.port,
    address: resolved.address,
    count: chain.length,
    chain,
    pem: chain.map((item) => item.pem).join('\n'),
    checkedAt: new Date().toISOString(),
    note: CERT_CHAIN_NOTE,
  };

  cache.set(key, result, config.certChain.cacheTtlMs);
  return {
    ...result,
    cached: false,
    ttlMs: config.certChain.cacheTtlMs,
  };
}

export function clearCertChainCache(): void {
  cache.clear();
}

export function certChainCacheSize(): number {
  return cache.size;
}
