import net from 'node:net';
import { UpstreamTimeoutError } from '../lib/errors.js';

export interface TcpResult {
  text: string;
  durationMs: number;
}

const HOST_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i;

/** 通过 43 端口执行一次原始 WHOIS 查询 */
export function queryWhoisTcp(
  host: string,
  port: number,
  query: string,
  timeoutMs: number,
  maxBytes = 256 * 1024,
): Promise<TcpResult> {
  if (!HOST_RE.test(host)) {
    return Promise.reject(new Error(`非法的 WHOIS 服务器地址：${host}`));
  }

  return new Promise<TcpResult>((resolve, reject) => {
    const startedAt = Date.now();
    let data = '';
    let settled = false;

    const socket = net.createConnection({ host, port });

    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve({ text: data, durationMs: Date.now() - startedAt });
    };

    const timer = setTimeout(() => {
      finish(new UpstreamTimeoutError(`${host}:${port}`));
    }, timeoutMs);

    socket.setEncoding('utf8');

    socket.on('connect', () => {
      socket.write(`${query}\r\n`);
    });
    socket.on('data', (chunk: string) => {
      data += chunk;
      if (data.length > maxBytes) finish();
    });
    socket.on('end', () => finish());
    socket.on('close', () => finish());
    socket.on('error', (error) => finish(error instanceof Error ? error : new Error(String(error))));
  });
}

export interface Referral {
  host: string;
  port: number;
}

const GENERIC_HOSTS = new Set(['whois.iana.org', 'whois.verisign-grs.com']);

/**
 * 从注册局响应中提取注册商 WHOIS 服务器 referral。
 * 只接受明确的 referral 字段，避免误把正文中的域名当成服务器。
 */
export function extractWhoisReferral(text: string, currentHost: string): Referral | null {
  const patterns = [
    /^\s*ReferralServer:\s*whois:\/\/([^\s/]+)/im,
    /^\s*Registrar WHOIS Server:\s*([^\s/]+)/im,
    /^\s*Whois Server:\s*([^\s/]+)/im,
  ];

  for (const pattern of patterns) {
    const match = pattern.exec(text);
    if (!match?.[1]) continue;

    let value = match[1].trim();
    if (value.startsWith('//')) value = value.slice(2);
    if (value.startsWith('whois://')) value = value.slice('whois://'.length);

    const [hostPart, portPart] = value.split(':');
    const host = (hostPart ?? '').toLowerCase().replace(/\.$/, '');
    const port = portPart ? Number(portPart) : 43;

    if (!host || !HOST_RE.test(host)) continue;
    if (host === currentHost.toLowerCase() || GENERIC_HOSTS.has(host)) continue;
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;

    return { host, port };
  }

  return null;
}
