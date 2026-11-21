import { ApiError } from '../lib/errors.js';
import type { ParsedDomain } from '../lib/domain.js';
import { mergeParsed } from './parsers.js';
import { buildWhoisQuery, resolveWhoisServer } from './tld.js';
import { extractWhoisReferral, queryWhoisTcp } from './tcp.js';
import { parseWhois } from './whois-text.js';
import type { ParsedRecord } from './types.js';

export interface WhoisQueryResult {
  parsed: ParsedRecord;
  server: string;
  raw: string;
  durationMs: number;
}

const RATE_LIMIT_RE = /(rate limit|quota exceeded|too many requests|query limit)/i;

/** 通过 WHOIS 43 端口查询；失败时抛出错误，由编排层决定是否可继续 */
export async function whoisLookup(
  domain: ParsedDomain,
  timeoutMs: number,
  followReferral: boolean,
): Promise<WhoisQueryResult | null> {
  const startedAt = Date.now();

  const server = await resolveWhoisServer(domain.tld, async (host, query) => {
    const result = await queryWhoisTcp(host, 43, query, Math.min(timeoutMs, 5000));
    return result.text;
  });

  if (!server) return null;

  const first = await queryWhoisTcp(
    server.host,
    server.port,
    buildWhoisQuery(server, domain.ascii),
    timeoutMs,
  );

  if (!first.text.trim()) {
    throw ApiError.upstream(`WHOIS 服务器 ${server.host} 返回空响应`);
  }
  if (RATE_LIMIT_RE.test(first.text)) {
    throw ApiError.upstream(`WHOIS 服务器 ${server.host} 触发限流`);
  }

  const primary = parseWhois(first.text);
  let parsed = primary;
  let raw = first.text;
  let usedServer = `${server.host}:${server.port}`;

  if (followReferral && !primary.available) {
    const referral = extractWhoisReferral(first.text, server.host);
    if (referral) {
      try {
        const second = await queryWhoisTcp(referral.host, referral.port, domain.ascii, timeoutMs);
        if (second.text.trim() && !RATE_LIMIT_RE.test(second.text)) {
          parsed = mergeParsed(primary, parseWhois(second.text));
          raw += `\n\n${'-'.repeat(48)}\nWHOIS referral: ${referral.host}:${referral.port}\n${'-'.repeat(48)}\n${second.text}`;
          usedServer = `${server.host}:${server.port} -> ${referral.host}:${referral.port}`;
        }
      } catch {
        // referral 失败不影响注册局主结果
      }
    }
  }

  return {
    parsed,
    server: usedServer,
    raw,
    durationMs: Date.now() - startedAt,
  };
}
