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

/** 明确的限流 / 配额提示，出现即视为上游故障 */
const HARD_FAILURE_RE = /(rate limit|quota exceeded|too many requests|query limit)/i;

/** 弱错误特征：仅在响应内容很短（通常是错误页）时生效，避免命中注册局长篇免责声明 */
const SOFT_FAILURE_RE =
  /(banned|blocked|access denied|not authorised|not authorized|connection refused|server busy|service unavailable|temporarily unavailable|try again later|internal error|unknown error)/i;

/** 判断 WHOIS 响应是否代表上游故障，而不是正常记录 */
export function isUpstreamFailure(text: string): boolean {
  if (!text.trim()) return true;
  if (HARD_FAILURE_RE.test(text.slice(0, 2000))) return true;
  const compact = text.replace(/\s+/g, ' ').trim();
  return compact.length <= 600 && SOFT_FAILURE_RE.test(compact);
}

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
  if (isUpstreamFailure(first.text)) {
    throw ApiError.upstream(`WHOIS 服务器 ${server.host} 返回异常状态`);
  }

  const primary = parseWhois(first.text);
  if (primary.conclusive === false) {
    // 无法从响应中判定注册状态（多为限流、封禁或异常页面），交由上层显示“无法确认”
    throw ApiError.upstream(`WHOIS 服务器 ${server.host} 未返回可判定的结果`);
  }
  let parsed = primary;
  let raw = first.text;
  let usedServer = `${server.host}:${server.port}`;

  if (followReferral && !primary.available) {
    const referral = extractWhoisReferral(first.text, server.host);
    if (referral) {
      try {
        const second = await queryWhoisTcp(referral.host, referral.port, domain.ascii, timeoutMs);
        if (second.text.trim() && !isUpstreamFailure(second.text)) {
          const secondary = parseWhois(second.text);
          parsed = secondary.conclusive === false ? primary : mergeParsed(primary, secondary);
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
