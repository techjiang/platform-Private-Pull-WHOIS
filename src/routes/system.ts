import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { config } from '../config.js';
import { DNS_TYPES } from '../services/dns.js';
import { PROP_RESOLVERS, PROP_TYPES } from '../services/dnsprop.js';
import { openapiSpec } from '../openapi.js';
import { listKnownTlds } from '../whois/tld.js';

/** 工具目录：供集成方发现全部接口与限制，不产生任何上游查询 */
const TOOL_CATALOG = [
  { key: 'whois', label: 'WHOIS 查询', path: '/v1/whois/{domain}' },
  { key: 'rdap', label: 'RDAP 查询', path: '/v1/rdap/{domain}' },
  { key: 'dns', label: 'DNS 记录查询', path: '/v1/dns/{domain}?type=A' },
  { key: 'ip', label: 'IP 地址查询', path: '/v1/ip/{ip}' },
  { key: 'uptime', label: '网站可用性检查', path: '/v1/uptime?target=' },
  { key: 'history', label: '域名历史快照', path: '/v1/history/{domain}' },
  { key: 'nameservers', label: '名称服务器反查', path: '/v1/nameservers/{host}' },
  { key: 'registrars', label: '注册商目录', path: '/v1/registrars' },
  { key: 'icp', label: 'ICP 备案查询', path: '/v1/icp/{domain}' },
  { key: 'tls', label: 'TLS 证书检查', path: '/v1/tls/{host}' },
  { key: 'certchain', label: 'TLS 证书链导出', path: '/v1/tls/{host}/chain' },
  { key: 'mail', label: '邮件安全记录', path: '/v1/mail/{domain}' },
  { key: 'http', label: 'HTTP 安全响应头体检', path: '/v1/http/{target}' },
  { key: 'dnsprop', label: 'DNS 多解析器传播对比', path: '/v1/dnsprop/{domain}?type=A' },
  { key: 'health', label: '域名健康评分', path: '/v1/health/{domain}' },
  { key: 'available', label: '批量可注册检测', path: '/v1/available?domains=' },
] as const;

function metaPayload() {
  return {
    name: 'Pull WHOIS',
    version: config.version,
    license: 'GPL-3.0-only',
    docs: '/docs',
    uptimeSec: Math.round(process.uptime()),
    tools: TOOL_CATALOG,
    dnsTypes: [...DNS_TYPES, 'ANY'],
    propagationTypes: [...PROP_TYPES],
    propagationResolvers: PROP_RESOLVERS.map((item) => ({ id: item.id, name: item.name, address: item.address })),
    limits: {
      batchDomains: config.availability.maxDomains,
      httpRedirects: 5,
      httpTimeoutMs: config.httpProbe.timeoutMs,
      dnsPropagationTimeoutMs: config.dnsProp.timeoutMs,
      healthUpstreamTimeoutMs: config.health.upstreamTimeoutMs,
    },
  };
}

export async function systemRoutes(app: FastifyInstance): Promise<void> {
  app.get('/health', async (_request, reply) => {
    reply.header('cache-control', 'no-store');
    return {
      success: true,
      data: {
        status: 'ok',
        version: config.version,
        uptimeSec: Math.round(process.uptime()),
        now: new Date().toISOString(),
      },
    };
  });

  const metaHandler = async (_request: FastifyRequest, reply: FastifyReply) => {
    reply.header('cache-control', 'public, max-age=300');
    return { success: true, data: metaPayload() };
  };

  app.get('/v1/meta', metaHandler);
  app.get('/web/v1/meta', metaHandler);

  app.get('/v1/tlds', async (_request, reply) => {
    const tlds = listKnownTlds();
    reply.header('cache-control', 'public, max-age=86400');
    return { success: true, data: { count: tlds.length, tlds } };
  });

  // 网页端使用独立前缀，与 API 的 Key 策略互不影响
  app.get('/web/v1/tlds', async (_request, reply) => {
    const tlds = listKnownTlds();
    reply.header('cache-control', 'public, max-age=86400');
    return { success: true, data: { count: tlds.length, tlds } };
  });

  app.get('/openapi.json', async (_request, reply) => {
    reply.header('cache-control', 'public, max-age=3600');
    return openapiSpec;
  });
}
