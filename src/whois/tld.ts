export interface WhoisServerInfo {
  host: string;
  port: number;
  /** 查询模板，{domain} 会被替换为 punycode 域名 */
  template?: string;
}

/** 常见后缀的 WHOIS 服务器，命中后无需再查 IANA */
const SERVERS: Record<string, WhoisServerInfo> = {
  com: { host: 'whois.verisign-grs.com', port: 43 },
  net: { host: 'whois.verisign-grs.com', port: 43 },
  org: { host: 'whois.pir.org', port: 43 },
  info: { host: 'whois.nic.info', port: 43 },
  biz: { host: 'whois.nic.biz', port: 43 },
  name: { host: 'whois.nic.name', port: 43 },
  mobi: { host: 'whois.nic.mobi', port: 43 },
  pro: { host: 'whois.nic.pro', port: 43 },
  io: { host: 'whois.nic.io', port: 43 },
  co: { host: 'whois.nic.co', port: 43 },
  ai: { host: 'whois.nic.ai', port: 43 },
  me: { host: 'whois.nic.me', port: 43 },
  tv: { host: 'whois.nic.tv', port: 43 },
  cc: { host: 'ccwhois.verisign-grs.com', port: 43 },
  ws: { host: 'whois.website.ws', port: 43 },
  fm: { host: 'whois.nic.fm', port: 43 },
  gg: { host: 'whois.gg', port: 43 },
  to: { host: 'whois.tonic.to', port: 43 },
  sh: { host: 'whois.nic.sh', port: 43 },
  ac: { host: 'whois.nic.ac', port: 43 },
  xyz: { host: 'whois.nic.xyz', port: 43 },
  app: { host: 'whois.nic.google', port: 43 },
  dev: { host: 'whois.nic.google', port: 43 },
  page: { host: 'whois.nic.google', port: 43 },
  uk: { host: 'whois.nic.uk', port: 43 },
  de: { host: 'whois.denic.de', port: 43, template: '-T dn,ace {domain}' },
  cn: { host: 'whois.cnnic.cn', port: 43 },
  jp: { host: 'whois.jprs.jp', port: 43, template: '{domain}/e' },
  fr: { host: 'whois.nic.fr', port: 43 },
  nl: { host: 'whois.domain-registry.nl', port: 43 },
  ru: { host: 'whois.tcinet.ru', port: 43 },
  br: { host: 'whois.registro.br', port: 43 },
  au: { host: 'whois.auda.org.au', port: 43 },
  ca: { host: 'whois.cira.ca', port: 43 },
  ch: { host: 'whois.nic.ch', port: 43 },
  it: { host: 'whois.nic.it', port: 43 },
  es: { host: 'whois.nic.es', port: 43 },
  se: { host: 'whois.iis.se', port: 43 },
  no: { host: 'whois.norid.no', port: 43 },
  dk: { host: 'whois.dk-hostmaster.dk', port: 43 },
  fi: { host: 'whois.fi', port: 43 },
  pl: { host: 'whois.dns.pl', port: 43 },
  be: { host: 'whois.dns.be', port: 43 },
  at: { host: 'whois.nic.at', port: 43 },
  nz: { host: 'whois.srs.net.nz', port: 43 },
  in: { host: 'whois.registry.in', port: 43 },
  kr: { host: 'whois.kr', port: 43 },
  tw: { host: 'whois.twnic.net.tw', port: 43 },
  hk: { host: 'whois.hkirc.hk', port: 43 },
  sg: { host: 'whois.sgnic.sg', port: 43 },
  mx: { host: 'whois.mx', port: 43 },
  ar: { host: 'whois.nic.ar', port: 43 },
  cl: { host: 'whois.nic.cl', port: 43 },
  ly: { host: 'whois.nic.ly', port: 43 },
  pt: { host: 'whois.dns.pt', port: 43 },
  cz: { host: 'whois.nic.cz', port: 43 },
  gr: { host: 'whois.nic.gr', port: 43 },
  ie: { host: 'whois.weare.ie', port: 43 },
  il: { host: 'whois.isoc.org.il', port: 43 },
  tr: { host: 'whois.trabis.gov.tr', port: 43 },
  ua: { host: 'whois.ua', port: 43 },
  id: { host: 'whois.id', port: 43 },
  my: { host: 'whois.mynic.my', port: 43 },
  ph: { host: 'whois.dot.ph', port: 43 },
  th: { host: 'whois.thnic.co.th', port: 43 },
  vn: { host: 'whois.vnnic.vn', port: 43 },
  eu: { host: 'whois.eu', port: 43 },
  asia: { host: 'whois.nic.asia', port: 43 },
  cat: { host: 'whois.nic.cat', port: 43 },
  tel: { host: 'whois.nic.tel', port: 43 },
  us: { host: 'whois.nic.us', port: 43 },
};

const IANA_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const ianaCache = new Map<string, { value: WhoisServerInfo | null; expiresAt: number }>();

export function getStaticWhoisServer(tld: string): WhoisServerInfo | null {
  return SERVERS[tld] ?? null;
}

export function listKnownTlds(): Array<{ tld: string; host: string; port: number }> {
  return Object.entries(SERVERS)
    .map(([tld, info]) => ({ tld, host: info.host, port: info.port }))
    .sort((a, b) => a.tld.localeCompare(b.tld));
}

export function buildWhoisQuery(info: WhoisServerInfo, domain: string): string {
  return (info.template ?? '{domain}').replace('{domain}', domain);
}

/**
 * 查询 IANA 获取后缀对应的 WHOIS 服务器，结果缓存 24 小时。
 * 失败或不存在时返回 null，由调用方决定降级策略。
 */
export async function resolveWhoisServer(
  tld: string,
  query: (host: string, query: string) => Promise<string>,
): Promise<WhoisServerInfo | null> {
  const staticServer = getStaticWhoisServer(tld);
  if (staticServer) return staticServer;

  const now = Date.now();
  const cached = ianaCache.get(tld);
  if (cached && cached.expiresAt > now) return cached.value;

  let result: WhoisServerInfo | null = null;
  try {
    const text = await query('whois.iana.org', tld);
    const match = /^\s*whois:\s*(\S+)/im.exec(text);
    if (match?.[1]) {
      result = { host: match[1].replace(/^whois:\/\//, '').split('/')[0] ?? match[1], port: 43 };
    }
  } catch {
    result = null;
  }

  ianaCache.set(tld, { value: result, expiresAt: now + IANA_CACHE_TTL_MS });
  return result;
}
