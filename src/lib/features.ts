export const FEATURE_KEYS = [
  'whois',
  'rdap',
  'dns',
  'ip',
  'uptime',
  'history',
  'nameservers',
  'registrars',
  'icp',
  'tls',
  'mail',
  'certchain',
  'http',
  'dnsprop',
  'health',
  'available',
] as const;

export type FeatureKey = (typeof FEATURE_KEYS)[number];
export type FeatureFlags = Record<FeatureKey, boolean>;

export const FEATURE_LABELS: Record<FeatureKey, string> = {
  whois: 'WHOIS 查询',
  rdap: 'RDAP 查询',
  dns: 'DNS 记录',
  ip: 'IP 地址查询',
  uptime: '可用性检查',
  history: '域名历史',
  nameservers: '名称服务器反查',
  registrars: '注册商目录',
  icp: 'ICP 备案查询',
  tls: 'TLS 证书检查',
  mail: '邮件安全记录',
  certchain: '证书链导出',
  http: 'HTTP 安全体检',
  dnsprop: 'DNS 传播对比',
  health: '域名健康评分',
  available: '批量可注册查询',
};

export const DEFAULT_FEATURES: FeatureFlags = {
  whois: true,
  rdap: true,
  dns: true,
  ip: true,
  uptime: true,
  history: true,
  nameservers: true,
  registrars: true,
  icp: true,
  tls: true,
  mail: true,
  certchain: true,
  http: true,
  dnsprop: true,
  health: true,
  available: true,
};

export function isFeatureKey(value: unknown): value is FeatureKey {
  return typeof value === 'string' && (FEATURE_KEYS as readonly string[]).includes(value);
}

/** 从 /v1/、/web/v1/ 路径解析出所属工具 */
export function toolOfPath(url: string): FeatureKey | null {
  const path = url.split('?')[0] ?? '';
  let rest = '';
  if (path.startsWith('/web/v1/')) rest = path.slice('/web/v1/'.length);
  else if (path.startsWith('/v1/')) rest = path.slice('/v1/'.length);
  else return null;

  const parts = rest.split('/');
  const segment = parts[0] ?? '';
  switch (segment) {
    case 'tls':
      return parts[2] === 'chain' ? 'certchain' : 'tls';
    case 'whois':
      return 'whois';
    case 'rdap':
      return 'rdap';
    case 'dns':
      return 'dns';
    case 'ip':
      return 'ip';
    case 'uptime':
      return 'uptime';
    case 'history':
      return 'history';
    case 'nameservers':
      return 'nameservers';
    case 'registrars':
      return 'registrars';
    case 'icp':
      return 'icp';
    case 'mail':
      return 'mail';
    case 'certchain':
      return 'certchain';
    case 'http':
      return 'http';
    case 'dnsprop':
      return 'dnsprop';
    case 'health':
      return 'health';
    case 'available':
      return 'available';
    default:
      return null;
  }
}
