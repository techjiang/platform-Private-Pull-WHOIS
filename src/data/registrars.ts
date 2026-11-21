export interface RegistrarRecord {
  /** 目录内唯一标识（优先使用 IANA ID） */
  id: string;
  ianaId: string | null;
  name: string;
  website: string;
  country: string;
  aliases?: string[];
}

/**
 * 精选注册商目录（IANA 认证注册商的一小部分）。
 * 域名数量等统计来自本站本地索引，不代表注册商的真实业务规模。
 */
export const REGISTRARS: RegistrarRecord[] = [
  {
    id: '146',
    ianaId: '146',
    name: 'GoDaddy.com, LLC',
    website: 'https://www.godaddy.com',
    country: 'US',
    aliases: ['godaddy', '狗爹'],
  },
  {
    id: '1068',
    ianaId: '1068',
    name: 'NameCheap, Inc.',
    website: 'https://www.namecheap.com',
    country: 'US',
    aliases: ['namecheap'],
  },
  {
    id: '69',
    ianaId: '69',
    name: 'Tucows Domains Inc.',
    website: 'https://www.tucows.com',
    country: 'CA',
    aliases: ['tucows', 'opensrs'],
  },
  {
    id: '2',
    ianaId: '2',
    name: 'Network Solutions, LLC',
    website: 'https://www.networksolutions.com',
    country: 'US',
    aliases: ['networksolutions'],
  },
  {
    id: '299',
    ianaId: '299',
    name: 'CSC Corporate Domains, Inc.',
    website: 'https://www.cscglobal.com',
    country: 'US',
    aliases: ['csc'],
  },
  {
    id: '292',
    ianaId: '292',
    name: 'MarkMonitor Inc.',
    website: 'https://www.markmonitor.com',
    country: 'US',
    aliases: ['markmonitor'],
  },
  {
    id: '468',
    ianaId: '468',
    name: 'Amazon Registrar, Inc.',
    website: 'https://aws.amazon.com/route53/domains/',
    country: 'US',
    aliases: ['amazon', 'route53', 'aws'],
  },
  {
    id: '1910',
    ianaId: '1910',
    name: 'Cloudflare, Inc.',
    website: 'https://www.cloudflare.com/products/registrar/',
    country: 'US',
    aliases: ['cloudflare'],
  },
  {
    id: '81',
    ianaId: '81',
    name: 'Gandi SAS',
    website: 'https://www.gandi.net',
    country: 'FR',
    aliases: ['gandi'],
  },
  {
    id: '433',
    ianaId: '433',
    name: 'OVH SAS',
    website: 'https://www.ovhcloud.com',
    country: 'FR',
    aliases: ['ovh'],
  },
  {
    id: '83',
    ianaId: '83',
    name: 'IONOS SE',
    website: 'https://www.ionos.com',
    country: 'DE',
    aliases: ['1&1', 'ionos', '1and1'],
  },
  {
    id: '269',
    ianaId: '269',
    name: 'Key-Systems GmbH',
    website: 'https://www.key-systems.net',
    country: 'DE',
    aliases: ['key-systems', 'domaindiscount24'],
  },
  {
    id: '138',
    ianaId: '138',
    name: 'PSI-USA, Inc. d/b/a Domain Robot',
    website: 'https://www.psi-usa.info',
    country: 'DE',
    aliases: ['domain robot', 'psi-usa'],
  },
  {
    id: '106',
    ianaId: '106',
    name: 'Ascio Technologies, Inc.',
    website: 'https://www.ascio.com',
    country: 'DK',
    aliases: ['ascio'],
  },
  {
    id: '48',
    ianaId: '48',
    name: 'Enom, LLC',
    website: 'https://www.enom.com',
    country: 'US',
    aliases: ['enom'],
  },
  {
    id: '440',
    ianaId: '440',
    name: 'Wild West Domains, LLC',
    website: 'https://www.wildwestdomains.com',
    country: 'US',
    aliases: ['wildwest'],
  },
  {
    id: '1479',
    ianaId: '1479',
    name: 'NameSilo, LLC',
    website: 'https://www.namesilo.com',
    country: 'US',
    aliases: ['namesilo'],
  },
  {
    id: '1861',
    ianaId: '1861',
    name: 'Porkbun LLC',
    website: 'https://porkbun.com',
    country: 'US',
    aliases: ['porkbun'],
  },
  {
    id: '472',
    ianaId: '472',
    name: 'Dynadot LLC',
    website: 'https://www.dynadot.com',
    country: 'US',
    aliases: ['dynadot'],
  },
  {
    id: '625',
    ianaId: '625',
    name: 'Name.com, Inc.',
    website: 'https://www.name.com',
    country: 'US',
    aliases: ['name.com'],
  },
  {
    id: '886',
    ianaId: '886',
    name: 'Domain.com, LLC',
    website: 'https://www.domain.com',
    country: 'US',
    aliases: ['domain.com'],
  },
  {
    id: '420',
    ianaId: '420',
    name: 'Alibaba Cloud Computing Ltd. d/b/a HiChina',
    website: 'https://wanwang.aliyun.com',
    country: 'CN',
    aliases: ['alibaba', 'aliyun', '阿里云', '万网', 'hichina'],
  },
  {
    id: '1556',
    ianaId: '1556',
    name: 'Chengdu West Dimension Digital Technology Co., Ltd.',
    website: 'https://www.west.cn',
    country: 'CN',
    aliases: ['west.cn', '西部数码', 'westdimension'],
  },
  {
    id: '120',
    ianaId: '120',
    name: 'Xin Net Technology Corporation',
    website: 'https://www.xinnet.com',
    country: 'CN',
    aliases: ['xinnet', '新网'],
  },
  {
    id: '3827',
    ianaId: '3827',
    name: 'Squarespace Domains LLC',
    website: 'https://domains.squarespace.com',
    country: 'US',
    aliases: ['squarespace', 'google domains'],
  },
];

export const REGISTRAR_NOTE =
  '目录为精选 IANA 认证注册商，域名数量统计仅来自本站本地索引（本站查询过的域名），不代表注册商真实规模。';

function haystack(record: RegistrarRecord): string {
  return [record.name, record.ianaId, record.id, ...(record.aliases ?? [])]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

export function findRegistrar(id: string): RegistrarRecord | null {
  const value = id.trim().toLowerCase();
  if (!value) return null;
  return (
    REGISTRARS.find((record) => record.id === value) ??
    REGISTRARS.find((record) => record.ianaId === value) ??
    null
  );
}

export function matchRegistrar(nameOrId: string): RegistrarRecord | null {
  const value = nameOrId.trim().toLowerCase();
  if (!value) return null;

  const direct = findRegistrar(value);
  if (direct) return direct;

  const exact = REGISTRARS.find((record) => record.name.toLowerCase() === value);
  if (exact) return exact;

  return (
    REGISTRARS.find((record) =>
      (record.aliases ?? []).some((alias) => alias.toLowerCase() === value),
    ) ?? null
  );
}

export function searchRegistrars(query: string): RegistrarRecord[] {
  const value = query.trim().toLowerCase();
  if (!value) return REGISTRARS;
  return REGISTRARS.filter((record) => haystack(record).includes(value));
}
