export type DnssecStatus = 'signed' | 'unsigned' | 'unknown';
export type LookupSource = 'rdap' | 'whois';

export interface RegistrarInfo {
  name: string | null;
  ianaId: string | null;
  url: string | null;
  abuseEmail: string | null;
  abusePhone: string | null;
}

export interface RegistrantInfo {
  name: string | null;
  organization: string | null;
  email: string | null;
  country: string | null;
  redacted: boolean;
}

export interface DatesInfo {
  created: string | null;
  updated: string | null;
  expires: string | null;
}

/** 统一后的域名信息，RDAP 与 WHOIS 两种来源共用 */
export interface WhoisData {
  domain: string;
  unicodeDomain: string;
  tld: string;
  sld: string;
  idn: boolean;
  available: boolean;
  registered: boolean;
  registrar: RegistrarInfo | null;
  registrant: RegistrantInfo | null;
  dates: DatesInfo;
  statuses: string[];
  nameservers: string[];
  dnssec: DnssecStatus;
  registryDomainId: string | null;
  raw?: string;
}

/** 解析器输出的中间结构 */
export interface ParsedRecord {
  available: boolean;
  /**
   * 结果是否足以判定注册状态。
   * false 表示上游既未给出“未注册”提示、也没有任何注册证据（可能是限流或异常响应），
   * 调用方应视为“无法确认”，不能当作“已注册”。
   */
  conclusive?: boolean;
  registrar: RegistrarInfo | null;
  registrant: RegistrantInfo | null;
  dates: DatesInfo;
  statuses: string[];
  nameservers: string[];
  dnssec: DnssecStatus;
  registryDomainId: string | null;
}

export interface LookupRecord {
  data: WhoisData;
  source: LookupSource;
  server: string;
  durationMs: number;
  queriedAt: string;
}

export interface LookupOptions {
  forceRefresh?: boolean;
  includeRaw?: boolean;
}

export interface SourceAttempt {
  source: LookupSource;
  server: string;
  ok: boolean;
  error?: string;
  durationMs: number;
}
