import { isIP } from 'node:net';

function ipv4ToBigInt(ip: string): bigint | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    value = (value << 8n) + BigInt(octet);
  }
  return value;
}

function ipv6ToBigInt(ip: string): bigint | null {
  const zoneIndex = ip.indexOf('%');
  let value = zoneIndex === -1 ? ip : ip.slice(0, zoneIndex);
  if (!value.includes(':')) return null;

  let embedded: bigint | null = null;
  const lastColon = value.lastIndexOf(':');
  const tail = value.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = ipv4ToBigInt(tail);
    if (v4 === null) return null;
    embedded = v4;
    value = `${value.slice(0, lastColon + 1)}0:0`;
  }

  const [headText, tailText] = value.split('::');
  const head = headText ? headText.split(':') : [];
  const rest = tailText === undefined ? [] : tailText ? tailText.split(':') : [];

  if (tailText === undefined) {
    if (head.length !== 8) return null;
  } else if (head.length + rest.length > 6) {
    return null;
  }

  const groups = [...head, ...Array(8 - head.length - rest.length).fill('0'), ...rest];
  let result = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) return null;
    result = (result << 16n) + BigInt(parseInt(group, 16));
  }

  if (embedded !== null) {
    result = (result & ~0xffffffffn) | embedded;
  }
  return result;
}

function bigIntOf(ip: string, version: 4 | 6): bigint | null {
  return version === 4 ? ipv4ToBigInt(ip) : ipv6ToBigInt(ip);
}

/** 校验单条 IP 规则（IPv4 / IPv6 / CIDR），返回规范化文本 */
export function normalizeIpRule(input: string): string | null {
  const rule = input.trim();
  if (!rule) return null;

  const [address, prefixText, extra] = rule.split('/');
  if (extra !== undefined || !address) return null;
  const version = isIP(address);
  if (version !== 4 && version !== 6) return null;

  if (prefixText === undefined) return address;
  const bits = version === 4 ? 32 : 128;
  const prefix = Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return null;
  return `${address}/${prefix}`;
}

/** 判断客户端 IP 是否落在规则内（支持单 IP 与 CIDR） */
export function matchIpRule(ip: string, rule: string): boolean {
  const normalized = normalizeIpRule(rule);
  if (!normalized) return false;

  const [address, prefixText] = normalized.split('/');
  const version = isIP(address ?? '');
  const clientVersion = isIP(ip);
  if (version !== 4 && version !== 6) return false;
  if (clientVersion !== version) return false;

  const client = bigIntOf(ip, version);
  const network = bigIntOf(address ?? '', version);
  if (client === null || network === null) return false;

  if (prefixText === undefined) return client === network;

  const bits = version === 4 ? 32 : 128;
  const prefix = Number(prefixText);
  if (prefix === 0) return true;
  const shift = BigInt(bits - prefix);
  return client >> shift === network >> shift;
}
