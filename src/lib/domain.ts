import { domainToASCII, domainToUnicode } from 'node:url';
import { ApiError } from './errors.js';

export interface ParsedDomain {
  /** ASCII / punycode 形式，用于查询 */
  ascii: string;
  /** Unicode 形式，用于展示 */
  unicode: string;
  tld: string;
  sld: string;
  idn: boolean;
}

const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * 接受域名、URL、邮箱中的域名等输入，输出规范化的 punycode 域名。
 * 非法输入抛出 INVALID_DOMAIN。
 */
export function parseDomain(input: string): ParsedDomain {
  if (typeof input !== 'string') {
    throw ApiError.invalidDomain('域名必须是字符串');
  }

  let value = input.trim();
  if (!value) throw ApiError.invalidDomain('域名不能为空');
  if (value.length > 512) throw ApiError.invalidDomain('输入内容过长');

  // 支持从邮箱、URL 中提取域名
  if (value.includes('@')) {
    value = value.slice(value.lastIndexOf('@') + 1);
  }
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  value = value.replace(/^\/\//, '');
  value = value.split(/[/?#\\]/)[0] ?? '';
  value = value.replace(/:\d+$/, '');
  value = value.replace(/\.+$/, '');
  value = value.trim().toLowerCase();

  if (!value) throw ApiError.invalidDomain('未找到有效域名');
  if (/\s/.test(value)) throw ApiError.invalidDomain('域名不能包含空格');
  if (value.includes(':') || IPV4_RE.test(value)) {
    throw ApiError.invalidDomain('不支持 IP 地址，请输入域名');
  }
  if (!value.includes('.')) {
    throw ApiError.invalidDomain('请输入完整域名（包含后缀），例如 example.com');
  }

  const ascii = domainToASCII(value);
  if (!ascii) throw ApiError.invalidDomain('域名格式无效或包含非法字符');
  if (ascii.length > 253) throw ApiError.invalidDomain('域名长度超过 253 个字符');

  const labels = ascii.split('.');
  if (labels.length < 2) {
    throw ApiError.invalidDomain('请输入完整域名（包含后缀），例如 example.com');
  }
  for (const label of labels) {
    if (!LABEL_RE.test(label)) {
      throw ApiError.invalidDomain(`域名标签不合法：${label}`);
    }
  }

  const tld = labels[labels.length - 1] as string;
  if (/^\d+$/.test(tld)) {
    throw ApiError.invalidDomain('顶级域名不能为纯数字');
  }
  if (tld.length < 2) {
    throw ApiError.invalidDomain('顶级域名长度不足');
  }

  const unicode = domainToUnicode(ascii) || ascii;

  return {
    ascii,
    unicode,
    tld,
    sld: labels[labels.length - 2] as string,
    idn: unicode !== ascii,
  };
}
