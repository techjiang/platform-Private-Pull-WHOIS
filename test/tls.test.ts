import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { PeerCertificate } from 'node:tls';
import { buildCertificateInfo, parseTlsTarget } from '../src/services/tls.js';

const CERT = {
  subject: { CN: 'example.com', O: 'Example Inc', C: 'US' },
  issuer: { CN: 'Example CA', O: 'Example Trust', C: 'US' },
  valid_from: 'Jan 1 00:00:00 2026 GMT',
  valid_to: 'Dec 31 23:59:59 2026 GMT',
  serialNumber: 'ABCDEF',
  fingerprint256: 'AA:BB:CC',
  subjectaltname: 'DNS:example.com, DNS:*.example.com, IP Address:1.2.3.4',
  bits: 2048,
} as unknown as PeerCertificate;

describe('TLS 目标解析', () => {
  it('解析裸域名并使用默认 443 端口', () => {
    assert.deepEqual(parseTlsTarget('Example.COM'), {
      host: 'example.com',
      port: 443,
      servername: 'example.com',
    });
  });

  it('解析带端口与路径的 URL', () => {
    assert.deepEqual(parseTlsTarget('https://example.com:8443/status?x=1'), {
      host: 'example.com',
      port: 8443,
      servername: 'example.com',
    });
  });

  it('允许查询参数覆盖端口', () => {
    assert.equal(parseTlsTarget('example.com', '9443').port, 9443);
  });

  it('拒绝 IP 地址', () => {
    assert.throws(() => parseTlsTarget('1.2.3.4'), /域名查询证书/);
  });

  it('拒绝非 http(s) 协议', () => {
    assert.throws(() => parseTlsTarget('ftp://example.com'), /http/);
  });

  it('拒绝越界端口', () => {
    assert.throws(() => parseTlsTarget('example.com', 70000), /端口/);
  });
});

describe('TLS 证书归一化', () => {
  it('提取主体、颁发者、SAN 与剩余天数', () => {
    const info = buildCertificateInfo(CERT, Date.parse('2026-12-01T00:00:00Z'));
    assert.ok(info);

    assert.equal(info.subject.commonName, 'example.com');
    assert.equal(info.issuer.organization, 'Example Trust');
    assert.deepEqual(info.san, ['example.com', '*.example.com']);
    assert.equal(info.keyBits, 2048);
    assert.equal(info.chainLength, 1);
    assert.equal(info.expired, false);
    assert.equal(info.notYetValid, false);
    assert.equal(info.daysRemaining, 30);
    assert.equal(info.validTo, '2026-12-31T23:59:59.000Z');
  });

  it('过期证书标记为 expired', () => {
    const info = buildCertificateInfo(CERT, Date.parse('2027-01-10T00:00:00Z'));
    assert.ok(info);
    assert.equal(info.expired, true);
    assert.ok(info.daysRemaining !== null && info.daysRemaining < 0);
  });

  it('空证书返回 null', () => {
    assert.equal(buildCertificateInfo(null), null);
  });
});
