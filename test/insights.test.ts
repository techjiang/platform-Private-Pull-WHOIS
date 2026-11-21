import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { normalizeDomainList } from '../src/services/available.js';
import { compareResolverRecords } from '../src/services/dnsprop.js';
import { normalizeDnsTypes } from '../src/services/dns.js';
import { scoreHealth } from '../src/services/health.js';
import { analyzeHttpHeaders } from '../src/services/httpcheck.js';

describe('normalizeDnsTypes', () => {
  it('解析并去重多类型', () => {
    assert.deepEqual(normalizeDnsTypes('a, AAAA ,mx'), ['A', 'AAAA', 'MX']);
  });

  it('拒绝非法类型与超量类型', () => {
    assert.deepEqual(normalizeDnsTypes('A,INVALID'), []);
    assert.deepEqual(normalizeDnsTypes('A,AAAA,MX,TXT,NS,CNAME,SOA'), []);
    assert.deepEqual(normalizeDnsTypes(''), []);
  });
});

describe('analyzeHttpHeaders', () => {
  it('完整安全头获得高分', () => {
    const result = analyzeHttpHeaders(
      {
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'content-security-policy': "default-src 'self'",
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=()',
        'cross-origin-opener-policy': 'same-origin',
      },
      {
        https: true,
        cookies: [{ name: 'sid', secure: true, httpOnly: true, sameSite: 'lax' }],
      },
    );

    assert.ok(result.score >= 90, `expected high score, got ${result.score}`);
    assert.equal(result.grade, 'A');
    assert.equal(result.security.every((item) => item.status === 'pass'), true);
    assert.equal(result.issues.length, 0);
  });

  it('缺失响应头时扣分并给出建议', () => {
    const result = analyzeHttpHeaders({}, { https: false, cookies: [] });

    assert.ok(result.score < 60);
    assert.ok(result.issues.length > 0);
    assert.equal(result.security.find((item) => item.id === 'hsts')?.status, 'fail');
  });
});

describe('compareResolverRecords', () => {
  it('记录一致时标记 consistent', () => {
    const result = compareResolverRecords([
      { id: 'ali', name: '阿里 DNS', records: ['1.1.1.1'], status: 'ok' },
      { id: 'cf', name: 'Cloudflare', records: ['1.1.1.1'], status: 'ok' },
    ]);

    assert.equal(result.consistent, true);
    assert.equal(result.groups.length, 1);
    assert.deepEqual(result.differences, []);
  });

  it('记录不一致时按组返回差异', () => {
    const result = compareResolverRecords([
      { id: 'ali', name: '阿里 DNS', records: ['1.1.1.1'], status: 'ok' },
      { id: 'cf', name: 'Cloudflare', records: ['2.2.2.2'], status: 'ok' },
    ]);

    assert.equal(result.consistent, false);
    assert.equal(result.differences.length, 2);
  });
});

describe('scoreHealth', () => {
  it('全部配置正确时接近满分', () => {
    const result = scoreHealth({
      whois: {
        available: false,
        registrar: 'Example Registrar',
        expires: new Date(Date.now() + 400 * 86_400_000).toISOString(),
        dnssec: 'signed',
      },
      dns: { ns: ['ns1.example.com', 'ns2.example.com'], a: ['1.1.1.1'], aaaa: [], soa: true },
      tls: { reachable: true, authorized: true, protocol: 'TLSv1.3', daysRemaining: 90 },
      mail: { mx: true, spf: 'pass', dmarc: 'pass', dkim: 'pass' },
    });

    assert.equal(result.score, 100);
    assert.equal(result.grade, 'A+');
    assert.equal(result.dimensions.length, 4);
    assert.equal(result.issues.length, 0);
  });

  it('上游失败时只降低对应维度', () => {
    const result = scoreHealth({
      whois: null,
      whoisError: 'timeout',
      dns: { ns: [], a: [], aaaa: [], soa: false },
      tls: null,
      mail: null,
    });

    assert.ok(result.score < 50);
    assert.ok(result.dimensions.some((item) => item.score === 0));
    assert.ok(result.issues.length >= 3);
  });
});

describe('normalizeDomainList', () => {
  it('支持多种分隔符并去重', () => {
    const result = normalizeDomainList('Example.com, example.com; test.net\nfoo.org', 10);

    assert.deepEqual(result.domains, ['Example.com', 'test.net', 'foo.org']);
    assert.equal(result.truncated, 0);
  });

  it('超出上限时截断并记录数量', () => {
    const result = normalizeDomainList(['a.com', 'b.com', 'c.com'], 2);

    assert.deepEqual(result.domains, ['a.com', 'b.com']);
    assert.equal(result.truncated, 1);
  });
});
