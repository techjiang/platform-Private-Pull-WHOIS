import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { isAvailableText, parseWhois } from '../src/whois/whois-text.js';

const VERISIGN_RECORD = `
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://res-dom.iana.org
Updated Date: 2026-08-14T08:01:43Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2027-08-13T04:00:00Z
Registrar: RESERVED-Internet Assigned Numbers Authority
Registrar IANA ID: 376
Registrar Abuse Contact Email: abuse@iana.org
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: ELLIOTT.NS.CLOUDFLARE.COM
Name Server: HERA.NS.CLOUDFLARE.COM
DNSSEC: signedDelegation
`;

describe('parseWhois', () => {
  it('解析 Verisign 风格的 .com 记录', () => {
    const parsed = parseWhois(VERISIGN_RECORD);
    assert.equal(parsed.available, false);
    assert.equal(parsed.registrar?.name, 'RESERVED-Internet Assigned Numbers Authority');
    assert.equal(parsed.registrar?.ianaId, '376');
    assert.equal(parsed.registrar?.abuseEmail, 'abuse@iana.org');
    assert.equal(parsed.dates.created, '1995-08-14T04:00:00.000Z');
    assert.equal(parsed.dates.updated, '2026-08-14T08:01:43.000Z');
    assert.equal(parsed.dates.expires, '2027-08-13T04:00:00.000Z');
    assert.deepEqual(parsed.statuses, ['clientDeleteProhibited', 'clientTransferProhibited']);
    assert.deepEqual(parsed.nameservers, ['elliott.ns.cloudflare.com', 'hera.ns.cloudflare.com']);
    assert.equal(parsed.dnssec, 'signed');
    assert.equal(parsed.registryDomainId, '2336799_DOMAIN_COM-VRSN');
  });

  it('解析 JPRS 方括号字段', () => {
    const parsed = parseWhois(`
[Domain Name]                   EXAMPLE.JP
[登録年月日]                    2000/01/01
[有効期限]                      2025/01/31
[状態]                          Active
[ネームサーバ]                  ns1.example.jp
[ネームサーバ]                  ns2.example.jp
`);
    assert.equal(parsed.available, false);
    assert.equal(parsed.dates.created, '2000-01-01T00:00:00.000Z');
    assert.equal(parsed.dates.expires, '2025-01-31T00:00:00.000Z');
    assert.deepEqual(parsed.statuses, ['active']);
    assert.deepEqual(parsed.nameservers, ['ns1.example.jp', 'ns2.example.jp']);
  });

  it('识别中文日期与多行续值', () => {
    const parsed = parseWhois(`
Domain Name: EXAMPLE.CN
Registrar: 示例注册商
注册时间: 2024年1月2日
到期时间: 2025-01-02
Domain Status: ok
DNS服务器: ns1.example.cn
`);
    assert.equal(parsed.registrar?.name, '示例注册商');
    assert.equal(parsed.dates.created, '2024-01-02T00:00:00.000Z');
    assert.equal(parsed.dates.expires, '2025-01-02T00:00:00.000Z');
    assert.deepEqual(parsed.statuses, ['ok']);
  });

  it('REDACTED 的 registryDomainId 被丢弃', () => {
    const parsed = parseWhois(`
Domain Name: PRIVATE.EXAMPLE
Registry Domain ID: REDACTED FOR PRIVACY
Registrar: Example Registrar
Creation Date: 2021-05-06
`);
    assert.equal(parsed.registryDomainId, null);
  });
});

describe('isAvailableText', () => {
  it('识别常见的未注册提示', () => {
    assert.equal(isAvailableText('No match for "NOT-REGISTERED-12345.COM".'), true);
    assert.equal(isAvailableText('Domain not found.'), true);
    assert.equal(isAvailableText('Status: free'), true);
    assert.equal(isAvailableText('The queried object does not exist.'), true);
  });

  it('已注册或上游限流文本不会误判为可注册', () => {
    assert.equal(isAvailableText(VERISIGN_RECORD), false);
    assert.equal(isAvailableText('Too many requests, please try again later.'), false);
    assert.equal(isAvailableText(''), false);
  });
});
