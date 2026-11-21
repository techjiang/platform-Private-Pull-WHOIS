import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ApiError } from '../src/lib/errors.js';
import { parseDomain } from '../src/lib/domain.js';

function expectInvalid(input: string): void {
  assert.throws(
    () => parseDomain(input),
    (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.code, 'INVALID_DOMAIN');
      return true;
    },
  );
}

describe('parseDomain', () => {
  it('规范化大小写、首尾空格与末尾根点', () => {
    const parsed = parseDomain('  Example.COM.  ');
    assert.equal(parsed.ascii, 'example.com');
    assert.equal(parsed.unicode, 'example.com');
    assert.equal(parsed.tld, 'com');
    assert.equal(parsed.sld, 'example');
    assert.equal(parsed.idn, false);
  });

  it('从 URL 中提取域名', () => {
    assert.equal(parseDomain('https://www.example.com/path?q=1#hash').ascii, 'www.example.com');
    assert.equal(parseDomain('http://example.com:8080/').ascii, 'example.com');
    assert.equal(parseDomain('//example.com/a').ascii, 'example.com');
  });

  it('从邮箱中提取域名', () => {
    assert.equal(parseDomain('user.name@example.co.uk').ascii, 'example.co.uk');
  });

  it('支持 IDN 并输出 punycode 与 Unicode 两种形式', () => {
    const parsed = parseDomain('münich.com');
    assert.equal(parsed.ascii, 'xn--mnich-kva.com');
    assert.equal(parsed.unicode, 'münich.com');
    assert.equal(parsed.idn, true);
    assert.equal(parsed.tld, 'com');
  });

  it('拒绝缺少后缀、IP、空格与非法字符', () => {
    expectInvalid('localhost');
    expectInvalid('1.2.3.4');
    expectInvalid('exa mple.com');
    expectInvalid('example.123');
    expectInvalid('http://');
    expectInvalid('');
    expectInvalid('-bad.example.com');
  });
});
