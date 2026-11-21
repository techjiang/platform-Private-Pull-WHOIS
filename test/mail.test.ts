import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { normalizeSelectors, parseDkim, parseDmarc, parseSpf } from '../src/services/mail.js';

describe('SPF 解析', () => {
  it('解析常见 SPF 记录', () => {
    const info = parseSpf('v=spf1 include:_spf.google.com a mx ip4:1.2.3.4 -all');
    assert.equal(info.version, true);
    assert.equal(info.valid, true);
    assert.deepEqual(info.includes, ['_spf.google.com']);
    assert.deepEqual(info.ip4, ['1.2.3.4']);
    assert.equal(info.all, 'all');
    assert.equal(info.allQualifier, '-');
    assert.equal(info.lookupCount, 3);
    assert.deepEqual(info.warnings, []);
  });

  it('缺少 all 机制给出提示但仍可用', () => {
    const info = parseSpf('v=spf1 include:example.com');
    assert.equal(info.valid, true);
    assert.equal(info.all, null);
    assert.equal(info.warnings.length, 1);
  });

  it('+all 标记为风险', () => {
    const info = parseSpf('v=spf1 +all');
    assert.equal(info.allQualifier, '+');
    assert.match(info.warnings[0], /伪造风险/);
  });

  it('DNS 查询机制超过 10 次判定无效', () => {
    const includes = Array.from({ length: 11 }, (_, index) => `include:spf${index}.example.com`).join(' ');
    const info = parseSpf(`v=spf1 ${includes} -all`);
    assert.equal(info.valid, false);
    assert.equal(info.lookupCount, 11);
    assert.match(info.errors[0], /10 次/);
  });

  it('缺少版本标识判定无效', () => {
    const info = parseSpf('include:example.com -all');
    assert.equal(info.version, false);
    assert.equal(info.valid, false);
  });
});

describe('DMARC 解析', () => {
  it('解析拒收策略与报告地址', () => {
    const info = parseDmarc('v=DMARC1; p=reject; sp=quarantine; pct=50; adkim=s; rua=mailto:a@example.com, mailto:b@example.com');
    assert.equal(info.valid, true);
    assert.equal(info.policy, 'reject');
    assert.equal(info.subdomainPolicy, 'quarantine');
    assert.equal(info.pct, 50);
    assert.equal(info.alignment.dkim, 's');
    assert.equal(info.alignment.spf, 'r');
    assert.equal(info.rua.length, 2);
  });

  it('缺失或非法策略判定无效', () => {
    const missing = parseDmarc('v=DMARC1; rua=mailto:a@example.com');
    assert.equal(missing.valid, false);
    assert.match(missing.errors.join(), /p=/);

    const invalid = parseDmarc('v=DMARC1; p=block');
    assert.equal(invalid.valid, false);
    assert.match(invalid.errors.join(), /block/);
  });

  it('pct 越界会被限制在 0-100', () => {
    assert.equal(parseDmarc('v=DMARC1; p=none; pct=200').pct, 100);
    assert.equal(parseDmarc('v=DMARC1; p=none; pct=-20').pct, 0);
  });
});

describe('DKIM 解析', () => {
  it('解析可用公钥记录', () => {
    const info = parseDkim('v=DKIM1; k=rsa; h=sha256; p=MIIBIjANBgkq');
    assert.equal(info.valid, true);
    assert.equal(info.keyType, 'rsa');
    assert.equal(info.keyPresent, true);
    assert.equal(info.revoked, false);
    assert.deepEqual(info.hashAlgorithms, ['sha256']);
  });

  it('空公钥视为撤销', () => {
    const info = parseDkim('v=DKIM1; k=rsa; p=');
    assert.equal(info.valid, false);
    assert.equal(info.revoked, true);
    assert.equal(info.keyPresent, false);
  });

  it('缺少公钥判定无效', () => {
    const info = parseDkim('v=DKIM1; k=rsa');
    assert.equal(info.valid, false);
    assert.match(info.errors.join(), /p=/);
  });
});

describe('DKIM 选择器', () => {
  it('去重并转小写', () => {
    assert.deepEqual(normalizeSelectors('Default, Google, default'), ['default', 'google']);
  });

  it('非法字符抛错', () => {
    assert.throws(() => normalizeSelectors('bad selector'), /格式/);
  });

  it('超过 6 个抛错', () => {
    assert.throws(() => normalizeSelectors('s1,s2,s3,s4,s5,s6,s7'), /6 个/);
  });
});
