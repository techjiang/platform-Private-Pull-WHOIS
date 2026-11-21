import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createRegistrant,
  emptyParsedRecord,
  extractNameservers,
  mergeParsed,
  normalizeDnssec,
  normalizeStatus,
  parseWhoisDate,
} from '../src/whois/parsers.js';

describe('parseWhoisDate', () => {
  it('解析 ISO 与常见分隔格式', () => {
    assert.equal(parseWhoisDate('2024-01-02T03:04:05Z'), '2024-01-02T03:04:05.000Z');
    assert.equal(parseWhoisDate('2024-01-02'), '2024-01-02T00:00:00.000Z');
    assert.equal(parseWhoisDate('2024.01.02'), '2024-01-02T00:00:00.000Z');
    assert.equal(parseWhoisDate('2024/01/02'), '2024-01-02T00:00:00.000Z');
    assert.equal(parseWhoisDate('20240102'), '2024-01-02T00:00:00.000Z');
  });

  it('解析英文月份与中文日期', () => {
    assert.equal(parseWhoisDate('02-Jan-2024'), '2024-01-02T00:00:00.000Z');
    assert.equal(parseWhoisDate('2 January 2024'), '2024-01-02T00:00:00.000Z');
    assert.equal(parseWhoisDate('Jan 2, 2024'), '2024-01-02T00:00:00.000Z');
    assert.equal(parseWhoisDate('2024年1月2日'), '2024-01-02T00:00:00.000Z');
  });

  it('点号按日优先、斜杠按月优先', () => {
    assert.equal(parseWhoisDate('02.01.2024'), '2024-01-02T00:00:00.000Z');
    assert.equal(parseWhoisDate('02/01/2024'), '2024-02-01T00:00:00.000Z');
  });

  it('无法确定时返回 null', () => {
    assert.equal(parseWhoisDate(''), null);
    assert.equal(parseWhoisDate(null), null);
    assert.equal(parseWhoisDate('not a date'), null);
    assert.equal(parseWhoisDate('2024-02-31'), null);
    assert.equal(parseWhoisDate('before 2020'), null);
  });
});

describe('normalizeStatus', () => {
  it('归一化 EPP 状态并去除 URL 与括号', () => {
    assert.equal(
      normalizeStatus('clientTransferProhibited https://icann.org/epp#clientTransferProhibited'),
      'clientTransferProhibited',
    );
    assert.equal(normalizeStatus('server delete prohibited'), 'serverDeleteProhibited');
    assert.equal(normalizeStatus('registered until expiry date'), 'active');
    assert.equal(normalizeStatus('  ACTIVE  '), 'active');
  });

  it('空值返回 null，未知状态保留原文', () => {
    assert.equal(normalizeStatus('   '), null);
    assert.equal(normalizeStatus('some custom state'), 'some custom state');
  });
});

describe('extractNameservers', () => {
  it('清洗、去重并过滤 IP 与非法值', () => {
    const servers = extractNameservers([
      'NS1.Example.COM 192.0.2.1',
      'ns2.example.com.',
      'ns1.example.com',
      'bad_host',
    ]);
    assert.deepEqual(servers, ['ns1.example.com', 'ns2.example.com']);
  });
});

describe('normalizeDnssec', () => {
  it('识别签名状态', () => {
    assert.equal(normalizeDnssec(['signedDelegation']), 'signed');
    assert.equal(normalizeDnssec(['yes']), 'signed');
    assert.equal(normalizeDnssec(['unsigned']), 'unsigned');
    assert.equal(normalizeDnssec(['no']), 'unsigned');
    assert.equal(normalizeDnssec([]), 'unknown');
    assert.equal(normalizeDnssec(['maybe']), 'unknown');
  });
});

describe('createRegistrant', () => {
  it('保留真实组织信息时不误标 redacted', () => {
    const registrant = createRegistrant({ organization: 'GitHub, Inc.' }, 'Registrant Country: US');
    assert.ok(registrant);
    assert.equal(registrant.organization, 'GitHub, Inc.');
    assert.equal(registrant.redacted, false);
  });

  it('字段被隐私保护时标记 redacted 并清空值', () => {
    const registrant = createRegistrant({ name: 'REDACTED FOR PRIVACY' }, '');
    assert.ok(registrant);
    assert.equal(registrant.name, null);
    assert.equal(registrant.redacted, true);
  });

  it('完全无数据但声明隐私保护时标记 redacted', () => {
    const registrant = createRegistrant({}, 'Registrant data protected by GDPR.');
    assert.ok(registrant);
    assert.equal(registrant.redacted, true);
  });

  it('无任何信息时返回 null', () => {
    assert.equal(createRegistrant({}, 'Domain Name: EXAMPLE.COM'), null);
  });
});

describe('mergeParsed', () => {
  it('主来源优先，缺失字段由次来源补齐', () => {
    const primary = emptyParsedRecord();
    primary.registrar = {
      name: 'Registry Registrar',
      ianaId: '1',
      url: null,
      abuseEmail: null,
      abusePhone: null,
    };
    primary.dates.created = '2020-01-01T00:00:00.000Z';
    primary.nameservers = ['ns1.example.com'];
    primary.dnssec = 'unknown';

    const secondary = emptyParsedRecord();
    secondary.dates.created = '2019-01-01T00:00:00.000Z';
    secondary.dates.expires = '2030-01-01T00:00:00.000Z';
    secondary.nameservers = ['ns2.example.com'];
    secondary.dnssec = 'signed';
    secondary.statuses = ['clientTransferProhibited'];

    const merged = mergeParsed(primary, secondary);
    assert.equal(merged.registrar?.name, 'Registry Registrar');
    assert.equal(merged.dates.created, '2020-01-01T00:00:00.000Z');
    assert.equal(merged.dates.expires, '2030-01-01T00:00:00.000Z');
    assert.deepEqual(merged.nameservers, ['ns1.example.com', 'ns2.example.com']);
    assert.equal(merged.dnssec, 'signed');
    assert.deepEqual(merged.statuses, ['clientTransferProhibited']);
  });

  it('任一来源标记可注册时直接返回主来源', () => {
    const primary = emptyParsedRecord();
    const merged = mergeParsed(primary, emptyParsedRecord(true));
    assert.equal(merged.available, false);
  });
});
