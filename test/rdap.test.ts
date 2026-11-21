import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseRdapDomain } from '../src/whois/rdap.js';

const RDAP_RECORD = {
  objectClassName: 'domain',
  handle: '2336799_DOMAIN_COM-VRSN',
  ldhName: 'EXAMPLE.COM',
  status: [
    'client delete prohibited',
    'client transfer prohibited',
    'active',
  ],
  events: [
    { eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' },
    { eventAction: 'last changed', eventDate: '2026-08-14T08:01:43Z' },
    { eventAction: 'expiration', eventDate: '2027-08-13T04:00:00Z' },
  ],
  nameservers: [{ ldhName: 'A.IANA-SERVERS.NET' }, { ldhName: 'B.IANA-SERVERS.NET' }],
  secureDNS: { delegationSigned: true },
  entities: [
    {
      roles: ['registrar'],
      publicIds: [{ type: 'IANA Registrar ID', identifier: '376' }],
      vcardArray: [
        'vcard',
        [
          ['version', {}, 'text', '4.0'],
          ['fn', {}, 'text', 'RESERVED-Internet Assigned Numbers Authority'],
          ['url', {}, 'uri', 'http://res-dom.iana.org'],
        ],
      ],
      entities: [
        {
          roles: ['abuse'],
          vcardArray: [
            'vcard',
            [
              ['fn', {}, 'text', 'IANA Abuse'],
              ['email', {}, 'text', 'abuse@iana.org'],
              ['tel', {}, 'text', 'tel:+1.555.0100'],
            ],
          ],
        },
      ],
    },
    {
      roles: ['registrant'],
      vcardArray: [
        'vcard',
        [
          ['fn', {}, 'text', 'Example Inc.'],
          ['adr', {}, 'text', ['', '', '', '', '', 'US']],
        ],
      ],
    },
  ],
};

describe('parseRdapDomain', () => {
  it('解析注册商、滥用联系人、注册人与日期', () => {
    const parsed = parseRdapDomain(RDAP_RECORD);
    assert.equal(parsed.available, false);
    assert.equal(parsed.registrar?.name, 'RESERVED-Internet Assigned Numbers Authority');
    assert.equal(parsed.registrar?.ianaId, '376');
    assert.equal(parsed.registrar?.url, 'http://res-dom.iana.org');
    assert.equal(parsed.registrar?.abuseEmail, 'abuse@iana.org');
    assert.equal(parsed.registrar?.abusePhone, '+1.555.0100');
    assert.equal(parsed.registrant?.name, 'Example Inc.');
    assert.equal(parsed.registrant?.country, 'US');
    assert.equal(parsed.dates.created, '1995-08-14T04:00:00.000Z');
    assert.equal(parsed.dates.updated, '2026-08-14T08:01:43.000Z');
    assert.equal(parsed.dates.expires, '2027-08-13T04:00:00.000Z');
    assert.deepEqual(parsed.statuses, [
      'clientDeleteProhibited',
      'clientTransferProhibited',
      'active',
    ]);
    assert.deepEqual(parsed.nameservers, ['a.iana-servers.net', 'b.iana-servers.net']);
    assert.equal(parsed.dnssec, 'signed');
    assert.equal(parsed.registryDomainId, '2336799_DOMAIN_COM-VRSN');
  });

  it('非 domain 对象或缺少 ldhName 时返回空记录', () => {
    const parsed = parseRdapDomain({ objectClassName: 'entity', ldhName: 'EXAMPLE.COM' });
    assert.equal(parsed.available, false);
    assert.equal(parsed.registrar, null);
    assert.equal(parsed.dates.created, null);
  });

  it('delegationSigned 为 false 时标记 unsigned', () => {
    const parsed = parseRdapDomain({ ...RDAP_RECORD, secureDNS: { delegationSigned: false } });
    assert.equal(parsed.dnssec, 'unsigned');
  });
});
