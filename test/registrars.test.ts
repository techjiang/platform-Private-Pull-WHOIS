import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { matchIpRule, normalizeIpRule } from '../src/lib/netmatch.js';
import {
  mergeRegistrars,
  parseCsv,
  parseIanaXml,
  parseIcannCsv,
  type RegistrarBase,
} from '../src/services/registrars.js';

const IANA_SAMPLE = `<?xml version="1.0"?>
<registry id="registrar-ids">
  <updated>2026-11-20</updated>
  <record updated="2026-11-01">
    <value>146</value>
    <name>GoDaddy.com, LLC</name>
    <status>Accredited</status>
    <server>https://rdap.godaddy.com/v1/</server>
  </record>
  <record updated="2026-10-01">
    <value>9999</value>
    <name>Example &amp; Partners</name>
    <status>Terminated</status>
  </record>
</registry>`;

const ICANN_SAMPLE = `Registrar Name,IANA Number,Country/Territory,Public Contact,Link
"GoDaddy.com, LLC",146,United States,+1.6021234567,https://www.godaddy.com
"Example & Partners",9999,Germany,,https://example.test
`;

describe('IANA / ICANN registrar sources', () => {
  it('parses IANA registrar XML with status and RDAP server', () => {
    const parsed = parseIanaXml(IANA_SAMPLE);
    assert.equal(parsed.updated, '2026-11-20');
    assert.equal(parsed.entries.length, 2);
    assert.equal(parsed.entries[0]?.ianaId, '146');
    assert.equal(parsed.entries[0]?.name, 'GoDaddy.com, LLC');
    assert.equal(parsed.entries[0]?.status, 'accredited');
    assert.equal(parsed.entries[0]?.rdapServer, 'https://rdap.godaddy.com/v1/');
    assert.equal(parsed.entries[0]?.updated, '2026-11-01');
    assert.equal(parsed.entries[1]?.name, 'Example & Partners');
    assert.equal(parsed.entries[1]?.status, 'terminated');
  });

  it('parses quoted CSV fields and normalizes websites', () => {
    const rows = parseCsv(ICANN_SAMPLE.replace(/^\uFEFF/, ''));
    assert.equal(rows.length, 3);
    assert.equal(rows[1]?.[0], 'GoDaddy.com, LLC');

    const entries = parseIcannCsv(ICANN_SAMPLE);
    assert.equal(entries.length, 2);
    assert.equal(entries[0]?.country, 'United States');
    assert.equal(entries[0]?.website, 'https://www.godaddy.com/');
    assert.equal(entries[0]?.contact, '+1.6021234567');
    assert.equal(entries[1]?.ianaId, '9999');
  });

  it('merges IANA status with ICANN enrichment and curated aliases', () => {
    const iana = parseIanaXml(IANA_SAMPLE).entries;
    const icann = parseIcannCsv(ICANN_SAMPLE);
    const curated: Parameters<typeof mergeRegistrars>[2] = [
      {
        id: 'godaddy',
        ianaId: '146',
        name: 'GoDaddy',
        website: 'https://www.godaddy.com',
        country: 'US',
        aliases: ['GoDaddy.com'],
      },
    ];

    const merged = mergeRegistrars(iana, icann, curated);
    const godaddy = merged.find((entry: RegistrarBase) => entry.ianaId === '146');
    assert.ok(godaddy);
    assert.equal(godaddy.country, 'United States');
    assert.equal(godaddy.status, 'accredited');
    assert.equal(godaddy.origin, 'iana+icann');
    assert.ok(godaddy.aliases.includes('GoDaddy.com'));

    const example = merged.find((entry: RegistrarBase) => entry.ianaId === '9999');
    assert.equal(example?.status, 'terminated');
    assert.equal(example?.country, 'Germany');
  });
});

describe('IP allowlist matching', () => {
  it('normalizes valid rules and rejects invalid ones', () => {
    assert.equal(normalizeIpRule(' 203.0.113.5 '), '203.0.113.5');
    assert.equal(normalizeIpRule('203.0.113.0/24'), '203.0.113.0/24');
    assert.equal(normalizeIpRule('2001:db8::/32'), '2001:db8::/32');
    assert.equal(normalizeIpRule('999.1.1.1'), null);
    assert.equal(normalizeIpRule('203.0.113.0/40'), null);
  });

  it('matches IPv4/IPv6 addresses and CIDR ranges', () => {
    assert.equal(matchIpRule('203.0.113.9', '203.0.113.0/24'), true);
    assert.equal(matchIpRule('203.0.114.9', '203.0.113.0/24'), false);
    assert.equal(matchIpRule('203.0.113.9', '203.0.113.9'), true);
    assert.equal(matchIpRule('2001:db8::1', '2001:db8::/32'), true);
    assert.equal(matchIpRule('2001:db9::1', '2001:db8::/32'), false);
    assert.equal(matchIpRule('::ffff:203.0.113.9', '203.0.113.0/24'), false);
  });
});
