import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { AdminStore } from '../src/admin/store.js';
import { diffSnapshots, snapshotOf, type HistorySnapshot } from '../src/services/history.js';
import { _internal, isPrivateAddress, normalizeIp } from '../src/services/ip.js';
import { normalizeTarget } from '../src/services/uptime.js';
import type { WhoisData } from '../src/whois/types.js';

const tempDirs: string[] = [];

after(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

function sampleData(registrar: string, nameservers: string[]): WhoisData {
  return {
    domain: 'example.com',
    unicodeDomain: 'example.com',
    tld: 'com',
    sld: 'example',
    idn: false,
    available: false,
    registered: true,
    registrar: {
      name: registrar,
      ianaId: '376',
      url: null,
      abuseEmail: null,
      abusePhone: null,
    },
    registrant: {
      name: 'Example',
      organization: 'Example Org',
      email: null,
      country: 'US',
      redacted: true,
    },
    dates: { created: '1995-08-14T04:00:00Z', updated: null, expires: '2026-08-13T04:00:00Z' },
    statuses: ['clientTransferProhibited'],
    nameservers,
    dnssec: 'signed',
    registryDomainId: '2336799_DOMAIN_COM-VRSN',
  };
}

describe('IP helpers', () => {
  it('parses IPv4 and IPv6', () => {
    assert.equal(_internal.ipv4ToBigInt('0.0.0.1'), 1n);
    assert.equal(_internal.ipv4ToBigInt('255.255.255.255'), 4294967295n);
    assert.equal(_internal.ipv6ToBigInt('::1'), 1n);
    assert.equal(_internal.ipv6ToBigInt('2001:db8::1'), 0x20010db8000000000000000000000001n);
    assert.equal(_internal.ipv6ToBigInt('::ffff:192.0.2.1'), 0xffffc0000201n);
  });

  it('blocks private and reserved addresses', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.1.1', '100.64.0.1', '169.254.1.1', '224.0.0.1']) {
      assert.equal(isPrivateAddress(ip), true, ip);
    }
    for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
      assert.equal(isPrivateAddress(ip), false, ip);
    }
    assert.equal(isPrivateAddress('::1'), true);
    assert.equal(isPrivateAddress('fc00::1'), true);
    assert.equal(isPrivateAddress('::ffff:127.0.0.1'), true);
  });

  it('normalizes IP input and rejects invalid values', () => {
    assert.deepEqual(normalizeIp('[2606:4700:4700::1111]'), {
      ip: '2606:4700:4700::1111',
      version: 6,
    });
    assert.throws(() => normalizeIp('not-an-ip'));
  });
});

describe('uptime target normalization', () => {
  it('adds https scheme', () => {
    assert.equal(normalizeTarget('example.com').href, 'https://example.com/');
    assert.equal(normalizeTarget('example.com:8443/path').href, 'https://example.com:8443/path');
  });

  it('rejects unsupported protocols and credentials', () => {
    assert.throws(() => normalizeTarget('ftp://example.com'), /仅支持/);
    assert.throws(() => normalizeTarget('https://user:pass@example.com'), /账号密码/);
  });
});

describe('history snapshots', () => {
  it('creates snapshots and diffs registrar and nameservers', () => {
    const first = snapshotOf(sampleData('Registrar A', ['ns1.example.com']), '2026-01-01T00:00:00Z');
    const second = snapshotOf(
      sampleData('Registrar B', ['ns1.example.com', 'ns2.example.com']),
      '2026-02-01T00:00:00Z',
    );
    const changes = diffSnapshots([first, second]);
    const fields = changes.map((change) => change.field);
    assert.ok(fields.includes('registrar'));
    assert.ok(fields.includes('nameservers'));

    const registrarChange = changes.find((change) => change.field === 'registrar');
    assert.equal(registrarChange?.from, 'Registrar A');
    assert.equal(registrarChange?.to, 'Registrar B');

    const third = snapshotOf(sampleData('Registrar B', ['ns1.example.com', 'ns2.example.com']), '2026-03-01T00:00:00Z');
    assert.equal(diffSnapshots([first, second, third]).length, changes.length);
  });

  it('keeps snapshots immutable to later mutation', () => {
    const snapshot: HistorySnapshot = snapshotOf(sampleData('Registrar A', ['ns1.example.com']));
    snapshot.nameservers.push('ns9.example.com');
    assert.equal(snapshot.nameservers.length, 2);
  });
});

describe('admin feature store', () => {
  it('migrates v2 state and persists feature toggles', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'pullwhois-'));
    tempDirs.push(dir);
    const file = join(dir, 'admin.json');
    await writeFile(
      file,
      JSON.stringify({
        version: 2,
        username: 'admin',
        password: null,
        requireKey: false,
        webEnabled: true,
        keys: [],
      }),
      'utf8',
    );

    const store = new AdminStore(file, { requireKey: false });
    await store.init();

    assert.equal(store.featureEnabled('dns'), true);
    assert.equal(store.featureEnabled('whois'), true);

    await store.setFeatures({ dns: false, uptime: false });
    assert.equal(store.featureEnabled('dns'), false);
    assert.equal(store.featureEnabled('uptime'), false);
    assert.equal(store.featureEnabled('whois'), true);

    const reloaded = new AdminStore(file, { requireKey: false });
    await reloaded.init();
    assert.equal(reloaded.featureEnabled('dns'), false);
    assert.equal(reloaded.featureEnabled('whois'), true);
  });
});
