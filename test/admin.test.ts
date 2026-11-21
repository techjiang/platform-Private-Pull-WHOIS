import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { AdminStore, hashKey, validateCredentials } from '../src/admin/store.js';

const tempDirs: string[] = [];

async function createStore(
  options: { password?: string; webEnabled?: boolean } = {},
): Promise<{ store: AdminStore; file: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'pull-whois-admin-'));
  tempDirs.push(dir);
  const file = join(dir, 'admin.json');
  const store = new AdminStore(file, {
    requireKey: false,
    username: 'admin',
    ...options,
  });
  await store.init();
  return { store, file };
}

after(async () => {
  await Promise.all(tempDirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

describe('AdminStore', () => {
  it('创建密钥后只暴露前缀与摘要', async () => {
    const { store } = await createStore();
    const created = await store.createKey('  生产环境  ');

    assert.match(created.token, /^pw_[A-Za-z0-9_-]{20,}$/);
    assert.equal(created.record.name, '生产环境');
    assert.equal(created.record.prefix, created.token.slice(0, 10));
    assert.equal(created.record.enabled, true);
    assert.equal(created.record.hash, hashKey(created.token));

    const listed = store.listKeys();
    assert.equal(listed.length, 1);
    assert.equal('hash' in listed[0], false);

    assert.ok(store.verify(created.token));
    assert.equal(store.verify('pw_invalid'), null);
  });

  it('停用、启用与删除会立即影响鉴权', async () => {
    const { store } = await createStore();
    const { record, token } = await store.createKey();
    assert.equal(record.name, '未命名密钥');

    const disabled = await store.updateKey(record.id, { enabled: false });
    assert.equal(disabled?.enabled, false);
    assert.equal(store.verify(token), null);

    const enabled = await store.updateKey(record.id, { enabled: true, name: '新名称' });
    assert.equal(enabled?.enabled, true);
    assert.equal(enabled?.name, '新名称');
    assert.ok(store.verify(token));

    assert.equal(await store.deleteKey(record.id), true);
    assert.equal(store.verify(token), null);
    assert.equal(await store.deleteKey(record.id), false);
  });

  it('访问策略与密钥可持久化并在重启后恢复', async () => {
    const { store, file } = await createStore();
    const { record, token } = await store.createKey('持久化测试');
    await store.setRequireKey(true);

    store.touch(record.id);
    store.touch(record.id);
    await store.flush();

    const reloaded = new AdminStore(file, { requireKey: false });
    await reloaded.init();

    assert.equal(reloaded.requireKey, true);
    assert.equal(reloaded.keyCount, 1);
    assert.equal(reloaded.listKeys()[0]?.requestCount, 2);
    assert.ok(reloaded.verify(token));
  });

  it('首次启动使用传入的默认策略', async () => {
    const { store } = await createStore();
    assert.equal(store.requireKey, false);
    assert.equal(store.webEnabled, true);

    const dir = await mkdtemp(join(tmpdir(), 'pull-whois-admin-'));
    tempDirs.push(dir);
    const strict = new AdminStore(join(dir, 'admin.json'), {
      requireKey: true,
      webEnabled: false,
    });
    await strict.init();
    assert.equal(strict.requireKey, true);
    assert.equal(strict.webEnabled, false);
  });

  it('管理员凭据以 scrypt 摘要持久化，且不落盘明文', async () => {
    const { store, file } = await createStore({ password: 'admin@114514' });

    assert.equal(store.hasCredentials, true);
    assert.equal(store.username, 'admin');
    assert.ok(await store.verifyCredentials('admin', 'admin@114514'));
    assert.equal(await store.verifyCredentials('admin', 'wrong-password'), false);
    assert.equal(await store.verifyCredentials('root', 'admin@114514'), false);

    const raw = JSON.parse(await readFile(file, 'utf8'));
    assert.equal(raw.version, 6);
    assert.equal(raw.webPolicy.rateLimit, 120);
    assert.deepEqual(raw.scheduler, { enabled: true, idleOnly: true });
    assert.equal(raw.password.algo, 'scrypt');
    assert.equal(raw.password.N, 32768);
    assert.equal(raw.username, 'admin');
    assert.equal(JSON.stringify(raw).includes('admin@114514'), false);

    await store.setCredentials('ops-admin', 'NewPass#2026');
    assert.equal(store.username, 'ops-admin');
    assert.ok(await store.verifyCredentials('ops-admin', 'NewPass#2026'));
    assert.equal(await store.verifyCredentials('admin', 'admin@114514'), false);

    const reloaded = new AdminStore(file, { requireKey: false });
    await reloaded.init();
    assert.equal(reloaded.username, 'ops-admin');
    assert.ok(await reloaded.verifyCredentials('ops-admin', 'NewPass#2026'));
  });

  it('网页端开关与 API 策略相互独立并可持久化', async () => {
    const { store, file } = await createStore({ password: 'admin@114514' });

    await store.setRequireKey(true);
    await store.setWebEnabled(false);
    assert.equal(store.requireKey, true);
    assert.equal(store.webEnabled, false);

    await store.setWebEnabled(true);
    assert.equal(store.requireKey, true);
    assert.equal(store.webEnabled, true);

    const policy = await store.setWebPolicy({
      rateLimit: 200,
      rateWindowSec: 30,
      dailyQuota: 500,
      blockAfter: 3,
      blockSec: 60,
    });
    assert.deepEqual(policy, {
      rateLimit: 200,
      rateWindowSec: 30,
      dailyQuota: 500,
      blockAfter: 3,
      blockSec: 60,
    });

    const reloaded = new AdminStore(file, { requireKey: false });
    await reloaded.init();
    assert.equal(reloaded.requireKey, true);
    assert.equal(reloaded.webEnabled, true);
    assert.deepEqual(reloaded.webPolicy, policy);
  });

  it('凭据规则校验', () => {
    assert.equal(validateCredentials('admin', 'admin@114514'), null);
    assert.ok(validateCredentials('ab', 'admin@114514'));
    assert.ok(validateCredentials('admin', 'short'));
    assert.ok(validateCredentials('admin space', 'admin@114514'));
  });

  it('密钥支持有效期、配额、限速、作用域与 IP 白名单', async () => {
    const { store } = await createStore();
    const { record, token } = await store.createKey('受限密钥', {
      expiresInDays: 30,
      quota: 2,
      rateLimit: 15,
      scopes: ['dns', 'ip'],
      allowedIps: ['203.0.113.0/24', '2001:db8::/32', '198.51.100.7'],
      note: '测试风控',
    });

    assert.ok(record.expiresAt);
    assert.equal(record.quota, 2);
    assert.equal(record.rateLimit, 15);
    assert.deepEqual(record.scopes, ['dns', 'ip']);
    assert.deepEqual(record.allowedIps, ['203.0.113.0/24', '2001:db8::/32', '198.51.100.7']);
    assert.equal(record.note, '测试风控');
    assert.equal(store.findByToken(token)?.id, record.id);

    assert.equal(store.evaluateKey(record, 'dns', '203.0.113.9'), null);
    assert.equal(store.evaluateKey(record, 'dns', '2001:db8::1'), null);
    assert.equal(store.evaluateKey(record, 'dns', '198.51.100.7'), null);
    assert.equal(store.evaluateKey(record, 'dns', '8.8.8.8'), 'KEY_IP_DENIED');
    assert.equal(store.evaluateKey(record, 'dns', '2001:db9::1'), 'KEY_IP_DENIED');
    assert.equal(store.evaluateKey(record, 'whois', '203.0.113.9'), 'KEY_SCOPE_DENIED');

    store.touch(record.id, '203.0.113.9');
    store.touch(record.id);
    assert.equal(store.evaluateKey(store.findByToken(token)!, 'dns', '203.0.113.9'), 'KEY_QUOTA_EXCEEDED');

    const reset = await store.resetKeyUsage(record.id);
    assert.equal(reset?.requestCount, 0);
    assert.equal(reset?.lastUsedIp, null);
    assert.equal(store.evaluateKey(store.findByToken(token)!, 'dns', '203.0.113.9'), null);

    const expired = await store.updateKey(record.id, { expiresInDays: null });
    assert.equal(expired?.expiresAt, null);

    await store.updateKey(record.id, { scopes: null, allowedIps: [] });
    const relaxed = store.findByToken(token)!;
    assert.equal(relaxed.scopes, null);
    assert.deepEqual(relaxed.allowedIps, []);
    assert.equal(store.evaluateKey(relaxed, 'whois', '8.8.8.8'), null);
  });
});
