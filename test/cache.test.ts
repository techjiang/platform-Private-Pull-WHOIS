import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { TtlCache } from '../src/lib/cache.js';
import { FixedWindowRateLimiter } from '../src/lib/ratelimit.js';

describe('TtlCache', () => {
  it('命中后返回剩余 TTL', () => {
    const cache = new TtlCache<string>(10);
    cache.set('a', 'value', 60_000);
    const hit = cache.get('a');
    assert.ok(hit);
    assert.equal(hit.value, 'value');
    assert.ok(hit.ttlMs > 0 && hit.ttlMs <= 60_000);
  });

  it('超过容量时淘汰最久未使用的条目', () => {
    const cache = new TtlCache<number>(2);
    cache.set('a', 1, 60_000);
    cache.set('b', 2, 60_000);
    cache.get('a');
    cache.set('c', 3, 60_000);
    assert.equal(cache.get('b'), undefined);
    assert.equal(cache.get('a')?.value, 1);
    assert.equal(cache.get('c')?.value, 3);
  });

  it('TTL 到期后失效', async () => {
    const cache = new TtlCache<string>(10);
    cache.set('a', 'value', 5);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(cache.get('a'), undefined);
  });
});

describe('FixedWindowRateLimiter', () => {
  it('在额度内放行，超额拒绝并给出重试时间', () => {
    const limiter = new FixedWindowRateLimiter(60_000);
    const first = limiter.hit('ip:test', 2);
    assert.equal(first.allowed, true);
    assert.equal(first.remaining, 1);

    const second = limiter.hit('ip:test', 2);
    assert.equal(second.allowed, true);
    assert.equal(second.remaining, 0);

    const third = limiter.hit('ip:test', 2);
    assert.equal(third.allowed, false);
    assert.equal(third.remaining, 0);
    assert.ok(third.retryAfterSec >= 1);
  });

  it('不同 key 互不影响', () => {
    const limiter = new FixedWindowRateLimiter(60_000);
    limiter.hit('ip:a', 1);
    assert.equal(limiter.hit('ip:b', 1).allowed, true);
  });
});
