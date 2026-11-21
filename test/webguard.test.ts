import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DEFAULT_WEB_POLICY, WebGuard } from '../src/lib/webguard.js';

describe('WebGuard', () => {
  it('允许窗口内的请求并给出剩余次数', () => {
    const guard = new WebGuard();
    const policy = { ...DEFAULT_WEB_POLICY, rateLimit: 3, rateWindowSec: 60, dailyQuota: 0 };

    const first = guard.check('1.1.1.1', policy);
    assert.equal(first.allowed, true);
    assert.equal(first.limit, 3);
    assert.equal(first.remaining, 2);

    assert.equal(guard.check('1.1.1.1', policy).remaining, 1);
    assert.equal(guard.check('1.1.1.1', policy).remaining, 0);
  });

  it('超过窗口上限后拒绝并给出 Retry-After', () => {
    const guard = new WebGuard();
    const policy = { ...DEFAULT_WEB_POLICY, rateLimit: 2, rateWindowSec: 30, blockAfter: 0 };

    guard.check('2.2.2.2', policy);
    guard.check('2.2.2.2', policy);
    const denied = guard.check('2.2.2.2', policy);

    assert.equal(denied.allowed, false);
    assert.equal(denied.reason, 'rate');
    assert.equal(denied.remaining, 0);
    assert.ok(denied.retryAfterSec > 0 && denied.retryAfterSec <= 30);
  });

  it('每日额度独立于窗口限速', () => {
    const guard = new WebGuard();
    const policy = { ...DEFAULT_WEB_POLICY, rateLimit: 0, rateWindowSec: 60, dailyQuota: 1, blockAfter: 0 };

    const first = guard.check('3.3.3.3', policy);
    assert.equal(first.allowed, true);
    assert.equal(first.quota, 1);
    assert.equal(first.quotaRemaining, 0);

    const second = guard.check('3.3.3.3', policy);
    assert.equal(second.allowed, false);
    assert.equal(second.reason, 'quota');
    assert.ok(second.retryAfterSec > 0);
  });

  it('累计违规后临时封禁，其他 IP 不受影响', () => {
    const guard = new WebGuard();
    const policy = {
      ...DEFAULT_WEB_POLICY,
      rateLimit: 1,
      rateWindowSec: 60,
      dailyQuota: 0,
      blockAfter: 2,
      blockSec: 120,
    };

    guard.check('4.4.4.4', policy);
    assert.equal(guard.check('4.4.4.4', policy).reason, 'rate');
    const blocked = guard.check('4.4.4.4', policy);
    assert.equal(blocked.reason, 'rate');

    const after = guard.check('4.4.4.4', policy);
    assert.equal(after.allowed, false);
    assert.equal(after.reason, 'blocked');
    assert.ok(after.retryAfterSec > 0);

    assert.equal(guard.check('5.5.5.5', policy).allowed, true);
    assert.equal(guard.snapshot().blockedIps, 1);
  });

  it('策略为 0 时全部放行', () => {
    const guard = new WebGuard();
    const policy = {
      rateLimit: 0,
      rateWindowSec: 60,
      dailyQuota: 0,
      blockAfter: 0,
      blockSec: 0,
    };
    for (let index = 0; index < 50; index += 1) {
      assert.equal(guard.check('6.6.6.6', policy).allowed, true);
    }
    assert.equal(guard.snapshot().dailyRequests, 0);
  });
});
