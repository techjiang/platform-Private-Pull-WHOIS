import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseOfflineIcp, parseRealtimeIcp } from '../src/services/icp.js';

const REALTIME_FILED = {
  code: 200,
  domain: 'qq.com',
  domainid: '190000203203',
  xz: '',
  mainid: '547280',
  icp: '粤B2-20090059',
  maintype: '企业',
  serviceid: '0',
  icpw: '粤B2-20090059-5',
  mainname: '深圳市腾讯计算机系统有限公司',
  uptime: '2026-01-15 11:27:48',
  hctime: '2026-11-21 09:11:00',
};

const REALTIME_EMPTY = {
  code: 200,
  domain: 'not-filed.example',
  domainid: null,
  xz: null,
  mainid: null,
  icp: null,
  maintype: null,
  serviceid: null,
  icpw: null,
  mainname: null,
  uptime: null,
  hctime: '2026-11-21 14:24:22',
};

const OFFLINE_FILED = {
  code: 200,
  td: '1-2',
  type: '企业',
  icp: '粤B2-20090059-5',
  unit: '深圳市腾讯计算机系统有限公司',
  domain: 'qq.com',
  time: '2026-01-15',
};

describe('ICP 备案解析', () => {
  it('解析实时库已备案记录', () => {
    const outcome = parseRealtimeIcp('qq.com', REALTIME_FILED);
    assert.equal(outcome.kind, 'ok');
    if (outcome.kind !== 'ok') return;

    assert.equal(outcome.result.domain, 'qq.com');
    assert.equal(outcome.result.filed, true);
    assert.equal(outcome.result.icpCode, '粤B2-20090059-5');
    assert.equal(outcome.result.subjectCode, '粤B2-20090059');
    assert.equal(outcome.result.unitName, '深圳市腾讯计算机系统有限公司');
    assert.equal(outcome.result.unitType, '企业');
    assert.equal(outcome.result.auditDate, '2026-01-15 11:27:48');
    assert.equal(outcome.result.updatedAt, '2026-11-21 09:11:00');
    assert.equal(outcome.result.source, 'icp-realtime');
    assert.match(outcome.result.note, /工信部/);
  });

  it('实时库返回空字段时标记为未备案', () => {
    const outcome = parseRealtimeIcp('not-filed.example', REALTIME_EMPTY);
    assert.equal(outcome.kind, 'not_filed');
    if (outcome.kind !== 'not_filed') return;

    assert.equal(outcome.result.filed, false);
    assert.equal(outcome.result.icpCode, null);
    assert.equal(outcome.result.subjectCode, null);
    assert.equal(outcome.result.unitName, null);
    assert.match(outcome.result.note, /未查询到/);
  });

  it('识别实时库的公共配额限频', () => {
    const outcome = parseRealtimeIcp('qq.com', {
      code: 400,
      msg: '该接口非彩钻用户限制15秒1次，共享基础资源池。',
    });
    assert.equal(outcome.kind, 'rate_limited');
    if (outcome.kind !== 'rate_limited') return;
    assert.equal(outcome.retryAfterSec, 15);
  });

  it('解析离线库已备案记录', () => {
    const outcome = parseOfflineIcp('qq.com', OFFLINE_FILED);
    assert.equal(outcome.kind, 'ok');
    if (outcome.kind !== 'ok') return;

    assert.equal(outcome.result.source, 'icp-offline');
    assert.equal(outcome.result.icpCode, '粤B2-20090059-5');
    assert.equal(outcome.result.subjectCode, '粤B2-20090059-5');
    assert.equal(outcome.result.unitName, '深圳市腾讯计算机系统有限公司');
    assert.equal(outcome.result.auditDate, '2026-01-15');
  });

  it('离线库“没有备案”视为未备案而非错误', () => {
    const outcome = parseOfflineIcp('not-filed.example', { code: 400, msg: '查询失败或没有备案。' });
    assert.equal(outcome.kind, 'not_filed');
    if (outcome.kind !== 'not_filed') return;
    assert.equal(outcome.result.filed, false);
    assert.equal(outcome.result.icpCode, null);
    assert.equal(outcome.result.updatedAt, null);
  });

  it('无法识别的上游错误按失败处理', () => {
    const outcome = parseOfflineIcp('qq.com', { code: 500, msg: 'server error' });
    assert.equal(outcome.kind, 'error');
    if (outcome.kind !== 'error') return;
    assert.equal(outcome.message, 'server error');
  });

  it('把字符串 null 视为空值', () => {
    const outcome = parseRealtimeIcp('qq.com', {
      code: 200,
      icp: 'null',
      icpw: 'null',
      mainname: 'null',
      maintype: 'null',
      uptime: 'null',
    });
    assert.equal(outcome.kind, 'not_filed');
    if (outcome.kind !== 'not_filed') return;
    assert.equal(outcome.result.filed, false);
    assert.equal(outcome.result.unitName, null);
  });
});
