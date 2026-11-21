/* ============================================================
   Pull WHOIS — 管理后台交互
   ============================================================ */
const $ = (id) => document.getElementById(id);

const dom = {
  loadingView: $('loadingView'),
  loginView: $('loginView'),
  disabledView: $('disabledView'),
  dashboardView: $('dashboardView'),
  loginForm: $('loginForm'),
  loginButton: $('loginButton'),
  loginError: $('loginError'),
  username: $('adminUsername'),
  password: $('adminPassword'),
  currentUser: $('currentUser'),
  logoutButton: $('logoutButton'),
  refreshButton: $('refreshButton'),
  statWeb: $('statWeb'),
  statWebHint: $('statWebHint'),
  statPolicy: $('statPolicy'),
  statPolicyHint: $('statPolicyHint'),
  statKeys: $('statKeys'),
  statActive: $('statActive'),
  statEnv: $('statEnv'),
  webSwitch: $('webSwitch'),
  webPill: $('webPill'),
  webNote: $('webNote'),
  requireKeySwitch: $('requireKeySwitch'),
  policyPill: $('policyPill'),
  policyNote: $('policyNote'),
  webPolicyPill: $('webPolicyPill'),
  webPolicyHint: $('webPolicyHint'),
  webPolicySave: $('webPolicySave'),
  webRateLimit: $('webRateLimit'),
  webRateWindow: $('webRateWindow'),
  webDailyQuota: $('webDailyQuota'),
  webBlockAfter: $('webBlockAfter'),
  webBlockSec: $('webBlockSec'),
  credentialsForm: $('credentialsForm'),
  credentialsButton: $('credentialsButton'),
  credentialsError: $('credentialsError'),
  currentPassword: $('currentPassword'),
  newUsername: $('newUsername'),
  newPassword: $('newPassword'),
  confirmPassword: $('confirmPassword'),
  createForm: $('createForm'),
  createButton: $('createButton'),
  createError: $('createError'),
  keyName: $('keyName'),
  keyExpiry: $('keyExpiry'),
  keyQuota: $('keyQuota'),
  keyRate: $('keyRate'),
  keyIps: $('keyIps'),
  keyNote: $('keyNote'),
  keyScopePicker: $('keyScopePicker'),
  tokenCard: $('tokenCard'),
  tokenValue: $('tokenValue'),
  tokenHint: $('tokenHint'),
  copyTokenButton: $('copyTokenButton'),
  keyList: $('keyList'),
  keyCount: $('keyCount'),
  usageNote: $('usageNote'),
  usageCode: $('usageCode'),
  copyCurlButton: $('copyCurlButton'),
  featureGrid: $('featureGrid'),
  featureCount: $('featureCount'),
  metricsGrid: $('metricsGrid'),
  registrarStats: $('registrarStats'),
  registrarNote: $('registrarNote'),
  registrarRefreshButton: $('registrarRefreshButton'),
  schedulerPill: $('schedulerPill'),
  schedulerEnabled: $('schedulerEnabled'),
  schedulerIdleOnly: $('schedulerIdleOnly'),
  schedulerRunAll: $('schedulerRunAll'),
  schedulerJobs: $('schedulerJobs'),
  schedulerHint: $('schedulerHint'),
  statsUptime: $('statsUptime'),
  recentQueries: $('recentQueries'),
  topTargets: $('topTargets'),
  clearCacheButton: $('clearCacheButton'),
  clearHistoryButton: $('clearHistoryButton'),
  clearIndexButton: $('clearIndexButton'),
  revokeSessionsButton: $('revokeSessionsButton'),
  toast: $('toast'),
  themeToggle: $('themeToggle'),
};

const TOKEN_KEY = 'pullwhois-theme';

const state = {
  keys: [],
  requireKey: false,
  webEnabled: true,
  webPolicy: {},
  username: '',
  envKeyCount: 0,
  features: {},
  featureLabels: {},
  stats: null,
  registrarStats: null,
  registrarStatus: null,
  scheduler: null,
  token: '',
};

let statsTimer = null;

/* ------------------------------------------------------------------ */
/* 通用                                                                */
/* ------------------------------------------------------------------ */
function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function showView(name) {
  const views = {
    loading: dom.loadingView,
    login: dom.loginView,
    disabled: dom.disabledView,
    dashboard: dom.dashboardView,
  };
  for (const [key, element] of Object.entries(views)) {
    element.hidden = key !== name;
  }
}

let toastTimer = null;
function showToast(message) {
  dom.toast.textContent = message;
  dom.toast.hidden = false;
  requestAnimationFrame(() => dom.toast.classList.add('show'));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    dom.toast.classList.remove('show');
    setTimeout(() => {
      dom.toast.hidden = true;
    }, 220);
  }, 2200);
}

async function api(path, options = {}) {
  const method = options.method ?? 'GET';
  const headers = { accept: 'application/json' };
  if (options.body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET') headers['x-admin-csrf'] = '1';

  const response = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });

  const payload = await response.json().catch(() => null);

  if (!response.ok) {
    if (
      response.status === 401 &&
      path !== '/admin/api/login' &&
      path !== '/admin/api/credentials'
    ) {
      showView('login');
      setLoginError('会话已失效，请重新登录');
    }
    const message = payload?.error?.message ?? `请求失败（HTTP ${response.status}）`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  return payload?.data;
}

async function copyText(text, successMessage = '已复制') {
  try {
    await navigator.clipboard.writeText(text);
    showToast(successMessage);
  } catch {
    const area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand('copy');
      showToast(successMessage);
    } catch {
      showToast('复制失败，请手动选择');
    }
    area.remove();
  }
}

function formatDate(value) {
  if (!value) return '从未';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '未知';
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

function formatTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date);
}

function formatDuration(seconds) {
  const total = Math.max(0, Math.floor(Number(seconds) || 0));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days > 0) return `${days} 天 ${hours} 小时`;
  if (hours > 0) return `${hours} 小时 ${minutes} 分`;
  return `${minutes} 分 ${total % 60} 秒`;
}

function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function setLoginError(message) {
  dom.loginError.textContent = message || '';
  dom.loginError.hidden = !message;
}

/* ------------------------------------------------------------------ */
/* 主题                                                                */
/* ------------------------------------------------------------------ */
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', theme === 'light' ? '#f4f5ef' : '#07080a');
}

function initTheme() {
  let stored = null;
  try {
    stored = localStorage.getItem(TOKEN_KEY);
  } catch {
    /* 忽略隐私模式限制 */
  }
  const preferred = window.matchMedia?.('(prefers-color-scheme: light)').matches
    ? 'light'
    : 'dark';
  applyTheme(stored === 'light' || stored === 'dark' ? stored : preferred);
}

dom.themeToggle?.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  applyTheme(next);
  try {
    localStorage.setItem(TOKEN_KEY, next);
  } catch {
    /* 忽略 */
  }
});

/* ------------------------------------------------------------------ */
/* 渲染                                                                */
/* ------------------------------------------------------------------ */
function renderStats() {
  const active = state.keys.filter((key) => key.enabled).length;

  dom.statWeb.textContent = state.webEnabled ? '已开启' : '已关闭';
  dom.statWeb.classList.toggle('is-on', state.webEnabled);
  dom.statWeb.classList.toggle('is-off', !state.webEnabled);
  dom.statWebHint.textContent = state.webEnabled
    ? webPolicySummary()
    : '/web/v1/ 返回 503 WEB_DISABLED';

  dom.statPolicy.textContent = state.requireKey ? '必须携带 Key' : '公开访问';
  dom.statPolicy.classList.toggle('is-on', state.requireKey);
  dom.statPolicy.classList.toggle('is-off', !state.requireKey);
  dom.statPolicyHint.textContent = state.requireKey
    ? '未携带密钥的请求返回 401'
    : '匿名请求可直接调用 /v1/';

  dom.statKeys.textContent = String(state.keys.length);
  dom.statActive.textContent = String(active);
  dom.statEnv.textContent = String(state.envKeyCount);
  dom.currentUser.textContent = state.username || '—';
}

function renderPolicy() {
  dom.webSwitch.setAttribute('aria-checked', String(state.webEnabled));
  dom.webPill.textContent = state.webEnabled ? '网页查询开放' : '网页查询已关闭';
  dom.webPill.className = state.webEnabled ? 'pill ok' : 'pill muted';
  dom.webNote.textContent = state.webEnabled
    ? '首页与 /web/v1/ 均可直接查询，无需 API Key。'
    : '首页查询会提示已关闭；API 调用不受影响。';

  dom.requireKeySwitch.setAttribute('aria-checked', String(state.requireKey));
  dom.policyPill.textContent = state.requireKey ? '已开启鉴权' : '允许匿名访问';
  dom.policyPill.className = state.requireKey ? 'pill ok' : 'pill muted';
  dom.policyNote.textContent = state.requireKey
    ? 'API 请求现在要求 x-api-key 或 Authorization: Bearer。'
    : '任何人均可调用 API，但仍受 IP 限流约束。';

  renderWebPolicy();
}

function webPolicySummary() {
  const policy = state.webPolicy ?? {};
  const rate = Number(policy.rateLimit) || 0;
  const windowSec = Number(policy.rateWindowSec) || 60;
  const quota = Number(policy.dailyQuota) || 0;
  return `${rate > 0 ? `${rate} 次/${windowSec} 秒` : '不限速'} · ${
    quota > 0 ? `每日 ${quota} 次` : '每日不限'
  }`;
}

function renderWebPolicy() {
  const policy = state.webPolicy ?? {};
  const value = (key, fallback) => {
    const num = Number(policy[key]);
    return Number.isFinite(num) ? String(Math.trunc(num)) : String(fallback);
  };

  dom.webRateLimit.value = value('rateLimit', 120);
  dom.webRateWindow.value = value('rateWindowSec', 60);
  dom.webDailyQuota.value = value('dailyQuota', 0);
  dom.webBlockAfter.value = value('blockAfter', 10);
  dom.webBlockSec.value = value('blockSec', 300);

  const blockAfter = Number(policy.blockAfter) || 0;
  const blockSec = Number(policy.blockSec) || 0;
  const risk =
    blockAfter > 0 && blockSec > 0
      ? `违规 ${blockAfter} 次封禁 ${blockSec} 秒`
      : '不启用临时封禁';
  dom.webPolicyPill.textContent = webPolicySummary();
  dom.webPolicyPill.className = 'pill ok';
  dom.webPolicyHint.textContent = `${webPolicySummary()} · ${risk}；超限返回 429。`;
}

const DAY_MS = 24 * 60 * 60 * 1000;

function featureLabel(key) {
  return state.featureLabels[key] ?? key;
}

function scopeList(scopes) {
  if (!scopes) return '全部功能';
  return scopes.map((key) => featureLabel(key)).join(' / ');
}

function keyStatus(key) {
  if (!key.enabled) return { tone: 'muted', label: '已停用' };
  if (key.expiresAt && Date.parse(key.expiresAt) <= Date.now()) {
    return { tone: 'bad', label: '已过期' };
  }
  if (key.quota !== null && Number(key.requestCount) >= Number(key.quota)) {
    return { tone: 'warn', label: '配额用尽' };
  }
  return { tone: 'ok', label: '启用中' };
}

function remainingDays(key) {
  if (!key.expiresAt) return '';
  const remaining = Math.ceil((Date.parse(key.expiresAt) - Date.now()) / DAY_MS);
  return remaining > 0 ? String(remaining) : '';
}

function scopePickerHtml(selected, scope = 'create') {
  const keys = Object.keys(state.featureLabels);
  const chosen = selected === null || selected === undefined ? keys : selected;
  return keys
    .map(
      (key) => `
        <label class="scope-chip">
          <input type="checkbox" data-scope="${esc(key)}" data-scope-group="${esc(scope)}" ${chosen.includes(key) ? 'checked' : ''} />
          <span>${esc(featureLabel(key))}</span>
        </label>
      `,
    )
    .join('');
}

function renderScopePicker() {
  if (!dom.keyScopePicker) return;
  dom.keyScopePicker.innerHTML = scopePickerHtml(null, 'create');
}

function readNumber(input) {
  const value = input?.value?.trim() ?? '';
  if (value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : null;
}

function readIps(input) {
  return (input?.value ?? '')
    .split(/[,，\s]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function readScopes(root, scope) {
  const checked = [...root.querySelectorAll(`input[data-scope-group="${scope}"]:checked`)].map(
    (input) => input.dataset.scope,
  );
  if (checked.length === 0) throw new Error('请至少选择一个接口作用域');
  return checked;
}

function renderKeys() {
  const active = state.keys.filter((key) => key.enabled).length;
  dom.keyCount.textContent = `${state.keys.length} 个 · ${active} 个启用`;

  if (state.keys.length === 0) {
    dom.keyList.innerHTML = '<div class="keys-empty">还没有密钥，在上方创建第一个 API Key。</div>';
    return;
  }

  dom.keyList.innerHTML = state.keys
    .map((key) => {
      const status = keyStatus(key);
      const toggleLabel = key.enabled ? '停用' : '启用';
      const quotaText = key.quota !== null
        ? `${Number(key.requestCount) || 0} / ${Number(key.quota)} 次`
        : `${Number(key.requestCount) || 0} 次（不限）`;
      const quotaPercent = key.quota !== null
        ? Math.min(100, Math.round(((Number(key.requestCount) || 0) / Number(key.quota)) * 100))
        : 0;
      const expiryText = key.expiresAt
        ? `到期 ${formatDate(key.expiresAt)}`
        : '永久有效';
      const ipText = key.allowedIps?.length ? `IP 白名单 ${key.allowedIps.length} 条` : 'IP 不限';
      const rateText = key.rateLimit ? `限速 ${key.rateLimit}/分钟` : '默认限速';

      return `
        <div class="key-row${key.enabled ? '' : ' is-disabled'}">
          <div class="key-main">
            <div class="key-title">
              <strong>${esc(key.name)}</strong>
              <span class="pill ${status.tone}">${status.label}</span>
            </div>
            <code class="key-prefix">${esc(key.prefix)}…</code>
            <div class="key-meta">
              创建于 ${esc(formatDate(key.createdAt))} · 最近使用 ${esc(formatDate(key.lastUsedAt))}${
                key.lastUsedIp ? ` · 来源 IP ${esc(key.lastUsedIp)}` : ''
              }
            </div>
            <div class="key-tags">
              <span class="key-tag">调用 ${esc(quotaText)}</span>
              <span class="key-tag">${esc(rateText)}</span>
              <span class="key-tag">${esc(expiryText)}</span>
              <span class="key-tag">${esc(ipText)}</span>
              <span class="key-tag key-tag-scope">作用域：${esc(scopeList(key.scopes))}</span>
            </div>
            ${
              key.quota !== null
                ? `<div class="key-usage"><span style="width:${quotaPercent}%"></span></div>`
                : ''
            }
            ${key.note ? `<p class="key-note">${esc(key.note)}</p>` : ''}
            <div class="key-editor" data-editor="${esc(key.id)}" hidden>
              <div class="key-policy-grid">
                <label class="key-field">
                  <span>剩余有效期（天）</span>
                  <input class="admin-input" data-field="expiry" type="number" min="1" max="3650" placeholder="留空永久" value="${esc(remainingDays(key))}" />
                </label>
                <label class="key-field">
                  <span>总配额（次）</span>
                  <input class="admin-input" data-field="quota" type="number" min="1" max="1000000000" placeholder="留空不限" value="${key.quota ?? ''}" />
                </label>
                <label class="key-field">
                  <span>每分钟限速</span>
                  <input class="admin-input" data-field="rate" type="number" min="1" max="1000000" placeholder="默认 600" value="${key.rateLimit ?? ''}" />
                </label>
                <label class="key-field key-field-wide">
                  <span>IP 白名单（逗号分隔，支持 CIDR）</span>
                  <input class="admin-input" data-field="ips" type="text" maxlength="600" placeholder="留空不限制" value="${esc((key.allowedIps ?? []).join(', '))}" />
                </label>
                <label class="key-field key-field-wide">
                  <span>备注</span>
                  <input class="admin-input" data-field="note" type="text" maxlength="200" value="${esc(key.note ?? '')}" />
                </label>
              </div>
              <div class="key-scopes">${scopePickerHtml(key.scopes, `edit-${key.id}`)}</div>
              <div class="key-editor-actions">
                <button class="mini" type="button" data-action="save" data-id="${esc(key.id)}">保存策略</button>
                <button class="mini" type="button" data-action="edit" data-id="${esc(key.id)}">取消</button>
              </div>
            </div>
          </div>
          <div class="key-actions">
            <button class="mini" type="button" data-action="edit" data-id="${esc(key.id)}">调整策略</button>
            <button class="mini" type="button" data-action="reset" data-id="${esc(key.id)}">重置用量</button>
            <button class="mini${key.enabled ? ' danger' : ''}" type="button" data-action="toggle" data-id="${esc(key.id)}">${toggleLabel}</button>
            <button class="mini danger" type="button" data-action="delete" data-id="${esc(key.id)}">删除</button>
          </div>
        </div>
      `;
    })
    .join('');
}

function renderUsage() {
  const origin = window.location.origin;
  const command = state.requireKey
    ? `curl "${origin}/v1/whois/example.com" \\\n  -H "x-api-key: 你的密钥"`
    : `curl "${origin}/v1/whois/example.com"`;

  dom.usageCode.textContent = `${command}\n\n# 网页端（无需 Key，独立开关）\ncurl "${origin}/web/v1/whois/example.com"`;
  dom.usageNote.textContent = state.requireKey
    ? 'API 当前要求密钥，请替换为后台生成的完整 Key；网页端始终无需密钥。'
    : 'API 当前允许匿名访问；网页端使用 /web/v1/ 且不受 API Key 策略影响。';
}

const FEATURE_HINTS = {
  whois: '域名注册人、注册商与日期',
  rdap: '结构化注册数据',
  dns: 'A / AAAA / MX / TXT 等记录',
  ip: 'IPv4 / IPv6 归属与 PTR',
  uptime: 'HTTP 可访问性与延迟',
  history: '本地快照与变更差异',
  nameservers: '按 NS 反查本站索引',
  registrars: '注册商目录与索引统计',
  icp: 'ICP 备案号、主办单位与审核时间',
  tls: 'TLS 握手、证书有效期与校验结果',
  mail: 'SPF、DMARC、DKIM 与 MX 记录',
  certchain: '导出完整证书链与 SHA-256 指纹',
  http: 'HSTS、CSP 等安全响应头体检',
  dnsprop: '多公共解析器结果一致性对比',
  health: '注册、DNS、TLS、邮件四维评分',
  available: '批量判断域名是否可注册',
};

function renderFeatures() {
  const keys = Object.keys(state.featureLabels);
  const enabled = keys.filter((key) => state.features[key] !== false).length;
  dom.featureCount.textContent = `${enabled}/${keys.length} 已开启`;

  dom.featureGrid.innerHTML = keys
    .map((key) => {
      const on = state.features[key] !== false;
      return `
        <div class="feature-item${on ? '' : ' is-off'}">
          <div class="feature-copy">
            <strong>${esc(state.featureLabels[key] ?? key)}</strong>
            <span>${esc(FEATURE_HINTS[key] ?? key)}</span>
          </div>
          <button
            class="switch"
            type="button"
            role="switch"
            data-feature="${esc(key)}"
            aria-checked="${on}"
            aria-label="切换${esc(state.featureLabels[key] ?? key)}"
          >
            <span class="switch-thumb"></span>
          </button>
        </div>
      `;
    })
    .join('');
}

function renderMetrics() {
  const stats = state.stats;
  if (!stats) return;

  const metrics = stats.metrics ?? {};
  const cache = stats.cache ?? {};
  const history = stats.history ?? {};
  const index = stats.index ?? {};

  let hits = 0;
  let misses = 0;
  for (const entry of Object.values(metrics.cache ?? {})) {
    hits += Number(entry.hits) || 0;
    misses += Number(entry.misses) || 0;
  }
  const totalLookups = hits + misses;
  const hitRate = totalLookups > 0 ? `${((hits / totalLookups) * 100).toFixed(1)}%` : '—';
  const cacheEntries =
    (Number(cache.whois) || 0) +
    (Number(cache.dns) || 0) +
    (Number(cache.ip) || 0) +
    (Number(cache.uptime) || 0) +
    (Number(cache.rdap) || 0) +
    (Number(cache.icp) || 0) +
    (Number(cache.tls) || 0) +
    (Number(cache.mail) || 0) +
    (Number(cache.http) || 0) +
    (Number(cache.dnsprop) || 0) +
    (Number(cache.health) || 0) +
    (Number(cache.available) || 0) +
    (Number(cache.certchain) || 0);

  const toolSummary = Object.entries(metrics.requests ?? {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([tool, count]) => `${tool.toUpperCase()} ${count}`)
    .join(' · ');

  const cards = [
    ['请求总数', String(metrics.totalRequests ?? 0), toolSummary || '暂无查询'],
    ['缓存命中率', hitRate, `命中 ${hits} · 未命中 ${misses}`],
    ['缓存条目', String(cacheEntries), `WHOIS ${cache.whois ?? 0} · DNS ${cache.dns ?? 0}`],
    ['历史快照', String(history.snapshotCount ?? 0), `${history.domainCount ?? 0} 个域名`],
    ['本地索引', String(index.domainCount ?? 0), `${index.registrarCount ?? 0} 个注册商`],
    ['内存占用', formatBytes(metrics.memory?.rss), `堆 ${formatBytes(metrics.memory?.heapUsed)}`],
  ];

  dom.metricsGrid.innerHTML = cards
    .map(
      ([label, value, foot]) => `
        <div class="admin-metric">
          <span>${esc(label)}</span>
          <strong>${esc(value)}</strong>
          <small>${esc(foot)}</small>
        </div>
      `,
    )
    .join('');

  dom.statsUptime.textContent = `运行 ${formatDuration(metrics.uptimeSec)}`;

  const recent = (metrics.recent ?? []).slice(0, 8);
  dom.recentQueries.innerHTML = recent.length
    ? recent
        .map(
          (item) => `
            <div class="admin-list-row">
              <span class="admin-list-tool">${esc(String(item.tool).toUpperCase())}</span>
              <code>${esc(item.target)}</code>
              <span class="admin-list-meta">${esc(formatTime(item.at))}${item.cached ? ' · 缓存' : ''}</span>
            </div>
          `,
        )
        .join('')
    : '<p class="admin-muted">暂无记录</p>';

  const top = metrics.topTargets ?? [];
  dom.topTargets.innerHTML = top.length
    ? top
        .map(
          (item) => `
            <div class="admin-list-row">
              <code>${esc(item.target)}</code>
              <span class="admin-list-count">${Number(item.count) || 0}</span>
            </div>
          `,
        )
        .join('')
    : '<p class="admin-muted">暂无记录</p>';
}

function renderRegistrars() {
  if (!dom.registrarStats) return;
  const stats = state.registrarStats ?? state.stats?.registrars ?? null;
  if (!stats) return;
  const status = state.registrarStatus ?? {};
  const sourceLabel = (value) => (value === 'ok' ? '正常' : '失败');
  const cards = [
    ['注册商总数', String(Number(stats.total) || 0), 'IANA + ICANN 合并去重'],
    ['已认证', String(Number(stats.accredited) || 0), '状态为 accredited'],
    ['覆盖国家/地区', String(Number(stats.countries) || 0), '来自 ICANN 列表'],
    [
      '最近同步',
      status.syncedAt ? formatDate(status.syncedAt) : '尚未同步',
      status.refreshing
        ? '正在同步…'
        : `IANA ${sourceLabel(status.sources?.iana)} · ICANN ${sourceLabel(status.sources?.icann)}`,
    ],
  ];

  dom.registrarStats.innerHTML = cards
    .map(
      ([label, value, foot]) => `
        <div class="admin-metric">
          <span>${esc(label)}</span>
          <strong>${esc(value)}</strong>
          <small>${esc(foot)}</small>
        </div>
      `,
    )
    .join('');

  dom.registrarNote.textContent = status.lastError
    ? `最近一次同步错误：${status.lastError}`
    : '目录每日自动同步；查询直接读取本地快照，不产生外部请求。';

  if (dom.registrarRefreshButton) {
    dom.registrarRefreshButton.disabled = Boolean(status.refreshing);
    dom.registrarRefreshButton.textContent = status.refreshing ? '同步中…' : '立即同步';
  }
}

function renderScheduler() {
  const snapshot = state.scheduler;
  if (!snapshot) {
    if (dom.schedulerJobs) {
      dom.schedulerJobs.innerHTML = '<p class="admin-muted">加载中…</p>';
    }
    return;
  }

  const policy = snapshot.policy ?? {};
  dom.schedulerEnabled?.setAttribute('aria-checked', String(policy.enabled !== false));
  dom.schedulerIdleOnly?.setAttribute('aria-checked', String(policy.idleOnly !== false));
  if (dom.schedulerPill) {
    dom.schedulerPill.textContent =
      policy.enabled === false ? '已暂停' : policy.idleOnly === false ? '自动 · 始终' : '自动 · 仅空闲';
    dom.schedulerPill.className = policy.enabled === false ? 'pill muted' : 'pill ok';
  }
  if (dom.schedulerHint) {
    const busy = Number(snapshot.inflight) > 0;
    dom.schedulerHint.textContent = `${busy ? '当前有在途请求' : '当前空闲'} · 事件循环延迟 ${
      Number(snapshot.loopLagMs) || 0
    } ms · 在途 ${Number(snapshot.inflight) || 0} · ${
      policy.idleOnly === false ? '不受空闲限制' : '延迟超过 80ms 自动避让'
    }`;
  }
  if (dom.schedulerRunAll) {
    dom.schedulerRunAll.disabled = Boolean(snapshot.running);
    dom.schedulerRunAll.textContent = snapshot.running ? '执行中…' : '立即运行全部';
  }
  if (!dom.schedulerJobs) return;

  const jobs = Array.isArray(snapshot.jobs) ? snapshot.jobs : [];
  dom.schedulerJobs.innerHTML = jobs
    .map((job) => {
      const statusClass =
        job.lastStatus === 'ok' ? 'pill ok' : job.lastStatus === 'error' ? 'pill warn' : 'pill muted';
      const statusText =
        job.lastStatus === 'ok' ? '正常' : job.lastStatus === 'error' ? '失败' : '未运行';
      const last = job.lastRunAt ? formatDate(job.lastRunAt) : '从未';
      const next = job.due ? '待执行' : job.nextRunAt ? formatDate(job.nextRunAt) : '—';
      const duration = job.lastDurationMs === null ? '—' : `${job.lastDurationMs} ms`;
      const retry =
        Number(job.consecutiveFailures) > 0 && job.backoffUntil
          ? ` · 连续失败 ${Number(job.consecutiveFailures)} 次，退避至 ${formatDate(job.backoffUntil)}`
          : '';
      const summary = job.lastSummary
        ? `<small>${esc(job.lastSummary)}</small>`
        : job.lastStatus === 'error' && job.lastError
          ? `<small class="is-danger">${esc(job.lastError)}</small>`
          : '';
      return `
        <div class="scheduler-job">
          <div class="scheduler-job-copy">
            <div class="scheduler-job-head">
              <strong>${esc(job.label)}</strong>
              <span class="${statusClass}">${statusText}</span>
            </div>
            <p>${esc(job.description)}</p>
            <small>上次 ${esc(last)} · 下次 ${esc(next)} · 耗时 ${esc(duration)} · 已运行 ${Number(job.runCount) || 0} 次${esc(retry)}</small>
            ${summary}
          </div>
          <button class="btn btn-ghost btn-sm" type="button" data-scheduler-run="${esc(job.key)}" ${
            job.running ? 'disabled' : ''
          }>${job.running ? '执行中…' : '运行'}</button>
        </div>
      `;
    })
    .join('');
}

async function runSchedulerJob(key) {
  const snapshot = await api('/admin/api/scheduler/run', {
    method: 'POST',
    body: key ? { job: key } : {},
  });
  state.scheduler = snapshot;
  renderScheduler();
  showToast(key ? '调度任务已执行' : '全部调度任务已执行');
}

function renderAll() {
  renderStats();
  renderPolicy();
  renderScopePicker();
  renderKeys();
  renderUsage();
  renderFeatures();
  renderMetrics();
  renderRegistrars();
  renderScheduler();
}

/* ------------------------------------------------------------------ */
/* 数据                                                                */
/* ------------------------------------------------------------------ */
async function loadStats() {
  const stats = await api('/admin/api/stats');
  state.stats = stats;
  if (stats.scheduler) state.scheduler = stats.scheduler;
  renderMetrics();
  renderScheduler();
}

async function loadData() {
  const [keys, featureData, stats, registrars, scheduler] = await Promise.all([
    api('/admin/api/keys'),
    api('/admin/api/features'),
    api('/admin/api/stats'),
    api('/admin/api/registrars'),
    api('/admin/api/scheduler'),
  ]);
  state.keys = keys.keys ?? [];
  state.requireKey = Boolean(keys.requireKey);
  state.webEnabled = keys.webEnabled !== false;
  state.webPolicy = keys.webPolicy ?? {};
  state.envKeyCount = Number(keys.envKeyCount) || 0;
  state.features = featureData.features ?? {};
  state.featureLabels = featureData.labels ?? {};
  state.stats = stats;
  state.registrarStats = registrars.stats ?? null;
  state.registrarStatus = registrars.status ?? null;
  state.scheduler = scheduler ?? null;
  renderAll();
}

function startStatsTimer() {
  stopStatsTimer();
  statsTimer = setInterval(() => {
    if (document.hidden || dom.dashboardView.hidden) return;
    loadStats().catch(() => undefined);
  }, 30_000);
}

function stopStatsTimer() {
  if (statsTimer) {
    clearInterval(statsTimer);
    statsTimer = null;
  }
}

async function bootstrap() {
  try {
    const session = await api('/admin/api/session');
    if (!session.adminEnabled) {
      showView('disabled');
      return;
    }
    state.username = session.username || '';
    state.webEnabled = session.webEnabled !== false;
    state.webPolicy = session.webPolicy ?? {};
    if (!session.authenticated) {
      showView('login');
      dom.password.focus();
      return;
    }
    showView('dashboard');
    await loadData();
    startStatsTimer();
    dom.currentUser.textContent = state.username || '—';
    dom.newUsername.value = state.username || '';
  } catch (error) {
    showView('login');
    setLoginError(error.message);
  }
}

/* ------------------------------------------------------------------ */
/* 交互                                                                */
/* ------------------------------------------------------------------ */
dom.loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  setLoginError('');
  const username = dom.username.value.trim();
  const password = dom.password.value;
  if (!username || !password) return;

  dom.loginButton.disabled = true;
  dom.loginButton.textContent = '登录中…';

  try {
    await api('/admin/api/login', { method: 'POST', body: { username, password } });
    dom.password.value = '';
    dom.tokenCard.hidden = true;
    state.username = username;
    showView('dashboard');
    await loadData();
    startStatsTimer();
    dom.newUsername.value = state.username;
    showToast('已登录');
  } catch (error) {
    setLoginError(error.message);
  } finally {
    dom.loginButton.disabled = false;
    dom.loginButton.textContent = '登录';
  }
});

dom.logoutButton.addEventListener('click', async () => {
  try {
    await api('/admin/api/logout', { method: 'POST' });
  } catch {
    /* 会话可能已过期 */
  }
  state.keys = [];
  state.stats = null;
  stopStatsTimer();
  dom.tokenCard.hidden = true;
  showView('login');
  dom.password.value = '';
  dom.password.focus();
  showToast('已退出登录');
});

dom.refreshButton.addEventListener('click', async () => {
  try {
    await loadData();
    showToast('已刷新');
  } catch (error) {
    showToast(error.message);
  }
});

dom.webSwitch.addEventListener('click', async () => {
  const next = !state.webEnabled;
  dom.webSwitch.disabled = true;

  try {
    const data = await api('/admin/api/settings', {
      method: 'PATCH',
      body: { webEnabled: next },
    });
    state.webEnabled = Boolean(data.webEnabled);
    renderStats();
    renderPolicy();
    renderUsage();
    showToast(state.webEnabled ? '网页端查询已开启' : '网页端查询已关闭');
  } catch (error) {
    showToast(error.message);
  } finally {
    dom.webSwitch.disabled = false;
  }
});

dom.webPolicySave.addEventListener('click', async () => {
  dom.webPolicySave.disabled = true;
  dom.webPolicySave.textContent = '保存中…';
  try {
    const data = await api('/admin/api/settings', {
      method: 'PATCH',
      body: {
        webPolicy: {
          rateLimit: Number(dom.webRateLimit.value),
          rateWindowSec: Number(dom.webRateWindow.value),
          dailyQuota: Number(dom.webDailyQuota.value),
          blockAfter: Number(dom.webBlockAfter.value),
          blockSec: Number(dom.webBlockSec.value),
        },
      },
    });
    state.webPolicy = data.webPolicy ?? {};
    renderStats();
    renderPolicy();
    showToast('网页端限流、额度与风控策略已保存');
  } catch (error) {
    showToast(error.message);
  } finally {
    dom.webPolicySave.disabled = false;
    dom.webPolicySave.textContent = '保存策略';
  }
});

dom.requireKeySwitch.addEventListener('click', async () => {
  const next = !state.requireKey;
  dom.requireKeySwitch.disabled = true;

  try {
    const data = await api('/admin/api/settings', {
      method: 'PATCH',
      body: { requireKey: next },
    });
    state.requireKey = Boolean(data.requireKey);
    renderStats();
    renderPolicy();
    renderUsage();
    showToast(state.requireKey ? '已开启 API Key 鉴权' : '已关闭鉴权，允许匿名访问');
  } catch (error) {
    showToast(error.message);
  } finally {
    dom.requireKeySwitch.disabled = false;
  }
});

dom.credentialsForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  dom.credentialsError.hidden = true;

  const currentPassword = dom.currentPassword.value;
  const username = dom.newUsername.value.trim();
  const password = dom.newPassword.value;
  const confirm = dom.confirmPassword.value;

  if (password !== confirm) {
    dom.credentialsError.textContent = '两次输入的新密码不一致';
    dom.credentialsError.hidden = false;
    return;
  }

  dom.credentialsButton.disabled = true;
  dom.credentialsButton.textContent = '保存中…';

  try {
    await api('/admin/api/credentials', {
      method: 'POST',
      body: { currentPassword, username, password },
    });

    dom.credentialsForm.reset();
    state.keys = [];
    state.token = '';
    state.stats = null;
    stopStatsTimer();
    dom.tokenCard.hidden = true;
    showView('login');
    dom.username.value = username;
    dom.password.value = '';
    dom.password.focus();
    showToast('账号密码已更新，请重新登录');
  } catch (error) {
    dom.credentialsError.textContent = error.message;
    dom.credentialsError.hidden = false;
  } finally {
    dom.credentialsButton.disabled = false;
    dom.credentialsButton.textContent = '保存修改';
  }
});

dom.createForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  dom.createError.hidden = true;
  dom.createButton.disabled = true;
  dom.createButton.textContent = '生成中…';

  try {
    const scopes = readScopes(dom.createForm, 'create');
    const name = dom.keyName.value.trim() || '未命名密钥';
    const data = await api('/admin/api/keys', {
      method: 'POST',
      body: {
        name,
        expiresInDays: readNumber(dom.keyExpiry),
        quota: readNumber(dom.keyQuota),
        rateLimit: readNumber(dom.keyRate),
        allowedIps: readIps(dom.keyIps),
        note: dom.keyNote.value.trim(),
        scopes,
      },
    });

    state.keys.unshift(data.key);
    state.token = data.token;
    dom.tokenValue.textContent = data.token;
    dom.tokenHint.textContent = `名称：${data.key.name} · 作用域：${scopeList(data.key.scopes)} · ${
      data.key.expiresAt ? `到期 ${formatDate(data.key.expiresAt)}` : '永久有效'
    } · 只显示这一次`;
    dom.tokenCard.hidden = false;
    dom.keyName.value = '';
    dom.keyExpiry.value = '';
    dom.keyQuota.value = '';
    dom.keyRate.value = '';
    dom.keyIps.value = '';
    dom.keyNote.value = '';
    renderAll();
    dom.keyScopePicker
      .querySelectorAll('input[data-scope]')
      .forEach((input) => {
        input.checked = true;
      });
    dom.tokenCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
    showToast('密钥已生成');
  } catch (error) {
    dom.createError.textContent = error.message;
    dom.createError.hidden = false;
  } finally {
    dom.createButton.disabled = false;
    dom.createButton.textContent = '生成密钥';
  }
});

dom.copyTokenButton.addEventListener('click', () => {
  if (state.token) copyText(state.token, '密钥已复制');
});

dom.copyCurlButton.addEventListener('click', () => {
  copyText(dom.usageCode.textContent ?? '', '调用示例已复制');
});

dom.keyList.addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;

  const id = button.dataset.id;
  const key = state.keys.find((item) => item.id === id);
  if (!key) return;

  const action = button.dataset.action;

  if (action === 'edit') {
    const editor = dom.keyList.querySelector(`[data-editor="${CSS.escape(id)}"]`);
    if (editor) editor.hidden = !editor.hidden;
    return;
  }

  button.disabled = true;

  try {
    if (action === 'toggle') {
      const data = await api(`/admin/api/keys/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: { enabled: !key.enabled },
      });
      replaceKey(data.key);
      renderAll();
      showToast(data.key.enabled ? '密钥已启用' : '密钥已停用');
    } else if (action === 'delete') {
      const confirmed = window.confirm(`确定删除密钥「${key.name}」？删除后无法恢复。`);
      if (!confirmed) {
        button.disabled = false;
        return;
      }
      await api(`/admin/api/keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
      state.keys = state.keys.filter((item) => item.id !== id);
      renderAll();
      showToast('密钥已删除');
    } else if (action === 'reset') {
      const confirmed = window.confirm(`确定重置「${key.name}」的累计调用次数与最近使用记录？`);
      if (!confirmed) {
        button.disabled = false;
        return;
      }
      const data = await api(`/admin/api/keys/${encodeURIComponent(id)}/reset`, {
        method: 'POST',
      });
      replaceKey(data.key);
      renderAll();
      showToast('调用用量已重置');
    } else if (action === 'save') {
      const editor = button.closest('[data-editor]');
      if (!editor) return;
      const field = (name) => editor.querySelector(`[data-field="${name}"]`);
      const scopes = readScopes(editor, `edit-${id}`);
      const data = await api(`/admin/api/keys/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: {
          expiresInDays: readNumber(field('expiry')),
          quota: readNumber(field('quota')),
          rateLimit: readNumber(field('rate')),
          allowedIps: readIps(field('ips')),
          note: field('note')?.value.trim() ?? '',
          scopes,
        },
      });
      replaceKey(data.key);
      renderAll();
      showToast('策略已保存');
    }
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
  }
});

function replaceKey(next) {
  const index = state.keys.findIndex((item) => item.id === next.id);
  if (index !== -1) state.keys[index] = next;
}

dom.registrarRefreshButton?.addEventListener('click', async () => {
  dom.registrarRefreshButton.disabled = true;
  dom.registrarRefreshButton.textContent = '同步中…';
  try {
    const data = await api('/admin/api/registrars/refresh', { method: 'POST' });
    state.registrarStats = data.stats ?? null;
    state.registrarStatus = data.status ?? null;
    renderRegistrars();
    showToast(`注册商目录已同步，共 ${data.stats?.total ?? 0} 条`);
  } catch (error) {
    showToast(error.message);
    renderRegistrars();
  }
});

dom.featureGrid.addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-feature]');
  if (!button) return;

  const feature = button.dataset.feature;
  const next = state.features[feature] === false;
  button.disabled = true;

  try {
    const data = await api('/admin/api/features', {
      method: 'PATCH',
      body: { [feature]: next },
    });
    state.features = data.features ?? state.features;
    renderFeatures();
    showToast(next ? '功能已开启' : '功能已关闭');
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
  }
});

dom.schedulerEnabled?.addEventListener('click', async () => {
  const next = state.scheduler?.policy?.enabled === false;
  dom.schedulerEnabled.disabled = true;
  try {
    const snapshot = await api('/admin/api/scheduler', {
      method: 'PATCH',
      body: { enabled: next },
    });
    state.scheduler = snapshot;
    renderScheduler();
    showToast(next ? '自动调度已开启' : '自动调度已暂停');
  } catch (error) {
    showToast(error.message);
  } finally {
    dom.schedulerEnabled.disabled = false;
  }
});

dom.schedulerIdleOnly?.addEventListener('click', async () => {
  const next = state.scheduler?.policy?.idleOnly === false;
  dom.schedulerIdleOnly.disabled = true;
  try {
    const snapshot = await api('/admin/api/scheduler', {
      method: 'PATCH',
      body: { idleOnly: next },
    });
    state.scheduler = snapshot;
    renderScheduler();
    showToast(next ? '已切换为仅空闲执行' : '已切换为始终执行');
  } catch (error) {
    showToast(error.message);
  } finally {
    dom.schedulerIdleOnly.disabled = false;
  }
});

dom.schedulerRunAll?.addEventListener('click', async () => {
  dom.schedulerRunAll.disabled = true;
  try {
    await runSchedulerJob('');
  } catch (error) {
    showToast(error.message);
  } finally {
    renderScheduler();
  }
});

dom.schedulerJobs?.addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-scheduler-run]');
  if (!button) return;
  button.disabled = true;
  try {
    await runSchedulerJob(button.dataset.schedulerRun);
  } catch (error) {
    showToast(error.message);
  } finally {
    renderScheduler();
  }
});

dom.clearCacheButton.addEventListener('click', async () => {
  dom.clearCacheButton.disabled = true;
  try {
    await api('/admin/api/cache/clear', { method: 'POST' });
    await loadStats();
    showToast('查询缓存已清空');
  } catch (error) {
    showToast(error.message);
  } finally {
    dom.clearCacheButton.disabled = false;
  }
});

dom.clearHistoryButton.addEventListener('click', async () => {
  if (!window.confirm('确定清空全部域名历史快照？该操作不可恢复。')) return;
  dom.clearHistoryButton.disabled = true;
  try {
    await api('/admin/api/history', { method: 'DELETE' });
    await loadStats();
    showToast('历史快照已清空');
  } catch (error) {
    showToast(error.message);
  } finally {
    dom.clearHistoryButton.disabled = false;
  }
});

dom.clearIndexButton.addEventListener('click', async () => {
  if (!window.confirm('确定清空本地域名索引？名称服务器反查与注册商统计将重置。')) return;
  dom.clearIndexButton.disabled = true;
  try {
    await api('/admin/api/index', { method: 'DELETE' });
    await loadStats();
    showToast('本地索引已清空');
  } catch (error) {
    showToast(error.message);
  } finally {
    dom.clearIndexButton.disabled = false;
  }
});

dom.revokeSessionsButton.addEventListener('click', async () => {
  if (!window.confirm('所有后台会话将立即失效，当前页面也会退出登录。确定继续？')) return;
  dom.revokeSessionsButton.disabled = true;
  try {
    await api('/admin/api/sessions/revoke', { method: 'POST' });
    state.keys = [];
    state.stats = null;
    stopStatsTimer();
    showView('login');
    dom.password.value = '';
    dom.password.focus();
    showToast('全部会话已失效，请重新登录');
  } catch (error) {
    showToast(error.message);
  } finally {
    dom.revokeSessionsButton.disabled = false;
  }
});

initTheme();
bootstrap();
