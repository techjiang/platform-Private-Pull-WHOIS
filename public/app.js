const STATUS_LABELS = {
  ok: '正常',
  active: '正常',
  inactive: '未激活',
  connect: '已连接',
  free: '可注册',
  reserved: '保留',
  blocked: '已阻止',
  clientTransferProhibited: '客户端禁止转移',
  clientDeleteProhibited: '客户端禁止删除',
  clientUpdateProhibited: '客户端禁止更新',
  clientRenewProhibited: '客户端禁止续费',
  clientHold: '客户端暂停解析',
  serverTransferProhibited: '注册局禁止转移',
  serverDeleteProhibited: '注册局禁止删除',
  serverUpdateProhibited: '注册局禁止更新',
  serverRenewProhibited: '注册局禁止续费',
  serverHold: '注册局暂停解析',
  pendingCreate: '创建处理中',
  pendingDelete: '删除处理中',
  pendingRenew: '续费处理中',
  pendingTransfer: '转移处理中',
  pendingUpdate: '更新处理中',
  pendingRestore: '恢复处理中',
  redemptionPeriod: '赎回期',
  autoRenewPeriod: '自动续费宽限期',
  addPeriod: '新注册宽限期',
  renewPeriod: '续费宽限期',
  transferPeriod: '转移宽限期',
  restorePeriod: '恢复期',
};

const DNSSEC_LABELS = {
  signed: '已签名',
  unsigned: '未签名',
  unknown: '未知',
};

const TOOLS = {
  whois: {
    label: 'WHOIS',
    title: 'WHOIS 查询',
    placeholder: '输入域名，例如 example.com',
    api: '/v1/whois/{value}',
    chips: ['example.com', 'github.io', 'google.co.uk', 'denic.de', 'münich.com'],
    hint: '支持域名、URL、邮箱中的域名，以及 IDN / punycode。',
    idle: [
      ['灵活输入', '域名、URL、邮箱中的域名，支持 IDN / punycode'],
      ['统一字段', '注册商 · 日期 · EPP 状态 · DNS · DNSSEC · 注册人'],
      ['策略独立', '网页查询与 API 是否需要 Key 由后台分别控制，互不影响'],
    ],
  },
  rdap: {
    label: 'RDAP',
    title: 'RDAP 查询',
    placeholder: '输入域名，例如 example.com',
    api: '/v1/rdap/{value}',
    chips: ['example.com', 'cloudflare.com', 'google.com', 'nic.io'],
    hint: 'RDAP 是现代 WHOIS 继任者，返回结构化注册数据。',
    idle: [
      ['结构化数据', '注册商、状态、事件与实体字段由 RDAP 直接返回'],
      ['标准化', '避免解析上百种注册局 WHOIS 文本格式'],
      ['原始响应', '可切换到原始数据标签查看完整 RDAP JSON'],
    ],
  },
  dns: {
    label: 'DNS',
    title: 'DNS 记录查询',
    placeholder: '输入域名，例如 example.com',
    api: '/v1/dns/{value}?type=A',
    chips: ['example.com', 'cloudflare.com', 'github.com', 'qq.com'],
    hint: '支持 A、AAAA、MX、TXT、NS、CNAME、SOA、SRV、CAA 与全部记录。',
    idle: [
      ['九种记录', 'A / AAAA / MX / TXT / NS / CNAME / SOA / SRV / CAA'],
      ['一次拉全', '选择 ANY 可并行查询全部记录类型'],
      ['短缓存', '默认 5 分钟缓存，降低解析压力、响应更快'],
    ],
  },
  ip: {
    label: 'IP',
    title: 'IP 地址查询',
    placeholder: '输入 IPv4 或 IPv6，例如 8.8.8.8',
    api: '/v1/ip/{value}',
    chips: ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '114.114.114.114'],
    hint: '支持 IPv4 与 IPv6，返回 PTR、网络归属、组织与国家/地区。',
    idle: [
      ['双栈支持', '同时支持 IPv4 与 IPv6 地址'],
      ['网络归属', '通过 IANA RDAP 引导文件匹配对应 RIR'],
      ['反向解析', '附带 PTR 记录，便于识别主机用途'],
    ],
  },
  uptime: {
    label: '可用性',
    title: '网站可用性检查',
    placeholder: '输入域名或网址，例如 example.com',
    api: '/v1/uptime?target={value}',
    chips: ['example.com', 'github.com', 'cloudflare.com', 'baidu.com'],
    hint: '支持域名或完整 http(s) URL，自动跟随重定向并统计延迟。',
    idle: [
      ['真实探测', 'HEAD 优先，失败自动回退 GET'],
      ['安全防护', '拒绝内网与保留地址，避免 SSRF'],
      ['结果清晰', 'HTTP 状态、延迟、最终地址与检查时间'],
    ],
  },
  history: {
    label: '历史',
    title: '域名历史快照',
    placeholder: '输入域名，例如 example.com',
    api: '/v1/history/{value}',
    chips: ['example.com', 'github.com', 'google.com'],
    hint: '对比注册商、注册人、DNS 与状态变化，数据来自本站查询快照。',
    idle: [
      ['变更对比', '自动比较相邻快照的注册商、注册人与 DNS'],
      ['有界存储', '每个域名保留最近若干条快照，低占用'],
      ['数据说明', '历史自功能启用后积累，不虚构 2007 年数据'],
    ],
  },
  nameservers: {
    label: 'NS 反查',
    title: '名称服务器反查',
    placeholder: '输入名称服务器，例如 ns1.cloudflare.com',
    api: '/v1/nameservers/{value}',
    chips: ['ns1.cloudflare.com', 'ns1.google.com', 'dns1.registrar-servers.com'],
    hint: '查看本站索引中由该名称服务器托管的域名。',
    idle: [
      ['反查索引', '基于本站成功查询过的域名建立本地索引'],
      ['注册商统计', '同时展示域名所属注册商'],
      ['边界说明', '索引不等于全网数据，可接入外部数据源扩展'],
    ],
  },
  registrars: {
    label: '注册商',
    title: '注册商目录',
    placeholder: '搜索注册商，例如 Cloudflare / 146',
    api: '/v1/registrars',
    chips: ['Cloudflare', 'GoDaddy', '阿里云', 'Namecheap'],
    hint: '合并 IANA Registrar IDs 与 ICANN 认证列表，可搜索名称、IANA ID 与国家。',
    idle: [
      ['官方数据', '每日同步 IANA 与 ICANN 注册商目录，查询读取本地快照'],
      ['本地统计', '域名数量仅统计本站查询过的域名'],
      ['独立接口', '目录、详情与索引域名分别提供独立接口'],
    ],
  },
  icp: {
    label: '备案',
    title: 'ICP 备案查询',
    placeholder: '输入域名，例如 qq.com',
    api: '/v1/icp/{value}',
    chips: ['qq.com', 'baidu.com', 'taobao.com', 'bilibili.com'],
    hint: '查询中国大陆 ICP 备案：网站备案号、主体备案号、主办单位与审核时间。',
    idle: [
      ['备案信息', '网站备案号、主体备案号、主办单位性质与审核时间'],
      ['本站缓存', '结果由本站持久化缓存优先返回，7 天内直接命中'],
      ['按需回源', '仅缓存未命中或显式刷新时回源公开备案数据，失败时回退离线备份'],
    ],
  },
  tls: {
    label: '证书',
    title: 'TLS 证书检查',
    placeholder: '输入域名，例如 example.com',
    api: '/v1/tls/{value}',
    chips: ['example.com', 'github.com', 'cloudflare.com', 'qq.com'],
    hint: '自研 TLS 握手：检查证书颁发者、有效期、SAN、协议、加密套件与校验结果。',
    idle: [
      ['自研握手', '直接连接目标端口读取证书，不依赖第三方检测服务'],
      ['证书细节', '颁发者、有效期、剩余天数、SAN、指纹与证书链'],
      ['协议信息', 'TLS 版本、加密套件与 ALPN 协商结果'],
    ],
  },
  mail: {
    label: '邮件安全',
    title: '邮件安全记录',
    placeholder: '输入域名，例如 example.com',
    api: '/v1/mail/{value}',
    chips: ['example.com', 'google.com', 'github.com', 'qq.com'],
    hint: '自研 DNS 解析 SPF、DMARC、DKIM 与 MX，逐项给出邮件安全配置结论。',
    idle: [
      ['三项核心', 'SPF 发信来源、DMARC 策略、DKIM 公钥与 MX 记录'],
      ['本地解析', '全部通过本站 DNS 查询后解析，不调用第三方检测接口'],
      ['透明结论', '逐项 pass / warn / fail，并给出具体原因'],
    ],
  },
  http: {
    label: '安全体检',
    title: 'HTTP 安全响应头体检',
    placeholder: '输入域名或网址，例如 example.com',
    api: '/v1/http/{value}',
    chips: ['example.com', 'github.com', 'cloudflare.com', 'baidu.com'],
    hint: '直连目标站点读取响应头，检查 HSTS、CSP、点击劫持与 Cookie 安全属性。',
    idle: [
      ['九项检查', 'HSTS · CSP · 点击劫持 · MIME · Referrer · 权限 · COOP · Cookie'],
      ['评分与建议', '按权重计算 0-100 分与 A-E 等级，逐项给出改进建议'],
      ['轻量安全', '只读取响应头，不下载正文、不执行脚本，拒绝内网地址'],
    ],
  },
  dnsprop: {
    label: '解析传播',
    title: 'DNS 多解析器传播对比',
    placeholder: '输入域名，例如 example.com',
    api: '/v1/dnsprop/{value}?type=A',
    chips: ['example.com', 'cloudflare.com', 'qq.com', 'github.com'],
    hint: '同时对比阿里 DNS、DNSPod、Cloudflare 与 Google DNS 的解析结果。',
    idle: [
      ['四路并发', '四个公共递归解析器同时查询，逐项展示记录与耗时'],
      ['差异分组', '按记录集合分组，快速定位尚未传播的解析器'],
      ['七种记录', '支持 A / AAAA / MX / TXT / NS / CNAME / CAA'],
    ],
  },
  health: {
    label: '健康评分',
    title: '域名健康评分',
    placeholder: '输入域名，例如 example.com',
    api: '/v1/health/{value}',
    chips: ['example.com', 'cloudflare.com', 'github.com', 'qq.com'],
    hint: '注册、DNS、TLS、邮件四个维度各 25 分，聚合为 0-100 健康评分。',
    idle: [
      ['四维评分', '注册与所有权、DNS 解析、HTTPS 证书、邮件安全'],
      ['等级与建议', '输出 A+ 至 E 等级，并列出可直接执行的改进项'],
      ['降级容错', '单一上游暂时不可用只影响对应维度，不会整体失败'],
    ],
  },
  available: {
    label: '可注册',
    title: '批量可注册查询',
    placeholder: '输入 1-10 个域名，用逗号分隔',
    api: '/v1/available?domains={value}',
    chips: ['example.com,example.net', 'github.com,gitlab.com', 'qq.com,taobao.com'],
    hint: '一次最多 10 个域名，优先 RDAP、未覆盖时回退 WHOIS。',
    idle: [
      ['批量检测', '逗号、分号或空格分隔，最多 10 个域名'],
      ['双通道', '优先注册局 RDAP，未覆盖时自动回退 WHOIS 43'],
      ['短缓存', '可注册状态短缓存，避免返回过期结论'],
    ],
  },
  certchain: {
    label: '证书链',
    title: 'TLS 证书链导出',
    placeholder: '输入域名，例如 example.com',
    api: '/v1/tls/{value}/chain',
    chips: ['example.com', 'github.com', 'cloudflare.com', 'qq.com'],
    hint: '导出完整证书链与标准 PEM，便于排查链缺失与顺序问题。',
    idle: [
      ['完整链条', '按服务器返回顺序展示每一级证书的主体与颁发者'],
      ['指纹与 PEM', '每张证书提供 SHA-256 指纹与可直接复制的 PEM'],
      ['一键下载', '可下载合并后的 PEM 文件，用于本地证书链排查'],
    ],
  },
};

const dom = {
  form: document.querySelector('#searchForm'),
  input: document.querySelector('#domainInput'),
  button: document.querySelector('#searchBtn'),
  result: document.querySelector('#result'),
  toast: document.querySelector('#toast'),
  themeToggle: document.querySelector('#themeToggle'),
  copyCurl: document.querySelector('#copyCurl'),
  curlUrl: document.querySelector('#curlUrl'),
  toolSwitch: document.querySelector('#toolSwitch'),
  toolOptions: document.querySelector('#toolOptions'),
  dnsType: document.querySelector('#dnsType'),
  toolOptionNote: document.querySelector('#toolOptionNote'),
  dnsPropOptions: document.querySelector('#dnsPropOptions'),
  dnsPropType: document.querySelector('#dnsPropType'),
  chips: document.querySelector('.chips'),
  codePath: document.querySelector('.code-path'),
};

const state = { tool: 'whois' };
let current = null;
let requestSeq = 0;
let activeController = null;
let toastTimer = null;

/* ------------------------------------------------------------------ */
/* 工具函数                                                             */
/* ------------------------------------------------------------------ */
function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => {
    switch (char) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      default:
        return '&#39;';
    }
  });
}

function safeUrl(value) {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.protocol === 'http:' || url.protocol === 'https:') return esc(url.href);
  } catch {
    /* 非法 URL 直接忽略 */
  }
  return null;
}

function isEmail(value) {
  return Boolean(value) && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function formatDate(iso) {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    timeZone: 'UTC',
  }).format(date);
}

function relativeTime(iso) {
  if (!iso) return '';
  const target = new Date(iso).getTime();
  if (!Number.isFinite(target)) return '';
  const diff = target - Date.now();
  const abs = Math.abs(diff);
  const minute = 60_000;
  const hour = 60 * minute;
  const day = 24 * hour;
  const units = [
    ['year', 365 * day],
    ['month', 30 * day],
    ['day', day],
    ['hour', hour],
    ['minute', minute],
  ];
  const formatter = new Intl.RelativeTimeFormat('zh-CN', { numeric: 'auto' });
  for (const [unit, ms] of units) {
    if (abs >= ms || unit === 'minute') {
      return formatter.format(Math.round(diff / ms), unit);
    }
  }
  return '';
}

function daysUntil(iso) {
  if (!iso) return null;
  const target = new Date(iso).getTime();
  if (!Number.isFinite(target)) return null;
  return Math.ceil((target - Date.now()) / 86_400_000);
}

function expiryNote(iso) {
  const days = daysUntil(iso);
  if (days === null) return { text: '', warn: false };
  if (days < 0) return { text: `已过期 ${Math.abs(days)} 天`, warn: true };
  if (days === 0) return { text: '今天到期', warn: true };
  return { text: `还有 ${days} 天到期`, warn: days <= 30 };
}

function showToast(message) {
  dom.toast.textContent = message;
  dom.toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => dom.toast.classList.remove('show'), 1800);
}

async function copyText(text) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    showToast('已复制到剪贴板');
  } catch {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand('copy');
      showToast('已复制到剪贴板');
    } catch {
      showToast('复制失败，请手动选择');
    }
    area.remove();
  }
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
    stored = localStorage.getItem('pullwhois-theme');
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
    localStorage.setItem('pullwhois-theme', next);
  } catch {
    /* 忽略 */
  }
});

/* ------------------------------------------------------------------ */
/* 渲染片段                                                             */
/* ------------------------------------------------------------------ */
function pill(text, tone = 'muted', dot = false) {
  return `<span class="pill ${tone}">${dot ? '<span class="dot"></span>' : ''}${esc(text)}</span>`;
}

function statusTag(status) {
  const label = STATUS_LABELS[status] ?? status;
  const warn = /prohibit|hold|redemption|pending/i.test(status);
  return `<span class="tag ${warn ? 'is-warn' : 'is-neutral'}" title="${esc(status)}">${esc(label)}</span>`;
}

function personRow(label, value) {
  return `<div class="person-row"><span class="person-label">${esc(label)}</span><span class="person-value">${value}</span></div>`;
}

const LOCK_ICON = `<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="5" y="10" width="14" height="10" rx="2.2" stroke="currentColor" stroke-width="1.6"/><path d="M8.5 10V7.8a3.5 3.5 0 1 1 7 0V10" stroke="currentColor" stroke-width="1.6"/></svg>`;

function registrantBlock(registrant) {
  if (!registrant) {
    return '<p class="empty-line">注册局未提供注册人信息</p>';
  }

  const rows = [];
  if (registrant.organization) {
    rows.push(personRow('组织', esc(registrant.organization)));
  }
  if (registrant.name) {
    rows.push(personRow('姓名', esc(registrant.name)));
  }
  if (registrant.email) {
    const email = registrant.email;
    rows.push(
      personRow(
        '邮箱',
        isEmail(email)
          ? `<a href="mailto:${encodeURIComponent(email)}">${esc(email)}</a>`
          : esc(email),
      ),
    );
  }
  if (registrant.country) {
    rows.push(personRow('国家/地区', esc(registrant.country)));
  }
  if (rows.length === 0) {
    rows.push('<p class="empty-line">注册人信息未公开</p>');
  }

  const note = registrant.redacted
    ? `<div class="redaction-note">${LOCK_ICON}<span>部分字段受隐私保护政策隐藏。原始响应仍保留在「原始数据」标签中。</span></div>`
    : '';

  return `<div class="person-block">${rows.join('')}</div>${note}`;
}

function registrarBlock(registrar) {
  if (!registrar) {
    return '<p class="empty-line">注册局未提供注册商联系方式</p>';
  }

  const rows = [];
  if (registrar.ianaId) rows.push(personRow('IANA ID', `<code>${esc(registrar.ianaId)}</code>`));

  const website = safeUrl(registrar.url);
  if (website) {
    rows.push(
      personRow(
        '网站',
        `<a href="${website}" target="_blank" rel="noopener noreferrer">${esc(registrar.url)}</a>`,
      ),
    );
  }

  if (registrar.abuseEmail) {
    const email = registrar.abuseEmail;
    rows.push(
      personRow(
        '滥用邮箱',
        isEmail(email)
          ? `<a href="mailto:${encodeURIComponent(email)}">${esc(email)}</a>`
          : esc(email),
      ),
    );
  }

  if (registrar.abusePhone) {
    rows.push(personRow('滥用电话', esc(registrar.abusePhone)));
  }

  if (rows.length === 0) {
    rows.push('<p class="empty-line">注册局未提供注册商联系方式</p>');
  }

  return `<div class="person-block">${rows.join('')}</div>`;
}

function outputSection(data, meta, options = {}) {
  const displayData = { ...data };
  delete displayData.raw;
  const json = JSON.stringify({ success: true, data: displayData, meta }, null, 2);
  const raw = options.raw ?? data.raw ?? json;
  const hasNs = Array.isArray(data.nameservers) && data.nameservers.length > 0;
  const filename = options.filename || data.domain || data.ip || data.host || 'result';

  current = { json, raw, domain: filename, payload: { success: true, data, meta } };

  return `
    <div class="output">
      <div class="output-head">
        <div class="tabs" role="tablist" aria-label="数据视图">
          <button type="button" class="tab is-active" data-tab="json" role="tab" aria-selected="true">JSON</button>
          <button type="button" class="tab" data-tab="raw" role="tab" aria-selected="false">原始数据</button>
        </div>
        <div class="output-actions">
          ${hasNs ? '<button type="button" class="ghost-btn" data-copy="ns">复制 DNS</button>' : ''}
          <button type="button" class="ghost-btn" data-copy="json">复制 JSON</button>
          <button type="button" class="ghost-btn" data-copy="download">下载</button>
        </div>
      </div>
      <div class="output-panel is-active" data-panel="json" role="tabpanel">
        <pre>${esc(json)}</pre>
      </div>
      <div class="output-panel" data-panel="raw" role="tabpanel">
        <pre>${esc(raw)}</pre>
      </div>
    </div>
  `;
}

function metaFooter(meta) {
  const items = [];
  if (meta.source) items.push(`<span class="meta-item">来源 <strong>${esc(String(meta.source).toUpperCase())}</strong></span>`);
  if (meta.server) items.push(`<span class="meta-item">${esc(meta.server)}</span>`);
  if (typeof meta.durationMs === 'number') items.push(`<span class="meta-item">${meta.durationMs} ms</span>`);
  items.push(
    `<span class="meta-item"><span class="cache-pill">${meta.cached ? '缓存命中' : '实时查询'}</span></span>`,
  );
  if (meta.rateLimit) {
    items.push(
      `<span class="meta-item">配额 ${esc(meta.rateLimit.remaining)} / ${esc(meta.rateLimit.limit)}</span>`,
    );
  }
  if (meta.queriedAt) {
    const time = new Date(meta.queriedAt);
    if (!Number.isNaN(time.getTime())) {
      items.push(
        `<span class="meta-item">${esc(time.toLocaleTimeString('zh-CN', { hour12: false }))}</span>`,
      );
    }
  }
  return `<footer class="result-meta">${items.join('')}</footer>`;
}

function registeredTemplate(data, meta) {
  const registrar = data.registrar;
  const createdNote = relativeTime(data.dates.created);
  const updatedNote = relativeTime(data.dates.updated);
  const expiry = expiryNote(data.dates.expires);
  const dnssec = DNSSEC_LABELS[data.dnssec] ?? '未知';
  const source = String(meta.source ?? 'unknown').toUpperCase();
  const initial = (data.unicodeDomain || data.domain || '?').charAt(0).toUpperCase();

  const subParts = [`<span>${esc(String(data.tld).toUpperCase())} 后缀</span>`];
  if (data.idn && data.unicodeDomain !== data.domain) {
    subParts.push(`<span>${esc(data.unicodeDomain)}</span>`);
  }
  if (data.registryDomainId) subParts.push(`<code>${esc(data.registryDomainId)}</code>`);
  subParts.push(`<span>DNSSEC ${esc(dnssec)}</span>`);

  const statuses = data.statuses.length
    ? data.statuses.map(statusTag).join('')
    : '<p class="empty-line">注册局未返回状态码</p>';

  const nameservers = data.nameservers.length
    ? `<ul class="ns-list">${data.nameservers
        .map(
          (host, index) =>
            `<li class="ns-item"><span class="ns-index">${String(index + 1).padStart(2, '0')}</span><span class="ns-host">${esc(host)}</span></li>`,
        )
        .join('')}</ul>`
    : '<p class="empty-line">未返回 DNS 服务器</p>';

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar" aria-hidden="true">${esc(initial)}</div>
          <div>
            <div class="title-row">
              <h2>${esc(data.unicodeDomain || data.domain)}</h2>
              ${pill('已注册', 'ok', true)}
            </div>
            <p class="subline">${subParts.join('<span class="sep">·</span>')}</p>
          </div>
        </div>
        <div class="head-side">
          <span class="src-badge">${esc(source)}</span>
          <span class="src-note">${meta.cached ? '缓存命中' : '实时查询'}</span>
        </div>
      </header>

      <div class="stat-grid">
        <div class="stat">
          <span class="stat-label">注册商</span>
          <span class="stat-value ${registrar?.name ? '' : 'muted'}" title="${esc(registrar?.name ?? '')}">${esc(registrar?.name ?? '未公开')}</span>
          <span class="stat-sub">${registrar?.ianaId ? `IANA ID ${esc(registrar.ianaId)}` : '注册局未提供'}</span>
        </div>
        <div class="stat">
          <span class="stat-label">创建时间</span>
          <span class="stat-value mono ${data.dates.created ? '' : 'muted'}">${esc(formatDate(data.dates.created) ?? '—')}</span>
          <span class="stat-sub">${esc(createdNote || '无记录')}</span>
        </div>
        <div class="stat">
          <span class="stat-label">到期时间</span>
          <span class="stat-value mono ${data.dates.expires ? '' : 'muted'}">${esc(formatDate(data.dates.expires) ?? '—')}</span>
          <span class="stat-sub ${expiry.warn ? 'warn' : ''}">${esc(expiry.text || '无记录')}</span>
        </div>
        <div class="stat">
          <span class="stat-label">最近更新</span>
          <span class="stat-value mono ${data.dates.updated ? '' : 'muted'}">${esc(formatDate(data.dates.updated) ?? '—')}</span>
          <span class="stat-sub">${esc(updatedNote || '无记录')}</span>
        </div>
      </div>

      <div class="detail-grid">
        <section class="detail">
          <div class="section-head">
            <h3>域名状态 <span class="count">${data.statuses.length}</span></h3>
          </div>
          <div class="tag-wrap">${statuses}</div>
        </section>

        <section class="detail">
          <div class="section-head">
            <h3>DNS 服务器 <span class="count">${data.nameservers.length}</span></h3>
            ${data.nameservers.length ? '<button type="button" class="mini-btn" data-copy="ns">复制</button>' : ''}
          </div>
          ${nameservers}
        </section>

        <section class="detail">
          <div class="section-head"><h3>注册人</h3></div>
          ${registrantBlock(data.registrant)}
        </section>

        <section class="detail">
          <div class="section-head"><h3>注册商联系方式</h3></div>
          ${registrarBlock(registrar)}
        </section>
      </div>

      ${outputSection(data, meta)}
      ${metaFooter(meta)}
    </article>
  `;
}

function availableTemplate(data, meta) {
  const source = String(meta.source ?? 'unknown').toUpperCase();

  return `
    <article class="result-card">
      <div class="available-banner">
        <div class="check-badge" aria-hidden="true">✓</div>
        <div>
          <div class="title-row">${pill('可注册', 'ok', true)}<span class="src-badge">${esc(source)}</span></div>
          <h2>${esc(data.unicodeDomain || data.domain)}</h2>
          <p>注册局未返回该域名的注册记录，通常表示可以注册。最终可用性与价格请以注册商的实时查询结果为准。</p>
        </div>
      </div>

      <div class="available-body">
        <div class="fact">
          <span>后缀</span>
          <strong>.${esc(data.tld)}</strong>
        </div>
        <div class="fact">
          <span>域名形式</span>
          <strong>${data.idn ? `IDN · ${esc(data.domain)}` : 'ASCII'}</strong>
        </div>
        <div class="fact">
          <span>查询来源</span>
          <strong>${esc(source)}${meta.cached ? ' · 缓存' : ''}</strong>
        </div>
      </div>

      ${outputSection(data, meta)}
      ${metaFooter(meta)}
    </article>
  `;
}

/* ------------------------------------------------------------------ */
/* 其它工具模板                                                         */
/* ------------------------------------------------------------------ */
function formatDnsValue(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string' || typeof value === 'number') return String(value);
  if (Array.isArray(value)) return value.join(' · ');
  if (typeof value === 'object') {
    if (typeof value.text === 'string') return value.text;
    if (value.exchange !== undefined) {
      // 空 exchange 为 RFC 7505 的 Null MX，用 "." 表示
      return `${value.priority ?? 0} ${value.exchange || '.'}`.trim();
    }
    if (value.name && value.port !== undefined) {
      return `${value.priority ?? 0} ${value.weight ?? 0} ${value.port} ${value.name}`;
    }
    if (value.nsname) {
      return `${value.nsname} · ${value.hostmaster ?? ''} · serial ${value.serial ?? '—'}`;
    }
    if (value.issue || value.issuewild || value.iodef) {
      return Object.entries(value)
        .filter(([, item]) => item !== undefined && item !== null && item !== '')
        .map(([key, item]) => `${key}=${item}`)
        .join(' ');
    }
    return JSON.stringify(value);
  }
  return String(value);
}

function dnsTemplate(data, meta) {
  const order = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'TXT', 'SOA', 'SRV', 'CAA'];
  const groups = new Map();
  for (const record of data.records ?? []) {
    const type = String(record.type ?? 'OTHER');
    if (!groups.has(type)) groups.set(type, []);
    groups.get(type).push(record);
  }
  const types = [...groups.keys()].sort((a, b) => {
    const ai = order.indexOf(a);
    const bi = order.indexOf(b);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });

  const body = types.length
    ? types
        .map((type) => {
          const records = groups.get(type) ?? [];
          return `
            <section class="detail">
              <div class="section-head">
                <h3>${esc(type)} <span class="count">${records.length}</span></h3>
              </div>
              <ul class="record-list">
                ${records
                  .map((record) => {
                    const value = formatDnsValue(record.value);
                    return `<li class="record-item"><code>${esc(value)}</code><button type="button" class="mini-btn" data-copy-value="${esc(value)}">复制</button></li>`;
                  })
                  .join('')}
              </ul>
            </section>
          `;
        })
        .join('')
    : `<div class="empty-card"><h3>未查询到记录</h3><p>该域名在 ${esc(data.type)} 类型下没有返回记录，可能使用其他记录类型或尚未配置解析。</p></div>`;

  const statusPill =
    data.status === 'ok' ? pill('已解析', 'ok', true) : pill('无记录', 'warn', true);

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar" aria-hidden="true">D</div>
          <div>
            <div class="title-row">
              <h2>${esc(data.domain)}</h2>
              ${statusPill}
            </div>
            <p class="subline">
              <span>DNS ${esc(data.type)} 记录</span>
              <span class="sep">·</span>
              <span>${(data.records ?? []).length} 条结果</span>
              <span class="sep">·</span>
              <span>${esc(data.durationMs)} ms</span>
            </p>
          </div>
        </div>
        <div class="head-side">
          <span class="src-badge">DNS</span>
          <span class="src-note">${meta.cached ? '缓存命中' : '实时查询'}</span>
        </div>
      </header>
      <div class="detail-grid">${body}</div>
      ${outputSection(data, meta, { filename: data.domain })}
      ${metaFooter(meta)}
    </article>
  `;
}

function ipTemplate(data, meta) {
  const network = data.network ?? {};
  const asn = data.asn ?? null;
  const ptr = data.ptr ?? [];
  const rangeText = network.range?.start && network.range?.end
    ? `${network.range.start} – ${network.range.end}`
    : asn?.prefix ?? '未公开';
  const facts = [
    ['网络名称', network.name ?? '未公开'],
    ['组织', network.organization ?? asn?.name ?? '未公开'],
    ['国家/地区', network.country ?? asn?.country ?? '未公开'],
    ['地址范围', rangeText],
    ['网络 Handle', network.handle ?? '未公开'],
    ['网络类型', network.type ?? '未公开'],
    ['注册时间', formatDate(network.registered) ?? asn?.allocated ?? '未公开'],
    ['最后更新', formatDate(network.updated) ?? '未公开'],
  ];
  const asnRows = asn
    ? [
        ['ASN', asn.asn ? `AS${asn.asn}` : '未公开'],
        ['AS 名称', asn.name ?? '未公开'],
        ['路由前缀', asn.prefix ?? '未公开'],
        ['注册机构', asn.registry ? asn.registry.toUpperCase() : '未公开'],
        ['分配日期', asn.allocated ?? '未公开'],
      ]
    : [];

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar" aria-hidden="true">IP</div>
          <div>
            <div class="title-row">
              <h2>${esc(data.ip)}</h2>
              ${pill(data.version === 6 ? 'IPv6' : 'IPv4', 'ok', true)}
            </div>
            <p class="subline">
              <span>${esc(data.server ?? 'RDAP')}</span>
              <span class="sep">·</span>
              <span>${esc(data.durationMs)} ms</span>
              <span class="sep">·</span>
              <span>${ptr.length} 条 PTR</span>
            </p>
          </div>
        </div>
        <div class="head-side">
          <span class="src-badge">IP RDAP</span>
          <span class="src-note">${meta.cached ? '缓存命中' : '实时查询'}</span>
        </div>
      </header>

      <div class="stat-grid">
        <div class="stat">
          <span class="stat-label">组织</span>
          <span class="stat-value">${esc(network.organization ?? asn?.name ?? network.name ?? '未公开')}</span>
          <span class="stat-sub">${esc(network.handle ?? (asn?.asn ? `AS${asn.asn}` : 'RDAP'))}</span>
        </div>
        <div class="stat">
          <span class="stat-label">国家/地区</span>
          <span class="stat-value">${esc(network.country ?? asn?.country ?? '未公开')}</span>
          <span class="stat-sub">${esc(network.type ?? (asn?.registry ? asn.registry.toUpperCase() : '网络类型未知'))}</span>
        </div>
        <div class="stat">
          <span class="stat-label">地址范围</span>
          <span class="stat-value mono">${esc(network.range?.start ?? asn?.prefix ?? '—')}${network.range?.end ? ` – ${esc(network.range.end)}` : ''}</span>
          <span class="stat-sub">${esc(network.parentHandle ? `上级 ${network.parentHandle}` : 'RDAP 网络对象')}</span>
        </div>
        <div class="stat">
          <span class="stat-label">PTR 反向解析</span>
          <span class="stat-value mono">${ptr.length ? esc(ptr[0]) : '未配置'}</span>
          <span class="stat-sub">${ptr.length > 1 ? `另有 ${ptr.length - 1} 条` : '反向 DNS'}</span>
        </div>
      </div>

      <div class="detail-grid">
        ${
          asn
            ? `<section class="detail">
                <div class="section-head">
                  <h3>自治系统（ASN）</h3>
                  ${
                    asn.asn
                      ? `<a class="mini-btn" href="https://bgp.he.net/AS${esc(asn.asn)}" target="_blank" rel="noopener nofollow">BGP 详情</a>`
                      : ''
                  }
                </div>
                <div class="person-block">
                  ${asnRows
                    .map(
                      ([label, value]) =>
                        `<div class="person-row"><span class="person-label">${esc(label)}</span><span class="person-value">${esc(value)}</span></div>`,
                    )
                    .join('')}
                </div>
              </section>`
            : ''
        }
        <section class="detail">
          <div class="section-head"><h3>网络归属</h3></div>
          <div class="person-block">
            ${facts
              .map(
                ([label, value]) =>
                  `<div class="person-row"><span class="person-label">${esc(label)}</span><span class="person-value">${esc(value)}</span></div>`,
              )
              .join('')}
          </div>
        </section>
        <section class="detail">
          <div class="section-head">
            <h3>PTR 记录 <span class="count">${ptr.length}</span></h3>
            ${ptr.length ? '<button type="button" class="mini-btn" data-copy-value="' + esc(ptr.join('\n')) + '">复制</button>' : ''}
          </div>
          ${
            ptr.length
              ? `<ul class="ns-list">${ptr
                  .map(
                    (host, index) =>
                      `<li class="ns-item"><span class="ns-index">${String(index + 1).padStart(2, '0')}</span><span class="ns-host">${esc(host)}</span></li>`,
                  )
                  .join('')}</ul>`
              : '<p class="empty-line">该地址没有可用的 PTR 记录</p>'
          }
        </section>
        ${
          network.statuses?.length
            ? `<section class="detail"><div class="section-head"><h3>网络状态</h3></div><div class="tag-wrap">${network.statuses
                .map((status) => `<span class="tag is-neutral">${esc(status)}</span>`)
                .join('')}</div></section>`
            : ''
        }
      </div>

      ${data.note ? `<p class="callout">RDAP 提示：${esc(data.note)}</p>` : ''}
      ${outputSection(data, meta, { filename: data.ip })}
      ${metaFooter(meta)}
    </article>
  `;
}

function uptimeTemplate(data, meta) {
  const tone = data.ok ? 'ok' : data.reachable ? 'warn' : 'bad';
  const label = data.ok ? '访问正常' : data.reachable ? '可访问但异常' : '无法访问';
  const finalUrl = safeUrl(data.finalUrl);

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar ${tone}" aria-hidden="true">${data.reachable ? '✓' : '!'}</div>
          <div>
            <div class="title-row">
              <h2>${esc(data.target)}</h2>
              ${pill(label, tone, true)}
            </div>
            <p class="subline">
              <span>${esc(data.status ?? '无响应')}${data.statusText ? ` ${esc(data.statusText)}` : ''}</span>
              <span class="sep">·</span>
              <span>${esc(data.latencyMs)} ms</span>
              <span class="sep">·</span>
              <span>${esc(data.method ?? '—')}</span>
            </p>
          </div>
        </div>
        <div class="head-side">
          <span class="src-badge">UPTIME</span>
          <span class="src-note">${meta.cached ? '60 秒内缓存' : '实时探测'}</span>
        </div>
      </header>

      <div class="stat-grid">
        <div class="stat">
          <span class="stat-label">HTTP 状态</span>
          <span class="stat-value mono">${esc(data.status ?? '—')}</span>
          <span class="stat-sub">${esc(data.reachable ? '收到响应' : '连接失败')}</span>
        </div>
        <div class="stat">
          <span class="stat-label">响应延迟</span>
          <span class="stat-value mono">${esc(data.latencyMs)} ms</span>
          <span class="stat-sub">${esc(data.method ?? '—')} 请求</span>
        </div>
        <div class="stat">
          <span class="stat-label">重定向</span>
          <span class="stat-value">${data.redirected ? '是' : '否'}</span>
          <span class="stat-sub">${esc(data.redirected ? '已跟随到最终地址' : '未发生跳转')}</span>
        </div>
        <div class="stat">
          <span class="stat-label">检查时间</span>
          <span class="stat-value mono">${esc(new Date(data.checkedAt).toLocaleTimeString('zh-CN', { hour12: false }))}</span>
          <span class="stat-sub">${esc(new Date(data.checkedAt).toLocaleDateString('zh-CN'))}</span>
        </div>
      </div>

      <div class="detail-grid">
        <section class="detail">
          <div class="section-head"><h3>最终地址</h3></div>
          <p class="break-text">${finalUrl ? `<a href="${finalUrl}" target="_blank" rel="noopener noreferrer">${esc(data.finalUrl)}</a>` : esc(data.finalUrl)}</p>
          <div class="person-block">
            <div class="person-row"><span class="person-label">原始目标</span><span class="person-value break-text">${esc(data.target)}</span></div>
            <div class="person-row"><span class="person-label">检查方式</span><span class="person-value">${esc(data.method ?? '—')} · 手动跟随重定向</span></div>
          </div>
        </section>
        <section class="detail">
          <div class="section-head"><h3>结果说明</h3></div>
          ${
            data.error
              ? `<p class="callout">${esc(data.error)}</p>`
              : `<p class="empty-line">${data.ok ? '目标返回 2xx/3xx 状态，站点访问正常。' : '目标可达，但返回了 4xx/5xx 状态，请结合业务判断。'}</p>`
          }
        </section>
      </div>

      ${outputSection(data, meta, { filename: data.target })}
      ${metaFooter(meta)}
    </article>
  `;
}

function formatChangeValue(value) {
  if (Array.isArray(value)) return value.length ? value.join(', ') : '（空）';
  if (typeof value === 'boolean') return value ? '是' : '否';
  if (value === null || value === undefined || value === '') return '（空）';
  return String(value);
}

function historyTemplate(data, meta) {
  const snapshots = [...(data.snapshots ?? [])].reverse();
  const changes = data.changes ?? [];

  const snapshotList = snapshots.length
    ? `<ol class="timeline">${snapshots
        .map((snapshot) => {
          const at = new Date(snapshot.at);
          const time = Number.isNaN(at.getTime())
            ? snapshot.at
            : at.toLocaleString('zh-CN', { hour12: false });
          return `
            <li class="timeline-item">
              <div class="timeline-dot"></div>
              <div class="timeline-body">
                <div class="timeline-head">
                  <strong>${esc(snapshot.registrar ?? (snapshot.available ? '可注册' : '注册商未公开'))}</strong>
                  <time>${esc(time)}</time>
                </div>
                <p>${snapshot.nameservers?.length ? `${snapshot.nameservers.length} 个 DNS · ${esc(snapshot.nameservers.slice(0, 3).join(', '))}` : '无 DNS 记录'}</p>
                <p class="muted-text">${snapshot.statuses?.length ? snapshot.statuses.map(esc).join(' · ') : '无状态码'}</p>
              </div>
            </li>
          `;
        })
        .join('')}</ol>`
    : `<div class="empty-card"><h3>暂无历史快照</h3><p>该域名还没有保存的快照。发起一次 WHOIS / RDAP 查询后，本站会自动记录后续变化。</p></div>`;

  const changeList = changes.length
    ? `<ul class="change-list">${changes
        .slice(0, 30)
        .map((change) => {
          const at = new Date(change.at);
          const time = Number.isNaN(at.getTime())
            ? change.at
            : at.toLocaleString('zh-CN', { hour12: false });
          return `<li class="change-item"><span class="change-label">${esc(change.label)}</span><span class="change-values"><span>${esc(formatChangeValue(change.from))}</span><span class="change-arrow">→</span><span>${esc(formatChangeValue(change.to))}</span></span><span class="change-time">${esc(time)}</span></li>`;
        })
        .join('')}</ul>`
    : '<p class="empty-line">暂无字段变化</p>';

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar" aria-hidden="true">H</div>
          <div>
            <div class="title-row">
              <h2>${esc(data.domain)}</h2>
              ${pill(`${snapshots.length} 条快照`, 'ok', true)}
            </div>
            <p class="subline">
              <span>${changes.length} 项字段变化</span>
              <span class="sep">·</span>
              <span>本地快照历史</span>
            </p>
          </div>
        </div>
        <div class="head-side">
          <span class="src-badge">HISTORY</span>
          <button type="button" class="mini-btn" data-refresh-history="${esc(data.domain)}">刷新快照</button>
        </div>
      </header>

      <div class="detail-grid">
        <section class="detail">
          <div class="section-head"><h3>快照时间线 <span class="count">${snapshots.length}</span></h3></div>
          ${snapshotList}
        </section>
        <section class="detail">
          <div class="section-head"><h3>字段变化 <span class="count">${changes.length}</span></h3></div>
          ${changeList}
        </section>
      </div>

      <p class="callout">${esc(data.note)}</p>
      ${outputSection(data, meta, { filename: data.domain })}
      ${metaFooter(meta)}
    </article>
  `;
}

function nameserverTemplate(data, meta) {
  const domains = data.domains ?? [];

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar" aria-hidden="true">NS</div>
          <div>
            <div class="title-row">
              <h2>${esc(data.host)}</h2>
              ${pill(`${data.total} 个域名`, 'ok', true)}
            </div>
            <p class="subline">
              <span>来自本站本地索引</span>
              <span class="sep">·</span>
              <span>点击域名可直接查询 WHOIS</span>
            </p>
          </div>
        </div>
        <div class="head-side">
          <span class="src-badge">NS LOOKUP</span>
        </div>
      </header>

      ${
        domains.length
          ? `<div class="domain-list">${domains
              .map(
                (entry) => `
                  <div class="domain-row">
                    <button type="button" class="domain-link" data-query-domain="${esc(entry.domain)}">${esc(entry.domain)}</button>
                    <span class="domain-registrar">${esc(entry.registrar ?? '注册商未知')}</span>
                    <span class="domain-time">${esc(formatDate(entry.lastSeen) ?? '—')}</span>
                  </div>
                `,
              )
              .join('')}</div>`
          : `<div class="empty-card"><h3>索引中没有匹配域名</h3><p>本站只会索引成功查询过的域名。先查询该 NS 下的域名，随后即可在这里反查。</p></div>`
      }

      <p class="callout">${esc(data.note)}</p>
      ${outputSection(data, meta, { filename: data.host })}
      ${metaFooter(meta)}
    </article>
  `;
}

function icpTemplate(data, meta) {
  const filed = Boolean(data.filed);
  const sourceLabel = data.source === 'icp-offline' ? '离线备案数据' : '实时备案数据';
  const originLabel = meta?.cached ? '本站缓存' : sourceLabel;
  const rows = filed
    ? [
        ['网站备案号', data.icpCode],
        ['主体备案号', data.subjectCode],
        ['主办单位', data.unitName],
        ['单位性质', data.unitType],
        ['审核时间', data.auditDate],
      ]
    : [];

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar" aria-hidden="true">ICP</div>
          <div>
            <div class="title-row">
              <h2>${esc(data.domain)}</h2>
              ${filed ? pill('已备案', 'ok', true) : pill('未备案', 'muted', true)}
              ${data.stale ? pill('缓存数据', 'warn', true) : ''}
            </div>
            <p class="subline">
              <span>${filed ? '中国大陆 ICP 备案信息' : '未查询到备案记录'}</span>
              <span class="sep">·</span>
              <span>数据来源：${esc(originLabel)}</span>
            </p>
          </div>
        </div>
        <div class="head-side">
          <span class="src-badge">ICP</span>
          <span class="src-note">${meta?.cached ? '本地缓存' : '实时回源'}</span>
        </div>
      </header>

      ${
        filed
          ? `<div class="detail-grid">
              <section class="detail">
                <div class="section-head"><h3>备案信息</h3></div>
                <div class="person-block">
                  ${rows
                    .map(
                      ([label, value]) => `
                        <div class="person-row">
                          <span class="person-label">${label}</span>
                          <span class="person-value">
                            ${esc(value ?? '未提供')}
                            ${value ? `<button type="button" class="mini-btn" data-copy-value="${esc(value)}">复制</button>` : ''}
                          </span>
                        </div>
                      `,
                    )
                    .join('')}
                </div>
              </section>
              <section class="detail">
                <div class="section-head"><h3>数据说明</h3></div>
                <div class="person-block">
                  <div class="person-row"><span class="person-label">数据来源</span><span class="person-value">${esc(originLabel)}</span></div>
                  <div class="person-row"><span class="person-label">数据更新时间</span><span class="person-value">${esc(data.updatedAt ?? '未提供')}</span></div>
                </div>
              </section>
            </div>`
          : `<div class="empty-card"><h3>未查询到 ICP 备案</h3><p>境外域名或未备案域名通常没有记录。若域名刚完成备案，数据源可能存在延迟；最终请以工信部备案系统为准。</p></div>`
      }

      <p class="callout">${esc(data.note)}</p>
      ${outputSection(data, meta, { filename: `${data.domain}-icp` })}
      ${metaFooter(meta)}
    </article>
  `;
}

function tlsTemplate(data, meta) {
  const cert = data.certificate;
  const expired = Boolean(cert?.expired);
  const trusted = Boolean(data.authorized) && !expired && !cert?.notYetValid;
  const tone = expired ? 'danger' : trusted ? 'ok' : 'warn';
  const label = expired ? '证书已过期' : trusted ? '证书有效' : '校验未通过';
  const days = cert?.daysRemaining;
  const daysText = typeof days === 'number' ? (days >= 0 ? `${days} 天` : `已过期 ${Math.abs(days)} 天`) : '未知';
  const sans = Array.isArray(cert?.san) ? cert.san : [];

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar" aria-hidden="true">TLS</div>
          <div>
            <div class="title-row">
              <h2>${esc(data.host)}</h2>
              ${pill(label, tone, true)}
            </div>
            <p class="subline">
              <span>端口 ${esc(data.port)}</span>
              <span class="sep">·</span>
              <span>${esc(data.protocol ?? '未知协议')}</span>
              <span class="sep">·</span>
              <span>${esc(data.alpn ?? '无 ALPN')}</span>
            </p>
          </div>
        </div>
        <div class="head-side"><span class="src-badge">TLS</span></div>
      </header>

      ${
        cert
          ? `<div class="detail-grid">
              <section class="detail">
                <div class="section-head"><h3>证书</h3></div>
                <div class="person-block">
                  <div class="person-row"><span class="person-label">主体</span><span class="person-value">${esc(cert.subject?.commonName ?? '未提供')}</span></div>
                  <div class="person-row"><span class="person-label">颁发者</span><span class="person-value">${esc([cert.issuer?.organization, cert.issuer?.commonName].filter(Boolean).join(' / ') || '未提供')}</span></div>
                  <div class="person-row"><span class="person-label">生效时间</span><span class="person-value">${esc(formatDate(cert.validFrom) ?? '未知')}</span></div>
                  <div class="person-row"><span class="person-label">到期时间</span><span class="person-value">${esc(formatDate(cert.validTo) ?? '未知')}${typeof days === 'number' ? ` · 剩余 ${esc(daysText)}` : ''}</span></div>
                  <div class="person-row"><span class="person-label">公钥</span><span class="person-value">${cert.keyBits ? `${esc(cert.keyBits)} bit` : '未提供'}</span></div>
                  <div class="person-row"><span class="person-label">证书链</span><span class="person-value">${esc(cert.chainLength ?? 0)} 级</span></div>
                </div>
              </section>
              <section class="detail">
                <div class="section-head"><h3>连接与校验</h3></div>
                <div class="person-block">
                  <div class="person-row"><span class="person-label">连接地址</span><span class="person-value"><code>${esc(data.address)}</code></span></div>
                  <div class="person-row"><span class="person-label">加密套件</span><span class="person-value">${esc(data.cipher?.name ?? '未协商')}</span></div>
                  <div class="person-row"><span class="person-label">校验结果</span><span class="person-value">${trusted ? '通过' : esc(data.authorizationError ?? '未通过')}</span></div>
                  <div class="person-row"><span class="person-label">证书序列号</span><span class="person-value">${esc(cert.serialNumber ?? '未提供')}</span></div>
                  <div class="person-row"><span class="person-label">SHA-256</span><span class="person-value">${cert.fingerprint256 ? `<code>${esc(cert.fingerprint256)}</code><button type="button" class="mini-btn" data-copy-value="${esc(cert.fingerprint256)}">复制</button>` : '未提供'}</span></div>
                </div>
              </section>
            </div>
            ${
              sans.length
                ? `<section class="detail">
                    <div class="section-head"><h3>覆盖域名 <span class="count">${sans.length}</span></h3></div>
                    <div class="chips">${sans.slice(0, 24).map((item) => `<span class="chip" title="${esc(item)}">${esc(item)}</span>`).join('')}${sans.length > 24 ? `<span class="chip">+${sans.length - 24}</span>` : ''}</div>
                  </section>`
                : ''
            }`
          : '<div class="empty-card"><h3>未获取到证书</h3><p>目标端口完成了连接但没有返回证书，可能不是 TLS 服务。</p></div>'
      }

      <p class="callout">${esc(data.note)}</p>
      ${outputSection(data, meta, { filename: `${data.host}-tls` })}
      ${metaFooter(meta)}
    </article>
  `;
}

const CHECK_TONE = { pass: 'ok', warn: 'warn', fail: 'danger' };
const CHECK_LABEL = { pass: '通过', warn: '建议改进', fail: '缺失' };

function mailTemplate(data, meta) {
  const checks = Array.isArray(data.checks) ? data.checks : [];
  const tone = data.summary === '良好' ? 'ok' : data.summary === '需改进' ? 'warn' : 'danger';
  const mx = Array.isArray(data.mx) ? data.mx : [];
  const selectors = Array.isArray(data.dkim) ? data.dkim : [];
  const spf = data.spf;
  const dmarc = data.dmarc;

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar" aria-hidden="true">MX</div>
          <div>
            <div class="title-row">
              <h2>${esc(data.domain)}</h2>
              ${pill(data.summary, tone, true)}
            </div>
            <p class="subline">
              <span>SPF ${spf ? (spf.valid ? '已配置' : '需修正') : '缺失'}</span>
              <span class="sep">·</span>
              <span>DMARC ${dmarc ? (dmarc.policy ?? '需修正') : '缺失'}</span>
              <span class="sep">·</span>
              <span>DKIM ${selectors.filter((item) => item.found && item.info?.valid).length} 个选择器可用</span>
            </p>
          </div>
        </div>
        <div class="head-side"><span class="src-badge">MAIL</span></div>
      </header>

      <section class="detail">
        <div class="section-head"><h3>检查结论</h3></div>
        <div class="person-block">
          ${checks
            .map(
              (check) => `
                <div class="person-row">
                  <span class="person-label">${esc(check.label)}</span>
                  <span class="person-value">
                    ${pill(CHECK_LABEL[check.status] ?? check.status, CHECK_TONE[check.status] ?? 'muted')}
                    ${esc(check.detail)}
                  </span>
                </div>
              `,
            )
            .join('')}
        </div>
      </section>

      <div class="detail-grid">
        <section class="detail">
          <div class="section-head"><h3>SPF</h3></div>
          <div class="person-block">
            ${
              spf
                ? `<div class="person-row"><span class="person-label">原始记录</span><span class="person-value"><code>${esc(spf.raw)}</code></span></div>
                   <div class="person-row"><span class="person-label">all 策略</span><span class="person-value">${esc((spf.allQualifier ?? '') + (spf.all ?? '')) || '未设置'}</span></div>
                   <div class="person-row"><span class="person-label">DNS 查询机制</span><span class="person-value">${esc(spf.lookupCount)} / 10</span></div>
                   <div class="person-row"><span class="person-label">include</span><span class="person-value">${spf.includes?.length ? spf.includes.map((item) => `<code>${esc(item)}</code>`).join(' ') : '无'}</span></div>
                   <div class="person-row"><span class="person-label">IP 白名单</span><span class="person-value">${[...(spf.ip4 ?? []), ...(spf.ip6 ?? [])].length ? [...(spf.ip4 ?? []), ...(spf.ip6 ?? [])].map((item) => `<code>${esc(item)}</code>`).join(' ') : '无'}</span></div>`
                : '<p class="empty-line">未找到 SPF 记录，收信方无法判断哪些服务器有权代发邮件。</p>'
            }
          </div>
        </section>
        <section class="detail">
          <div class="section-head"><h3>DMARC</h3></div>
          <div class="person-block">
            ${
              dmarc
                ? `<div class="person-row"><span class="person-label">策略</span><span class="person-value">${esc(dmarc.policy ?? '未设置')}${dmarc.subdomainPolicy ? ` · 子域 ${esc(dmarc.subdomainPolicy)}` : ''}</span></div>
                   <div class="person-row"><span class="person-label">覆盖率</span><span class="person-value">${esc(dmarc.pct ?? 100)}%</span></div>
                   <div class="person-row"><span class="person-label">对齐方式</span><span class="person-value">DKIM ${esc(dmarc.alignment?.dkim ?? 'r')} · SPF ${esc(dmarc.alignment?.spf ?? 'r')}</span></div>
                   <div class="person-row"><span class="person-label">报告地址</span><span class="person-value">${dmarc.rua?.length ? dmarc.rua.map((item) => `<code>${esc(item)}</code>`).join(' ') : '未设置'}</span></div>`
                : '<p class="empty-line">未找到 DMARC 记录，域外伪造邮件无法被策略拦截。</p>'
            }
          </div>
        </section>
      </div>

      <div class="detail-grid">
        <section class="detail">
          <div class="section-head"><h3>DKIM 选择器</h3></div>
          <div class="person-block">
            ${selectors
              .map(
                (item) => `
                  <div class="person-row">
                    <span class="person-label">${esc(item.selector)}</span>
                    <span class="person-value">${
                      item.found
                        ? `${pill(
                            item.info?.valid ? '公钥可用' : item.info?.revoked ? '已撤销' : '存在异常',
                            item.info?.valid ? 'ok' : 'warn',
                            true,
                          )}${esc(item.info?.keyType ?? 'rsa')}`
                        : '<span class="muted-text">未找到公钥</span>'
                    }</span>
                  </div>
                `,
              )
              .join('')}
          </div>
        </section>
        <section class="detail">
          <div class="section-head"><h3>MX 记录 <span class="count">${mx.length}</span></h3></div>
          <div class="person-block">
            ${
              mx.length
                ? mx
                    .map(
                      (item) => `
                        <div class="person-row">
                          <span class="person-label">优先级 ${esc(item.priority)}</span>
                          <span class="person-value"><code>${esc(item.exchange)}</code></span>
                        </div>
                      `,
                    )
                    .join('')
                : `<p class="empty-line">${
                    Array.isArray(data.aFallback) && data.aFallback.length
                      ? `未配置 MX，按 RFC 回退到 A 记录：${data.aFallback.map((item) => `<code>${esc(item)}</code>`).join(' ')}`
                      : '未配置 MX 记录，该域名可能无法接收邮件。'
                  }</p>`
            }
          </div>
        </section>
      </div>

      <p class="callout">${esc(data.note)}</p>
      ${outputSection(data, meta, { filename: `${data.domain}-mail` })}
      ${metaFooter(meta)}
    </article>
  `;
}

const REGISTRAR_STATUS_LABELS = {
  accredited: ['已认证', 'ok'],
  terminated: ['已终止', 'muted'],
  reserved: ['保留', 'muted'],
  unknown: ['未知', 'muted'],
};

const REGISTRAR_SOURCE_LABELS = {
  'iana+icann': 'IANA + ICANN',
  iana: 'IANA',
  icann: 'ICANN',
  curated: '精选目录',
  local: '本地索引',
};

function registrarStatusPill(status) {
  const [label, tone] = REGISTRAR_STATUS_LABELS[status] ?? REGISTRAR_STATUS_LABELS.unknown;
  return `<span class="pill ${tone}">${label}</span>`;
}

function registrarCard(entry) {
  return `
    <button type="button" class="registrar-card" data-registrar-id="${esc(entry.id)}">
      <span class="registrar-head">
        <strong>${esc(entry.name)}</strong>
        ${registrarStatusPill(entry.status)}
      </span>
      <span class="registrar-meta">
        ${entry.ianaId ? `IANA ${esc(entry.ianaId)}` : 'IANA 未收录'}
        ${entry.country ? ` · ${esc(entry.country)}` : ''}
      </span>
      <span class="registrar-foot">
        ${entry.indexedDomains ?? 0} 个索引域名 ·
        ${esc(REGISTRAR_SOURCE_LABELS[entry.source] ?? '目录')}
      </span>
    </button>
  `;
}

function registrarPager(data) {
  const totalPages = Number(data.totalPages) || 1;
  if (totalPages <= 1) return '';
  const page = Number(data.page) || 1;
  return `
    <div class="registrar-pager">
      <button class="mini-btn" type="button" data-registrar-page="${page - 1}" ${page <= 1 ? 'disabled' : ''}>上一页</button>
      <span>第 ${page} / ${totalPages} 页 · 共 ${Number(data.total) || 0} 家</span>
      <button class="mini-btn" type="button" data-registrar-page="${page + 1}" ${page >= totalPages ? 'disabled' : ''}>下一页</button>
    </div>
  `;
}

function registrarsTemplate(data, meta) {
  const items = data.items ?? [];
  const stats = data.stats ?? {};
  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar" aria-hidden="true">R</div>
          <div>
            <div class="title-row">
              <h2>注册商目录</h2>
              ${pill(`${data.total} 家`, 'ok', true)}
            </div>
            <p class="subline">
              <span>第 ${data.page} / ${data.totalPages} 页</span>
              <span class="sep">·</span>
              <span>${Number(stats.accredited) || 0} 家已认证 · ${Number(stats.countries) || 0} 个国家/地区</span>
            </p>
          </div>
        </div>
        <div class="head-side"><span class="src-badge">REGISTRARS</span></div>
      </header>

      ${
        items.length
          ? `<div class="registrar-grid">${items.map(registrarCard).join('')}</div>${registrarPager(data)}`
          : `<div class="empty-card"><h3>没有匹配的注册商</h3><p>试试名称、IANA ID 或别名，例如 Cloudflare、146、阿里云。</p></div>`
      }

      <p class="callout">${esc(data.note)}</p>
      ${outputSection(data, meta, { filename: 'registrars' })}
      ${metaFooter(meta)}
    </article>
  `;
}

function registrarDetailTemplate(data, meta) {
  const registrar = data.registrar ?? {};
  const domains = data.domains?.items ?? [];
  const website = safeUrl(registrar.website);

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar" aria-hidden="true">R</div>
          <div>
            <div class="title-row">
              <h2>${esc(registrar.name)}</h2>
              ${pill(`${data.domains?.total ?? 0} 个索引域名`, 'ok', true)}
            </div>
            <p class="subline">
              ${registrar.ianaId ? `<span>IANA ${esc(registrar.ianaId)}</span><span class="sep">·</span>` : ''}
              <span>${esc(registrar.country ?? '地区未知')}</span>
            </p>
          </div>
        </div>
        <div class="head-side">
          <button type="button" class="mini-btn" data-back-registrars>返回目录</button>
        </div>
      </header>

      <div class="detail-grid">
        <section class="detail">
          <div class="section-head"><h3>注册商信息</h3></div>
          <div class="person-block">
            <div class="person-row"><span class="person-label">IANA ID</span><span class="person-value">${esc(registrar.ianaId ?? '未收录')}</span></div>
            <div class="person-row"><span class="person-label">认证状态</span><span class="person-value">${registrarStatusPill(registrar.status)}</span></div>
            <div class="person-row"><span class="person-label">官网</span><span class="person-value">${website ? `<a href="${website}" target="_blank" rel="noopener noreferrer">${esc(registrar.website)}</a>` : '未收录'}</span></div>
            <div class="person-row"><span class="person-label">联系方式</span><span class="person-value">${esc(registrar.contact ?? '未收录')}</span></div>
            <div class="person-row"><span class="person-label">RDAP 服务</span><span class="person-value">${registrar.rdapServer ? `<code>${esc(registrar.rdapServer)}</code>` : '未收录'}</span></div>
            <div class="person-row"><span class="person-label">数据来源</span><span class="person-value">${esc(REGISTRAR_SOURCE_LABELS[registrar.source] ?? '目录')}</span></div>
            <div class="person-row"><span class="person-label">索引域名</span><span class="person-value">${data.domains?.total ?? 0}</span></div>
            <div class="person-row"><span class="person-label">最近查询</span><span class="person-value">${esc(formatDate(registrar.lastSeen) ?? '—')}</span></div>
          </div>
        </section>
        <section class="detail">
          <div class="section-head"><h3>索引中的域名 <span class="count">${domains.length}</span></h3></div>
          ${
            domains.length
              ? `<div class="domain-list">${domains
                  .map(
                    (entry) => `
                      <div class="domain-row">
                        <button type="button" class="domain-link" data-query-domain="${esc(entry.domain)}">${esc(entry.domain)}</button>
                        <span class="domain-time">${esc(formatDate(entry.lastSeen) ?? '—')}</span>
                      </div>
                    `,
                  )
                  .join('')}</div>`
              : '<p class="empty-line">本站索引中还没有该注册商的域名。查询相关域名后会自动建立关联。</p>'
          }
        </section>
      </div>

      <p class="callout">${esc(data.note)}</p>
      ${outputSection(data, meta, { filename: registrar.name || 'registrar' })}
      ${metaFooter(meta)}
    </article>
  `;
}

/* ------------------------------------------------------------------ */
/* 状态切换                                                             */
/* ------------------------------------------------------------------ */
function setBusy(busy) {
  dom.result.setAttribute('aria-busy', busy ? 'true' : 'false');
  dom.button.disabled = busy;
}

function idleTemplate(tool) {
  const config = TOOLS[tool] ?? TOOLS.whois;
  return `
    <div class="idle-grid">
      ${config.idle
        .map(
          ([title, body], index) => `
            <article class="idle-card">
              <span class="idle-index">0${index + 1}</span>
              <h3>${esc(title)}</h3>
              <p>${esc(body)}</p>
            </article>
          `,
        )
        .join('')}
    </div>
  `;
}

function showIdle() {
  current = null;
  dom.result.innerHTML = idleTemplate(state.tool);
  document.title = `${TOOLS[state.tool].title} · Pull WHOIS`;
  setBusy(false);
}

function applyTool(tool, options = {}) {
  const key = TOOLS[tool] ? tool : 'whois';
  const config = TOOLS[key];
  state.tool = key;

  dom.toolSwitch?.querySelectorAll('[data-tool]').forEach((button) => {
    const active = button.dataset.tool === key;
    button.classList.toggle('is-active', active);
    button.setAttribute('aria-selected', active ? 'true' : 'false');
  });

  if (dom.input) {
    dom.input.placeholder = config.placeholder;
    dom.input.setAttribute('aria-label', config.placeholder);
  }
  if (dom.toolOptions) dom.toolOptions.hidden = key !== 'dns';
  if (dom.dnsPropOptions) dom.dnsPropOptions.hidden = key !== 'dnsprop';
  if (dom.toolOptionNote) dom.toolOptionNote.textContent = config.hint;

  if (dom.chips) {
    dom.chips.innerHTML =
      '<span class="chips-label">试试</span>' +
      config.chips
        .map(
          (value) =>
            `<button type="button" class="chip" data-domain="${esc(value)}">${esc(value)}</button>`,
        )
        .join('');
  }

  const sample = config.api.replace('{value}', config.chips[0] ?? 'example.com');
  if (dom.codePath) dom.codePath.textContent = `GET ${sample}`;
  if (dom.curlUrl) dom.curlUrl.textContent = `${location.origin}${sample}`;

  if (options.updateHash) {
    const url = new URL(location.href);
    url.hash = key;
    url.searchParams.delete('q');
    url.searchParams.delete('domain');
    url.searchParams.delete('type');
    history.pushState({ tool: key }, '', url);
  }

  if (options.keepResult !== true) {
    if (dom.input) dom.input.value = '';
    showIdle();
  }

  if (key === 'registrars' && options.loadDirectory !== false) {
    void loadRegistrars('', false);
  }
}

function showLoading(domain) {
  current = null;
  setBusy(true);
  dom.result.innerHTML = `
    <div class="skeleton-card" aria-label="正在查询 ${esc(domain)}">
      <div class="sk-head">
        <div class="sk-avatar"></div>
        <div class="sk-lines">
          <div class="sk-line w-40"></div>
          <div class="sk-line w-70"></div>
        </div>
      </div>
      <div class="sk-stats">
        <div class="sk-stat"></div><div class="sk-stat"></div>
        <div class="sk-stat"></div><div class="sk-stat"></div>
      </div>
      <div class="sk-body">
        <div class="sk-block"></div><div class="sk-block"></div>
      </div>
    </div>
  `;
}

function bindResultEvents() {
  dom.result.querySelectorAll('[data-tab]').forEach((button) => {
    button.addEventListener('click', () => {
      dom.result.querySelectorAll('[data-tab]').forEach((item) => {
        const active = item === button;
        item.classList.toggle('is-active', active);
        item.setAttribute('aria-selected', active ? 'true' : 'false');
      });
      dom.result.querySelectorAll('[data-panel]').forEach((panel) => {
        panel.classList.toggle('is-active', panel.dataset.panel === button.dataset.tab);
      });
    });
  });

  dom.result.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', () => {
      const kind = button.dataset.copy;
      if (!current) return;
      if (kind === 'json') void copyText(current.json);
      else if (kind === 'raw') void copyText(current.raw);
      else if (kind === 'ns') void copyText((current.payload.data.nameservers || []).join('\n'));
      else if (kind === 'download') {
        const blob = new Blob([JSON.stringify(current.payload, null, 2)], {
          type: 'application/json;charset=utf-8',
        });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `${current.domain}.whois.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        showToast('已下载 JSON');
      }
    });
  });

  dom.result.querySelectorAll('[data-copy-value]').forEach((button) => {
    button.addEventListener('click', () => {
      void copyText(button.dataset.copyValue || '');
    });
  });

  dom.result.querySelectorAll('[data-copy-pem]').forEach((button) => {
    button.addEventListener('click', () => {
      const index = Number(button.dataset.copyPem);
      const chain = current?.payload?.data?.chain;
      if (!Array.isArray(chain)) return;
      const item = chain.find((entry) => Number(entry.index) === index);
      if (!item?.pem) {
        showToast('该证书没有可复制的 PEM');
        return;
      }
      void copyText(item.pem);
    });
  });

  dom.result.querySelectorAll('[data-download-pem]').forEach((button) => {
    button.addEventListener('click', () => {
      const data = current?.payload?.data;
      if (!data?.pem) {
        showToast('没有可下载的 PEM');
        return;
      }
      const blob = new Blob([data.pem], { type: 'application/x-pem-file;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${data.host || 'certificate'}-chain.pem`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      showToast('已下载证书链 PEM');
    });
  });

  dom.result.querySelectorAll('[data-registrar-id]').forEach((button) => {
    button.addEventListener('click', () => {
      void loadRegistrar(button.dataset.registrarId || '');
    });
  });

  dom.result.querySelectorAll('[data-back-registrars]').forEach((button) => {
    button.addEventListener('click', () => {
      void loadRegistrars('', false);
    });
  });

  dom.result.querySelectorAll('[data-registrar-page]').forEach((button) => {
    button.addEventListener('click', () => {
      const page = Number(button.dataset.registrarPage) || 1;
      if (page < 1) return;
      void runQuery(dom.input.value.trim(), false, { page });
    });
  });

  dom.result.querySelectorAll('[data-query-domain]').forEach((button) => {
    button.addEventListener('click', () => {
      const value = button.dataset.queryDomain || '';
      applyTool('whois', { updateHash: true, loadDirectory: false });
      dom.input.value = value;
      void runQuery(value, true);
    });
  });

  dom.result.querySelectorAll('[data-refresh-history]').forEach((button) => {
    button.addEventListener('click', () => {
      const value = button.dataset.refreshHistory || '';
      void runQuery(value, false, { refresh: true });
    });
  });
}

function httpTemplate(data, meta) {
  const checks = Array.isArray(data.security) ? data.security : [];
  const issues = Array.isArray(data.issues) ? data.issues : [];
  const hasScore = typeof data.score === 'number';
  const tone = hasScore ? (data.score >= 80 ? 'ok' : data.score >= 60 ? 'warn' : 'danger') : 'danger';
  const redirects = Array.isArray(data.redirects) ? data.redirects : [];

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar avatar-words" aria-hidden="true">HTTP</div>
          <div>
            <div class="title-row">
              <h2>${esc(data.host)}</h2>
              ${hasScore ? pill(`${data.score} 分 · ${data.grade}`, tone, true) : pill('未评级', 'muted', true)}
              ${data.reachable ? '' : pill('不可访问', 'danger', true)}
            </div>
            <p class="subline">
              <span>${data.reachable ? `HTTP ${esc(data.status)}` : '连接失败'}</span>
              <span class="sep">·</span>
              <span>${esc(data.latencyMs)} ms</span>
              <span class="sep">·</span>
              <span>${data.https ? 'HTTPS' : 'HTTP'}</span>
              ${redirects.length ? `<span class="sep">·</span><span>${redirects.length} 次跳转</span>` : ''}
            </p>
          </div>
        </div>
        <div class="head-side"><span class="src-badge">HTTP</span></div>
      </header>

      ${
        data.error
          ? `<div class="empty-card"><h3>无法完成体检</h3><p>${esc(data.error)}</p></div>`
          : `<div class="score-spotlight">
              <div class="score-number tone-${tone}">${esc(data.score)}</div>
              <div class="score-copy">
                <strong>${esc(data.summary)}</strong>
                <p>${checks.length} 项安全检查 · 等级 ${esc(data.grade)} · 目标 ${esc(data.finalUrl)}</p>
              </div>
            </div>
            <div class="detail-grid">
              <section class="detail">
                <div class="section-head"><h3>安全检查</h3></div>
                <div class="check-list">
                  ${checks
                    .map(
                      (item) => `
                        <div class="check-item">
                          <span class="check-dot tone-${CHECK_TONE[item.status] ?? 'muted'}"></span>
                          <div>
                            <div class="check-head">
                              <strong>${esc(item.label)}</strong>
                              ${pill(CHECK_LABEL[item.status] ?? item.status, CHECK_TONE[item.status] ?? 'muted', true)}
                            </div>
                            <p>${esc(item.detail)}</p>
                          </div>
                        </div>
                      `,
                    )
                    .join('')}
                </div>
              </section>
              <section class="detail">
                <div class="section-head"><h3>响应概览</h3></div>
                <div class="person-block">
                  <div class="person-row"><span class="person-label">状态码</span><span class="person-value">${esc(data.status ?? '未知')} ${esc(data.statusText ?? '')}</span></div>
                  <div class="person-row"><span class="person-label">服务器</span><span class="person-value">${esc(data.server ?? '未暴露')}</span></div>
                  <div class="person-row"><span class="person-label">后端框架</span><span class="person-value">${esc(data.poweredBy ?? '未暴露')}</span></div>
                  <div class="person-row"><span class="person-label">内容类型</span><span class="person-value">${esc(data.contentType ?? '未提供')}</span></div>
                  <div class="person-row"><span class="person-label">压缩方式</span><span class="person-value">${esc(data.contentEncoding ?? '未启用')}</span></div>
                  <div class="person-row"><span class="person-label">缓存策略</span><span class="person-value">${esc(data.cacheControl ?? '未设置')}</span></div>
                  <div class="person-row"><span class="person-label">Cookie</span><span class="person-value">${Array.isArray(data.cookies) && data.cookies.length ? `${data.cookies.length} 个` : '未设置'}</span></div>
                </div>
              </section>
            </div>
            ${
              redirects.length
                ? `<section class="detail">
                    <div class="section-head"><h3>重定向链</h3></div>
                    <div class="check-list">
                      ${redirects
                        .map(
                          (hop) => `
                            <div class="check-item">
                              <span class="check-dot tone-muted"></span>
                              <div><strong>${esc(hop.status)}</strong><p>${esc(hop.from)} → ${esc(hop.to)}</p></div>
                            </div>
                          `,
                        )
                        .join('')}
                    </div>
                  </section>`
                : ''
            }
            ${
              issues.length
                ? `<section class="detail">
                    <div class="section-head"><h3>改进建议 <span class="count">${issues.length}</span></h3></div>
                    <div class="check-list">
                      ${issues
                        .map(
                          (item) => `
                            <div class="check-item">
                              <span class="check-dot tone-${item.severity === 'high' ? 'danger' : item.severity === 'medium' ? 'warn' : 'muted'}"></span>
                              <div><strong>${esc(item.label)}</strong><p>${esc(item.detail)}</p></div>
                            </div>
                          `,
                        )
                        .join('')}
                    </div>
                  </section>`
                : ''
            }`
      }

      <p class="callout">${esc(data.note)}</p>
      ${outputSection(data, meta, { filename: `${data.host}-http` })}
      ${metaFooter(meta)}
    </article>
  `;
}

function dnsPropTemplate(data, meta) {
  const resolvers = Array.isArray(data.resolvers) ? data.resolvers : [];
  const differences = Array.isArray(data.differences) ? data.differences : [];
  const tone = data.consistent ? 'ok' : 'warn';

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar" aria-hidden="true">DNS</div>
          <div>
            <div class="title-row">
              <h2>${esc(data.domain)}</h2>
              ${pill(data.consistent ? '解析一致' : '存在差异', tone, true)}
              ${pill(data.type, 'muted', true)}
            </div>
            <p class="subline">
              <span>${data.successful} 个解析器返回</span>
              <span class="sep">·</span>
              <span>${data.failed} 个失败</span>
              <span class="sep">·</span>
              <span>${data.consistent ? '结果完全一致' : `${differences.length} 组不同结果`}</span>
            </p>
          </div>
        </div>
        <div class="head-side"><span class="src-badge">DNS</span></div>
      </header>

      <section class="detail">
        <div class="section-head"><h3>解析器结果</h3></div>
        <div class="check-list">
          ${resolvers
            .map((item) => {
              const statusTone =
                item.status === 'ok' ? 'ok' : item.status === 'timeout' ? 'warn' : 'danger';
              const statusLabel =
                item.status === 'ok' ? '正常' : item.status === 'timeout' ? '超时' : '失败';
              const records = Array.isArray(item.records) ? item.records : [];
              return `
                <div class="check-item">
                  <span class="check-dot tone-${statusTone}"></span>
                  <div>
                    <div class="check-head">
                      <strong>${esc(item.name)}</strong>
                      ${pill(statusLabel, statusTone, true)}
                      <span class="check-meta">${esc(item.address)} · ${esc(item.durationMs)} ms</span>
                    </div>
                    ${
                      records.length
                        ? `<div class="record-chips">${records.map((record) => `<code>${esc(record)}</code>`).join('')}</div>`
                        : `<p>${esc(item.error ?? '没有返回记录')}</p>`
                    }
                  </div>
                </div>
              `;
            })
            .join('')}
        </div>
      </section>

      ${
        differences.length
          ? `<section class="detail">
              <div class="section-head"><h3>差异分组 <span class="count">${differences.length}</span></h3></div>
              <div class="check-list">
                ${differences
                  .map(
                    (group, index) => `
                      <div class="check-item">
                        <span class="check-dot tone-warn"></span>
                        <div>
                          <strong>第 ${index + 1} 组 · ${esc((group.resolvers || []).join('、'))}</strong>
                          <div class="record-chips">${(group.records || []).map((record) => `<code>${esc(record)}</code>`).join('')}</div>
                        </div>
                      </div>
                    `,
                  )
                  .join('')}
              </div>
            </section>`
          : ''
      }

      <p class="callout">${esc(data.note)}</p>
      ${outputSection(data, meta, { filename: `${data.domain}-dnsprop` })}
      ${metaFooter(meta)}
    </article>
  `;
}

function healthTemplate(data, meta) {
  const dimensions = Array.isArray(data.dimensions) ? data.dimensions : [];
  const issues = Array.isArray(data.issues) ? data.issues : [];
  const tone = data.score >= 80 ? 'ok' : data.score >= 60 ? 'warn' : 'danger';

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar" aria-hidden="true">评分</div>
          <div>
            <div class="title-row">
              <h2>${esc(data.domain)}</h2>
              ${pill(`${data.score} 分 · ${data.grade}`, tone, true)}
            </div>
            <p class="subline">
              <span>${esc(data.summary)}</span>
              <span class="sep">·</span>
              <span>${dimensions.length} 个维度</span>
            </p>
          </div>
        </div>
        <div class="head-side"><span class="src-badge">HEALTH</span></div>
      </header>

      <div class="score-spotlight">
        <div class="score-number tone-${tone}">${esc(data.score)}</div>
        <div class="score-copy">
          <strong>${esc(data.summary)}</strong>
          <p>注册与所有权、DNS、HTTPS 证书、邮件安全各 25 分，合计 100 分</p>
        </div>
      </div>

      <section class="detail">
        <div class="section-head"><h3>维度得分</h3></div>
        <div class="dimension-list">
          ${dimensions
            .map((item) => {
              const percent = item.max ? Math.round((item.score / item.max) * 100) : 0;
              const dimTone = percent >= 80 ? 'ok' : percent >= 50 ? 'warn' : 'danger';
              return `
                <div class="dimension-row">
                  <div class="dimension-meta">
                    <strong>${esc(item.label)}</strong>
                    <span>${esc(item.score)} / ${esc(item.max)}</span>
                  </div>
                  <div class="dimension-bar"><i class="dimension-fill ${dimTone}" style="width:${percent}%"></i></div>
                  <div class="check-list compact">
                    ${(item.checks || [])
                      .map(
                        (check) => `
                          <div class="check-item">
                            <span class="check-dot tone-${CHECK_TONE[check.status] ?? 'muted'}"></span>
                            <div><strong>${esc(check.label)}</strong><p>${esc(check.detail)}</p></div>
                          </div>
                        `,
                      )
                      .join('')}
                  </div>
                </div>
              `;
            })
            .join('')}
        </div>
      </section>

      ${
        issues.length
          ? `<section class="detail">
              <div class="section-head"><h3>待改进项 <span class="count">${issues.length}</span></h3></div>
              <div class="check-list">
                ${issues
                  .map(
                    (item) => `
                      <div class="check-item">
                        <span class="check-dot tone-${CHECK_TONE[item.status] ?? 'muted'}"></span>
                        <div><strong>${esc(item.label)}</strong><p>${esc(item.detail)}</p></div>
                      </div>
                    `,
                  )
                  .join('')}
              </div>
            </section>`
          : ''
      }

      <p class="callout">${esc(data.note)}</p>
      ${outputSection(data, meta, { filename: `${data.domain}-health` })}
      ${metaFooter(meta)}
    </article>
  `;
}

function availabilityTemplate(data, meta) {
  const items = Array.isArray(data.items) ? data.items : [];
  const statusMeta = {
    available: { label: '可注册', tone: 'ok' },
    registered: { label: '已注册', tone: 'muted' },
    unknown: { label: '未知', tone: 'warn' },
  };

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar" aria-hidden="true">域名</div>
          <div>
            <div class="title-row">
              <h2>批量可注册检测</h2>
              ${pill(`${data.available} 个可注册`, data.available > 0 ? 'ok' : 'muted', true)}
            </div>
            <p class="subline">
              <span>共 ${esc(data.total)} 个域名</span>
              <span class="sep">·</span>
              <span>耗时 ${esc(data.durationMs)} ms</span>
              ${data.truncated ? `<span class="sep">·</span><span>已忽略 ${esc(data.truncated)} 个超出上限的域名</span>` : ''}
            </p>
          </div>
        </div>
        <div class="head-side"><span class="src-badge">CHECK</span></div>
      </header>

      <div class="availability-summary">
        <div class="stat-chip"><span>可注册</span><strong class="tone-ok">${esc(data.available)}</strong></div>
        <div class="stat-chip"><span>已注册</span><strong>${esc(data.registered)}</strong></div>
        <div class="stat-chip"><span>未知</span><strong>${esc(data.unknown)}</strong></div>
        <div class="stat-chip"><span>总计</span><strong>${esc(data.total)}</strong></div>
      </div>

      <section class="detail">
        <div class="section-head"><h3>检测结果</h3></div>
        <div class="availability-list">
          ${items
            .map((item) => {
              const metaInfo = statusMeta[item.status] ?? statusMeta.unknown;
              const detail = [
                item.registrar ? `注册商 ${item.registrar}` : '',
                item.expires ? `到期 ${formatDate(item.expires) ?? item.expires}` : '',
                item.error ? item.error : '',
              ]
                .filter(Boolean)
                .join(' · ');
              return `
                <div class="availability-row">
                  <div class="availability-copy">
                    <strong>${esc(item.domain)}</strong>
                    <small>${esc(detail || (item.source ? `数据来源 ${item.source.toUpperCase()}` : '暂无更多信息'))}</small>
                  </div>
                  ${pill(metaInfo.label, metaInfo.tone, true)}
                  <button type="button" class="mini-btn" data-copy-value="${esc(item.domain)}">复制</button>
                </div>
              `;
            })
            .join('')}
        </div>
      </section>

      <p class="callout">${esc(data.note)}</p>
      ${outputSection(data, meta, { filename: 'availability' })}
      ${metaFooter(meta)}
    </article>
  `;
}

function chainTemplate(data, meta) {
  const chain = Array.isArray(data.chain) ? data.chain : [];

  return `
    <article class="result-card">
      <header class="result-head">
        <div class="identity">
          <div class="avatar avatar-words" aria-hidden="true">CHAIN</div>
          <div>
            <div class="title-row">
              <h2>${esc(data.host)}</h2>
              ${pill(`${data.count} 级证书`, 'ok', true)}
              ${pill(`端口 ${data.port}`, 'muted', true)}
            </div>
            <p class="subline">
              <span>连接地址 ${esc(data.address)}</span>
              <span class="sep">·</span>
              <span>${chain.filter((item) => item.selfSigned).length ? '包含自签名证书' : '证书链完整返回'}</span>
            </p>
          </div>
        </div>
        <div class="head-side">
          <span class="src-badge">TLS</span>
          <button type="button" class="mini-btn" data-download-pem>下载 PEM</button>
        </div>
      </header>

      <section class="detail">
        <div class="section-head"><h3>证书链</h3></div>
        <div class="chain-list">
          ${chain
            .map(
              (item) => `
                <div class="chain-item">
                  <div class="chain-index">${Number(item.index) + 1}</div>
                  <div class="chain-copy">
                    <div class="chain-head">
                      <strong>${esc(item.subject ?? '未知主体')}</strong>
                      ${item.selfSigned ? pill('自签名', 'warn', true) : ''}
                    </div>
                    <p>颁发者：${esc(item.issuer ?? '未知')}</p>
                    <p>有效期：${esc(formatDate(item.validFrom) ?? '未知')} → ${esc(formatDate(item.validTo) ?? '未知')}</p>
                    <p class="chain-fp">${esc(item.fingerprint256 ?? '无指纹')}</p>
                  </div>
                  <button type="button" class="mini-btn" data-copy-pem="${Number(item.index)}">复制 PEM</button>
                </div>
              `,
            )
            .join('')}
        </div>
      </section>

      <p class="callout">${esc(data.note)}</p>
      ${outputSection(data, meta, { filename: `${data.host}-chain` })}
      ${metaFooter(meta)}
    </article>
  `;
}

const RESULT_TEMPLATES = {
  dns: dnsTemplate,
  ip: ipTemplate,
  uptime: uptimeTemplate,
  history: historyTemplate,
  nameservers: nameserverTemplate,
  registrars: registrarsTemplate,
  icp: icpTemplate,
  tls: tlsTemplate,
  mail: mailTemplate,
  http: httpTemplate,
  dnsprop: dnsPropTemplate,
  health: healthTemplate,
  available: availabilityTemplate,
  certchain: chainTemplate,
};

function renderSuccess(body, tool = state.tool) {
  const { data, meta } = body;
  let html;
  let title;

  if (tool === 'whois' || tool === 'rdap') {
    html = data.available ? availableTemplate(data, meta) : registeredTemplate(data, meta);
    title = `${data.unicodeDomain || data.domain} · Pull WHOIS`;
  } else {
    const template = RESULT_TEMPLATES[tool] ?? registrarsTemplate;
    html = template(data, meta);
    const target = data.domain || data.ip || data.host || TOOLS[tool]?.title || 'Pull WHOIS';
    title = `${target} · ${TOOLS[tool]?.title ?? '查询'} · Pull WHOIS`;
  }

  dom.result.innerHTML = html;
  bindResultEvents();
  document.title = title;
  setBusy(false);
}

function renderRegistrarDetail(body) {
  const { data, meta } = body;
  dom.result.innerHTML = registrarDetailTemplate(data, meta);
  bindResultEvents();
  document.title = `${data.registrar?.name ?? '注册商'} · Pull WHOIS`;
  setBusy(false);
}

function renderError(message, code, details) {
  const hints = {
    INVALID_DOMAIN: '支持 example.com、https://example.com、user@example.com 以及 münich.com 等格式。',
    UPSTREAM_UNAVAILABLE: '上游数据源暂时不可用，可稍后重试。',
    UPSTREAM_TIMEOUT: '注册局响应超时，请稍后重试。',
    RATE_LIMITED: '触发限流，请等待窗口重置后再试。',
    UNAUTHORIZED: '该接口已开启 API Key 校验。',
    WEB_DISABLED: '管理员已关闭网页端查询，请改用 API 或联系站点管理员。',
    FEATURE_DISABLED: '该工具已被管理员关闭，可稍后再试或联系站点管理员。',
    BAD_REQUEST: '请检查输入格式，例如域名、IP 或网址是否正确。',
    NOT_FOUND: '没有找到对应资源，请确认输入是否准确。',
  };
  let hint = hints[code] ?? '请检查输入后重试。';
  if (code === 'RATE_LIMITED') {
    const retryAfter = details?.retryAfterSec;
    if (retryAfter) hint = `触发限流，请在 ${retryAfter} 秒后重试。`;
  }

  const attempts = Array.isArray(details?.attempts)
    ? details.attempts
        .map((attempt) => `${attempt.source}:${attempt.server} ${attempt.ok ? 'OK' : attempt.error ?? ''}`)
        .join(' · ')
    : '';

  current = null;
  dom.result.innerHTML = `
    <div class="error-card" role="alert">
      <div class="error-head">
        <span class="error-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none"><path d="M12 8v5M12 16.5v.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6"/></svg>
        </span>
        <h2>${
          code === 'INVALID_DOMAIN'
            ? '域名格式不正确'
            : code === 'WEB_DISABLED'
              ? '网页查询已关闭'
              : code === 'FEATURE_DISABLED'
                ? '该功能已关闭'
                : '查询未完成'
        }</h2>
        <span class="error-code">${esc(code || 'ERROR')}</span>
      </div>
      <p class="error-message">${esc(message || '请求失败，请稍后重试。')}</p>
      <p class="error-hint">${esc(hint)}${attempts ? `<br><span class="muted-text">${esc(attempts)}</span>` : ''}</p>
      <div class="error-actions">
        <button type="button" class="btn-primary" data-retry>重试</button>
        <button type="button" class="btn-secondary" data-clear>换个域名</button>
      </div>
    </div>
  `;

  dom.result.querySelector('[data-retry]')?.addEventListener('click', () => {
    const value = dom.input.value.trim();
    if (value) void runQuery(value, false);
  });
  dom.result.querySelector('[data-clear]')?.addEventListener('click', () => {
    dom.input.value = '';
    dom.input.focus();
    const url = new URL(location.href);
    url.searchParams.delete('q');
    url.searchParams.delete('domain');
    url.searchParams.delete('type');
    history.replaceState({}, '', url);
    showIdle();
  });

  document.title = '查询失败 · Pull WHOIS';
  setBusy(false);
}

/* ------------------------------------------------------------------ */
/* 查询                                                                */
/* ------------------------------------------------------------------ */
function buildToolUrl(tool, value, options = {}) {
  const encoded = encodeURIComponent(value);
  switch (tool) {
    case 'whois':
    case 'rdap':
      return `/web/v1/${tool}/${encoded}?raw=true`;
    case 'dns': {
      const type = dom.dnsType?.value || 'A';
      return `/web/v1/dns/${encoded}?type=${encodeURIComponent(type)}`;
    }
    case 'ip':
      return `/web/v1/ip/${encoded}?raw=true`;
    case 'uptime':
      return `/web/v1/uptime?target=${encoded}`;
    case 'history':
      return `/web/v1/history/${encoded}${options.refresh ? '?refresh=true' : ''}`;
    case 'nameservers':
      return `/web/v1/nameservers/${encoded}`;
    case 'icp':
      return `/web/v1/icp/${encoded}`;
    case 'tls':
      return `/web/v1/tls/${encoded}`;
    case 'mail':
      return `/web/v1/mail/${encoded}`;
    case 'http':
      return `/web/v1/http/${encoded}`;
    case 'dnsprop': {
      const type = dom.dnsPropType?.value || 'A';
      return `/web/v1/dnsprop/${encoded}?type=${encodeURIComponent(type)}`;
    }
    case 'health':
      return `/web/v1/health/${encoded}`;
    case 'available':
      return `/web/v1/available?domains=${encoded}`;
    case 'certchain':
      return `/web/v1/tls/${encoded}/chain`;
    case 'registrars': {
      const params = new URLSearchParams();
      if (value) params.set('q', value);
      if (Number(options.page) > 1) params.set('page', String(Number(options.page)));
      const query = params.toString();
      return `/web/v1/registrars${query ? `?${query}` : ''}`;
    }
    default:
      return `/web/v1/whois/${encoded}?raw=true`;
  }
}

async function runQuery(rawInput, pushHistory, options = {}) {
  const tool = state.tool;
  const value = String(rawInput ?? '').trim();

  if (tool !== 'registrars' && !value) {
    dom.input.focus();
    return;
  }

  activeController?.abort();
  activeController = new AbortController();
  const seq = ++requestSeq;

  setBusy(true);
  showLoading(value || TOOLS[tool].label);

  if (pushHistory) {
    const url = new URL(location.href);
    url.hash = tool;
    url.searchParams.delete('domain');
    if (value) url.searchParams.set('q', value);
    else url.searchParams.delete('q');
    if (tool === 'dns') url.searchParams.set('type', dom.dnsType?.value || 'A');
    else if (tool === 'dnsprop') url.searchParams.set('type', dom.dnsPropType?.value || 'A');
    else url.searchParams.delete('type');
    history.pushState({ tool, q: value }, '', url);
  }

  try {
    const response = await fetch(buildToolUrl(tool, value, options), {
      signal: activeController.signal,
      headers: { accept: 'application/json' },
    });

    const body = await response.json().catch(() => null);

    if (!response.ok || !body || body.success !== true) {
      const error = body?.error;
      const meta = body?.meta;
      const message =
        error?.message ||
        (response.status === 429
          ? '请求过于频繁，请稍后再试。'
          : `请求失败（HTTP ${response.status}）`);
      throw Object.assign(new Error(message), {
        code: error?.code || (response.status === 429 ? 'RATE_LIMITED' : 'HTTP_ERROR'),
        details: error?.details ?? {
          retryAfterSec: response.headers.get('retry-after'),
          attempts: meta?.attempts,
        },
      });
    }

    if (seq !== requestSeq) return;
    renderSuccess(body, tool);
  } catch (error) {
    if (error.name === 'AbortError') return;
    if (seq !== requestSeq) return;
    renderError(error.message, error.code, error.details);
  } finally {
    if (seq === requestSeq) setBusy(false);
  }
}

async function loadRegistrars(query, pushHistory) {
  if (state.tool !== 'registrars') {
    applyTool('registrars', { updateHash: true, keepResult: true, loadDirectory: false });
  }
  await runQuery(query, pushHistory);
}

async function loadRegistrar(id) {
  if (!id) return;

  activeController?.abort();
  activeController = new AbortController();
  setBusy(true);
  showLoading(id);

  const url = new URL(location.href);
  url.hash = 'registrars';
  url.searchParams.set('q', id);
  history.pushState({ tool: 'registrars', q: id }, '', url);

  try {
    const response = await fetch(`/web/v1/registrars/${encodeURIComponent(id)}`, {
      signal: activeController.signal,
      headers: { accept: 'application/json' },
    });
    const body = await response.json().catch(() => null);
    if (!response.ok || !body || body.success !== true) {
      const error = body?.error;
      throw Object.assign(
        new Error(error?.message || `请求失败（HTTP ${response.status}）`),
        { code: error?.code || 'HTTP_ERROR', details: error?.details },
      );
    }
    renderRegistrarDetail(body);
  } catch (error) {
    if (error.name === 'AbortError') return;
    renderError(error.message, error.code, error.details);
  } finally {
    setBusy(false);
  }
}

function toolFromHash() {
  const hash = decodeURIComponent(location.hash.replace(/^#/, ''));
  return TOOLS[hash] ? hash : null;
}

function syncFromUrl() {
  const tool = toolFromHash();
  if (tool) {
    if (tool !== state.tool) applyTool(tool, { loadDirectory: false });
  } else if (!location.hash || location.hash === '#') {
    if (state.tool !== 'whois') applyTool('whois', { loadDirectory: false });
  }

  const params = new URLSearchParams(location.search);
  const type = params.get('type');
  if (type && dom.dnsType) dom.dnsType.value = type.toUpperCase();
  if (type && dom.dnsPropType) dom.dnsPropType.value = type.toUpperCase();

  const value = params.get('q') || params.get('domain');
  if (value) {
    dom.input.value = value;
    void runQuery(value, false);
    return;
  }

  if (state.tool === 'registrars') {
    void loadRegistrars('', false);
    return;
  }

  showIdle();
}

function initFromUrl() {
  const tool = toolFromHash() ?? 'whois';
  applyTool(tool, { loadDirectory: false });
  syncFromUrl();
}

/* ------------------------------------------------------------------ */
/* 事件                                                                */
/* ------------------------------------------------------------------ */
dom.form?.addEventListener('submit', (event) => {
  event.preventDefault();
  if (state.tool === 'registrars' && !dom.input.value.trim()) {
    void loadRegistrars('', true);
    return;
  }
  void runQuery(dom.input.value, true);
});

dom.toolSwitch?.addEventListener('click', (event) => {
  const button = event.target.closest('[data-tool]');
  if (!button) return;
  const tool = button.dataset.tool;
  if (!TOOLS[tool]) return;
  if (tool === state.tool) {
    showIdle();
    return;
  }
  applyTool(tool, { updateHash: true });
});

dom.dnsType?.addEventListener('change', () => {
  if (state.tool !== 'dns') return;
  const value = dom.input.value.trim();
  if (value) void runQuery(value, false);
});

dom.chips?.addEventListener('click', (event) => {
  const chip = event.target.closest('.chip');
  if (!chip) return;
  dom.input.value = chip.dataset.domain || '';
  void runQuery(dom.input.value, true);
});

window.addEventListener('popstate', () => {
  syncFromUrl();
});

window.addEventListener('hashchange', () => {
  const tool = toolFromHash();
  if (tool && tool !== state.tool) applyTool(tool, { loadDirectory: false });
  if (tool) {
    const value = new URLSearchParams(location.search).get('q');
    if (value) {
      dom.input.value = value;
      void runQuery(value, false);
    } else if (tool === 'registrars') {
      void loadRegistrars('', false);
    } else {
      showIdle();
    }
  }
});

document.addEventListener('keydown', (event) => {
  const tag = document.activeElement?.tagName;
  if (event.key === '/' && !/INPUT|TEXTAREA|SELECT/.test(tag || '')) {
    event.preventDefault();
    dom.input.focus();
  }
  if (event.key === 'Escape' && document.activeElement === dom.input) {
    dom.input.blur();
  }
});

dom.copyCurl?.addEventListener('click', () => {
  const config = TOOLS[state.tool] ?? TOOLS.whois;
  const sample = config.api.replace('{value}', config.chips[0] ?? 'example.com');
  void copyText(`curl '${location.origin}${sample}' -H 'accept: application/json'`);
});

initTheme();
initFromUrl();
