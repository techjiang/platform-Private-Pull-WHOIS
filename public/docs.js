const docState = {
  spec: null,
  copyStore: new Map(),
  copySeq: 0,
};

const toast = document.querySelector('#toast');
let toastTimer = null;

function showToast(message) {
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 1800);
}

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

/* 主题：与首页保持一致 */
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', theme === 'light' ? '#f8f4f6' : '#0a0709');
}

function initTheme() {
  let stored = null;
  try {
    stored = localStorage.getItem('pullwhois-theme');
  } catch {
    /* 忽略 */
  }
  const preferred = window.matchMedia?.('(prefers-color-scheme: light)').matches
    ? 'light'
    : 'dark';
  applyTheme(stored === 'light' || stored === 'dark' ? stored : preferred);
}

document.querySelector('#themeToggle')?.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  applyTheme(next);
  try {
    localStorage.setItem('pullwhois-theme', next);
  } catch {
    /* 忽略 */
  }
});

function resolveSchema(schema) {
  if (!schema || typeof schema !== 'object') return schema;
  if (schema.$ref) {
    const name = schema.$ref.split('/').pop();
    const target = docState.spec.components.schemas[name];
    return target ? { ...target, ...schema, $ref: undefined } : schema;
  }
  return schema;
}

function typeLabel(schema) {
  const resolved = resolveSchema(schema);
  if (!resolved) return 'any';
  if (resolved.$ref) return resolved.$ref.split('/').pop();
  if (Array.isArray(resolved.type)) return resolved.type.join(' | ');
  if (resolved.oneOf) return resolved.oneOf.map(typeLabel).join(' | ');
  if (resolved.type === 'array') return `${typeLabel(resolved.items)}[]`;
  // 枚举值单独以标签展示，避免长列表挤在类型列里导致表格错位
  if (Array.isArray(resolved.enum)) return resolved.type || 'string';
  return resolved.type || 'object';
}

const ENUM_CHIP_LIMIT = 12;

function enumChips(schema) {
  const resolved = resolveSchema(schema);
  const values = Array.isArray(resolved?.enum) ? resolved.enum.map(String) : [];
  if (!values.length || values.length > ENUM_CHIP_LIMIT) return '';
  return `<span class="enum-chips">${values
    .map((value) => `<code>${esc(value)}</code>`)
    .join('')}</span>`;
}

function copyButton(text, label = '复制') {
  const key = `copy-${++docState.copySeq}`;
  docState.copyStore.set(key, text);
  return `<button type="button" class="ghost-btn" data-copy-key="${key}">${esc(label)}</button>`;
}

function anchorId(method, path) {
  return `${method}-${path}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function parameterRows(pathParams, queryParams) {
  const rows = [];
  for (const param of [...pathParams, ...queryParams]) {
    const schema = resolveSchema(param.schema) ?? {};
    rows.push(`
      <tr>
        <td><code>${esc(param.name)}</code>${param.required ? '<span class="req">必填</span>' : ''}</td>
        <td class="type-cell">${esc(param.in)}</td>
        <td class="type-cell">${esc(typeLabel(schema))}</td>
        <td>${esc(param.description || schema.description || '')}${enumChips(schema)}${schema.default !== undefined ? ` <span class="muted-text">默认 ${esc(schema.default)}</span>` : ''}</td>
      </tr>
    `);
  }
  return rows.join('');
}

function bodyRows(schema) {
  const resolved = resolveSchema(schema);
  if (!resolved?.properties) return '';
  const required = new Set(resolved.required || []);
  return Object.entries(resolved.properties)
    .map(([name, property]) => {
      const prop = resolveSchema(property) ?? {};
      const type = typeLabel(property);
      return `
        <tr>
          <td><code>${esc(name)}</code>${required.has(name) ? '<span class="req">必填</span>' : ''}</td>
          <td class="type-cell">body</td>
          <td class="type-cell">${esc(type)}</td>
          <td>${esc(prop.description || '')}${enumChips(property)}${prop.default !== undefined ? ` <span class="muted-text">默认 ${esc(prop.default)}</span>` : ''}</td>
        </tr>
      `;
    })
    .join('');
}

function sampleRequest(path, method, operation) {
  const urlPath = path
    .replace('{domain}', 'example.com')
    .replace('{target}', 'example.com')
    .replace('{domains}', 'example.com,example.net')
    .replace('{ip}', '8.8.8.8')
    .replace('{host}', 'example.com')
    .replace('{id}', '1910');
  const base = `${location.origin}${urlPath}`;

  if (method === 'get') {
    if (path === '/v1/whois') {
      return `curl '${base}?domain=example.com&raw=true' \\\n  -H 'accept: application/json'`;
    }
    if (path === '/v1/whois/{domain}' || path === '/v1/rdap/{domain}') {
      return `curl '${base}?raw=true' \\\n  -H 'accept: application/json'`;
    }
    if (path === '/v1/dns/{domain}') {
      return `curl '${base}?type=MX' \\\n  -H 'accept: application/json'`;
    }
    if (path === '/v1/uptime') {
      return `curl '${base}?target=example.com' \\\n  -H 'accept: application/json'`;
    }
    if (path === '/v1/available') {
      return `curl '${base}?domains=example.com,example.net' \\\n  -H 'accept: application/json'`;
    }
    if (path === '/v1/dnsprop/{domain}') {
      return `curl '${base}?type=A' \\\n  -H 'accept: application/json'`;
    }
    return `curl '${base}' \\\n  -H 'accept: application/json'`;
  }

  const example = operation.requestBody?.content?.['application/json']?.example;
  const body = example ?? { domains: ['example.com', 'github.com'] };
  return `curl -X POST '${base}' \\\n  -H 'content-type: application/json' \\\n  -d '${JSON.stringify(body)}'`;
}

function responseExample(operation) {
  const response = operation.responses?.['200'] ?? operation.responses?.['201'];
  return response?.content?.['application/json']?.example ?? null;
}

function renderEndpoint(path, method, operation) {
  const id = anchorId(method, path);
  const params = operation.parameters || [];
  const pathParams = params.filter((param) => param.in === 'path');
  const queryParams = params.filter((param) => param.in === 'query');
  const bodySchema = operation.requestBody?.content?.['application/json']?.schema;
  const request = sampleRequest(path, method, operation);
  const example = responseExample(operation);

  const paramTable = params.length
    ? `
      <table class="param-table">
        <thead><tr><th>参数</th><th>位置</th><th>类型</th><th>说明</th></tr></thead>
        <tbody>${parameterRows(pathParams, queryParams)}</tbody>
      </table>
    `
    : '<p class="empty-line">该接口无需请求参数。</p>';

  const bodyTable = bodySchema
    ? `
      <h3 class="docs-subhead" style="margin-top: 16px">请求体</h3>
      <table class="param-table">
        <thead><tr><th>字段</th><th>位置</th><th>类型</th><th>说明</th></tr></thead>
        <tbody>${bodyRows(bodySchema)}</tbody>
      </table>
    `
    : '';

  const responseBlock = example
    ? `
      <details class="response-block" open>
        <summary>响应示例 <span class="status-code">200</span> ${copyButton(JSON.stringify(example, null, 2), '复制响应')}</summary>
        <pre class="code-block">${esc(JSON.stringify(example, null, 2))}</pre>
      </details>
    `
    : '';

  return `
    <section class="endpoint-card" id="${id}">
      <div class="endpoint-head">
        <span class="method ${method}">${method.toUpperCase()}</span>
        <code class="endpoint-path">${esc(path)}</code>
        ${copyButton(request, '复制 cURL')}
      </div>
      <h2>${esc(operation.summary || path)}</h2>
      <p class="endpoint-desc">${esc(operation.description || '')}</p>

      <div class="endpoint-grid">
        <div>
          <h3 class="docs-subhead">请求参数</h3>
          ${paramTable}
          ${bodyTable}
        </div>
        <div>
          <h3 class="docs-subhead">请求示例</h3>
          <pre class="code-block">${esc(request)}</pre>
        </div>
      </div>

      ${responseBlock}
    </section>
  `;
}

function renderSchemas() {
  const container = document.querySelector('#schemas');
  if (!container) return;

  const schemas = docState.spec.components?.schemas ?? {};
  container.innerHTML = Object.entries(schemas)
    .map(([name, schema]) => {
      const properties = schema.properties ?? {};
      const required = new Set(schema.required || []);
      const rows = Object.entries(properties)
        .map(([field, property]) => {
          const prop = resolveSchema(property) ?? {};
          return `
            <tr>
              <td><code>${esc(field)}</code>${required.has(field) ? '<span class="req">必填</span>' : ''}</td>
              <td class="type-cell">${esc(typeLabel(property))}</td>
              <td>${esc(prop.description || '')}${enumChips(property)}</td>
            </tr>
          `;
        })
        .join('');

      return `
        <article class="schema-card">
          <h3>${esc(name)}</h3>
          <p>${esc(schema.description || '')}</p>
          <table class="param-table">
            <thead><tr><th>字段</th><th>类型</th><th>说明</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </article>
      `;
    })
    .join('');
}

function renderNav(endpoints) {
  const nav = document.querySelector('#docsNav');
  if (!nav) return;

  const endpointLinks = endpoints
    .map(
      (item) =>
        `<a href="#${item.id}" data-endpoint-link>${item.method.toUpperCase()} ${esc(item.path)}</a>`,
    )
    .join('');

  const modelLinks = Object.keys(docState.spec.components?.schemas ?? {})
    .map(
      (name) =>
        `<a class="nav-model" href="#model-${esc(name)}">${esc(name)}</a>`,
    )
    .join('');

  nav.innerHTML = `
    <a href="#intro">概览</a>
    <a href="#auth">认证与限流</a>
    <a href="#features">证书、邮件与站点体检</a>
    ${endpointLinks}
    <a href="#errors">错误码</a>
    <a href="#models">数据模型</a>
    ${modelLinks}
  `;

  // 为数据模型卡片补充锚点
  document.querySelectorAll('.schema-card').forEach((card) => {
    const name = card.querySelector('h3')?.textContent?.trim();
    if (name) card.id = `model-${name}`;
  });

  const links = [...nav.querySelectorAll('a')];
  const sections = links
    .map((link) => {
      const target = document.querySelector(link.getAttribute('href'));
      return target ? { link, target } : null;
    })
    .filter(Boolean);

  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        const active = sections.find((item) => item.target === entry.target);
        if (!active) continue;
        links.forEach((link) => link.classList.remove('active'));
        active.link.classList.add('active');
      }
    },
    { rootMargin: '-15% 0px -70% 0px', threshold: 0 },
  );

  sections.forEach((item) => observer.observe(item.target));
}

function bindCopy() {
  document.addEventListener('click', (event) => {
    const button = event.target.closest('[data-copy-key]');
    if (!button) return;
    const text = docState.copyStore.get(button.dataset.copyKey);
    if (!text) return;
    navigator.clipboard
      .writeText(text)
      .then(() => showToast('已复制到剪贴板'))
      .catch(() => showToast('复制失败，请手动选择'));
  });
}

async function init() {
  initTheme();
  bindCopy();

  try {
    const response = await fetch('/openapi.json', { headers: { accept: 'application/json' } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    docState.spec = await response.json();
  } catch (error) {
    document.querySelector('#endpoints').innerHTML = `
      <div class="error-card">
        <div class="error-head">
          <h2>无法加载 API 规范</h2>
          <span class="error-code">OPENAPI</span>
        </div>
        <p class="error-message">${esc(error.message)}</p>
        <p class="error-hint">请确认服务已启动，或直接访问 <a href="/openapi.json">/openapi.json</a>。</p>
      </div>
    `;
    return;
  }

  const version = document.querySelector('#specVersion');
  if (version) version.textContent = `v${docState.spec.info?.version ?? '1.0.0'}`;

  const endpoints = [];
  for (const [path, methods] of Object.entries(docState.spec.paths ?? {})) {
    for (const method of ['get', 'post']) {
      const operation = methods[method];
      if (!operation) continue;
      endpoints.push({
        id: anchorId(method, path),
        method,
        path,
        html: renderEndpoint(path, method, operation),
      });
    }
  }

  document.querySelector('#endpoints').innerHTML = endpoints.map((item) => item.html).join('');
  renderSchemas();

  // 数据模型卡片渲染后再生成导航，确保锚点存在
  renderNav(endpoints);
}

void init();
