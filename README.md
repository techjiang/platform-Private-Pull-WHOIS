# Pull WHOIS

简洁、易用、生产级的域名 WHOIS / RDAP 查询 API。优先读取注册局 RDAP 结构化数据，未覆盖或失败时自动回退 WHOIS 43 端口，并统一输出字段。

- 自带 Web 查询界面与动态 API 文档
- 单域名、查询参数、批量三种查询方式
- TTL + LRU 内存缓存、并发去重、固定窗口限流
- IDN 自动转 punycode，支持 URL / 邮箱输入
- 可选 API Key 鉴权、CORS、压缩与安全响应头

## 快速开始

```bash
npm install
npm run dev
```

打开 <http://localhost:3000> 使用查询界面，交互式文档在 <http://localhost:3000/docs>。

生产构建：

```bash
npm run build
npm start
```

运行测试：

```bash
npm test
npm run typecheck
```

## API

所有响应使用统一信封：

```json
{
  "success": true,
  "data": { "...": "..." },
  "meta": { "source": "rdap", "server": "rdap.verisign.com", "cached": false }
}
```

失败时：

```json
{
  "success": false,
  "error": { "code": "INVALID_DOMAIN", "message": "请输入完整域名（包含后缀），例如 example.com" },
  "meta": { "requestId": "req-1" }
}
```

### 查询单个域名

```bash
curl http://localhost:3000/v1/whois/example.com
curl "http://localhost:3000/v1/whois?domain=example.com"
curl "http://localhost:3000/v1/whois/example.com?raw=true&refresh=true"
```

| 参数 | 说明 |
| --- | --- |
| `domain` | 域名，可传 URL、邮箱或 IDN；路径与查询参数两种写法均可 |
| `raw` | `true` 时额外返回原始 RDAP JSON / WHOIS 文本 |
| `refresh` | `true` 时跳过缓存强制刷新 |

### 批量查询

```bash
curl -X POST http://localhost:3000/v1/whois/batch \
  -H "content-type: application/json" \
  -d '{"domains":["example.com","github.io"],"raw":false}'
```

批量默认上限 20 个域名，内部并发度 5，单项失败不影响其他结果。

### 其他接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/v1/tlds` | 内置 WHOIS 服务器覆盖的 TLD 列表 |
| `GET` | `/health` | 健康检查 |
| `GET` | `/openapi.json` | OpenAPI 3.1 规范 |
| `GET` | `/docs` | 动态 API 文档页 |

### 响应字段

```json
{
  "domain": "example.com",
  "unicodeDomain": "example.com",
  "tld": "com",
  "sld": "example",
  "idn": false,
  "available": false,
  "registered": true,
  "registrar": {
    "name": "RESERVED-Internet Assigned Numbers Authority",
    "ianaId": "376",
    "url": "http://res-dom.iana.org",
    "abuseEmail": "abuse@iana.org",
    "abusePhone": null
  },
  "registrant": {
    "name": null,
    "organization": null,
    "email": null,
    "country": "US",
    "redacted": true
  },
  "dates": {
    "created": "1995-08-14T04:00:00.000Z",
    "updated": "2026-08-14T08:01:43.000Z",
    "expires": "2027-08-13T04:00:00.000Z"
  },
  "statuses": ["clientDeleteProhibited", "clientTransferProhibited"],
  "nameservers": ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"],
  "dnssec": "signed",
  "registryDomainId": "2336799_DOMAIN_COM-VRSN"
}
```

`meta` 包含 `source`（`rdap` / `whois`）、`server`、`durationMs`、`cached`、`cacheTtlMs`、`queriedAt`、`requestId` 与 `rateLimit`。

### 错误码

| HTTP | code | 说明 |
| --- | --- | --- |
| 400 | `INVALID_DOMAIN` | 域名格式不合法 |
| 400 | `BAD_REQUEST` | 参数缺失或校验失败 |
| 401 | `UNAUTHORIZED` | 缺少或无效的 API Key |
| 404 | `NOT_FOUND` | 接口不存在 |
| 429 | `RATE_LIMITED` | 超出限流额度，返回 `Retry-After` |
| 502 | `UPSTREAM_UNAVAILABLE` | RDAP 与 WHOIS 均无结果 |
| 504 | `UPSTREAM_TIMEOUT` | 上游查询超时 |
| 500 | `INTERNAL` | 服务内部错误 |
| 503 | `ADMIN_DISABLED` | 管理后台未初始化管理员凭据 |
| 503 | `WEB_DISABLED` | 网页端查询已被管理员关闭 |

## 管理后台

访问 <http://localhost:3000/admin>，使用环境变量 `ADMIN_USERNAME` / `ADMIN_PASSWORD` 初始化并登录（首次启动写入 `data/admin.json`，仅保存 scrypt 摘要）。

后台可以：

- 分别切换 **网页端查询**（`/web/v1/*`）与 **API 是否需要 Key**（`/v1/*`），两者完全独立
- 创建 API Key，并设置用途名称
- 查看每个 Key 的前缀、创建时间、最近使用时间与调用次数
- 随时停用、重新启用或删除 Key
- 修改管理员账号与密码（修改后所有会话立即失效）

密钥明文只在创建成功时显示一次，服务端仅保存 SHA-256 摘要；管理员密码使用 scrypt（N=32768, r=8, p=1）加盐哈希，后台数据持久化在 `data/admin.json`（已加入 `.gitignore`，权限 0600）。

```bash
# 首次启动用于初始化管理员凭据
ADMIN_USERNAME='admin'
ADMIN_PASSWORD='替换为你的强密码'
```

会话保存在 HttpOnly + SameSite=Strict 的 Cookie 中（HTTPS 下自动加 Secure），默认 12 小时过期；登录接口有独立的风控限流。若数据文件中没有凭据且未设置 `ADMIN_PASSWORD`，后台页面会提示未启用，管理接口返回 `503 ADMIN_DISABLED`。

环境变量 `API_KEYS` 中的静态密钥仍然有效，与后台创建的密钥可以同时使用。

鉴权示例：

```bash
# API：是否要求 Key 由后台的 API 开关决定
curl http://localhost:3000/v1/whois/example.com -H "x-api-key: your-key"
curl http://localhost:3000/v1/whois/example.com -H "authorization: Bearer your-key"

# 网页端：无需 Key，仅受独立的网页查询开关控制
curl http://localhost:3000/web/v1/whois/example.com
```

## 环境变量

复制 `.env.example` 为 `.env` 后按需修改。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `3000` | 监听端口 |
| `HOST` | `0.0.0.0` | 监听地址 |
| `TRUST_PROXY` | `false` | 位于反向代理后时设为 `true` |
| `CORS_ORIGIN` | `*` | 逗号分隔的允许来源 |
| `LOG_LEVEL` | `info` | Pino 日志级别 |
| `API_KEYS` | 空 | 逗号分隔的静态密钥，与后台密钥可同时使用 |
| `API_REQUIRE_KEY` | 视情况 | 首次启动时是否要求 Key；未设置时，`API_KEYS` 非空则要求，否则公开 |
| `ADMIN_USERNAME` | `admin` | 首次启动时写入的管理员账号 |
| `ADMIN_PASSWORD` | 空 | 首次启动时写入的管理员密码；数据文件中已有凭据时忽略 |
| `WEB_QUERY_ENABLED` | `true` | 网页端查询开关默认值，与 API Key 策略独立 |
| `ADMIN_SESSION_TTL_MS` | `43200000` | 管理会话有效期（12 小时） |
| `ADMIN_DATA_FILE` | `data/admin.json` | 管理数据文件路径 |
| `CACHE_TTL_MS` | `600000` | 已注册域名缓存时长 |
| `CACHE_AVAILABLE_TTL_MS` | `60000` | 可注册域名缓存时长 |
| `CACHE_MAX_ENTRIES` | `2000` | 缓存条目上限 |
| `RATE_LIMIT_WINDOW_MS` | `60000` | 限流窗口 |
| `RATE_LIMIT_MAX` | `120` | 每窗口每 IP 请求数 |
| `RATE_LIMIT_KEY_MAX` | `600` | 每窗口每 API Key 请求数 |
| `RDAP_TIMEOUT_MS` | `8000` | RDAP 超时 |
| `WHOIS_TIMEOUT_MS` | `8000` | WHOIS 超时 |
| `WHOIS_FOLLOW_REFERRAL` | `true` | 是否跟随注册商 referral 并合并结果 |
| `BATCH_MAX_DOMAINS` | `20` | 批量查询上限 |

鉴权示例：

```bash
curl http://localhost:3000/v1/whois/example.com -H "x-api-key: your-key"
curl http://localhost:3000/v1/whois/example.com -H "authorization: Bearer your-key"
```

## 架构

```
src/
├── app.ts              Fastify 实例、CORS/静态资源/安全头/鉴权/限流/错误处理
├── server.ts           启动与优雅关闭
├── config.ts           环境变量配置
├── openapi.ts          OpenAPI 3.1 文档
├── routes/             /v1/whois、批量、/v1/tlds、/health、/admin
├── admin/              API Key 持久化存储与管理会话
├── lib/                域名解析、TTL 缓存、限流、HTTP、并发控制、错误类型
└── whois/
    ├── lookup.ts       查询编排：RDAP → WHOIS，缓存与并发去重
    ├── rdap.ts         IANA bootstrap + RDAP 解析
    ├── whois.ts        WHOIS 43 连接与 referral 合并
    ├── whois-text.ts   多注册局文本解析与可注册判断
    ├── parsers.ts      日期/状态/NS/DNSSEC/注册人归一化
    └── tld.ts          TLD → WHOIS 服务器映射
public/                 原生 HTML/CSS/JS 查询界面与文档页
test/                   Node 内置测试运行器用例
```

查询流程：解析并规范化域名 → 命中缓存直接返回 → RDAP（IANA bootstrap，缓存 24 小时）→ 失败时 WHOIS 43（可选 referral 合并）→ 统一字段并写入缓存。IANA bootstrap 不可用时使用内置 `.com` / `.net` / `.org` 等兜底列表。

## Docker

```bash
docker build -t pull-whois .
docker run -d --name pull-whois -p 3000:3000 --env-file .env \
  -v pull-whois-data:/app/data pull-whois
```

服务以非 root 用户运行，并内置基于 `/health` 的健康检查。挂载 `/app/data` 可持久化后台创建的 API Key 与访问策略。

## 说明

- WHOIS / RDAP 数据来自各注册局与注册商，字段完整性因后缀而异。
- 受 GDPR 或注册局隐私政策影响，注册人信息可能被隐藏（`registrant.redacted`）。
- 内置缓存与限流为单实例内存实现；多实例部署时可替换为 Redis 等共享存储。
- 管理后台请使用强密码，并在公网部署时启用 HTTPS；`/admin` 已带 `noindex` 且会话 Cookie 为 HttpOnly。
- 请合理控制查询频率，遵守上游注册局的使用条款。

## 许可证

本项目以 GNU General Public License v3.0（GPL-3.0-only）发布，完整条款见 [LICENSE](LICENSE)，或访问 <https://www.gnu.org/licenses/gpl-3.0.html>。
