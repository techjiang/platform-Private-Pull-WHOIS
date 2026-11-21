export const openapiSpec = {
  openapi: '3.1.0',
  info: {
    title: 'Pull WHOIS API',
    version: '1.1.1',
    description:
      '轻量、生产级的域名情报 API：WHOIS、RDAP、DNS 记录与传播对比、IP 归属、域名历史、可用性检查、批量可注册检测、名称服务器反查、注册商目录、ICP 备案、TLS 证书与证书链、HTTP 安全响应头体检、域名健康评分与邮件安全记录。域名查询优先通过注册局 RDAP 获取结构化数据，未覆盖时自动回退到 WHOIS 43 端口。所有工具同时提供 /v1（API）与 /web/v1（网页端）两套路径。',
    license: { name: 'GPL-3.0-only', url: 'https://www.gnu.org/licenses/gpl-3.0.html' },
  },
  servers: [{ url: '/', description: '当前服务' }],
  tags: [
    { name: 'WHOIS', description: '域名注册信息查询' },
    { name: 'RDAP', description: '结构化注册数据查询' },
    { name: 'DNS', description: 'DNS 记录查询' },
    { name: 'IP', description: 'IP 归属与 PTR 查询' },
    { name: 'Uptime', description: '网站可用性检查' },
    { name: 'History', description: '域名历史快照' },
    { name: 'Nameservers', description: '名称服务器反查' },
    { name: 'Registrars', description: '注册商目录' },
    { name: 'ICP', description: 'ICP 备案查询' },
    { name: 'TLS', description: 'TLS 证书检查与证书链导出（自研）' },
    { name: 'Mail', description: '邮件安全记录（自研 DNS 解析）' },
    { name: 'HTTP', description: 'HTTP 安全响应头体检（自研）' },
    { name: 'Health', description: '域名健康评分（自研聚合检测）' },
    { name: 'Availability', description: '域名批量可注册检测' },
    { name: 'System', description: '服务状态' },
    { name: 'Meta', description: '能力目录与限制（自发现）' },
  ],
  components: {
    securitySchemes: {
      ApiKeyAuth: { type: 'apiKey', in: 'header', name: 'x-api-key' },
      BearerAuth: { type: 'http', scheme: 'bearer' },
    },
    schemas: {
      Registrar: {
        type: 'object',
        description: '注册商信息',
        properties: {
          name: { type: ['string', 'null'], example: 'MarkMonitor Inc.' },
          ianaId: { type: ['string', 'null'], example: '292' },
          url: { type: ['string', 'null'], example: 'http://www.markmonitor.com' },
          abuseEmail: { type: ['string', 'null'], example: 'abusecomplaints@markmonitor.com' },
          abusePhone: { type: ['string', 'null'], example: '+1.2086851750' },
        },
      },
      Registrant: {
        type: 'object',
        description: '注册人信息。受 GDPR / 隐私保护影响时字段可能被隐藏。',
        properties: {
          name: { type: ['string', 'null'] },
          organization: { type: ['string', 'null'] },
          email: { type: ['string', 'null'] },
          country: { type: ['string', 'null'] },
          redacted: { type: 'boolean', description: '原始数据是否被隐私保护隐藏' },
        },
      },
      Dates: {
        type: 'object',
        properties: {
          created: { type: ['string', 'null'], format: 'date-time' },
          updated: { type: ['string', 'null'], format: 'date-time' },
          expires: { type: ['string', 'null'], format: 'date-time' },
        },
      },
      WhoisData: {
        type: 'object',
        properties: {
          domain: { type: 'string', example: 'example.com', description: 'ASCII / punycode 域名' },
          unicodeDomain: { type: 'string', example: 'example.com' },
          tld: { type: 'string', example: 'com' },
          sld: { type: 'string', example: 'example' },
          idn: { type: 'boolean' },
          available: { type: 'boolean', description: '域名是否可注册' },
          registered: { type: 'boolean' },
          registrar: { oneOf: [{ $ref: '#/components/schemas/Registrar' }, { type: 'null' }] },
          registrant: { oneOf: [{ $ref: '#/components/schemas/Registrant' }, { type: 'null' }] },
          dates: { $ref: '#/components/schemas/Dates' },
          statuses: {
            type: 'array',
            items: { type: 'string' },
            example: ['clientTransferProhibited'],
            description: '已归一化为 EPP 风格的状态码',
          },
          nameservers: {
            type: 'array',
            items: { type: 'string' },
            example: ['a.iana-servers.net', 'b.iana-servers.net'],
          },
          dnssec: { type: 'string', enum: ['signed', 'unsigned', 'unknown'] },
          registryDomainId: { type: ['string', 'null'] },
          raw: {
            type: 'string',
            description: '原始 RDAP JSON 或 WHOIS 文本，仅在 raw=true 时返回',
          },
        },
        required: ['domain', 'available', 'registered', 'statuses', 'nameservers'],
      },
      RateLimit: {
        type: 'object',
        properties: {
          limit: { type: 'integer', description: '当前窗口允许的最大请求数', example: 120 },
          remaining: { type: 'integer', description: '当前窗口剩余请求数', example: 118 },
          reset: { type: 'integer', description: '距离窗口重置的秒数', example: 42 },
        },
      },
      IcpRecord: {
        type: 'object',
        description: 'ICP 备案信息。结果优先来自本站本地持久化缓存，缓存未命中时才回源公开备案数据；未查询到记录时 filed 为 false 且其余字段为 null。',
        properties: {
          domain: { type: 'string', example: 'qq.com' },
          filed: { type: 'boolean', description: '是否查询到备案记录', example: true },
          icpCode: { type: ['string', 'null'], description: '网站备案号', example: '粤B2-20090059-5' },
          subjectCode: { type: ['string', 'null'], description: '主体备案号', example: '粤B2-20090059' },
          unitName: { type: ['string', 'null'], description: '主办单位名称', example: '深圳市腾讯计算机系统有限公司' },
          unitType: { type: ['string', 'null'], description: '主办单位性质', example: '企业' },
          auditDate: { type: ['string', 'null'], description: '审核时间', example: '2026-01-15 11:27:48' },
          updatedAt: { type: ['string', 'null'], description: '数据更新时间', example: '2026-11-21 09:11:00' },
          source: {
            type: 'string',
            enum: ['icp-realtime', 'icp-offline'],
            description: 'icp-realtime 为实时备案数据，icp-offline 为离线备份数据',
          },
          stale: {
            type: 'boolean',
            description: '回源暂时不可用时，是否展示了本地持久化缓存',
            example: false,
          },
          note: { type: 'string', description: '数据来源说明与免责声明' },
        },
        required: ['domain', 'filed', 'source', 'stale', 'note'],
      },
      TlsCheck: {
        type: 'object',
        description: 'TLS 握手与证书信息，由本站直接连接目标端口读取。',
        properties: {
          host: { type: 'string', example: 'example.com' },
          port: { type: 'integer', example: 443 },
          address: { type: 'string', description: '实际连接的公网地址' },
          authorized: { type: 'boolean', description: '证书链与主机名校验是否通过' },
          authorizationError: { type: ['string', 'null'], description: '校验失败原因' },
          protocol: { type: ['string', 'null'], example: 'TLSv1.3' },
          cipher: {
            type: ['object', 'null'],
            properties: { name: { type: 'string' }, version: { type: 'string' } },
          },
          alpn: { type: ['string', 'null'], example: 'h2' },
          certificate: {
            type: ['object', 'null'],
            properties: {
              subject: { type: 'object' },
              issuer: { type: 'object' },
              validFrom: { type: ['string', 'null'] },
              validTo: { type: ['string', 'null'] },
              daysRemaining: { type: ['integer', 'null'] },
              expired: { type: 'boolean' },
              notYetValid: { type: 'boolean' },
              serialNumber: { type: ['string', 'null'] },
              fingerprint256: { type: ['string', 'null'] },
              san: { type: 'array', items: { type: 'string' } },
              keyBits: { type: ['integer', 'null'] },
              chainLength: { type: 'integer' },
            },
          },
          checkedAt: { type: 'string', format: 'date-time' },
        },
        required: ['host', 'port', 'authorized', 'checkedAt'],
      },
      MailAuth: {
        type: 'object',
        description: 'SPF / DMARC / DKIM / MX 的 DNS 解析与本地评估结果。',
        properties: {
          domain: { type: 'string', example: 'example.com' },
          mx: {
            type: 'array',
            items: {
              type: 'object',
              properties: { priority: { type: 'integer' }, exchange: { type: 'string' } },
            },
          },
          aFallback: { type: 'array', items: { type: 'string' }, description: '无 MX 时回退的 A 记录' },
          spf: {
            type: ['object', 'null'],
            properties: {
              raw: { type: 'string' },
              valid: { type: 'boolean' },
              includes: { type: 'array', items: { type: 'string' } },
              ip4: { type: 'array', items: { type: 'string' } },
              ip6: { type: 'array', items: { type: 'string' } },
              allQualifier: { type: ['string', 'null'], example: '-' },
              lookupCount: { type: 'integer' },
              errors: { type: 'array', items: { type: 'string' } },
              warnings: { type: 'array', items: { type: 'string' } },
            },
          },
          dmarc: {
            type: ['object', 'null'],
            properties: {
              raw: { type: 'string' },
              valid: { type: 'boolean' },
              policy: { type: ['string', 'null'], example: 'reject' },
              subdomainPolicy: { type: ['string', 'null'] },
              pct: { type: 'integer' },
              rua: { type: 'array', items: { type: 'string' } },
              alignment: { type: 'object' },
            },
          },
          dkim: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                selector: { type: 'string' },
                found: { type: 'boolean' },
                info: { type: ['object', 'null'] },
              },
            },
          },
          checks: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string', enum: ['mx', 'spf', 'dmarc', 'dkim'] },
                label: { type: 'string' },
                status: { type: 'string', enum: ['pass', 'warn', 'fail'] },
                detail: { type: 'string' },
              },
            },
          },
          summary: { type: 'string', enum: ['良好', '需改进', '缺少关键配置'] },
          note: { type: 'string' },
        },
        required: ['domain', 'checks', 'summary'],
      },
      Meta: {
        type: 'object',
        description: '每次响应附带的元信息，用于判断数据来源、缓存命中与调用配额。',
        properties: {
          source: {
            type: 'string',
            description:
              '数据来源：rdap 与 whois 为域名注册信息，dns 为解析记录，ip-rdap 为 IP 归属，uptime 为可用性探测，history 为历史快照，local-index 为本站域名索引，registrar-directory 为 IANA + ICANN 注册商目录，icp 为本站缓存与公开备案数据回源，tls 为本站 TLS 握手，mail-dns 为本站 DNS 解析。',
            enum: [
              'rdap',
              'whois',
              'dns',
              'ip-rdap',
              'uptime',
              'history',
              'local-index',
              'registrar-directory',
              'icp',
              'tls',
              'mail-dns',
            ],
          },
          server: { type: 'string', description: '本次查询实际使用的上游服务器', example: 'rdap.verisign.com' },
          durationMs: { type: 'integer', description: '本次查询耗时（毫秒）', example: 612 },
          cached: { type: 'boolean', description: '是否命中进程内缓存' },
          cacheTtlMs: { type: 'integer', description: '缓存有效期（毫秒），0 表示不缓存', example: 600000 },
          queriedAt: { type: 'string', format: 'date-time', description: '查询完成时间（ISO 8601）' },
          requestId: { type: 'string', description: '请求 ID，便于日志排查' },
          rateLimit: { $ref: '#/components/schemas/RateLimit' },
        },
      },
      SuccessEnvelope: {
        type: 'object',
        required: ['success', 'data', 'meta'],
        properties: {
          success: { type: 'boolean', const: true },
          data: { $ref: '#/components/schemas/WhoisData' },
          meta: { $ref: '#/components/schemas/Meta' },
        },
      },
      ErrorEnvelope: {
        type: 'object',
        required: ['success', 'error'],
        properties: {
          success: { type: 'boolean', const: false },
          error: {
            type: 'object',
            properties: {
              code: {
                type: 'string',
                enum: [
                  'INVALID_DOMAIN',
                  'BAD_REQUEST',
                  'UNAUTHORIZED',
                  'NOT_FOUND',
                  'RATE_LIMITED',
                  'UPSTREAM_UNAVAILABLE',
                  'UPSTREAM_TIMEOUT',
                  'ADMIN_DISABLED',
                  'WEB_DISABLED',
                  'WEB_QUOTA_EXCEEDED',
                  'FEATURE_DISABLED',
                  'INTERNAL',
                ],
              },
              message: { type: 'string' },
              details: {},
            },
          },
          meta: {
            type: 'object',
            properties: { requestId: { type: 'string' } },
          },
        },
      },
      BatchRequest: {
        type: 'object',
        required: ['domains'],
        properties: {
          domains: {
            type: 'array',
            minItems: 1,
            maxItems: 20,
            items: { type: 'string' },
            example: ['example.com', 'github.com', 'example.invalid'],
          },
          raw: { type: 'boolean', default: false },
          refresh: { type: 'boolean', default: false },
        },
      },
    },
  },
  paths: {
    '/v1/whois/{domain}': {
      get: {
        tags: ['WHOIS'],
        operationId: 'lookupDomainByPath',
        summary: '查询单个域名',
        description:
          '查询域名注册信息。优先使用注册局 RDAP，未覆盖时自动回退 WHOIS。结果默认缓存 10 分钟，可注册域名缓存 60 秒。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'domain',
            in: 'path',
            required: true,
            description: '域名、URL 或邮箱中的域名，支持 IDN',
            schema: { type: 'string', example: 'example.com' },
          },
          {
            name: 'raw',
            in: 'query',
            description: '返回原始 RDAP JSON / WHOIS 文本',
            schema: { type: 'boolean', default: false },
          },
          {
            name: 'refresh',
            in: 'query',
            description: '跳过缓存强制刷新',
            schema: { type: 'boolean', default: false },
          },
        ],
        responses: {
          '200': {
            description: '查询成功',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessEnvelope' },
                example: {
                  success: true,
                  data: {
                    domain: 'example.com',
                    unicodeDomain: 'example.com',
                    tld: 'com',
                    sld: 'example',
                    idn: false,
                    available: false,
                    registered: true,
                    registrar: {
                      name: 'RESERVED-Internet Assigned Numbers Authority',
                      ianaId: '376',
                      url: 'https://www.iana.org/',
                      abuseEmail: null,
                      abusePhone: null,
                    },
                    registrant: null,
                    dates: {
                      created: '1995-08-14T04:00:00.000Z',
                      updated: '2025-08-14T07:01:38.000Z',
                      expires: '2026-08-13T04:00:00.000Z',
                    },
                    statuses: ['clientTransferProhibited'],
                    nameservers: ['a.iana-servers.net', 'b.iana-servers.net'],
                    dnssec: 'unsigned',
                    registryDomainId: '2336799_DOMAIN_COM-VRSN',
                  },
                  meta: {
                    source: 'rdap',
                    server: 'rdap.verisign.com',
                    durationMs: 612,
                    cached: false,
                    cacheTtlMs: 600000,
                    queriedAt: '2026-11-21T08:00:00.000Z',
                    requestId: 'req-1',
                    rateLimit: { limit: 120, remaining: 118, reset: 42 },
                  },
                },
              },
            },
          },
          '400': {
            description: '域名格式不合法',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ErrorEnvelope' },
                example: {
                  success: false,
                  error: { code: 'INVALID_DOMAIN', message: '请输入完整域名（包含后缀），例如 example.com' },
                  meta: { requestId: 'req-2' },
                },
              },
            },
          },
          '429': { description: '触发限流', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorEnvelope' } } } },
          '502': { description: '上游 RDAP / WHOIS 不可用', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorEnvelope' } } } },
        },
      },
    },
    '/v1/whois': {
      get: {
        tags: ['WHOIS'],
        operationId: 'lookupDomainByQuery',
        summary: '查询单个域名（查询参数形式）',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'domain',
            in: 'query',
            required: true,
            schema: { type: 'string', example: 'example.com' },
          },
          {
            name: 'raw',
            in: 'query',
            schema: { type: 'boolean', default: false },
          },
          {
            name: 'refresh',
            in: 'query',
            schema: { type: 'boolean', default: false },
          },
        ],
        responses: {
          '200': {
            description: '查询成功',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SuccessEnvelope' },
                example: {
                  success: true,
                  data: {
                    domain: 'example.com',
                    unicodeDomain: 'example.com',
                    tld: 'com',
                    sld: 'example',
                    idn: false,
                    available: false,
                    registered: true,
                    registrar: {
                      name: 'RESERVED-Internet Assigned Numbers Authority',
                      ianaId: '376',
                      url: 'https://www.iana.org/',
                      abuseEmail: null,
                      abusePhone: null,
                    },
                    registrant: null,
                    dates: {
                      created: '1995-08-14T04:00:00.000Z',
                      updated: '2025-08-14T07:01:38.000Z',
                      expires: '2026-08-13T04:00:00.000Z',
                    },
                    statuses: ['clientTransferProhibited'],
                    nameservers: ['a.iana-servers.net', 'b.iana-servers.net'],
                    dnssec: 'unsigned',
                    registryDomainId: '2336799_DOMAIN_COM-VRSN',
                  },
                  meta: {
                    source: 'rdap',
                    server: 'rdap.verisign.com',
                    durationMs: 612,
                    cached: false,
                    cacheTtlMs: 600000,
                    queriedAt: '2026-11-21T08:00:00.000Z',
                    requestId: 'req-1',
                    rateLimit: { limit: 120, remaining: 118, reset: 42 },
                  },
                },
              },
            },
          },
          '400': { description: '参数不合法', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorEnvelope' } } } },
        },
      },
    },
    '/v1/whois/batch': {
      post: {
        tags: ['WHOIS'],
        operationId: 'lookupDomainsBatch',
        summary: '批量查询域名',
        description: '一次最多查询 20 个域名，服务端以 5 个并发执行。单个域名失败不会影响其他结果。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/BatchRequest' },
              example: { domains: ['example.com', 'github.com'], raw: false },
            },
          },
        },
        responses: {
          '200': {
            description: '批量查询结果',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', const: true },
                    results: {
                      type: 'array',
                      items: {
                        oneOf: [
                          { $ref: '#/components/schemas/SuccessEnvelope' },
                          { $ref: '#/components/schemas/ErrorEnvelope' },
                        ],
                      },
                    },
                    meta: {
                      type: 'object',
                      properties: {
                        count: { type: 'integer' },
                        durationMs: { type: 'integer' },
                        requestId: { type: 'string' },
                      },
                    },
                  },
                },
                example: {
                  success: true,
                  results: [
                    {
                      success: true,
                      data: {
                        domain: 'example.com',
                        unicodeDomain: 'example.com',
                        tld: 'com',
                        sld: 'example',
                        idn: false,
                        available: false,
                        registered: true,
                        registrar: {
                          name: 'RESERVED-Internet Assigned Numbers Authority',
                          ianaId: '376',
                          url: 'https://www.iana.org/',
                          abuseEmail: null,
                          abusePhone: null,
                        },
                        registrant: null,
                        dates: {
                          created: '1995-08-14T04:00:00.000Z',
                          updated: '2025-08-14T07:01:38.000Z',
                          expires: '2026-08-13T04:00:00.000Z',
                        },
                        statuses: ['clientTransferProhibited'],
                        nameservers: ['a.iana-servers.net', 'b.iana-servers.net'],
                        dnssec: 'unsigned',
                        registryDomainId: '2336799_DOMAIN_COM-VRSN',
                      },
                      meta: {
                        source: 'rdap',
                        server: 'rdap.verisign.com',
                        durationMs: 480,
                        cached: false,
                        cacheTtlMs: 600000,
                        queriedAt: '2026-11-21T08:00:00.000Z',
                        requestId: 'req-3',
                        rateLimit: { limit: 120, remaining: 110, reset: 40 },
                      },
                    },
                    {
                      success: false,
                      error: { code: 'INVALID_DOMAIN', message: '请输入完整域名（包含后缀），例如 example.com' },
                    },
                  ],
                  meta: { count: 2, durationMs: 731, requestId: 'req-3' },
                },
              },
            },
          },
          '400': { description: '请求体不合法', content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorEnvelope' } } } },
        },
      },
    },
    '/v1/tlds': {
      get: {
        tags: ['WHOIS'],
        operationId: 'listTlds',
        summary: '列出内置支持的 TLD 与 WHOIS 服务器',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        responses: {
          '200': {
            description: '已内置映射的 TLD 列表（其他后缀会动态向 IANA 查询）',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', const: true },
                    data: {
                      type: 'object',
                      properties: {
                        count: { type: 'integer' },
                        tlds: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              tld: { type: 'string' },
                              host: { type: 'string' },
                              port: { type: 'integer' },
                            },
                          },
                        },
                      },
                    },
                  },
                },
                example: {
                  success: true,
                  data: { count: 2, tlds: [{ tld: 'com', host: 'whois.verisign-grs.com', port: 43 }] },
                },
              },
            },
          },
        },
      },
    },
    '/v1/meta': {
      get: {
        tags: ['Meta'],
        operationId: 'getMeta',
        summary: '获取服务能力目录与限制',
        description: '返回工具清单、支持的 DNS 记录类型、传播解析器与各项限制，便于客户端自动发现能力。',
        responses: {
          '200': {
            description: '能力目录',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', const: true },
                    data: {
                      type: 'object',
                      properties: {
                        name: { type: 'string' },
                        version: { type: 'string' },
                        license: { type: 'string', example: 'GPL-3.0-only' },
                        uptimeSec: { type: 'integer' },
                        tools: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              key: { type: 'string' },
                              label: { type: 'string' },
                              path: { type: 'string' },
                            },
                          },
                        },
                        dnsTypes: { type: 'array', items: { type: 'string' } },
                        propagationTypes: { type: 'array', items: { type: 'string' } },
                        propagationResolvers: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              id: { type: 'string' },
                              name: { type: 'string' },
                              address: { type: 'string' },
                            },
                          },
                        },
                        limits: { type: 'object' },
                      },
                    },
                  },
                },
                example: {
                  success: true,
                  data: {
                    name: 'Pull WHOIS',
                    version: '1.0.0',
                    license: 'GPL-3.0-only',
                    uptimeSec: 3600,
                    tools: [{ key: 'whois', label: 'WHOIS 查询', path: '/v1/whois/{domain}' }],
                    dnsTypes: ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'CAA', 'ANY'],
                    propagationTypes: ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'CAA'],
                    limits: { batchDomains: 10, httpRedirects: 5, httpTimeoutMs: 8000 },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/v1/rdap/{domain}': {
      get: {
        tags: ['RDAP'],
        operationId: 'lookupDomainRdap',
        summary: '通过 RDAP 查询域名',
        description: '直接查询注册局 RDAP，返回与 WHOIS 相同的归一化字段，并在 meta.source 中标记为 rdap。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'domain',
            in: 'path',
            required: true,
            schema: { type: 'string', example: 'example.com' },
          },
          {
            name: 'raw',
            in: 'query',
            description: '返回完整 RDAP JSON',
            schema: { type: 'boolean', default: false },
          },
        ],
        responses: {
          '200': {
            description: '查询成功',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessEnvelope' } } },
          },
          '502': { description: 'RDAP 未覆盖或暂时不可用' },
        },
      },
    },
    '/v1/dns/{domain}': {
      get: {
        tags: ['DNS'],
        operationId: 'lookupDnsRecords',
        summary: '查询 DNS 记录',
        description: '查询 A、AAAA、MX、TXT、NS、CNAME、SOA、SRV、CAA，或使用 ANY 一次获取全部记录。默认缓存 5 分钟。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'domain',
            in: 'path',
            required: true,
            schema: { type: 'string', example: 'example.com' },
          },
          {
            name: 'type',
            in: 'query',
            schema: {
              type: 'string',
              enum: ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'CAA', 'ANY'],
              default: 'A',
            },
          },
        ],
        responses: {
          '200': {
            description: 'DNS 查询结果',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { const: true },
                    data: { type: 'object' },
                    meta: { type: 'object' },
                  },
                },
                example: {
                  success: true,
                  data: {
                    domain: 'example.com',
                    type: 'A',
                    status: 'ok',
                    records: [
                      { type: 'A', value: '93.184.216.34' },
                      { type: 'A', value: '93.184.216.35' },
                    ],
                    durationMs: 18,
                    cached: false,
                    ttlMs: 300000,
                  },
                  meta: { source: 'dns', requestId: 'req-dns', rateLimit: { limit: 120, remaining: 119, reset: 60 } },
                },
              },
            },
          },
          '400': { description: '域名或记录类型不合法' },
        },
      },
    },
    '/v1/ip/{ip}': {
      get: {
        tags: ['IP'],
        operationId: 'lookupIpAddress',
        summary: '查询 IPv4 / IPv6 归属',
        description:
          '返回 PTR 反向解析、ASN 自治系统信息（Team Cymru DNS，毫秒级）与 RDAP 网络归属（组织、国家/地区、地址范围、注册与更新时间）。RDAP 超时不影响 ASN 数据返回。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'ip',
            in: 'path',
            required: true,
            schema: { type: 'string', example: '8.8.8.8' },
          },
          {
            name: 'raw',
            in: 'query',
            description: '返回原始 RDAP 网络对象',
            schema: { type: 'boolean', default: false },
          },
        ],
        responses: {
          '200': {
            description: 'IP 查询结果',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { success: { const: true }, data: { type: 'object' }, meta: { type: 'object' } },
                },
                example: {
                  success: true,
                  data: {
                    ip: '8.8.8.8',
                    version: 4,
                    ptr: ['dns.google'],
                    network: {
                      handle: 'NET-8-8-8-0-1',
                      name: 'GOGL',
                      range: { start: '8.8.8.0', end: '8.8.8.255' },
                      ipVersion: 'v4',
                      country: 'US',
                      type: 'DIRECT ALLOCATION',
                      parentHandle: 'NET-8-0-0-0-0',
                      organization: 'Google LLC',
                      registered: '2023-12-28T09:00:00-05:00',
                      updated: '2023-12-28T09:00:00-05:00',
                      statuses: ['active'],
                    },
                    asn: {
                      asn: 15169,
                      name: 'GOOGLE - Google LLC, US',
                      prefix: '8.8.8.0/24',
                      country: 'US',
                      registry: 'arin',
                      allocated: '2023-12-28',
                    },
                    server: 'rdap.arin.net',
                    cached: false,
                    ttlMs: 600000,
                    durationMs: 355,
                  },
                  meta: { source: 'ip-rdap', requestId: 'req-ip' },
                },
              },
            },
          },
          '400': { description: 'IP 地址不合法' },
        },
      },
    },
    '/v1/uptime': {
      get: {
        tags: ['Uptime'],
        operationId: 'checkUptime',
        summary: '检查网站可用性',
        description: 'HEAD 优先并在失败时回退 GET，自动跟随重定向；拒绝内网与保留地址以避免 SSRF。结果缓存 60 秒。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'target',
            in: 'query',
            required: true,
            description: '域名或完整 http(s) URL',
            schema: { type: 'string', example: 'example.com' },
          },
        ],
        responses: {
          '200': {
            description: '检查结果',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { success: { const: true }, data: { type: 'object' }, meta: { type: 'object' } },
                },
                example: {
                  success: true,
                  data: {
                    target: 'https://example.com/',
                    finalUrl: 'https://example.com/',
                    reachable: true,
                    ok: true,
                    status: 200,
                    statusText: 'OK',
                    method: 'HEAD',
                    latencyMs: 182,
                    redirected: false,
                    error: null,
                    checkedAt: '2026-11-21T08:00:00.000Z',
                    cached: false,
                    ttlMs: 60000,
                  },
                  meta: { source: 'uptime', requestId: 'req-up' },
                },
              },
            },
          },
          '400': { description: '目标不合法或指向内网地址' },
        },
      },
    },
    '/v1/history/{domain}': {
      get: {
        tags: ['History'],
        operationId: 'getDomainHistory',
        summary: '获取域名历史快照',
        description:
          '返回本站保存的域名快照与字段变化。历史自功能启用后开始积累，不虚构 2007 年全网历史；可接入外部历史数据源扩展。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'domain',
            in: 'path',
            required: true,
            schema: { type: 'string', example: 'example.com' },
          },
          {
            name: 'refresh',
            in: 'query',
            description: '立即执行一次实时查询并写入快照',
            schema: { type: 'boolean', default: false },
          },
        ],
        responses: {
          '200': {
            description: '历史快照与变更',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { success: { const: true }, data: { type: 'object' }, meta: { type: 'object' } },
                },
                example: {
                  success: true,
                  data: {
                    domain: 'example.com',
                    snapshots: [
                      {
                        at: '2026-11-21T08:00:00.000Z',
                        available: false,
                        registrar: 'RESERVED-Internet Assigned Numbers Authority',
                        registrarIanaId: '376',
                        registrantName: null,
                        registrantOrg: null,
                        registrantCountry: null,
                        nameservers: ['a.iana-servers.net', 'b.iana-servers.net'],
                        statuses: ['clientTransferProhibited'],
                        created: '1995-08-14T04:00:00.000Z',
                        updated: '2025-08-14T07:01:38.000Z',
                        expires: '2026-08-13T04:00:00.000Z',
                      },
                    ],
                    changes: [],
                    note: '历史记录来自本站成功查询时保存的快照……',
                  },
                  meta: { source: 'history', requestId: 'req-his' },
                },
              },
            },
          },
        },
      },
    },
    '/v1/nameservers/{host}': {
      get: {
        tags: ['Nameservers'],
        operationId: 'reverseNameserver',
        summary: '名称服务器反查',
        description: '根据本站本地索引，列出由指定名称服务器托管的域名。索引不构成全网数据。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'host',
            in: 'path',
            required: true,
            schema: { type: 'string', example: 'ns1.cloudflare.com' },
          },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 100, maximum: 200 } },
          { name: 'offset', in: 'query', schema: { type: 'integer', default: 0 } },
        ],
        responses: {
          '200': {
            description: '反查结果',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { success: { const: true }, data: { type: 'object' }, meta: { type: 'object' } },
                },
                example: {
                  success: true,
                  data: {
                    host: 'ns1.cloudflare.com',
                    total: 1,
                    domains: [
                      {
                        domain: 'example.com',
                        registrar: 'Cloudflare, Inc.',
                        registrarIanaId: '1910',
                        nameservers: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
                        firstSeen: '2026-11-20T10:00:00.000Z',
                        lastSeen: '2026-11-21T08:00:00.000Z',
                      },
                    ],
                    note: '本地索引仅包含本站成功查询过的域名……',
                  },
                  meta: { source: 'local-index', requestId: 'req-ns' },
                },
              },
            },
          },
        },
      },
    },
    '/v1/registrars': {
      get: {
        tags: ['Registrars'],
        operationId: 'listRegistrars',
        summary: '浏览注册商目录',
        description:
          '合并 IANA Registrar IDs 与 ICANN 认证注册商列表的本地快照（每日同步），并附带本站本地索引中的域名数量。支持名称、IANA ID、国家与状态筛选。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          { name: 'q', in: 'query', schema: { type: 'string', example: 'cloudflare' } },
          {
            name: 'country',
            in: 'query',
            description: 'ICANN 登记的国家/地区名称，例如 United States of America、China',
            schema: { type: 'string', example: 'China' },
          },
          {
            name: 'status',
            in: 'query',
            description: '认证状态；all 表示包含全部状态，默认排除 terminated/reserved',
            schema: {
              type: 'string',
              enum: ['all', 'accredited', 'terminated', 'reserved', 'unknown'],
              example: 'accredited',
            },
          },
          { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 24, maximum: 200 } },
        ],
        responses: {
          '200': {
            description: '注册商目录',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { success: { const: true }, data: { type: 'object' }, meta: { type: 'object' } },
                },
                example: {
                  success: true,
                  data: {
                    total: 1,
                    page: 1,
                    limit: 24,
                    totalPages: 1,
                    items: [
                      {
                        id: '1910',
                        ianaId: '1910',
                        name: 'Cloudflare, Inc.',
                        website: 'https://www.cloudflare.com/products/registrar/',
                        country: 'US',
                        contact: 'https://www.cloudflare.com/abuse/',
                        status: 'accredited',
                        rdapServer: 'https://rdap.cloudflare.com/',
                        updated: '2026-11-20',
                        source: 'iana+icann',
                        indexedDomains: 1,
                        lastSeen: '2026-11-21T08:00:00.000Z',
                      },
                    ],
                    stats: { total: 2431, accredited: 2104, countries: 97 },
                    sync: {
                      syncedAt: '2026-11-21T02:00:00.000Z',
                      ianaUpdated: '2026-11-19',
                      sources: { iana: 'ok', icann: 'ok' },
                      refreshing: false,
                      total: 2431,
                    },
                    note: '注册商目录来自 IANA Registrar IDs 与 ICANN 认证注册商列表……',
                  },
                  meta: { source: 'registrar-directory', requestId: 'req-reg' },
                },
              },
            },
          },
        },
      },
    },
    '/v1/registrars/{id}': {
      get: {
        tags: ['Registrars'],
        operationId: 'getRegistrar',
        summary: '查看注册商与索引域名',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            description: '目录 ID、IANA ID 或注册商名称',
            schema: { type: 'string', example: '1910' },
          },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 40, maximum: 200 } },
          { name: 'offset', in: 'query', schema: { type: 'integer', default: 0 } },
        ],
        responses: {
          '200': { description: '注册商详情' },
          '404': { description: '注册商不存在' },
        },
      },
    },
    '/v1/registrars/{id}/domains': {
      get: {
        tags: ['Registrars'],
        operationId: 'listRegistrarDomains',
        summary: '查看注册商在本站索引中的域名',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            description: '目录 ID、IANA ID 或注册商名称',
            schema: { type: 'string', example: '1910' },
          },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 40, maximum: 200 } },
          { name: 'offset', in: 'query', schema: { type: 'integer', default: 0 } },
        ],
        responses: {
          '200': { description: '索引域名列表' },
          '404': { description: '注册商不存在' },
        },
      },
    },
    '/v1/tls/{host}': {
      get: {
        tags: ['TLS'],
        operationId: 'checkTlsCertificate',
        summary: '检查 TLS 证书',
        description:
          '由本站直接与目标端口完成 TLS 握手，返回证书主体、颁发者、有效期、SAN、指纹、公钥位数、证书链长度、TLS 协议、加密套件与 ALPN。不发送 HTTP 请求，不依赖第三方检测服务。拒绝内网与保留地址。注意：证书校验结果来自握手，不会因证书无效而中断连接。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'host',
            in: 'path',
            required: true,
            description: '域名',
            schema: { type: 'string', example: 'example.com' },
          },
          {
            name: 'port',
            in: 'query',
            description: '端口，默认 443',
            schema: { type: 'integer', minimum: 1, maximum: 65535, default: 443 },
          },
        ],
        responses: {
          '200': {
            description: 'TLS 握手与证书信息',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { const: true },
                    data: { $ref: '#/components/schemas/TlsCheck' },
                    meta: { $ref: '#/components/schemas/Meta' },
                  },
                },
                example: {
                  success: true,
                  data: {
                    host: 'example.com',
                    port: 443,
                    servername: 'example.com',
                    address: '93.184.216.34',
                    family: 4,
                    reachable: true,
                    authorized: true,
                    authorizationError: null,
                    protocol: 'TLSv1.3',
                    cipher: { name: 'TLS_AES_128_GCM_SHA256', version: 'TLSv1.3' },
                    alpn: 'h2',
                    certificate: {
                      subject: { commonName: 'example.com', organization: null, country: 'US' },
                      issuer: { commonName: 'DigiCert TLS RSA SHA256 2020 CA1', organization: 'DigiCert Inc', country: 'US' },
                      validFrom: '2026-01-01T00:00:00.000Z',
                      validTo: '2026-12-31T23:59:59.000Z',
                      daysRemaining: 40,
                      expired: false,
                      notYetValid: false,
                      san: ['example.com', 'www.example.com'],
                      keyBits: 2048,
                      chainLength: 2,
                    },
                    checkedAt: '2026-11-21T08:00:00.000Z',
                  },
                  meta: { source: 'tls', cached: false, durationMs: 238 },
                },
              },
            },
          },
          '400': { description: '域名/端口不合法，或目标为内网地址' },
          '502': { description: '目标拒绝连接或不是 TLS 服务' },
          '504': { description: 'TLS 握手超时' },
        },
      },
    },
    '/v1/tls/{host}/chain': {
      get: {
        tags: ['TLS'],
        operationId: 'exportTlsCertificateChain',
        summary: '导出 TLS 证书链',
        description:
          '与目标端口完成一次 TLS 握手，按服务器返回顺序整理完整证书链，并输出每张证书的主体、颁发者、有效期、SHA-256 指纹与标准 PEM。传 format=pem 时直接返回可直接保存的 PEM 文件，便于排查证书链缺失、顺序错误与交叉签名问题。全流程由本站直连完成，不依赖第三方服务。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'host',
            in: 'path',
            required: true,
            description: '域名',
            schema: { type: 'string', example: 'example.com' },
          },
          {
            name: 'port',
            in: 'query',
            description: '端口，默认 443',
            schema: { type: 'integer', minimum: 1, maximum: 65535, default: 443 },
          },
          {
            name: 'format',
            in: 'query',
            description: 'json 返回结构化结果，pem 直接返回证书链文本',
            schema: { type: 'string', enum: ['json', 'pem'], default: 'json' },
          },
        ],
        responses: {
          '200': {
            description: '完整证书链',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { const: true },
                    data: {
                      type: 'object',
                      properties: {
                        host: { type: 'string' },
                        port: { type: 'integer' },
                        address: { type: 'string' },
                        count: { type: 'integer', description: '证书链长度' },
                        chain: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              index: { type: 'integer' },
                              subject: { type: ['string', 'null'] },
                              issuer: { type: ['string', 'null'] },
                              validFrom: { type: ['string', 'null'], format: 'date-time' },
                              validTo: { type: ['string', 'null'], format: 'date-time' },
                              fingerprint256: { type: ['string', 'null'] },
                              selfSigned: { type: 'boolean' },
                              pem: { type: 'string' },
                            },
                          },
                        },
                        pem: { type: 'string', description: '拼接后的完整 PEM' },
                        note: { type: 'string' },
                        checkedAt: { type: 'string', format: 'date-time' },
                        cached: { type: 'boolean' },
                        ttlMs: { type: 'integer' },
                      },
                    },
                    meta: { $ref: '#/components/schemas/Meta' },
                  },
                },
                example: {
                  success: true,
                  data: {
                    host: 'example.com',
                    port: 443,
                    address: '93.184.216.34',
                    count: 2,
                    chain: [
                      {
                        index: 0,
                        subject: 'example.com',
                        issuer: 'DigiCert TLS RSA SHA256 2020 CA1',
                        validFrom: '2026-01-01T00:00:00.000Z',
                        validTo: '2026-12-31T23:59:59.000Z',
                        fingerprint256: '5A:1B:…',
                        selfSigned: false,
                        pem: '-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n',
                      },
                    ],
                    pem: '-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n',
                    note: '证书链由本站直接与目标端口完成 TLS 握手后导出。',
                    checkedAt: '2026-11-21T08:00:00.000Z',
                    cached: false,
                    ttlMs: 1800000,
                  },
                  meta: { source: 'cert-chain', cached: false, count: 2 },
                },
              },
              'application/x-pem-file': {
                schema: { type: 'string', description: 'format=pem 时的证书链文本' },
              },
            },
          },
          '400': { description: '域名或端口不合法，或目标为内网地址' },
          '502': { description: '目标拒绝连接或未返回证书' },
          '504': { description: 'TLS 握手超时' },
        },
      },
    },
    '/v1/mail/{domain}': {
      get: {
        tags: ['Mail'],
        operationId: 'checkMailAuthentication',
        summary: '检查邮件安全记录',
        description:
          '由本站直接查询 DNS 并解析 SPF、DMARC、DKIM 与 MX：给出 SPF 机制与 all 策略、DMARC 策略与对齐方式、DKIM 公钥探测结果，以及逐项检查结论。DKIM 选择器无法通过 DNS 枚举，默认探测常见选择器，可用 selector 指定（逗号分隔，最多 6 个）。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'domain',
            in: 'path',
            required: true,
            description: '域名',
            schema: { type: 'string', example: 'example.com' },
          },
          {
            name: 'selector',
            in: 'query',
            description: 'DKIM 选择器，逗号分隔，最多 6 个',
            schema: { type: 'string', example: 'default,google' },
          },
        ],
        responses: {
          '200': {
            description: '邮件安全记录与检查结论',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { const: true },
                    data: { $ref: '#/components/schemas/MailAuth' },
                    meta: { $ref: '#/components/schemas/Meta' },
                  },
                },
                example: {
                  success: true,
                  data: {
                    domain: 'example.com',
                    mx: [{ priority: 10, exchange: 'mail.example.com' }],
                    aFallback: [],
                    spf: {
                      raw: 'v=spf1 include:_spf.example.com -all',
                      valid: true,
                      includes: ['_spf.example.com'],
                      ip4: [],
                      ip6: [],
                      allQualifier: '-',
                      lookupCount: 1,
                      errors: [],
                      warnings: [],
                    },
                    dmarc: {
                      raw: 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com',
                      valid: true,
                      policy: 'reject',
                      subdomainPolicy: null,
                      pct: 100,
                      rua: ['mailto:dmarc@example.com'],
                      alignment: { dkim: 'r', spf: 'r' },
                    },
                    dkim: [{ selector: 'default', found: true, info: { version: 'DKIM1', keyType: 'rsa', keyPresent: true, revoked: false, valid: true } }],
                    checks: [
                      { id: 'mx', label: 'MX 邮件交换记录', status: 'pass', detail: '1 条 MX 记录' },
                      { id: 'spf', label: 'SPF 发信来源', status: 'pass', detail: '包含 2 个机制，all=-all' },
                      { id: 'dmarc', label: 'DMARC 策略', status: 'pass', detail: 'p=reject' },
                      { id: 'dkim', label: 'DKIM 签名公钥', status: 'pass', detail: '命中选择器：default' },
                    ],
                    summary: '良好',
                    note: 'SPF、DMARC、DKIM 与 MX 均由本站直接查询 DNS 后解析，不依赖第三方检测服务。',
                  },
                  meta: { source: 'mail-dns', cached: false, selectors: ['default', 'google', 'selector1', 'selector2'] },
                },
              },
            },
          },
          '400': { description: '域名或 DKIM 选择器格式不合法' },
        },
      },
    },
    '/v1/http/{target}': {
      get: {
        tags: ['HTTP'],
        operationId: 'checkHttpSecurityHeaders',
        summary: 'HTTP 安全响应头体检',
        description:
          '由本站直接向目标站点发起一次轻量请求（只读取响应头，不下载正文、不执行脚本），分析 HSTS、CSP、点击劫持防护、MIME 嗅探防护、Referrer-Policy、Permissions-Policy、COOP、Cookie 安全属性等，并给出 0-100 分、等级与逐项改进建议。自动跟随最多 5 次重定向，拒绝内网与保留地址。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'target',
            in: 'path',
            required: true,
            description: '域名或完整 URL',
            schema: { type: 'string', example: 'example.com' },
          },
          {
            name: 'refresh',
            in: 'query',
            required: false,
            description: '传 1 强制重新体检并绕过缓存',
            schema: { type: 'boolean', default: false },
          },
        ],
        responses: {
          '200': {
            description: 'HTTP 响应头与安全分析结果',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { const: true },
                    data: {
                      type: 'object',
                      properties: {
                        target: { type: 'string' },
                        finalUrl: { type: 'string' },
                        host: { type: 'string' },
                        https: { type: 'boolean' },
                        reachable: { type: 'boolean' },
                        status: { type: ['integer', 'null'] },
                        statusText: { type: ['string', 'null'] },
                        latencyMs: { type: 'integer' },
                        redirects: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              from: { type: 'string' },
                              to: { type: 'string' },
                              status: { type: 'integer' },
                            },
                          },
                        },
                        server: { type: ['string', 'null'] },
                        poweredBy: { type: ['string', 'null'] },
                        contentType: { type: ['string', 'null'] },
                        contentEncoding: { type: ['string', 'null'] },
                        cacheControl: { type: ['string', 'null'] },
                        via: { type: ['string', 'null'] },
                        headers: { type: 'object', additionalProperties: { type: 'string' } },
                        security: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              id: { type: 'string' },
                              label: { type: 'string' },
                              status: { type: 'string', enum: ['pass', 'warn', 'fail', 'info'] },
                              weight: { type: 'integer' },
                              value: { type: ['string', 'null'] },
                              detail: { type: 'string' },
                            },
                          },
                        },
                        cookies: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              name: { type: 'string' },
                              secure: { type: 'boolean' },
                              httpOnly: { type: 'boolean' },
                              sameSite: { type: ['string', 'null'] },
                            },
                          },
                        },
                        score: { type: 'integer', minimum: 0, maximum: 100 },
                        grade: { type: 'string', example: 'A' },
                        issues: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              id: { type: 'string' },
                              label: { type: 'string' },
                              severity: { type: 'string', enum: ['high', 'medium', 'low'] },
                              detail: { type: 'string' },
                            },
                          },
                        },
                        summary: { type: 'string' },
                        error: { type: ['string', 'null'] },
                        checkedAt: { type: 'string', format: 'date-time' },
                        cached: { type: 'boolean' },
                        ttlMs: { type: 'integer' },
                        note: { type: 'string' },
                      },
                    },
                    meta: { $ref: '#/components/schemas/Meta' },
                  },
                },
                example: {
                  success: true,
                  data: {
                    target: 'https://example.com/',
                    finalUrl: 'https://example.com/',
                    host: 'example.com',
                    https: true,
                    reachable: true,
                    status: 200,
                    statusText: 'OK',
                    latencyMs: 186,
                    redirects: [],
                    server: 'nginx',
                    poweredBy: null,
                    contentType: 'text/html; charset=UTF-8',
                    contentEncoding: 'gzip',
                    cacheControl: 'max-age=3600',
                    via: null,
                    headers: { 'strict-transport-security': 'max-age=31536000' },
                    security: [
                      { id: 'hsts', label: 'HSTS 强制 HTTPS', status: 'pass', weight: 14, value: 'max-age=31536000', detail: '已开启 HSTS，浏览器会强制使用 HTTPS' },
                      { id: 'csp', label: '内容安全策略 CSP', status: 'fail', weight: 12, value: null, detail: '未设置 CSP，页面注入脚本的防护较弱' },
                    ],
                    cookies: [],
                    score: 86,
                    grade: 'B',
                    issues: [{ id: 'csp', label: '内容安全策略 CSP', severity: 'high', detail: '未设置 CSP，页面注入脚本的防护较弱' }],
                    summary: '基础配置可用，仍有可加固项',
                    error: null,
                    checkedAt: '2026-11-21T08:00:00.000Z',
                    cached: false,
                    ttlMs: 300000,
                    note: '响应头由本站直接请求目标站点获取并分析。',
                  },
                  meta: { source: 'http-probe', cached: false, durationMs: 186 },
                },
              },
            },
          },
          '400': { description: '目标格式不合法，或目标为内网地址' },
          '504': { description: '目标响应超时' },
        },
      },
    },
    '/v1/dnsprop/{domain}': {
      get: {
        tags: ['DNS'],
        operationId: 'checkDnsPropagation',
        summary: 'DNS 多解析器传播对比',
        description:
          '由本站同时向阿里 DNS、DNSPod、Cloudflare、Google DNS 四个公共递归解析器发起标准 DNS 查询，对比同一域名、同一记录类型的结果是否一致，返回每个解析器的记录、耗时、错误与差异分组。支持 A、AAAA、MX、TXT、NS、CNAME、CAA，默认 A。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'domain',
            in: 'path',
            required: true,
            description: '域名',
            schema: { type: 'string', example: 'example.com' },
          },
          {
            name: 'type',
            in: 'query',
            description: '记录类型',
            schema: {
              type: 'string',
              enum: ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'CAA'],
              default: 'A',
            },
          },
        ],
        responses: {
          '200': {
            description: '各解析器查询结果与一致性结论',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { const: true },
                    data: {
                      type: 'object',
                      properties: {
                        domain: { type: 'string' },
                        type: { type: 'string' },
                        consistent: { type: 'boolean', description: '成功返回的解析器结果是否完全一致' },
                        successful: { type: 'integer' },
                        failed: { type: 'integer' },
                        resolvers: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              id: { type: 'string' },
                              name: { type: 'string' },
                              address: { type: 'string' },
                              status: { type: 'string', enum: ['ok', 'error', 'timeout'] },
                              records: { type: 'array', items: { type: 'string' } },
                              durationMs: { type: 'integer' },
                              error: { type: ['string', 'null'] },
                            },
                          },
                        },
                        groups: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              records: { type: 'array', items: { type: 'string' } },
                              resolvers: { type: 'array', items: { type: 'string' } },
                            },
                          },
                        },
                        differences: {
                          type: 'array',
                          description: '存在差异时的分组结果，一致时为空数组',
                          items: {
                            type: 'object',
                            properties: {
                              records: { type: 'array', items: { type: 'string' } },
                              resolvers: { type: 'array', items: { type: 'string' } },
                            },
                          },
                        },
                        note: { type: 'string' },
                        checkedAt: { type: 'string', format: 'date-time' },
                        cached: { type: 'boolean' },
                        ttlMs: { type: 'integer' },
                      },
                    },
                    meta: { $ref: '#/components/schemas/Meta' },
                  },
                },
                example: {
                  success: true,
                  data: {
                    domain: 'example.com',
                    type: 'A',
                    consistent: true,
                    successful: 4,
                    failed: 0,
                    resolvers: [
                      { id: 'alidns', name: '阿里 DNS', address: '223.5.5.5', status: 'ok', records: ['93.184.216.34'], durationMs: 32, error: null },
                      { id: 'dnspod', name: 'DNSPod', address: '119.29.29.29', status: 'ok', records: ['93.184.216.34'], durationMs: 28, error: null },
                      { id: 'cloudflare', name: 'Cloudflare', address: '1.1.1.1', status: 'ok', records: ['93.184.216.34'], durationMs: 61, error: null },
                      { id: 'google', name: 'Google DNS', address: '8.8.8.8', status: 'ok', records: ['93.184.216.34'], durationMs: 74, error: null },
                    ],
                    groups: [
                      { records: ['93.184.216.34'], resolvers: ['阿里 DNS', 'DNSPod', 'Cloudflare', 'Google DNS'] },
                    ],
                    differences: [],
                    note: '对比结果由本站直接向多个公共递归 DNS 发起查询后计算。',
                    checkedAt: '2026-11-21T08:00:00.000Z',
                    cached: false,
                    ttlMs: 60000,
                  },
                  meta: { source: 'dns-propagation', cached: false },
                },
              },
            },
          },
          '400': { description: '域名或记录类型不合法' },
        },
      },
    },
    '/v1/health/{domain}': {
      get: {
        tags: ['Health'],
        operationId: 'checkDomainHealth',
        summary: '域名健康评分',
        description:
          '把注册信息、DNS 解析、HTTPS 证书、邮件安全四个维度各 25 分的自建检测结果汇总为 0-100 分，输出 A+ 至 E 等级、每个维度的检查项与可执行的改进建议。任一上游暂时不可用时按维度降级，不会整体失败。可用 dimensions 参数只评估部分维度，减少上游请求并按所选维度归一化评分。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'domain',
            in: 'path',
            required: true,
            description: '域名',
            schema: { type: 'string', example: 'example.com' },
          },
          {
            name: 'refresh',
            in: 'query',
            required: false,
            description: '传 1 强制重新评分并绕过缓存',
            schema: { type: 'boolean', default: false },
          },
          {
            name: 'dimensions',
            in: 'query',
            required: false,
            description:
              '只评估指定维度，逗号分隔：registration、dns、tls、mail。仅评估所选维度，未选维度不发起上游请求，分数按所选维度归一化为 0-100。',
            schema: {
              type: 'string',
              example: 'dns,tls',
              maxLength: 80,
            },
          },
        ],
        responses: {
          '200': {
            description: '健康评分与维度明细',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { const: true },
                    data: {
                      type: 'object',
                      properties: {
                        domain: { type: 'string' },
                        score: { type: 'integer', minimum: 0, maximum: 100 },
                        grade: { type: 'string', example: 'A' },
                        summary: { type: 'string' },
                        dimensions: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              key: { type: 'string', enum: ['registration', 'dns', 'tls', 'mail'] },
                              label: { type: 'string' },
                              score: { type: 'integer' },
                              max: { type: 'integer', example: 25 },
                              status: { type: 'string', enum: ['pass', 'warn', 'fail', 'info'] },
                              checks: {
                                type: 'array',
                                items: {
                                  type: 'object',
                                  properties: {
                                    id: { type: 'string' },
                                    label: { type: 'string' },
                                    status: { type: 'string', enum: ['pass', 'warn', 'fail', 'info'] },
                                    detail: { type: 'string' },
                                  },
                                },
                              },
                            },
                          },
                        },
                        issues: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              dimension: { type: 'string' },
                              label: { type: 'string' },
                              status: { type: 'string' },
                              detail: { type: 'string' },
                            },
                          },
                        },
                        checkedAt: { type: 'string', format: 'date-time' },
                        cached: { type: 'boolean' },
                        ttlMs: { type: 'integer' },
                        note: { type: 'string' },
                      },
                    },
                    meta: { $ref: '#/components/schemas/Meta' },
                  },
                },
                example: {
                  success: true,
                  data: {
                    domain: 'example.com',
                    score: 88,
                    grade: 'A',
                    summary: '域名整体状况良好',
                    dimensions: [
                      {
                        key: 'registration',
                        label: '注册与所有权',
                        score: 21,
                        max: 25,
                        status: 'pass',
                        checks: [
                          { id: 'registered', label: '注册状态', status: 'pass', detail: '域名已注册且注册信息可读取' },
                          { id: 'expiry', label: '到期时间', status: 'warn', detail: '域名剩余 60 天，建议提前安排续费' },
                        ],
                      },
                    ],
                    issues: [
                      { dimension: 'mail', label: 'DMARC', status: 'fail', detail: 'DMARC 缺失，域外伪造邮件难以拦截' },
                    ],
                    checkedAt: '2026-11-21T08:00:00.000Z',
                    cached: false,
                    ttlMs: 600000,
                    note: '健康评分由本站自建的注册信息、DNS、TLS 与邮件安全检测结果综合计算。',
                  },
                  meta: { source: 'health-score', cached: false, score: 88, grade: 'A' },
                },
              },
            },
          },
          '400': { description: '域名格式不合法' },
        },
      },
    },
    '/v1/available': {
      get: {
        tags: ['Availability'],
        operationId: 'checkDomainsAvailability',
        summary: '批量检测域名是否可注册',
        description:
          '一次最多检测 10 个域名，逐个优先查询注册局 RDAP，未覆盖时回退 WHOIS 43，返回每个域名的可注册状态、注册商、注册与到期时间。结果按域名缓存，可注册状态缓存较短，避免给出过期结论。也支持 /v1/available/{domains} 路径形式。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'domains',
            in: 'query',
            required: true,
            description: '域名列表，逗号、分号或空格分隔，最多 10 个',
            schema: { type: 'string', example: 'example.com,example.net' },
          },
        ],
        responses: {
          '200': {
            description: '批量检测结果',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { const: true },
                    data: {
                      type: 'object',
                      properties: {
                        total: { type: 'integer' },
                        available: { type: 'integer' },
                        registered: { type: 'integer' },
                        unknown: { type: 'integer' },
                        truncated: { type: 'integer', description: '超出上限被忽略的域名数量' },
                        durationMs: { type: 'integer' },
                        items: {
                          type: 'array',
                          items: {
                            type: 'object',
                            properties: {
                              domain: { type: 'string' },
                              status: { type: 'string', enum: ['available', 'registered', 'unknown'] },
                              registrar: { type: ['string', 'null'] },
                              expires: { type: ['string', 'null'] },
                              created: { type: ['string', 'null'] },
                              source: { type: ['string', 'null'], enum: ['rdap', 'whois', null] },
                              durationMs: { type: 'integer' },
                              error: { type: ['string', 'null'] },
                            },
                          },
                        },
                        note: { type: 'string' },
                        checkedAt: { type: 'string', format: 'date-time' },
                        cached: { type: 'boolean' },
                        ttlMs: { type: 'integer' },
                      },
                    },
                    meta: { $ref: '#/components/schemas/Meta' },
                  },
                },
                example: {
                  success: true,
                  data: {
                    total: 2,
                    available: 1,
                    registered: 1,
                    unknown: 0,
                    truncated: 0,
                    durationMs: 1420,
                    items: [
                      { domain: 'example.com', status: 'registered', registrar: 'RESERVED-Internet Assigned Numbers Authority', expires: '2026-08-13T04:00:00Z', created: '1995-08-14T04:00:00Z', source: 'rdap', durationMs: 424, error: null },
                      { domain: 'pullwhois-demo-2026.com', status: 'available', registrar: null, expires: null, created: null, source: 'rdap', durationMs: 386, error: null },
                    ],
                    note: '可注册性由本站直接查询注册局 RDAP 或 WHOIS 判断。',
                    checkedAt: '2026-11-21T08:00:00.000Z',
                    cached: false,
                    ttlMs: 600000,
                  },
                  meta: { source: 'availability', total: 2, available: 1 },
                },
              },
            },
          },
          '400': { description: '未提供域名或域名格式不合法' },
        },
      },
    },
    '/v1/icp/{domain}': {
      get: {
        tags: ['ICP'],
        operationId: 'lookupIcpFiling',
        summary: '查询域名 ICP 备案',
        description:
          '查询域名在中国大陆的 ICP 备案信息（网站备案号、主体备案号、主办单位、性质与审核时间）。结果优先来自本站本地持久化缓存（已备案最高 7 天可直接返回），缓存未命中时才回源公开备案数据（实时数据优先，失败时回退离线备份）；传 refresh=true 可强制回源。未查询到记录时 filed=false，不做任何推测补全，最终以工信部备案系统为准。',
        security: [{ ApiKeyAuth: [] }, { BearerAuth: [] }, {}],
        parameters: [
          {
            name: 'domain',
            in: 'path',
            required: true,
            description: '域名、URL 或邮箱中的域名',
            schema: { type: 'string', example: 'qq.com' },
          },
          {
            name: 'refresh',
            in: 'query',
            required: false,
            description: '传 true 时跳过本地缓存，强制回源公开备案数据',
            schema: { type: 'boolean', default: false },
          },
        ],
        responses: {
          '200': {
            description: '备案查询结果（含未备案）',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { const: true },
                    data: { $ref: '#/components/schemas/IcpRecord' },
                    meta: { $ref: '#/components/schemas/Meta' },
                  },
                },
                example: {
                  success: true,
                  data: {
                    domain: 'qq.com',
                    filed: true,
                    icpCode: '粤B2-20090059-5',
                    subjectCode: '粤B2-20090059',
                    unitName: '深圳市腾讯计算机系统有限公司',
                    unitType: '企业',
                    auditDate: '2026-01-15 11:27:48',
                    updatedAt: '2026-11-21 09:11:00',
                    source: 'icp-realtime',
                    stale: false,
                    note: '备案结果由本站缓存并提供，仅在本地缓存未命中或显式刷新时回源公开备案数据；最终以工信部备案系统（beian.miit.gov.cn）为准。',
                  },
                  meta: {
                    source: 'icp',
                    cached: false,
                    durationMs: 842,
                    queriedAt: '2026-11-21T08:00:00.000Z',
                    requestId: 'req-icp',
                    rateLimit: { limit: 120, remaining: 119, reset: 58 },
                  },
                },
              },
            },
          },
          '400': { description: '域名格式不合法' },
          '429': {
            description: '触发本站限流，或备案回源接口公共配额冷却中（details.retryAfterSec 给出建议等待秒数）',
          },
          '502': { description: '回源暂时不可用且本地无缓存，details.attempts 包含每次尝试' },
        },
      },
    },
    '/health': {
      get: {
        tags: ['System'],
        operationId: 'health',
        summary: '健康检查',
        responses: {
          '200': {
            description: '服务正常',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    success: { type: 'boolean', const: true },
                    data: {
                      type: 'object',
                      properties: {
                        status: { type: 'string', example: 'ok' },
                        version: { type: 'string', example: '1.0.0' },
                        uptimeSec: { type: 'integer' },
                        now: { type: 'string', format: 'date-time' },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
} as const;
