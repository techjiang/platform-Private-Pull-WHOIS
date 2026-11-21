export type ErrorCode =
  | 'INVALID_DOMAIN'
  | 'BAD_REQUEST'
  | 'UNAUTHORIZED'
  | 'NOT_FOUND'
  | 'RATE_LIMITED'
  | 'UPSTREAM_UNAVAILABLE'
  | 'UPSTREAM_TIMEOUT'
  | 'INTERNAL'
  | 'UNSUPPORTED_MEDIA_TYPE'
  | 'ADMIN_DISABLED'
  | 'WEB_DISABLED'
  | 'WEB_QUOTA_EXCEEDED'
  | 'FEATURE_DISABLED'
  | 'KEY_DISABLED'
  | 'KEY_EXPIRED'
  | 'KEY_QUOTA_EXCEEDED'
  | 'KEY_SCOPE_DENIED'
  | 'KEY_IP_DENIED';

export interface ApiErrorBody {
  success: false;
  error: {
    code: ErrorCode;
    message: string;
    details?: unknown;
  };
}

export class ApiError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: ErrorCode,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }

  toJSON(): ApiErrorBody {
    return {
      success: false,
      error: {
        code: this.code,
        message: this.message,
        ...(this.details === undefined ? {} : { details: this.details }),
      },
    };
  }

  static invalidDomain(message: string): ApiError {
    return new ApiError(400, 'INVALID_DOMAIN', message);
  }

  static badRequest(message: string, details?: unknown): ApiError {
    return new ApiError(400, 'BAD_REQUEST', message, details);
  }

  static unauthorized(message = '缺少或无效的 API Key'): ApiError {
    return new ApiError(401, 'UNAUTHORIZED', message);
  }

  static notFound(message = '资源不存在'): ApiError {
    return new ApiError(404, 'NOT_FOUND', message);
  }

  static rateLimited(retryAfterSec: number): ApiError {
    return new ApiError(429, 'RATE_LIMITED', '请求过于频繁，请稍后再试', {
      retryAfterSec,
    });
  }

  static upstream(message: string, details?: unknown): ApiError {
    return new ApiError(502, 'UPSTREAM_UNAVAILABLE', message, details);
  }

  static timeout(message = '上游查询超时'): ApiError {
    return new ApiError(504, 'UPSTREAM_TIMEOUT', message);
  }

  static internal(message = '服务内部错误'): ApiError {
    return new ApiError(500, 'INTERNAL', message);
  }

  static adminDisabled(message = '管理后台未启用，请先配置 ADMIN_PASSWORD'): ApiError {
    return new ApiError(503, 'ADMIN_DISABLED', message);
  }

  static webDisabled(message = '网页端查询已关闭，请通过 API 调用'): ApiError {
    return new ApiError(503, 'WEB_DISABLED', message);
  }

  static featureDisabled(feature: string): ApiError {
    return new ApiError(503, 'FEATURE_DISABLED', `功能「${feature}」已被管理员关闭`);
  }

  /** 将密钥风控结果转换为具体错误 */
  static keyIssue(issue: string, tool?: string | null): ApiError {
    switch (issue) {
      case 'KEY_DISABLED':
        return new ApiError(401, 'KEY_DISABLED', '该 API Key 已被停用');
      case 'KEY_EXPIRED':
        return new ApiError(401, 'KEY_EXPIRED', '该 API Key 已过期');
      case 'KEY_QUOTA_EXCEEDED':
        return new ApiError(403, 'KEY_QUOTA_EXCEEDED', '该 API Key 已达到调用配额上限');
      case 'KEY_SCOPE_DENIED':
        return new ApiError(
          403,
          'KEY_SCOPE_DENIED',
          tool ? `该 API Key 无权访问「${tool}」接口` : '该 API Key 无权访问此接口',
          tool ? { tool } : undefined,
        );
      case 'KEY_IP_DENIED':
        return new ApiError(403, 'KEY_IP_DENIED', '当前 IP 不在该 API Key 的白名单内');
      default:
        return new ApiError(401, 'UNAUTHORIZED', 'API Key 无效');
    }
  }
}

export class UpstreamTimeoutError extends Error {
  constructor(
    public readonly target: string,
    message = '上游查询超时',
  ) {
    super(message);
    this.name = 'UpstreamTimeoutError';
  }
}
