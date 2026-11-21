import { randomBytes } from 'node:crypto';

export const ADMIN_COOKIE = 'pw_admin';

/** 管理后台会话（内存实现，重启后需重新登录） */
export class AdminSessions {
  private readonly sessions = new Map<string, number>();
  private readonly timer: NodeJS.Timeout;

  constructor(private readonly ttlMs: number) {
    this.timer = setInterval(() => this.sweep(), Math.min(ttlMs, 10 * 60 * 1000));
    this.timer.unref();
  }

  get ttlSeconds(): number {
    return Math.max(1, Math.round(this.ttlMs / 1000));
  }

  create(): string {
    const token = randomBytes(32).toString('base64url');
    this.sessions.set(token, Date.now() + this.ttlMs);
    return token;
  }

  has(token: string | null | undefined): boolean {
    if (!token) return false;
    const expiresAt = this.sessions.get(token);
    if (!expiresAt) return false;
    if (expiresAt <= Date.now()) {
      this.sessions.delete(token);
      return false;
    }
    return true;
  }

  destroy(token: string | null | undefined): void {
    if (token) this.sessions.delete(token);
  }

  /** 使全部会话失效（修改账号密码后调用） */
  destroyAll(): void {
    this.sessions.clear();
  }

  private sweep(): void {
    const now = Date.now();
    for (const [token, expiresAt] of this.sessions) {
      if (expiresAt <= now) this.sessions.delete(token);
    }
  }
}

export function parseCookie(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    if (part.slice(0, index).trim() !== name) continue;
    const value = part.slice(index + 1).trim();
    return value ? decodeURIComponent(value) : null;
  }
  return null;
}

export function sessionCookie(token: string, ttlSeconds: number, secure: boolean): string {
  const flags = ['Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${ttlSeconds}`];
  if (secure) flags.push('Secure');
  return `${ADMIN_COOKIE}=${encodeURIComponent(token)}; ${flags.join('; ')}`;
}

export function clearedSessionCookie(secure: boolean): string {
  const flags = ['Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0'];
  if (secure) flags.push('Secure');
  return `${ADMIN_COOKIE}=; ${flags.join('; ')}`;
}
