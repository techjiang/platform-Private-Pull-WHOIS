import { UpstreamTimeoutError } from './errors.js';

export interface HttpResult {
  status: number;
  headers: Headers;
  text: string;
  durationMs: number;
}

export interface HttpOptions {
  timeoutMs: number;
  headers?: Record<string, string>;
  maxBytes?: number;
}

const DEFAULT_UA =
  'PullWhois/1.0 (+https://github.com/pull-whois/pull-whois; domain lookup API)';

/** 带超时与体积保护的 GET 请求 */
export async function httpGet(url: string, options: HttpOptions): Promise<HttpResult> {
  const startedAt = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs);

  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'user-agent': DEFAULT_UA,
        accept: 'application/json, application/rdap+json, text/plain, */*',
        ...options.headers,
      },
    });

    const maxBytes = options.maxBytes ?? 2 * 1024 * 1024;
    const reader = response.body?.getReader();
    let text = '';

    if (reader) {
      const decoder = new TextDecoder();
      let received = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          received += value.byteLength;
          if (received > maxBytes) {
            await reader.cancel();
            break;
          }
          text += decoder.decode(value, { stream: true });
        }
      }
      text += decoder.decode();
    } else {
      text = await response.text();
    }

    return {
      status: response.status,
      headers: response.headers,
      text,
      durationMs: Date.now() - startedAt,
    };
  } catch (error) {
    if (error instanceof Error && (error.name === 'AbortError' || error.name === 'TimeoutError')) {
      throw new UpstreamTimeoutError(url);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export function parseJson<T>(text: string): T | null {
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
