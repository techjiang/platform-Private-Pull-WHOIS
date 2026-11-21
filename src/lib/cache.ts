interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

export interface CacheHit<T> {
  value: T;
  ttlMs: number;
}

/** 记录所有缓存实例，供智能调度在空闲时统一清理过期条目 */
const registry = new Set<WeakRef<TtlCache<unknown>>>();

/** 带 TTL 与 LRU 淘汰的内存缓存 */
export class TtlCache<T> {
  private readonly map = new Map<string, CacheEntry<T>>();
  private readonly maxEntries: number;

  constructor(maxEntries: number) {
    this.maxEntries = maxEntries;
    registry.add(new WeakRef(this as unknown as TtlCache<unknown>));
  }

  get(key: string): CacheHit<T> | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= Date.now()) {
      this.map.delete(key);
      return undefined;
    }
    // 重新插入以维持 LRU 顺序
    this.map.delete(key);
    this.map.set(key, entry);
    return { value: entry.value, ttlMs: entry.expiresAt - Date.now() };
  }

  set(key: string, value: T, ttlMs: number): void {
    if (ttlMs <= 0) return;
    this.map.delete(key);
    this.map.set(key, { value, expiresAt: Date.now() + ttlMs });

    if (this.map.size > this.maxEntries) {
      // 容量满时先清掉已过期条目，避免长期运行后缓存只增不减
      const now = Date.now();
      for (const [itemKey, entry] of this.map) {
        if (entry.expiresAt <= now) this.map.delete(itemKey);
      }
    }

    while (this.map.size > this.maxEntries) {
      const oldest = this.map.keys().next();
      if (oldest.done) break;
      this.map.delete(oldest.value);
    }
  }

  delete(key: string): void {
    this.map.delete(key);
  }

  clear(): void {
    this.map.clear();
  }

  /** 清理已过期条目，返回清理数量 */
  prune(): number {
    const now = Date.now();
    let removed = 0;
    for (const [key, entry] of this.map) {
      if (entry.expiresAt <= now) {
        this.map.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  get size(): number {
    return this.map.size;
  }
}

/** 清理全部缓存中的过期条目（供后台调度使用） */
export function pruneAllCaches(): { entries: number; removed: number } {
  let entries = 0;
  let removed = 0;
  for (const ref of registry) {
    const cache = ref.deref();
    if (!cache) {
      registry.delete(ref);
      continue;
    }
    entries += cache.size;
    removed += cache.prune();
  }
  return { entries, removed };
}
