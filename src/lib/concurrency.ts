/** 以固定并发度执行异步任务，保持输入顺序 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  task: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;

  async function worker(): Promise<void> {
    while (true) {
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      results[index] = await task(items[index] as T, index);
    }
  }

  const workers = Array.from(
    { length: Math.min(Math.max(1, concurrency), items.length) },
    () => worker(),
  );
  await Promise.all(workers);
  return results;
}
