type FirstString<T> = T extends [infer S extends string, ...unknown[]] ? S : never;

export function first<T extends unknown[]>(items: T): FirstString<T> {
  return items[0] as FirstString<T>;
}
