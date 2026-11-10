export function tuple<const T extends readonly unknown[]>(items: T): T {
  return items;
}
