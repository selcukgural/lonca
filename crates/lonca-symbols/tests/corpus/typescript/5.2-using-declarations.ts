class Lock implements Disposable {
  [Symbol.dispose](): void {}
}

export async function guarded(open: () => AsyncDisposable): Promise<number> {
  using lock = new Lock();
  await using file = open();
  return 1;
}
