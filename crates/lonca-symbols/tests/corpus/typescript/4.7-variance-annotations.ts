interface Source<out T> {
  get(): T;
}

interface Sink<in T> {
  put(value: T): void;
}

export function pipe<T>(from: Source<T>, to: Sink<T>): void {
  to.put(from.get());
}
