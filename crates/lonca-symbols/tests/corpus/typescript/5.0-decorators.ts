function logged<This, Args extends unknown[], R>(
  target: (this: This, ...args: Args) => R,
  _context: ClassMethodDecoratorContext<This, (this: This, ...args: Args) => R>,
) {
  return target;
}

export class Service {
  @logged
  run(x: number): number {
    return x;
  }
}
