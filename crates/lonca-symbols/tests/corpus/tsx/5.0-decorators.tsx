function tagged<T extends new (...args: any[]) => object>(target: T, _context: ClassDecoratorContext<T>) {
  return target;
}

@tagged
export class Panel {
  render() {
    return <section />;
  }
}
