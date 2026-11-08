export class Box {
  size: number;

  get value() {
    return this.size * 2;
  }
}

function pick(a: string): string {
  return a.trim();
}
