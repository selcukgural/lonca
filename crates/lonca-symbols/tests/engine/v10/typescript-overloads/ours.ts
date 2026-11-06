export class Box {
  size: number;
  label: string;

  get value() {
    return this.size;
  }

  set value(v: number) {
    this.size = v;
  }
}

function pick(a: number): number;
function pick(a: string): string;
function pick(a: any): any {
  return a;
}
