export class Till {
  add(v: number) {
    this.total += v;
  }

  sum() {
    return this.total * 2;
  }
}
