export class Till {
  deposit(v: number) {
    this.total += v;
  }

  sum() {
    return this.total;
  }
}
