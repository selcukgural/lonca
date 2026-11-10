export class Counter {
  count = 0;
  static instances = 0;
  #step = 1;

  next() {
    this.count += this.#step;
    return this.count;
  }
}
