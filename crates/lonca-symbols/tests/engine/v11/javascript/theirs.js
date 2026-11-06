import { readFileSync } from "fs";
import { join } from "path";

export function charge(amount) {
  return amount;
}

export function sig(a, b) {
  return a + b;
}

export function added() {
  return join("a", "b");
}

export class Ledger {
  constructor() {
    this.entries = new Map();
  }

  add(k, v) {
    if (!this.entries.has(k)) this.entries.set(k, v);
  }
}

test.skip("charges", () => {
  expect(charge(2)).toBe(2);
});
