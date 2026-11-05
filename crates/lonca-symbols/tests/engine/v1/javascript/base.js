import { readFileSync } from "fs";

export function charge(amount) {
  return amount;
}

export function gone() {}

export function sig(a) {
  return a + 1;
}

export class Ledger {
  constructor() {
    this.entries = new Map();
  }

  add(k, v) {
    this.entries.set(k, v);
  }
}

test("charges", () => {
  expect(charge(2)).toBe(2);
});
