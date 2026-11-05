import { readFileSync } from "fs";
import { join } from "path";

export function charge(amount: number): number {
  return amount;
}

export function sig(a: number, b: number): number {
  return a + b;
}

export function added(): string {
  return join("a", "b");
}

export class Ledger {
  private entries = new Map<string, number>();

  add(k: string, v: number): void {
    if (!this.entries.has(k)) this.entries.set(k, v);
  }

  total(): number {
    let t = 0;
    for (const v of this.entries.values()) t += v;
    return t;
  }
}

export const rate = (x: number): number => x * 0.5;

describe("charge", () => {
  it.skip("charges", () => {
    expect(charge(2)).toBe(2);
  });
});
