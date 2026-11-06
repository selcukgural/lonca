import { readFileSync } from "fs";

export function charge(amount: number): number {
  return amount;
}

export function gone(): void {}

export function sig(a: number): number {
  return a + 1;
}

export class Ledger {
  private entries = new Map<string, number>();

  add(k: string, v: number): void {
    this.entries.set(k, v);
  }

  total(): number {
    let t = 0;
    for (const v of this.entries.values()) t += v;
    return t;
  }
}

export const rate = (x: number): number => x * 0.5;

describe("charge", () => {
  it("charges", () => {
    expect(charge(2)).toBe(2);
  });
});
