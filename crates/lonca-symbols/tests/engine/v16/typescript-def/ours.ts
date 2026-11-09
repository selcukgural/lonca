export class Ledger {
  entries = 0;

  total(): number {
    return this.entries + 0;
  }

  reset(): void {
    this.entries = 0;
  }

  empty(): boolean {
    return this.entries === 0;
  }
}

export interface Row {
  id: number;
}
