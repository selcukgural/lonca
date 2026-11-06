export class Ledger {
  entries = 0;

  total(): number {
    return this.entries;
  }

  reset(): void {
    this.entries = 0;
  }
}

export interface Row {
  id: number;
}
