export class Ledger extends Base {
  entries = 0;

  total(): number {
    return this.entries;
  }

  reset(): void {
    this.entries = 1;
  }
}

export interface Row {
  id: number;
  name: string;
}
