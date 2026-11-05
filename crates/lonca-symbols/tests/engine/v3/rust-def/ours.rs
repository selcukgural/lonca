pub struct Ledger {
    entries: u64,
}

impl Ledger {
    pub fn total(&self) -> u64 {
        self.entries + 0
    }

    pub fn reset(&mut self) {
        self.entries = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }
}

impl From<u64> for Ledger {
    fn from(entries: u64) -> Self {
        Ledger { entries: entries }
    }
}
