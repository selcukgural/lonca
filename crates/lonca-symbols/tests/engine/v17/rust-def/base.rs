pub struct Ledger {
    entries: u64,
}

impl Ledger {
    pub fn total(&self) -> u64 {
        self.entries
    }

    pub fn reset(&mut self) {
        self.entries = 0;
    }
}

impl From<u64> for Ledger {
    fn from(entries: u64) -> Self {
        Ledger { entries }
    }
}
