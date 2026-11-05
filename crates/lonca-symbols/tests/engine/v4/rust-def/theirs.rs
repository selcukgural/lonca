pub struct Ledger {
    entries: u64,
    closed: bool,
}

#[cfg(unix)]
impl Ledger {
    pub fn total(&self) -> u64 {
        self.entries
    }

    pub fn reset(&mut self) {
        self.entries = 1;
    }
}

impl From<u64> for Ledger {
    fn from(entries: u64) -> Self {
        Ledger { entries }
    }
}
