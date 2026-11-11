pub struct Ledger {
    entries: Vec<u64>,
}

impl Ledger {
    /// Adds up what is due.
    pub fn total(&self, fee: u64) -> u64 {
        let mut sum = 0u64;
        for e in &self.entries {
            sum += e;
        }
        let fee = fee;
        fee + sum
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }
}
