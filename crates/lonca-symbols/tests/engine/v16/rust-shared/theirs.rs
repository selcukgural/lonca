pub struct Ledger {
    entries: Vec<u64>,
}

impl Ledger {
    /// Adds up what is due.
    pub fn total(&self, fee: u64) -> u64 {
        let mut sum = 0;
        for e in &self.entries {
            sum += e;
        }
        let fee = fee.min(100);
        sum + fee
    }

    pub fn count(&self) -> usize {
        self.entries.iter().count()
    }
}
