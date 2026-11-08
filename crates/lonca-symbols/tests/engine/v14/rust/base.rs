use std::collections::BTreeMap;

/// Charges an amount.
pub fn charge(amount: u64) -> u64 {
    amount
}

pub fn gone() {}

pub fn sig(a: u32) -> u32 {
    a + 1
}

pub struct Ledger {
    entries: BTreeMap<String, u64>,
}

impl Ledger {
    pub fn add(&mut self, k: &str, v: u64) {
        self.entries.insert(k.into(), v);
    }

    pub fn total(&self) -> u64 {
        self.entries.values().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charges() {
        assert_eq!(charge(2), 2);
    }
}
