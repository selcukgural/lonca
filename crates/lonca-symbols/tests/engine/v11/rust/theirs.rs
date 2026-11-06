use std::collections::BTreeMap;
use std::fmt::Write;

/// Charges an amount.
pub fn charge(amount: u64) -> u64 {
    amount
}

pub fn sig(a: u32, b: u32) -> u32 {
    a + b
}

pub fn added() -> String {
    let mut s = String::new();
    write!(s, "x").unwrap();
    s
}

pub struct Ledger {
    entries: BTreeMap<String, u64>,
}

impl Ledger {
    pub fn add(&mut self, k: &str, v: u64) {
        self.entries.entry(k.into()).or_insert(v);
    }

    pub fn total(&self) -> u64 {
        self.entries.values().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn charges() {
        assert_eq!(charge(2), 2);
    }
}
