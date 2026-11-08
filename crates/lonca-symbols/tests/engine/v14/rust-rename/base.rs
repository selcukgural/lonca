struct Till;

impl Till {
    fn add(&mut self, v: u64) {
        self.total += v;
    }

    fn sum(&self) -> u64 {
        self.total
    }
}
