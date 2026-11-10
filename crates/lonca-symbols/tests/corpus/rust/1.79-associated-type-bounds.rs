pub fn total<I: Iterator<Item: Into<u64>>>(items: I) -> u64 {
    items.map(Into::into).sum()
}
