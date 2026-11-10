pub trait Fetch {
    async fn fetch(&self, url: &str) -> Vec<u8>;
    fn names(&self) -> impl Iterator<Item = String>;
}
