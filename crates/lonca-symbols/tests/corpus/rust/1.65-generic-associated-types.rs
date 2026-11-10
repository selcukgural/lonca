pub trait Lending {
    type Item<'a>
    where
        Self: 'a;
    fn next<'a>(&'a mut self) -> Option<Self::Item<'a>>;
}
