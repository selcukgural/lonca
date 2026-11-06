pub struct Id(u64);

impl From<u32> for Id {
    fn from(v: u32) -> Id {
        Id(u64::from(v))
    }
}
