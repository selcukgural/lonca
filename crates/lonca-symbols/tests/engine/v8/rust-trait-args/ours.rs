pub struct Id(u64);

impl From<u8> for Id {
    fn from(v: u8) -> Id {
        Id(v as u64)
    }
}

impl From<u32> for Id {
    fn from(v: u32) -> Id {
        Id(v as u64)
    }
}
