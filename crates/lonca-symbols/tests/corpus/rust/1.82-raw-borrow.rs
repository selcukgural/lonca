#[repr(packed)]
pub struct Packed {
    pub tag: u8,
    pub value: u32,
}

pub fn value_of(p: &Packed) -> u32 {
    let at = &raw const p.value;
    unsafe { at.read_unaligned() }
}
