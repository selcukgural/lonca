pub fn evens<'a, T>(items: &'a [T], _scratch: &mut Vec<u8>) -> impl Iterator<Item = &'a T> + use<'a, T> {
    items.iter().step_by(2)
}
