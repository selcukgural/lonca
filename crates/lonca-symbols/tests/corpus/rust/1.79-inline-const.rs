pub fn zeros<const N: usize>() -> [Vec<u8>; N] {
    [const { Vec::new() }; N]
}
