unsafe extern "C" {
    pub safe fn abs(x: i32) -> i32;
    pub unsafe fn strlen(s: *const std::ffi::c_char) -> usize;
}

pub fn magnitude(x: i32) -> i32 {
    abs(x)
}
