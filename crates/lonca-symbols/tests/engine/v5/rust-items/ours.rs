//! Crate docs.

use std::fmt;

// Section.

extern "C" {
    fn f(a: u16);
    static X: u8;
}

thread_local! { static A: u8 = 1; }

m!(c);
m!(b);

fn g() {}
