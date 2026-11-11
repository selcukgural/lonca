//! On Linux, links `c/wctype.c` whole: its `iswspace` and the like are the
//! ones the grammars' scanners get, in place of the C library's, so a parse
//! does not depend on which C library a build has (musl knows Unicode, glibc
//! and macOS in the C locale know ASCII). Whole, because a linker that reads
//! its archives once would otherwise have passed these by before a scanner
//! asked for them.
//!
//! macOS needs none of it: its `<wctype.h>` compiles the classes into the
//! scanner as a look-up in the current locale, which is the C locale as long
//! as nothing in the process calls `setlocale`, and nothing does.

fn main() {
    println!("cargo:rerun-if-changed=c/wctype.c");
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    let mut c = cc::Build::new();
    c.std("c11").file("c/wctype.c").cargo_metadata(false);
    c.compile("lonca_wctype");
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    println!("cargo:rustc-link-search=native={out}");
    println!("cargo:rustc-link-lib=static:+whole-archive=lonca_wctype");
}
