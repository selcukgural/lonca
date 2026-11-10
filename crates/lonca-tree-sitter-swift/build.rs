//! Compiles the grammar's generated parser and its external scanner, as the
//! upstream crate does.

fn main() {
    let src = std::path::Path::new("src");
    let mut c = cc::Build::new();
    c.std("c11")
        .include(src)
        .flag_if_supported("-Wno-unused-value")
        .file(src.join("parser.c"))
        .file(src.join("scanner.c"));
    #[cfg(target_env = "msvc")]
    c.flag("-utf-8");
    println!("cargo:rerun-if-changed=src/parser.c");
    println!("cargo:rerun-if-changed=src/scanner.c");
    c.compile("lonca-tree-sitter-swift");
}
