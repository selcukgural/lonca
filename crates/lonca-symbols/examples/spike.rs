use tree_sitter::{Language, Node, Parser};
fn grammar(n: &str) -> Language {
    match n {
        "java" => tree_sitter_java::LANGUAGE.into(),
        "kotlin" => tree_sitter_kotlin_ng::LANGUAGE.into(),
        "c" => tree_sitter_c::LANGUAGE.into(),
        "cpp" => tree_sitter_cpp::LANGUAGE.into(),
        "ruby" => tree_sitter_ruby::LANGUAGE.into(),
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "swift" => tree_sitter_swift::LANGUAGE.into(),
        _ => panic!(),
    }
}
fn show(n: Node, src: &str, depth: usize, field: Option<&str>) {
    if depth > 6 {
        return;
    }
    let t = &src[n.start_byte()..n.end_byte()];
    let t: String = t
        .chars()
        .take(32)
        .map(|c| if c == '\n' { ' ' } else { c })
        .collect();
    println!(
        "{}{}{} «{}»",
        "  ".repeat(depth),
        field.map(|f| format!("{f}: ")).unwrap_or_default(),
        n.kind(),
        t
    );
    let mut c = n.walk();
    let kids: Vec<_> = n.children(&mut c).collect();
    for (i, k) in kids.iter().enumerate() {
        if k.is_named() {
            show(*k, src, depth + 1, n.field_name_for_child(i as u32));
        }
    }
}
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let src = std::fs::read_to_string(&a[2]).unwrap();
    let g = grammar(&a[1]);
    println!("abi {}", g.abi_version());
    let mut p = Parser::new();
    p.set_language(&g).unwrap();
    let t = p.parse(&src, None).unwrap();
    println!("error: {}", t.root_node().has_error());
    show(t.root_node(), &src, 0, None);
}
