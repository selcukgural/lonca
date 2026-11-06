fn show(s: &[lonca_symbols::Sym], d: usize) {
    for x in s {
        println!(
            "{}{}{}{}{} sig={:?} def={:?}",
            "  ".repeat(d),
            x.name,
            if x.container { " [c]" } else { "" },
            if x.is_test { " [test]" } else { "" },
            if x.skipped { " [skip]" } else { "" },
            x.signature,
            x.def_of
        );
        show(&x.children, d + 1);
    }
}
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let src = std::fs::read_to_string(&a[1]).unwrap();
    let lang = lonca_symbols::Lang::detect(&a[1]).unwrap();
    let [p] =
        lonca_symbols::parse_together(lonca_symbols::engine::ENGINE_CURRENT, lang, [src.as_str()]);
    println!(
        "--- {lang:?} error={} imports={} js_tests={:?}",
        p.has_error,
        p.imports.len(),
        p.js_tests
            .iter()
            .map(|t| (&t.name, t.skipped))
            .collect::<Vec<_>>()
    );
    show(&p.syms, 0);
}
