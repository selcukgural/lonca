//! What each built-in harness gets from `lonca harness setup`, byte for byte.
//! A harness that moves on changes its fixture here, on purpose. Regenerate
//! with `LONCA_GOLDEN_OUT=1 cargo test -p lonca-policy --test harness_setup`.

use std::path::PathBuf;

use lonca_policy::harness::built_in;

#[test]
fn every_built_in_harness_gets_the_files_and_flags_of_its_fixture() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/harness-setup");
    assert_eq!(
        built_in().len(),
        4,
        "a new built-in harness needs a fixture"
    );
    for (name, profile) in built_in() {
        let filled = profile.setup.fill("RULES", "/s/lonca.sock", "/w").unwrap();
        let got = serde_json::to_string_pretty(&filled).unwrap();
        let path = dir.join(format!("{name}.json"));
        if std::env::var_os("LONCA_GOLDEN_OUT").is_some() {
            std::fs::write(&path, &got).unwrap();
        }
        let want = std::fs::read_to_string(&path).unwrap();
        assert_eq!(got, want, "{name}");
    }
}
