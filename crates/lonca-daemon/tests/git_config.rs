//! The daemon's git child does not take the caller's git configuration
//! (issue #57). A test binary with one test: it changes the process
//! environment, which every test in a binary shares.

mod common;
use common::*;

fn upstream(root: &Path, name: &str, text: &str) -> PathBuf {
    let up = root.join(name);
    std::fs::create_dir_all(&up).unwrap();
    git(&up, &["init", "-q", "-b", "main"]);
    git(&up, &["config", "user.email", "t@t"]);
    git(&up, &["config", "user.name", "t"]);
    std::fs::write(up.join("README.md"), text).unwrap();
    git(&up, &["add", "."]);
    git(&up, &["commit", "-q", "-m", text]);
    up
}

/// A global `url.<x>.insteadOf`, given to the daemon's process the ways git
/// reads it (the global file and `GIT_CONFIG_*`), does not change where the
/// daemon fetches from.
#[test]
#[allow(
    unsafe_code,
    reason = "the test sets the environment a git child would inherit"
)]
fn the_callers_git_config_does_not_steer_a_fetch() {
    let mut e = Env::new();
    let real = upstream(&e.root, "real", "real\n");
    let evil = upstream(&e.root, "evil", "evil\n");
    let config = e.root.join("evil.gitconfig");
    let rewrite = format!(
        "[url \"{}\"]\n\tinsteadOf = {}\n",
        evil.display(),
        real.display()
    );
    std::fs::write(&config, rewrite).unwrap();
    let user_home = e.root.join("user");
    std::fs::create_dir_all(&user_home).unwrap();
    std::fs::copy(&config, user_home.join(".gitconfig")).unwrap();
    // SAFETY: this binary runs this one test.
    unsafe {
        std::env::set_var("HOME", &user_home);
        std::env::set_var("GIT_CONFIG_GLOBAL", &config);
        std::env::set_var("GIT_CONFIG_COUNT", "1");
        std::env::set_var(
            "GIT_CONFIG_KEY_0",
            format!("url.{}.insteadOf", evil.display()),
        );
        std::env::set_var("GIT_CONFIG_VALUE_0", real.display().to_string());
    }
    // The rewrite works on a git that inherits the environment.
    let probe = std::process::Command::new("git")
        .args(["ls-remote", real.to_str().unwrap(), "HEAD"])
        .output()
        .unwrap();
    let evil_head = git(&evil, &["rev-parse", "HEAD"]);
    assert!(String::from_utf8_lossy(&probe.stdout).contains(&evil_head));

    e.init(Some(real.to_str().unwrap()));
    assert_eq!(e.trunk().0, git(&real, &["rev-parse", "HEAD"]));
}
