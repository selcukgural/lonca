//! The installers' generated Claude Code settings must satisfy Lonca's own
//! inspection (locked hooks + locked sandbox with the proxy port).

use std::path::PathBuf;
use std::process::Command;

fn render(script: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = tempfile::tempdir().unwrap().keep();
    let status = Command::new("/bin/sh")
        .arg(root.join(script))
        .args(["--render", out.to_str().unwrap(), "--dev-uid", "501"])
        .args(["--daemon-uid", "77"])
        .status()
        .unwrap();
    assert!(status.success());
    out
}

#[test]
fn installer_settings_pass_inspection() {
    for script in [
        "packaging/macos/install-hardened.sh",
        "packaging/linux/install-hardened.sh",
    ] {
        let dir = render(script);
        let profile = &lonca_policy::harness::built_in()["claude-code"];
        let locked = profile.locked.as_ref().unwrap();
        let ins = lonca_daemon::hooks::inspect(locked, &dir.join("managed-settings.json"), false);
        assert!(ins.managed_hooks, "{script}: {:?}", ins.notes);
        assert!(ins.locked_sandbox, "{script}: {:?}", ins.notes);
        assert!(ins.hook_binary_protected, "{script}: {:?}", ins.notes);
        let text = std::fs::read_to_string(dir.join("managed-settings.json")).unwrap();
        assert!(
            text.contains("\"httpProxyPort\": 8471"),
            "proxy port matches the daemon default"
        );
        let config = std::fs::read_to_string(dir.join("daemon.toml")).unwrap();
        assert_eq!(
            lonca_daemon::trust::parse_config(&config),
            Some(77),
            "{script}: clients read what the installer writes"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
