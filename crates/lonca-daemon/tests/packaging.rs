//! The installers' generated Claude Code settings must satisfy Lonca's own
//! inspection (locked hooks + locked sandbox with the proxy port).

use std::path::PathBuf;
use std::process::Command;

fn render(script: &str) -> PathBuf {
    render_with(script, &[])
}

fn render_with(script: &str, extra: &[&str]) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = tempfile::tempdir().unwrap().keep();
    let status = Command::new("/bin/sh")
        .arg(root.join(script))
        .args(["--render", out.to_str().unwrap(), "--dev-uid", "501"])
        .args(["--daemon-uid", "77"])
        .args(extra)
        .status()
        .unwrap();
    assert!(status.success());
    out
}

/// The override reaches the daemon only when the installer was told.
#[test]
fn the_unit_starts_without_a_sandbox_only_when_told() {
    let script = "packaging/linux/install-hardened.sh";
    let unit = |extra: &[&str]| {
        let dir = render_with(script, extra);
        let text = std::fs::read_to_string(dir.join("lonca.service")).unwrap();
        let _ = std::fs::remove_dir_all(dir);
        text
    };
    assert!(!unit(&[]).contains("--allow-unsandboxed"));
    assert!(unit(&["--allow-unsandboxed"]).contains(" --allow-unsandboxed\n"));
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
        let file = dir.join("managed-settings.json");
        let ins = lonca_daemon::hooks::inspect(locked, &file, false, Some(8471));
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

/// Both daemons read the import directory the installer creates, and the
/// developer's bundles reach them nowhere else (#10).
#[test]
fn the_daemon_is_given_the_import_directory() {
    for (script, file, dir) in [
        (
            "packaging/linux/install-hardened.sh",
            "lonca.service",
            "--import-dir /var/lib/lonca-import",
        ),
        (
            "packaging/macos/install-hardened.sh",
            "dev.lonca.daemon.plist",
            "<string>--import-dir</string><string>/Library/Lonca/import</string>",
        ),
    ] {
        let out = render(script);
        let text = std::fs::read_to_string(out.join(file)).unwrap();
        assert!(text.contains(dir), "{script}: {text}");
        assert!(!text.contains("--local-root"), "{script}");
        let _ = std::fs::remove_dir_all(out);
    }
}

/// Run with sudo, a script is root: it finds nothing by a name in the
/// caller's `PATH`, and it installs nothing from files the developer's
/// account (and so an agent) can change.
#[cfg(unix)]
#[test]
fn the_installers_take_nothing_from_the_callers_account() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for os in ["macos", "linux"] {
        for name in ["install-hardened.sh", "uninstall-hardened.sh"] {
            let script = root.join("packaging").join(os).join(name);
            let text = std::fs::read_to_string(&script).unwrap();
            let code: Vec<&str> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            assert_eq!(
                code[..3],
                [
                    "set -eu",
                    "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                    "export PATH"
                ],
                "{os}/{name}: the first thing it does"
            );
        }
    }

    // This platform's installer, asked about this checkout: the developer's.
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let script = root.join("packaging").join(os).join("install-hardened.sh");
    let empty = tempfile::tempdir().unwrap();
    let out = Command::new("/bin/sh")
        .arg(&script)
        .arg("--check-source")
        .args(["--bin", empty.path().to_str().unwrap()])
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{said}");
    assert!(said.contains("not root's alone"), "{said}");
    assert!(said.contains("install-hardened.sh\n"), "{said}");

    // The rule itself, on a file of the system's and on one of ours.
    let text = std::fs::read_to_string(&script).unwrap();
    let start = text.find("roots_alone() {").unwrap();
    let end = start + text[start..].find("\n}\n").unwrap() + 3;
    let rule = &text[start..end];
    let alone = |path: &std::path::Path| {
        let path = path.canonicalize().unwrap();
        Command::new("/bin/sh")
            .args(["-c", &format!("{rule}\nroots_alone \"$1\""), "sh"])
            .arg(path)
            .status()
            .unwrap()
            .success()
    };
    assert!(alone(std::path::Path::new("/usr/bin/env")));
    let mine = empty.path().join("lonca");
    std::fs::write(&mine, "x").unwrap();
    assert!(!alone(&mine));
    assert!(!alone(empty.path()));
}
