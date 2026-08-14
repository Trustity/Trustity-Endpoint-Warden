use crate::finding::Finding;
use std::path::Path;

pub fn audit() -> Vec<Finding> {
    #[cfg(windows)]
    {
        windows_permissions()
    }
    #[cfg(unix)]
    {
        unix_permissions()
    }
    #[cfg(not(any(windows, unix)))]
    {
        vec![Finding::info(
            "Permissions",
            "unsupported platform",
            "permission audit is implemented for Windows and Unix",
        )]
    }
}

#[cfg(windows)]
fn windows_permissions() -> Vec<Finding> {
    let mut findings = Vec::new();
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
    let candidates = [
        format!(r"{windir}\System32\config\SAM"),
        format!(r"{windir}\repair\SAM"),
        r"C:\Windows\Temp".to_string(),
    ];
    for p in candidates {
        let path = Path::new(&p);
        if path.exists() {
            findings.push(Finding::info(
                "Permissions",
                format!("present: {p}"),
                "existence check only; use icacls for ACL review",
            ));
        }
    }

    if let Some(home) = std::env::var_os("USERPROFILE") {
        let ssh = Path::new(&home).join(".ssh");
        if ssh.is_dir() {
            findings.push(Finding::info(
                "Permissions",
                format!("SSH directory {}", ssh.display()),
                "ensure private keys are not world-readable (icacls)",
            ));
        }
    }

    findings.push(Finding::pass(
        "Permissions",
        "Windows ACL deep-scan not performed",
        "experimental: flag presence of sensitive paths; elevate + icacls for full ACL audit",
    ));
    findings
}

#[cfg(unix)]
fn unix_permissions() -> Vec<Finding> {
    use std::os::unix::fs::PermissionsExt;

    let mut findings = Vec::new();
    let mut issues = 0usize;

    let sensitive_files = [
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
    ];
    for p in sensitive_files {
        match std::fs::metadata(p) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                let world_w = mode & 0o002 != 0;
                let world_r = mode & 0o004 != 0;
                if world_w || (p.contains("id_") && (world_r || mode & 0o077 != 0)) {
                    issues += 1;
                    findings.push(Finding::fail(
                        "Permissions",
                        format!("{p} mode {:o} is too open", mode),
                        "restrict to 600/640 as appropriate",
                    ));
                } else if world_r && p == "/etc/shadow" {
                    issues += 1;
                    findings.push(Finding::fail(
                        "Permissions",
                        "/etc/shadow is world-readable",
                        format!("mode {mode:o}"),
                    ));
                } else {
                    findings.push(Finding::pass(
                        "Permissions",
                        format!("{p} permissions look constrained"),
                        format!("mode {mode:o}"),
                    ));
                }
            }
            Err(_) => {}
        }
    }

    let world_writable_dirs = ["/tmp", "/var/tmp", "/dev/shm"];
    for p in world_writable_dirs {
        if let Ok(meta) = std::fs::metadata(p) {
            let mode = meta.permissions().mode() & 0o777;
            let sticky = meta.permissions().mode() & 0o1000 != 0;
            if mode & 0o002 != 0 && !sticky {
                issues += 1;
                findings.push(Finding::fail(
                    "Permissions",
                    format!("{p} is world-writable without sticky bit"),
                    format!("mode {mode:o}"),
                ));
            } else {
                findings.push(Finding::pass(
                    "Permissions",
                    format!("{p} sticky/world-write policy ok"),
                    format!("mode {mode:o}"),
                ));
            }
        }
    }

    if let Some(home) = std::env::var_os("HOME") {
        let ssh = Path::new(&home).join(".ssh");
        if ssh.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&ssh) {
                for ent in rd.flatten() {
                    let name = ent.file_name();
                    let name = name.to_string_lossy();
                    if name.starts_with("id_") && !name.ends_with(".pub") {
                        if let Ok(meta) = ent.metadata() {
                            let mode = meta.permissions().mode() & 0o777;
                            if mode & 0o077 != 0 {
                                issues += 1;
                                findings.push(Finding::fail(
                                    "Permissions",
                                    format!("{} is group/world accessible", ent.path().display()),
                                    format!("mode {mode:o}, expected 600"),
                                ));
                            } else {
                                findings.push(Finding::pass(
                                    "Permissions",
                                    format!("{} mode ok", name),
                                    format!("{mode:o}"),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    if issues == 0 && findings.is_empty() {
        findings.push(Finding::info(
            "Permissions",
            "no sensitive paths readable from this user",
            "run as root for a fuller filesystem audit",
        ));
    }

    findings
}
