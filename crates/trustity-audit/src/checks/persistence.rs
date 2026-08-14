use crate::finding::Finding;
use std::fs;
use std::path::Path;

pub fn audit() -> Vec<Finding> {
    #[cfg(windows)]
    {
        windows_persistence()
    }
    #[cfg(not(windows))]
    {
        unix_persistence()
    }
}

#[cfg(windows)]
fn windows_persistence() -> Vec<Finding> {
    let mut findings = Vec::new();
    let hives: &[(&str, winreg::RegKey, &str)] = &[
        (
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER),
            r"Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER),
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
    ];

    let mut total = 0usize;
    for (label, root, sub) in hives {
        match root.open_subkey(sub) {
            Ok(key) => {
                let names: Vec<String> = key.enum_values().filter_map(|v| v.ok().map(|(n, _)| n)).collect();
                total += names.len();
                if names.is_empty() {
                    findings.push(Finding::pass(
                        "Persistence",
                        format!("{label} empty"),
                        "no autorun values",
                    ));
                } else {
                    findings.push(Finding::warn(
                        "Persistence",
                        format!("{label}: {} value(s)", names.len()),
                        names.join(", "),
                    ));
                }
            }
            Err(err) => findings.push(Finding::info(
                "Persistence",
                format!("could not read {label}"),
                err.to_string(),
            )),
        }
    }

    let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    match hklm.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run") {
        Ok(key) => {
            let names: Vec<String> = key.enum_values().filter_map(|v| v.ok().map(|(n, _)| n)).collect();
            total += names.len();
            if names.is_empty() {
                findings.push(Finding::pass(
                    "Persistence",
                    r"HKLM\...\Run empty",
                    "no machine autorun values",
                ));
            } else {
                findings.push(Finding::warn(
                    "Persistence",
                    format!(r"HKLM\...\Run: {} value(s)", names.len()),
                    names.join(", "),
                ));
            }
        }
        Err(_) => findings.push(Finding::info(
            "Persistence",
            r"HKLM Run not readable",
            "open an elevated shell for machine-wide keys",
        )),
    }

    let startup = dirs_startup_windows();
    if let Some(dir) = startup {
        match count_entries(&dir) {
            Ok(0) => findings.push(Finding::pass(
                "Persistence",
                "Startup folder empty",
                dir.display().to_string(),
            )),
            Ok(n) => findings.push(Finding::warn(
                "Persistence",
                format!("Startup folder has {n} item(s)"),
                dir.display().to_string(),
            )),
            Err(err) => findings.push(Finding::info("Persistence", "startup folder unread", err)),
        }
    }

    if total == 0 {
        findings.push(Finding::info(
            "Persistence",
            "Windows autorun scan complete",
            "review WARN entries; not every autorun is malicious",
        ));
    }

    findings
}

#[cfg(windows)]
fn dirs_startup_windows() -> Option<std::path::PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    Some(std::path::PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup"))
}

#[cfg(not(windows))]
fn unix_persistence() -> Vec<Finding> {
    let mut findings = Vec::new();

    let systemd_paths = [
        "/etc/systemd/system",
        "/etc/systemd/user",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ];
    if let Some(home) = std::env::var_os("HOME") {
        let user_sys = Path::new(&home).join(".config/systemd/user");
        scan_dir(&mut findings, "systemd user units", &user_sys, Some(".service"));
    }
    for p in systemd_paths {
        scan_dir(&mut findings, "systemd units", Path::new(p), Some(".service"));
    }

    let cron_paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
    ];
    for p in cron_paths {
        let path = Path::new(p);
        if path.is_file() {
            findings.push(Finding::info(
                "Persistence",
                format!("cron file present: {p}"),
                "inspect scheduled jobs",
            ));
        } else {
            scan_dir(&mut findings, "cron", path, None);
        }
    }

    if let Some(home) = std::env::var_os("HOME") {
        let launch = Path::new(&home).join("Library/LaunchAgents");
        scan_dir(&mut findings, "launch agents", &launch, Some(".plist"));
    }
    scan_dir(
        &mut findings,
        "launch daemons",
        Path::new("/Library/LaunchDaemons"),
        Some(".plist"),
    );

    if findings.is_empty() {
        findings.push(Finding::pass(
            "Persistence",
            "No common autorun paths found",
            "cron / systemd / launchd locations were absent or empty",
        ));
    }

    findings
}

fn scan_dir(out: &mut Vec<Finding>, label: &str, path: &Path, suffix: Option<&str>) {
    match count_entries_filtered(path, suffix) {
        Ok(0) => {
            if path.exists() {
                out.push(Finding::pass(
                    "Persistence",
                    format!("{label} empty ({})", path.display()),
                    "no entries",
                ));
            }
        }
        Ok(n) => out.push(Finding::warn(
            "Persistence",
            format!("{label}: {n} item(s)"),
            path.display().to_string(),
        )),
        Err(_) => {}
    }
}

#[cfg(windows)]
fn count_entries(path: &Path) -> Result<usize, String> {
    count_entries_filtered(path, None)
}

fn count_entries_filtered(path: &Path, suffix: Option<&str>) -> Result<usize, String> {
    if !path.exists() {
        return Ok(0);
    }
    if path.is_file() {
        return Ok(1);
    }
    let rd = fs::read_dir(path).map_err(|e| e.to_string())?;
    let mut n = 0usize;
    for ent in rd.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        if let Some(suf) = suffix {
            if !name.ends_with(suf) {
                continue;
            }
        }
        n += 1;
    }
    Ok(n)
}
