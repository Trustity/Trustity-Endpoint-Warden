use crate::finding::Finding;
#[cfg(not(target_os = "linux"))]
use std::process::Command;

pub fn audit() -> Vec<Finding> {
    #[cfg(windows)]
    {
        from_netstat(&["netstat", "-ano"])
    }
    #[cfg(target_os = "linux")]
    {
        linux_proc_net()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        from_lsof()
    }
}

#[cfg(target_os = "linux")]
fn linux_proc_net() -> Vec<Finding> {
    let mut findings = Vec::new();
    let tables = [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp6"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp6"),
    ];
    let mut listen = 0usize;
    let mut established = 0usize;
    let mut samples: Vec<String> = Vec::new();

    for (path, proto) in tables {
        let Ok(body) = std::fs::read_to_string(path) else {
            continue;
        };
        for (i, line) in body.lines().enumerate() {
            if i == 0 {
                continue;
            }
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            let local = parse_proc_addr(cols[1]);
            let remote = parse_proc_addr(cols[2]);
            let state = cols[3];
            // TCP listen = 0A, established = 01
            if proto.starts_with("tcp") && state.eq_ignore_ascii_case("0A") {
                listen += 1;
                if samples.len() < 8 {
                    samples.push(format!("{proto} LISTEN {local}"));
                }
            } else if proto.starts_with("tcp") && state.eq_ignore_ascii_case("01") {
                established += 1;
                if samples.len() < 12 {
                    samples.push(format!("{proto} ESTAB {local} → {remote}"));
                }
            }
        }
    }

    if listen == 0 && established == 0 {
        findings.push(Finding::info(
            "Network",
            "No TCP listen/established sockets in /proc/net",
            "udp tables were scanned; privileged sockets may be hidden",
        ));
        return findings;
    }

    findings.push(Finding::info(
        "Network",
        format!("{listen} listening TCP socket(s)"),
        if samples.is_empty() {
            "see /proc/net/tcp*".into()
        } else {
            samples.iter().take(6).cloned().collect::<Vec<_>>().join("; ")
        },
    ));
    findings.push(Finding::info(
        "Network",
        format!("{established} established TCP connection(s)"),
        "review unexpected outbound destinations",
    ));
    if listen > 20 {
        findings.push(Finding::warn(
            "Network",
            "Large listen surface",
            format!("{listen} listening sockets — tighten unused services"),
        ));
    } else {
        findings.push(Finding::pass(
            "Network",
            "Listen count within a typical workstation range",
            format!("{listen} listeners"),
        ));
    }
    findings
}

#[cfg(target_os = "linux")]
fn parse_proc_addr(field: &str) -> String {
    let Some((ip_hex, port_hex)) = field.split_once(':') else {
        return field.to_string();
    };
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
    if ip_hex.len() == 8 {
        if let Ok(n) = u32::from_str_radix(ip_hex, 16) {
            let b = n.to_le_bytes();
            return format!("{}.{}.{}.{}:{port}", b[0], b[1], b[2], b[3]);
        }
    }
    format!("[{ip_hex}]:{port}")
}

#[cfg(windows)]
fn from_netstat(cmd: &[&str]) -> Vec<Finding> {
    parse_command_output(cmd, "netstat")
}

#[cfg(not(any(windows, target_os = "linux")))]
fn from_lsof() -> Vec<Finding> {
    let listen = Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:LISTEN"])
        .output();
    let estab = Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:ESTABLISHED"])
        .output();

    let mut findings = Vec::new();
    match listen {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = text.lines().skip(1).filter(|l| !l.is_empty()).collect();
            let n = lines.len();
            let preview = lines.iter().take(6).cloned().collect::<Vec<_>>().join(" | ");
            findings.push(Finding::info(
                "Network",
                format!("{n} listening TCP socket(s)"),
                preview,
            ));
            if n > 20 {
                findings.push(Finding::warn(
                    "Network",
                    "Large listen surface",
                    format!("{n} listeners via lsof"),
                ));
            } else {
                findings.push(Finding::pass(
                    "Network",
                    "Listen count within a typical workstation range",
                    format!("{n} listeners"),
                ));
            }
        }
        _ => findings.push(Finding::info(
            "Network",
            "lsof listen scan unavailable",
            "install lsof or run with sufficient privileges",
        )),
    }

    match estab {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let n = text.lines().skip(1).filter(|l| !l.is_empty()).count();
            findings.push(Finding::info(
                "Network",
                format!("{n} established TCP connection(s)"),
                "review unexpected outbound destinations",
            ));
        }
        _ => {}
    }

    findings
}

#[cfg(windows)]
fn parse_command_output(cmd: &[&str], label: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let output = Command::new(cmd[0]).args(&cmd[1..]).output();
    match output {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let listen = text
                .lines()
                .filter(|l| l.to_ascii_uppercase().contains("LISTEN"))
                .count();
            let established = text
                .lines()
                .filter(|l| {
                    let u = l.to_ascii_uppercase();
                    u.contains("ESTABLISHED") || u.contains("ESTAB")
                })
                .count();
            findings.push(Finding::info(
                "Network",
                format!("{listen} listening entries ({label})"),
                "active local bind points",
            ));
            findings.push(Finding::info(
                "Network",
                format!("{established} established entries ({label})"),
                "outbound or accepted sessions",
            ));
            if listen > 20 {
                findings.push(Finding::warn(
                    "Network",
                    "Large listen surface",
                    format!("{listen} LISTEN rows"),
                ));
            } else {
                findings.push(Finding::pass(
                    "Network",
                    "Listen count within a typical workstation range",
                    format!("{listen} LISTEN rows"),
                ));
            }
        }
        Ok(out) => findings.push(Finding::info(
            "Network",
            format!("{label} exited {}", out.status),
            String::from_utf8_lossy(&out.stderr).chars().take(180).collect(),
        )),
        Err(err) => findings.push(Finding::info(
            "Network",
            format!("could not run {label}"),
            err.to_string(),
        )),
    }
    findings
}
