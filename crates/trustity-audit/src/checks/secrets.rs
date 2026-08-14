use crate::finding::Finding;
use regex::Regex;
use std::sync::OnceLock;

fn patterns() -> &'static [(Regex, &'static str)] {
    static CELL: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    CELL.get_or_init(|| {
        let pairs = [
            (r"(?i)sk-[a-zA-Z0-9]{20,}", "OpenAI-style API key"),
            (r"(?i)ghp_[A-Za-z0-9]{20,}", "GitHub personal access token"),
            (r"(?i)github_pat_[A-Za-z0-9_]{20,}", "GitHub fine-grained PAT"),
            (r"(?i)xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
            (r"(?i)AKIA[0-9A-Z]{16}", "AWS access key id"),
            (
                r"(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
                "PEM private key",
            ),
            (
                r"(?i)eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                "JWT-like token",
            ),
        ];
        pairs
            .into_iter()
            .map(|(p, label)| (Regex::new(p).expect("valid secret regex"), label))
            .collect()
    })
}

fn name_looks_sensitive(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    const SKIP: &[&str] = &[
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "SECURITYSESSIONID",
        "XPC_SERVICE_NAME",
        "LAUNCH_AUTH",
        "HOME",
        "USER",
        "LOGNAME",
        "PATH",
        "TMPDIR",
        "TERM",
        "TERM_PROGRAM",
        "TERM_SESSION_ID",
        "COLORTERM",
        "LANG",
        "LC_ALL",
        "SHELL",
        "PWD",
        "OLDPWD",
        "SHLVL",
        "DISPLAY",
        "XDG_RUNTIME_DIR",
        "XDG_SESSION_TYPE",
        "DBUS_SESSION_BUS_ADDRESS",
        "SSH_CONNECTION",
        "SSH_CLIENT",
        "SSH_TTY",
    ];
    if SKIP.iter().any(|s| n == *s) {
        return false;
    }
    n.contains("SECRET")
        || n.contains("TOKEN")
        || n.contains("API_KEY")
        || n.contains("APIKEY")
        || n.contains("PASSWORD")
        || n.contains("PASSWD")
        || n.contains("PRIVATE_KEY")
        || n.contains("ACCESS_KEY")
        || (n.contains("AUTH") && n.contains("KEY"))
}

fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "********".into();
    }
    format!(
        "{}..{} ({} chars)",
        chars.iter().take(4).collect::<String>(),
        chars.iter().rev().take(2).rev().collect::<String>(),
        chars.len()
    )
}

pub fn audit() -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut hits = 0usize;

    for (key, value) in std::env::vars() {
        if value.is_empty() {
            continue;
        }
        let mut matched_label: Option<&'static str> = None;
        for (re, label) in patterns() {
            if re.is_match(&value) {
                matched_label = Some(*label);
                break;
            }
        }
        if matched_label.is_none() && name_looks_sensitive(&key) && value.len() >= 8 {
            matched_label = Some("sensitive-looking environment variable");
        }
        if let Some(label) = matched_label {
            hits += 1;
            findings.push(Finding::fail(
                "Secrets",
                format!("{key} may expose {label}"),
                format!("value looks like a secret: {}", redact(&value)),
            ));
        }
    }

    if hits == 0 {
        findings.push(Finding::pass(
            "Secrets",
            "No high-confidence secrets in environment",
            "regex + name heuristics over process environment",
        ));
    } else {
        findings.push(Finding::info(
            "Secrets",
            format!("{hits} potential secret(s) in environment"),
            "rotate and remove unused credentials from the shell profile",
        ));
    }

    findings
}
