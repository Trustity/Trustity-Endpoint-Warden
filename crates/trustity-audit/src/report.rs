use crate::finding::{Report, Status};
use crate::cli::ExportFormat;
use owo_colors::OwoColorize;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

pub const BRAND_FOOTER: &str =
    "Generated securely by Trustity Labs (https://trustity.co)";

pub fn print_terminal(report: &Report) {
    println!(
        "  host {}  ·  os {}  ·  {}\n",
        report.host.bright_white(),
        report.os.bright_white(),
        report.generated_at.dimmed()
    );

    let mut current = "";
    for f in &report.findings {
        if f.check != current {
            current = &f.check;
            println!("  {}", format!("▸ {current}").bright_cyan().bold());
        }
        let badge = match f.status {
            Status::Pass => format!("[{}]", f.status).green().to_string(),
            Status::Warn => format!("[{}]", f.status).yellow().bold().to_string(),
            Status::Fail => format!("[{}]", f.status).red().bold().to_string(),
            Status::Info => format!("[{}]", f.status).blue().to_string(),
        };
        println!("    {badge} {}", f.title.bright_white());
        if !f.detail.is_empty() {
            println!("           {}", f.detail.dimmed());
        }
    }

    let (pass, warn, fail, info) = report.counts();
    println!();
    println!(
        "  summary  {} pass  {} warn  {} fail  {} info",
        pass.to_string().green(),
        warn.to_string().yellow(),
        fail.to_string().red(),
        info.to_string().blue()
    );
    println!("  {}\n", BRAND_FOOTER.dimmed());
}

pub fn export(report: &Report, format: ExportFormat, path: &Path) -> io::Result<()> {
    let body = match format {
        ExportFormat::Markdown => render_markdown(report),
        ExportFormat::Html => render_html(report),
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut file = fs::File::create(path)?;
    file.write_all(body.as_bytes())?;
    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_markdown(report: &Report) -> String {
    let (pass, warn, fail, info) = report.counts();
    let mut out = String::new();
    out.push_str("# Trustity Labs - Endpoint Warden\n\n");
    out.push_str(&format!("- **Host:** {}\n", report.host));
    out.push_str(&format!("- **OS:** {}\n", report.os));
    out.push_str(&format!("- **Generated:** {}\n\n", report.generated_at));
    out.push_str(&format!(
        "**Summary:** {pass} PASS · {warn} WARN · {fail} FAIL · {info} INFO\n\n"
    ));
    out.push_str("| Status | Check | Finding | Detail |\n| --- | --- | --- | --- |\n");
    for f in &report.findings {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            f.status.as_str(),
            md_cell(&f.check),
            md_cell(&f.title),
            md_cell(&f.detail)
        ));
    }
    out.push_str("\n---\n\n");
    out.push_str(&format!("*{BRAND_FOOTER}*\n"));
    out
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', "<br>")
}

fn render_html(report: &Report) -> String {
    let (pass, warn, fail, info) = report.counts();
    let mut rows = String::new();
    for f in &report.findings {
        let cls = f.status.as_str().to_lowercase();
        rows.push_str(&format!(
            "<tr class=\"{cls}\"><td><span class=\"badge {cls}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            f.status.as_str(),
            html_escape(&f.check),
            html_escape(&f.title),
            html_escape(&f.detail),
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Trustity Labs Endpoint Warden - {host}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
         background: #050607; color: #e8ece8; }}
  header {{ padding: 2.5rem 2rem 1.5rem; border-bottom: 1px solid rgba(61,255,138,.2);
            background: radial-gradient(ellipse at top, rgba(61,255,138,.08), transparent 55%); }}
  h1 {{ margin: 0; font-size: 1.4rem; letter-spacing: .04em; }}
  .sub {{ color: #7a857a; margin-top: .4rem; font-size: .85rem; }}
  .accent {{ color: #3dff8a; }}
  .brand {{ color: #c967e5; }}
  main {{ padding: 1.5rem 2rem 4rem; max-width: 1100px; }}
  .summary span {{ margin-right: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 1.5rem; font-size: .82rem; }}
  th {{ text-align: left; color: #7a857a; font-weight: 500; padding: .6rem; border-bottom: 1px solid #1a1e1a; }}
  td {{ padding: .65rem .6rem; border-bottom: 1px solid #121412; vertical-align: top; }}
  .badge {{ font-size: .72rem; padding: .12rem .4rem; border: 1px solid currentColor; }}
  .pass {{ color: #3dff8a; }}
  .warn {{ color: #e8a84a; }}
  .fail {{ color: #ff5c7a; }}
  .info {{ color: #6cb6ff; }}
  footer {{ margin-top: 3rem; padding-top: 1.2rem; border-top: 1px solid rgba(61,255,138,.2);
            color: #7a857a; font-size: .8rem; }}
  footer a {{ color: #3dff8a; }}
</style>
</head>
<body>
<header>
  <h1><span class="brand">TRUSTITY</span> <span class="accent">LABS</span> - Endpoint Warden</h1>
  <p class="sub">{host} · {os} · {when}</p>
</header>
<main>
  <p class="summary">
    <span class="pass">{pass} PASS</span>
    <span class="warn">{warn} WARN</span>
    <span class="fail">{fail} FAIL</span>
    <span class="info">{info} INFO</span>
  </p>
  <table>
    <thead><tr><th>Status</th><th>Check</th><th>Finding</th><th>Detail</th></tr></thead>
    <tbody>
{rows}
    </tbody>
  </table>
  <footer>
    <strong>{footer}</strong>
  </footer>
</main>
</body>
</html>
"#,
        host = html_escape(&report.host),
        os = html_escape(&report.os),
        when = html_escape(&report.generated_at),
        footer = html_escape(BRAND_FOOTER),
        rows = rows,
        pass = pass,
        warn = warn,
        fail = fail,
        info = info,
    )
}

pub fn default_output_path(format: ExportFormat) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("trustity-audit-report.{}", format.extension()))
}
