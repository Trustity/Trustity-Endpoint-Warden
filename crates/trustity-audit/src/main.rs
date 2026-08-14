mod banner;
mod checks;
mod cli;
mod finding;
mod report;

use clap::Parser;
use cli::Cli;
use finding::Report;

fn main() {
    let cli = Cli::parse();
    if !cli.quiet {
        banner::print_banner();
    }

    let host = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown-host".into());
    let os = std::env::consts::OS.to_string();
    let generated_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string();

    let findings = checks::run_all(&cli);
    let report = Report {
        host,
        os,
        generated_at,
        findings,
    };

    report::print_terminal(&report);

    if let Some(format) = cli.export {
        let path = cli
            .output
            .unwrap_or_else(|| report::default_output_path(format));
        match report::export(&report, format, &path) {
            Ok(()) => eprintln!("  exported {}", path.display()),
            Err(err) => {
                eprintln!("  export failed: {err}");
                std::process::exit(2);
            }
        }
    }

    let fail = report
        .findings
        .iter()
        .any(|f| f.status == finding::Status::Fail);
    if fail {
        std::process::exit(1);
    }
}
