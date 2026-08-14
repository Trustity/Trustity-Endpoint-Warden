use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Markdown,
    Html,
}

impl ExportFormat {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Markdown => "md",
            Self::Html => "html",
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "trustity-audit",
    version,
    about = "Trustity Labs Endpoint Warden — local security & hardening audit",
    long_about = "Experimental research CLI. Scans persistence, network, permissions, and leaked secrets on this host. Not for production decisions without human review."
)]
pub struct Cli {
    /// Quiet banner (still prints findings)
    #[arg(short, long)]
    pub quiet: bool,

    /// Export report next to CWD (or --output)
    #[arg(long, value_enum)]
    pub export: Option<ExportFormat>,

    /// Output path for --export (default: trustity-audit-report.<ext>)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Skip network inspection
    #[arg(long)]
    pub skip_network: bool,

    /// Skip persistence / autorun inspection
    #[arg(long)]
    pub skip_persistence: bool,

    /// Skip permission checks
    #[arg(long)]
    pub skip_permissions: bool,

    /// Skip environment-variable secret scan
    #[arg(long)]
    pub skip_secrets: bool,
}
