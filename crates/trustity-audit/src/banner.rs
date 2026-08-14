use owo_colors::OwoColorize;

const BANNER: &str = r#"
 ████████╗██████╗ ██╗   ██╗███████╗████████╗██╗████████╗██╗   ██╗
 ╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║╚══██╔══╝╚██╗ ██╔╝
    ██║   ██████╔╝██║   ██║███████╗   ██║   ██║   ██║    ╚████╔╝
    ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██║   ██║     ╚██╔╝
    ██║   ██║  ██║╚██████╔╝███████║   ██║   ██║   ██║      ██║
    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝   ╚═╝      ╚═╝
"#;

pub fn print_banner() {
    eprintln!("{}", BANNER.trim_start_matches('\n').green());
    eprintln!(
        "  {} {}",
        "Trustity Labs".bright_white().bold(),
        "- Endpoint Warden".bright_green().bold()
    );
    eprintln!(
        "  {}\n",
        "local endpoint security & hardening audit  ·  experimental"
            .dimmed()
    );
}
