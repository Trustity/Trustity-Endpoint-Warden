# Trustity Endpoint Warden

[![Release](https://img.shields.io/github/v/release/Trustity/Trustity-Endpoint-Warden)](https://github.com/Trustity/Trustity-Endpoint-Warden/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/Trustity/Trustity-Endpoint-Warden/total.svg)](https://github.com/Trustity/Trustity-Endpoint-Warden/releases)

**`trustity-audit`** is an open-source CLI from [Trustity Labs](https://trustitylabs.com). It runs a local endpoint security and hardening audit on Windows and Linux (macOS works for local use).

No telemetry. No cloud. The scan stays on the machine you run it on.

```
 ████████╗██████╗ ██╗   ██╗███████╗████████╗██╗████████╗██╗   ██╗
 ╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║╚══██╔══╝╚██╗ ██╔╝
    ██║   ██████╔╝██║   ██║███████╗   ██║   ██║   ██║    ╚████╔╝
    ██║   ██╔══██╗██║   ██║╚════██║   ██║   ██║   ██║     ╚██╔╝
    ██║   ██║  ██║╚██████╔╝███████║   ██║   ██║   ██║      ██║
    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝   ╚═╝      ╚═╝

  Trustity Labs - Endpoint Warden
  local endpoint security & hardening audit  ·  experimental
```

---

> **Experimental Engineering**
>
> All tools and POCs in Trustity Labs are strictly for research and experimental purposes.
> **Use at your own risk. Not for production environments.**
> Findings are heuristics. Review them before you act.

---

## Download (no compile)

Grab a prebuilt binary from the latest release:

**[github.com/Trustity/Trustity-Endpoint-Warden/releases/latest](https://github.com/Trustity/Trustity-Endpoint-Warden/releases/latest)**

| Archive | Platform |
|---------|----------|
| `*-x86_64-unknown-linux-gnu.tar.gz` | Linux x86_64 |
| `*-x86_64-pc-windows-msvc.zip` | Windows x86_64 |
| `*-aarch64-apple-darwin.tar.gz` | macOS Apple Silicon |
| `*-x86_64-apple-darwin.tar.gz` | macOS Intel |

Linux / macOS:

```bash
tar -xzf trustity-audit-*.tar.gz
cd trustity-audit-*
chmod +x trustity-audit
./trustity-audit
```

Windows (cmd or PowerShell — keep the window open):

```bat
cd path\to\extracted-folder
trustity-audit.exe
```

Double-clicking the `.exe` also runs the scan; the window stays open until you press Enter.

Checksums: `SHA256SUMS.txt` on the same release page.

---

## Clone

```bash
git clone https://github.com/Trustity/Trustity-Endpoint-Warden.git
cd Trustity-Endpoint-Warden
```

---

## Build from source

Requires [Rust](https://rustup.rs/) 1.75+ (`rustc`, `cargo`).

```bash
cargo build --release
```

| Platform | Binary |
|----------|--------|
| Linux / macOS | `./target/release/trustity-audit` |
| Windows | `.\target\release\trustity-audit.exe` |

Optional:

```bash
cargo install --path crates/trustity-audit
```

---

## Usage

```bash
./target/release/trustity-audit
./target/release/trustity-audit --quiet
./target/release/trustity-audit --skip-network
./target/release/trustity-audit --export markdown
./target/release/trustity-audit --export html --output ./warden-report.html
```

| Flag | Description |
|------|-------------|
| `--export markdown\|html` | Write a Markdown or HTML audit report |
| `-o, --output PATH` | Report path (default: `trustity-audit-report.<ext>`) |
| `-q, --quiet` | Skip the ASCII banner |
| `--skip-persistence` | Skip autorun / cron / systemd / registry |
| `--skip-network` | Skip listen / established sockets |
| `--skip-permissions` | Skip sensitive path permission checks |
| `--skip-secrets` | Skip environment-variable secret scan |

Exit codes: `0` if no `FAIL` · `1` if any `FAIL` · `2` if report export fails.

Exported reports include:

**Generated securely by Trustity Labs (https://trustity.co)**

---

## What it checks

| Area | Windows | Linux |
|------|---------|--------|
| Startup / persistence | `HKCU`/`HKLM` Run keys, Startup folder | cron paths, systemd units |
| Network | `netstat` listen + established | `/proc/net/tcp*` |
| Permissions | Presence of sensitive paths | World-writable dirs, SSH key modes, `/etc/shadow` |
| Secrets | Regex + name heuristics over the process environment (values redacted) | Same |

---

## Example terminal output

```text
  Trustity Labs - Endpoint Warden
  local endpoint security & hardening audit  ·  experimental

  host workstation-01  ·  os linux  ·  2026-08-14 23:50:00 UTC

  ▸ Persistence
    [WARN] systemd units: 42 item(s)
           /etc/systemd/system
  ▸ Network
    [INFO] 8 listening TCP socket(s)
    [PASS] Listen count within a typical workstation range
    [INFO] 14 established TCP connection(s)
  ▸ Permissions
    [PASS] /tmp sticky/world-write policy ok
    [FAIL] ~/.ssh/id_ed25519 is group/world accessible
           mode 644, expected 600
  ▸ Secrets
    [PASS] No high-confidence secrets in environment

  summary  2 pass  1 warn  1 fail  2 info
  Generated securely by Trustity Labs (https://trustity.co)
```

Statuses: **PASS** (green) · **WARN** (amber) · **FAIL** (red) · **INFO** (blue).

---

## Workspace layout

```text
Trustity-Endpoint-Warden/
├── Cargo.toml
├── LICENSE
├── README.md
└── crates/trustity-audit/
```

---

## Safety notes

- Inspects this host only. Results are not uploaded to Trustity.
- Secret matches print redacted previews, never full tokens.
- Some checks (`HKLM`, `/etc/shadow`) need elevation for a complete picture.

---

## Trustity Labs

Endpoint Warden is a research surface of [Trustity Labs](https://trustitylabs.com/#endpoint-warden).
Product suite: [trustity.co](https://trustity.co).

---

## License

MIT. See [LICENSE](LICENSE).
