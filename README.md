# Trustity Endpoint Warden

**`trustity-audit`** is a high-performance, open-source CLI from [Trustity Labs](https://labs.trustity.co). It runs a **local endpoint security and hardening audit** on Windows and Linux (Unix/macOS supported for local use).

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

> **⚠️ Experimental Engineering**  
> All tools and POCs in Trustity Labs are strictly for **research and experimental purposes**.  
> **Use at your own risk. Not for production environments.**  
> Findings are heuristics — always review with a human before acting.

---

## Clone / download

```bash
git clone https://github.com/Trustity/Trustity-Endpoint-Warden.git
cd Trustity-Endpoint-Warden
```

Repository: [github.com/Trustity/Trustity-Endpoint-Warden](https://github.com/Trustity/Trustity-Endpoint-Warden)

---

## Requirements

- [Rust](https://rustup.rs/) **1.75+** (`rustc`, `cargo`)
- Windows, Linux, or macOS

---

## Build

```bash
cargo build --release
```

The optimized binary is written to:

| Platform | Path |
|----------|------|
| Linux / macOS | `./target/release/trustity-audit` |
| Windows | `.\target\release\trustity-audit.exe` |

Install onto your `PATH` (optional):

```bash
cargo install --path crates/trustity-audit
```

---

## Usage

```bash
# Full audit (banner + colorized findings)
./target/release/trustity-audit

# Skip ASCII banner
./target/release/trustity-audit --quiet

# Skip a category
./target/release/trustity-audit --skip-network

# Export a branded report
./target/release/trustity-audit --export markdown
./target/release/trustity-audit --export html --output ./warden-report.html
```

### Flags

| Flag | Description |
|------|-------------|
| `--export markdown\|html` | Write a Markdown or HTML audit report |
| `-o, --output PATH` | Report path (default: `trustity-audit-report.<ext>`) |
| `-q, --quiet` | Skip the ASCII banner |
| `--skip-persistence` | Skip autorun / cron / systemd / registry |
| `--skip-network` | Skip listen / established sockets |
| `--skip-permissions` | Skip sensitive path permission checks |
| `--skip-secrets` | Skip environment-variable secret scan |

**Exit codes:** `0` if no `FAIL` findings · `1` if any `FAIL` · `2` if report export fails.

Exported reports always include:

**Generated securely by Trustity Labs (https://trustity.co)**

---

## What it checks

| Area | Windows | Linux |
|------|---------|--------|
| **Startup / persistence** | `HKCU`/`HKLM` Run keys, Startup folder | cron paths, systemd units |
| **Network** | `netstat` listen + established | `/proc/net/tcp*` |
| **Permissions** | Presence of sensitive paths | World-writable dirs, SSH key modes, `/etc/shadow` |
| **Secrets** | Regex + name heuristics over process environment (values redacted) | Same |

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
           mode 644 — expected 600
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
├── Cargo.toml                 # workspace
├── LICENSE
├── README.md
└── crates/trustity-audit/     # binary crate → trustity-audit
    ├── Cargo.toml
    └── src/
        ├── main.rs
        ├── banner.rs
        ├── cli.rs
        ├── finding.rs
        ├── report.rs
        └── checks/
```

---

## Safety notes

- The tool inspects **this host only**. It does not upload results to Trustity.
- Secret matches print **redacted** previews, never full tokens.
- Some checks (HKLM, `/etc/shadow`) need elevation for a complete picture.

---

## Trustity Labs

Endpoint Warden is a research surface of [Trustity Labs](https://labs.trustity.co/#endpoint-warden).  
Trustity builds endpoint and edge security products — see [trustity.co](https://trustity.co).

---

## License

MIT. See [LICENSE](LICENSE).
