<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-white.svg">
    <img src="assets/logo.svg" alt="gli" width="320">
  </picture>
</p>

<p align="center">Configure, secure, and provision a Linux VPS from one declarative file.</p>

gli is a single static Rust binary that hardens and sets up a server from a
declarative `gli.toml`. Every change is idempotent, previewed before it
runs, and reversible. It fills the gap left by fragile bash scripts (no safety,
no idempotence), Ansible (too heavy for one box), and PaaS tools like Coolify
(deploy apps but don't secure the OS).

Runs locally or over SSH against one host or a tagged fleet. Works on
Debian/Ubuntu, Fedora, Rocky/RHEL, Arch, and openSUSE.

## Why

When you rent a new VPS there is a pile of setup before it is safe or useful:
lock down SSH, put up a firewall, create a deploy user, enable automatic
updates, add fail2ban, install Docker, deploy an app with HTTPS, add monitoring.
gli does all of it from one config file, safely and repeatably.

## Principles

- **Idempotent**: every action re-runs with no side effects once converged.
- **Preview first**: `plan` shows the diff; `apply` confirms before touching anything.
- **Reversible**: each module snapshots state and supports `rollback` and `uninstall`.
- **Lockout-safe**: SSH and firewall changes are validated (`sshd -t`, `nft -c`) and, after an interactive apply, a detached guard auto-rolls-back within 60s unless you confirm.
- **Single binary**: no Python or Ruby on the target.
- **Cross-distro**: detects the host and adapts service names and package managers.

## Install

Prebuilt binary (Linux x86_64/arm64, macOS Intel/Apple Silicon):

```sh
curl -fsSL https://raw.githubusercontent.com/KodjoTouglo/gli/main/install.sh | sh
```

Windows: download the `.zip` from the [Releases](https://github.com/KodjoTouglo/gli/releases) page.

With Cargo, or from source (Rust 1.85+):

```sh
cargo install --git https://github.com/KodjoTouglo/gli gli-cli
# or
git clone https://github.com/KodjoTouglo/gli.git && cd gli
cargo build --release --bin gli
```

To remove the `gli` binary:

```sh
curl -fsSL https://raw.githubusercontent.com/KodjoTouglo/gli/main/uninstall.sh | sh
```

To undo what gli configured on a host, run `gli uninstall` (add `--purge` to
delete data) before removing the binary.

## Quickstart

```sh
gli init            # write a starter gli.toml
gli plan            # preview the changes (read-only)
sudo gli apply      # apply, with confirmation
gli tui             # or drive it all from the dashboard
```

## Commands

| Command | Description |
|---|---|
| `init` | Write a starter `gli.toml` (`--force` to overwrite) |
| `plan` | Show the changes `apply` would make (read-only) |
| `apply` | Converge the system (`--dry-run`, `--yes`, `--no-guard`) |
| `audit` | Per-module compliance and a score (`--json` for machine output) |
| `rollback [module]` | Restore state from before the last apply |
| `uninstall [module]` | Remove modules; `--purge` also deletes data |
| `recipes` | List the builtin recipes |
| `servers [group]` | List inventory servers (`--check` probes SSH) |
| `history` | Show recent apply/rollback/uninstall events |
| `tui` | Launch the interactive dashboard |

Global flags select the target: `--target user@host[:port]`, `--group <tag>`
with `--inventory`, plus SSH auth (`--identity`, `--ask-pass`,
`$GLI_SSH_PASSWORD`) and host-key policy (`--strict-host-key`,
`--insecure-host-key`, `--known-hosts`).

## Modules

| Module | Category | What it does |
|---|---|---|
| `ssh` | Security | Custom port, disable root/password login, modern ciphers |
| `firewall` | Security | nftables default-deny, allow-list, SSH always permitted |
| `users` | Security | Create users, grant sudo via `sudoers.d`, install SSH keys |
| `fail2ban` | Security | Install fail2ban, enable jails (sshd tracks the SSH port) |
| `system` | System | Set hostname, timezone, and a swap file |
| `updates` | System | Automatic security updates (unattended-upgrades / dnf-automatic) |
| `monitoring` | System | Metrics agent: netdata dashboard or Prometheus node_exporter |
| `docker` | Runtime | Install Docker, enable it, add users to the docker group |
| `postgres` | Runtime | Install PostgreSQL, enable it, create databases |
| `redis` | Runtime | Install Redis and enable it |
| `caddy` | Network | Reverse proxy with automatic HTTPS (Let's Encrypt) |
| `tailscale` | Network | Install Tailscale and join the tailnet |
| `app` | App | Deploy an app (Django, Laravel, Node, WordPress, ...) |

Security modules form an always-on baseline; provisioning modules are opt-in.

## Configuration

`gli.toml` (excerpt; see [examples/configs/gli.toml](examples/configs/gli.toml)):

```toml
profile = "balanced"   # homelab | balanced | strict | paranoid

[ssh]
port = 2222
permit_root_login = false
password_auth = false

[firewall]
default = "deny"
allow = ["80/tcp", "443/tcp", "22/tcp from 10.0.0.0/8"]

[users.deploy]
sudo = true
ssh_keys = ["ssh-ed25519 AAAA... deploy@host"]

[monitoring]
enabled = true
backend = "netdata"    # netdata | node_exporter

[app]
enabled = true
framework = "django"   # django|laravel|node|fastapi|rails|php|wordpress|generic|static
domain = "app.example.com"   # auto-creates a Caddy HTTPS site
database = "postgres"        # auto-enables the postgres module
repo = "https://github.com/me/myapp.git"
```

Setting `app.domain` wires a Caddy reverse-proxy site with HTTPS; setting
`app.database` enables the matching database module. One `[app]` block sets up
the app, its HTTPS front, and its database.

### Recipes

A recipe is a named preset; your own keys layer on top (yours win):

```toml
recipe = "wordpress"

[app]
domain = "blog.example.com"
```

`gli apply` then stands up a full WordPress + MariaDB stack behind
automatic HTTPS. Builtin: `baseline`, `web-server`, `docker-host`, `wordpress`
(`gli recipes`).

## Remote and fleets

```sh
gli plan --target root@203.0.113.10           # one host, read-only
gli audit --group prod --json | jq            # a tagged fleet, as JSON
gli servers --check                           # inventory + connectivity
```

Remote execution is agentless (russh); host keys are verified against
known_hosts (trust-on-first-use by default). `inventory.toml` defines servers by
name and tag.

## Architecture

Cargo workspace:

```
crates/
  gli-core/      Module trait, Context, recipes, Platform, FileSystem
  gli-modules/   the 13 modules
  gli-cli/       the gli binary (clap)
  gli-tui/       ratatui dashboard
  gli-agent/     remote execution over SSH (russh)
  gli-state/     SQLite history
```

Every module implements one trait (`check`/`plan`/`apply`/`rollback`/
`uninstall`). The `Context` injects the filesystem and command runner, so the
same modules run locally and remotely and are unit-tested against a tempdir with
a mock runner.

## Roadmap

- Native (non-Docker) runtimes per framework
- Server-side lockout guard for remote apply
- Homebrew, winget, npm, and PyPI packages
- Compliance reports (CIS, ANSSI)

## Assets

Logo and icon variations live in [assets/](assets/):

| File | Use |
|---|---|
| `logo.svg` | Full logo (wordmark + mark) on light backgrounds |
| `logo-white.svg` | Full logo for dark backgrounds |
| `icon.svg` | Standalone mark on light backgrounds |
| `icon-white.svg` | Standalone mark for dark backgrounds |
| `favico.ico` | Favicon |

## Development

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
cargo test --workspace
```

## License

Apache-2.0. See [LICENSE](LICENSE).
