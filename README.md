# xairas-cve

CLI tool to monitor CVE vulnerabilities for your specific tech stack and get notified via Telegram when new ones drop.

Unlike generic CVE feeds that blast every vulnerability, **xairas-cve** only alerts you about CVEs that affect the exact technologies and versions you're running.

## Features

- **Version-aware matching** — only CVEs affecting your specific versions
- **Multi-ecosystem support** — npm, PyPI, Go, Maven, Ubuntu, Debian packages via [OSV.dev](https://osv.dev)
- **Hardware & infrastructure** — MikroTik, Fortinet, Cisco, HPE, etc. via [NVD](https://nvd.nist.gov) with automatic CPE discovery
- **Custom categories** — define your own categories mapped to any ecosystem
- **Telegram notifications** — with forum topic support and custom API URL (for regions where Telegram is restricted)
- **Deduplication** — never get the same CVE twice (SQLite state tracking)
- **One-shot scan** — audit your stack on demand
- **Continuous monitor** — long-running mode with configurable interval

## Install
```bash
npm install -g xairas-cve
```

## Quick Start
```bash
# 1. Configure Telegram
xairas-cve config set --bot-token <YOUR_BOT_TOKEN> --chat-id <YOUR_CHAT_ID>

# Optional: set topic thread ID for forum groups
xairas-cve config set --thread-id <THREAD_ID>

# Optional: custom Telegram API URL (for restricted regions)
xairas-cve config set --api-url https://your-telegram-proxy.com

# 2. Add your technologies
xairas-cve stack add --name express --version 4.18.2 --category npm
xairas-cve stack add --name openssl --version 3.0.13 --category ubuntu-pkg
xairas-cve stack add --name routeros --version 7.14 --category hardware
xairas-cve stack add --name django --version 4.2.0 --category pypi

# 3. Run a one-time scan
xairas-cve scan

# 4. Start continuous monitoring
xairas-cve monitor
```

## Categories

Built-in categories auto-map to the right data source:

| Category | Data Source | Examples |
|---|---|---|
| `npm` | OSV.dev | express, fastify, axios |
| `pypi` | OSV.dev | django, flask, requests |
| `go` | OSV.dev | golang.org/x/crypto |
| `maven` | OSV.dev | log4j, spring-boot |
| `ubuntu-pkg` | OSV.dev | openssl, curl |
| `debian-pkg` | OSV.dev | openssl, nginx |
| `infrastructure` | NVD | nginx, postgresql, rabbitmq |
| `hardware` | NVD | mikrotik, fortinet, hpe |

Custom categories are supported with `--ecosystem`:
```bash
# Map to an OSV ecosystem
xairas-cve stack add --name my-pkg --version 1.0 --category my-custom --ecosystem PyPI

# Map to NVD
xairas-cve stack add --name my-appliance --version 2.0 --category my-custom --ecosystem nvd
```

## Commands

### `xairas-cve config set [options]`

| Option | Description |
|---|---|
| `--bot-token <token>` | Telegram bot token |
| `--chat-id <id>` | Telegram chat ID |
| `--thread-id <id>` | Telegram topic/thread ID |
| `--api-url <url>` | Telegram API URL (default: `https://api.telegram.org`) |
| `--nvd-api-key <key>` | NVD API key (optional, increases rate limit) |
| `--scan-interval <interval>` | Scan interval: `30m`, `6h`, `1d` |
| `--min-cvss <score>` | Minimum CVSS score to notify (0-10) |

### `xairas-cve config show`

Display current configuration (tokens are masked).

### `xairas-cve stack add [options]`

| Option | Description |
|---|---|
| `--name <name>` | Technology name |
| `--version <version>` | Version you are running |
| `--category <category>` | Category (see table above) |
| `--ecosystem <ecosystem>` | OSV ecosystem or `nvd` (for custom categories) |
| `--cpe <vendor:product>` | Skip CPE discovery, use exact CPE |

### `xairas-cve stack list`

List all monitored technologies grouped by category.

### `xairas-cve stack remove --name <name>`

### `xairas-cve stack update --name <name> --version <version>`

### `xairas-cve scan`

One-shot scan. Checks all technologies, reports vulnerabilities, sends Telegram alerts for new ones.

### `xairas-cve monitor [--interval <interval>]`

Continuous monitoring. Runs scan at the configured interval and sends Telegram alerts for new CVEs only.

### `xairas-cve history scans`

### `xairas-cve history cves`

## Data Sources

- **[OSV.dev](https://osv.dev)** — free, no API key required. Covers npm, PyPI, Go, Maven, Ubuntu, Debian, and many more.
- **[NVD](https://nvd.nist.gov)** — free, optional API key for higher rate limits. Covers hardware, vendor software, and anything with a CPE.

## Running as a Service
```bash
# Using PM2
pm2 start "xairas-cve monitor" --name xairas-cve

# Using systemd (create /etc/systemd/system/xairas-cve.service)
# ExecStart=/usr/bin/xairas-cve monitor
# Restart=always
```

## Data Storage

All data is stored locally in `~/.xairas-cve/`:

- `config.json` — configuration and tech stack
- `data.db` — SQLite database for deduplication and scan history

## License

MIT

## Author

**Amir Rezvani** — [amirzvni@gmail.com](mailto:amirzvni@gmail.com)
