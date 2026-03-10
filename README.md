# homelab-sentinel

> **⚠️ Pre-release software (v0.x)** — APIs, config format, and commands may change between versions.

A Telegram bot for real-time server monitoring and active response, built on top of Wazuh 4.x.

Provides read-only status commands and TOTP-protected active response commands via Telegram, plus a daily digest covering system health, security events, services, and Bitcoin node status.

## Features

- **System monitoring** — uptime, load, memory, disk
- **Wazuh integration** — agent status, alert queries via OpenSearch indexer, rule lookups
- **Active response** — ban/unblock IPs, open/close ports, lockdown/restore firewall
- **TOTP protection** — all destructive commands require a time-based OTP code
- **Daily digest** — automated morning summary at configurable time
- **Bitcoin node** — block height sync check, fee rates, LND channel health
- **Uptime Kuma** — service monitor rollup from status page API

## Commands

### Read-Only
| Command | Description |
|---|---|
| `/status` | System overview + 24h active response events |
| `/top` | Top triggered Wazuh rules (24h) |
| `/alerts` | Recent Level 8+ alerts |
| `/event [id]` | Full detail on a specific alert |
| `/agents` | Wazuh agent status |
| `/blocked` | Currently banned IPs + recent ban history |
| `/disk` | Disk usage |
| `/uptime` | System uptime |
| `/services` | Docker container status |
| `/digest` | Send daily digest on demand |

### Active Response (TOTP required)
| Command | Description |
|---|---|
| `/block [ip] [totp]` | Block an IP via iptables |
| `/unblock [ip] [totp]` | Remove IP block |
| `/closeport [port] [totp]` | Close a UFW port |
| `/openport [port] [totp]` | Open a UFW port |
| `/lockdown [totp]` | Deny all inbound/outbound except SSH |
| `/restore [totp]` | Restore pre-lockdown firewall rules |
| `/restart [target] [totp]` | Restart wazuh manager or agent |
| `/syscheck [agent_id] [totp]` | Trigger integrity scan |
| `/shutdown [totp]` | Shutdown the server |

## Architecture

```
┌─────────────────────────────────────────┐
│  masterserver                           │
│                                         │
│  telegram-commander.py (systemd)        │
│    ├── Wazuh Manager API :55000         │
│    ├── OpenSearch Indexer :9200         │
│    ├── Uptime Kuma :3001                │
│    └── minibolt.local                  │
│          ├── mempool :4081              │
│          └── LND REST :8080            │
│                                         │
│  notify-ban.py (active-response/bin)   │
│    └── Fires on Wazuh active response  │
└─────────────────────────────────────────┘
```

## Installation

### 1. Clone and configure

```bash
git clone https://github.com/atamti/homelab-sentinel
cd homelab-sentinel
```

### 2. Deploy

```bash
# Preview what will happen
./deploy.sh --dry-run

# Deploy to localhost (run on the server)
./deploy.sh

# Or deploy to a remote server
./deploy.sh user@host
```

## Wazuh Configuration

homelab-sentinel depends on Wazuh being configured with the correct rules and active response entries. The [`wazuh/`](wazuh/README.md) directory contains reference configurations:

- **`local_rules.xml.example`** — per-agent port change whitelisting and escalation rules
- **`ossec-active-response.xml.example`** — command definitions, active response rules with timeout rationale, and IP whitelist
- **`generate_rules.py`** — generates port whitelist rules from `homelab-sentinel.yaml` so you can maintain ports in YAML and produce merge-ready XML

These are reference files — merge them selectively into your existing Wazuh config. See [`wazuh/README.md`](wazuh/README.md) for details.

The deploy script will:
- Copy `sentinel/` shared library to `/var/ossec/integrations/sentinel/`
- Copy scripts to their Wazuh destinations
- Install the systemd service
- Seed `/etc/homelab-sentinel.env` from `.env.example` if it doesn't exist

### 3. Configure environment

```bash
sudo nano /etc/homelab-sentinel.env
```

Fill in your real Telegram bot token, chat IDs, Wazuh API credentials, etc.

### 4. Start the service

```bash
sudo systemctl enable homelab-sentinel
sudo systemctl start homelab-sentinel
```

### 5. LND readonly macaroon

On your Bitcoin node:

```bash
sudo base64 -w 0 /data/lnd/data/chain/bitcoin/mainnet/readonly.macaroon
```

Paste the output as `LND_READONLY_MACAROON_B64` in `/etc/homelab-sentinel.env`.

### 6. Syntax check before restart

```bash
sudo /var/ossec/framework/python/bin/python3 -m py_compile \
  /var/ossec/integrations/telegram-commander.py && echo "OK"
```

## Wazuh ossec.conf configuration

Add the integration and active response entries to `/var/ossec/etc/ossec.conf`. A ready-to-paste snippet is provided in [`ossec-snippet.conf`](ossec-snippet.conf):

```bash
# Review the snippet
cat ossec-snippet.conf

# Edit ossec.conf and paste the blocks inside <ossec_config>
sudo nano /var/ossec/etc/ossec.conf

# Restart the manager
sudo systemctl restart wazuh-manager
```

The deploy script will warn you if these entries are missing.

## Security notes

- Secrets are loaded from `/etc/homelab-sentinel.env` (mode 600, root-owned)
- All destructive commands require a TOTP code (valid 30s window)
- Only the configured `TELEGRAM_AUTHORIZED_USER` can issue commands
- The LND readonly macaroon grants query access only — no payment or channel management capability
- The bot runs as root (required for iptables). A future improvement would be a dedicated service user with specific sudo rules.

## Dependencies

```bash
/var/ossec/framework/python/bin/pip install requests pyotp
```

## Logs

- Commander activity: `/var/ossec/logs/commander-errors.log`
- Ban history: `/var/ossec/logs/ban-history.log`
- Active response: `/var/ossec/logs/active-responses.log`
