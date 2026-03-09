# wazuh-commander

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
git clone https://github.com/yourusername/wazuh-commander
cd wazuh-commander

sudo cp .env.example /etc/wazuh-commander.env
sudo chmod 600 /etc/wazuh-commander.env
sudo nano /etc/wazuh-commander.env
```

### 2. Deploy scripts

```bash
sudo cp telegram-commander.py /var/ossec/integrations/telegram-commander.py
sudo chmod 750 /var/ossec/integrations/telegram-commander.py

sudo cp notify-ban.py /var/ossec/active-response/bin/notify-ban.py
sudo chmod 750 /var/ossec/active-response/bin/notify-ban.py
sudo chown root:wazuh /var/ossec/active-response/bin/notify-ban.py
```

### 3. Install systemd service

```bash
sudo cp systemd/wazuh-telegram-bot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable wazuh-telegram-bot
sudo systemctl start wazuh-telegram-bot
```

### 4. Create required log files

```bash
sudo touch /var/ossec/logs/ban-history.log
sudo chown root:wazuh /var/ossec/logs/ban-history.log
sudo chmod 664 /var/ossec/logs/ban-history.log
```

### 5. LND readonly macaroon

On your Bitcoin node:

```bash
sudo base64 -w 0 /data/lnd/data/chain/bitcoin/mainnet/readonly.macaroon
```

Paste the output as `LND_READONLY_MACAROON_B64` in `/etc/wazuh-commander.env`.

### 6. Syntax check before restart

```bash
sudo /var/ossec/framework/python/bin/python3 -m py_compile \
  /var/ossec/integrations/telegram-commander.py && echo "OK"
```

## Wazuh ossec.conf configuration

Register `notify-ban.py` as a command and add active response rules. See the Wazuh documentation for `ossec.conf` active response configuration.

## Security notes

- Secrets are loaded from `/etc/wazuh-commander.env` (mode 600, root-owned)
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
