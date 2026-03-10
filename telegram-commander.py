#!/usr/bin/env python3
"""
telegram-commander.py - Homelab Sentinel Telegram Command Bot
=============================================================
Provides read-only status commands and TOTP-protected active response
commands via Telegram. Queries Wazuh Manager API, OpenSearch indexer,
LND REST API, local mempool, and Uptime Kuma.

Also sends a daily digest at DIGEST_TIME.

Configuration:
  Copy .env.example to .env and fill in values.
  The systemd unit injects these as environment variables.

Deployment:
  sudo cp telegram-commander.py /var/ossec/integrations/telegram-commander.py
  sudo chmod 750 /var/ossec/integrations/telegram-commander.py
  sudo systemctl restart homelab-sentinel
"""

import base64
import os
import re
import signal
import subprocess
import sys
import time
import traceback

sys.path.insert(0, os.environ.get("SENTINEL_LIB", os.path.dirname(os.path.abspath(__file__))))

import pyotp
import requests

from sentinel import telegram, wazuh
from sentinel.config import VERSION, env, get_cfg, require_env
from sentinel.sanitize import sanitize, summarize_docker_output
from sentinel.telegram import esc
from sentinel.validate import validated_ip, validated_port

# ══════════════════════════════════════════════════════════════════════════════
# Configuration — loaded from environment variables
# ══════════════════════════════════════════════════════════════════════════════

BOT_TOKEN = require_env("TELEGRAM_BOT_TOKEN")
AUTHORIZED_USER = require_env("TELEGRAM_AUTHORIZED_USER")
TOTP_SECRET = require_env("TOTP_SECRET")
DIGEST_CHAT_ID = require_env("TELEGRAM_AUTHORIZED_USER")  # same as authorized user
FULL_LOG_CHAT_ID = env("TELEGRAM_FULL_LOG_CHAT_ID")
CRITICAL_CHAT_ID = env("TELEGRAM_CRITICAL_CHAT_ID")

WAZUH_API = env("WAZUH_API_URL", "https://127.0.0.1:55000")
WAZUH_USER = require_env("WAZUH_API_USER")
WAZUH_PASS = require_env("WAZUH_API_PASS")

INDEXER_URL = env("INDEXER_URL", "https://localhost:9200")
INDEXER_USER = require_env("INDEXER_USER")
INDEXER_PASS = require_env("INDEXER_PASS")

LND_MACAROON_B64 = require_env("LND_READONLY_MACAROON_B64")

LOG_FILE = env("COMMANDER_LOG", "/var/ossec/logs/commander-errors.log")


# ══════════════════════════════════════════════════════════════════════════════
# Logging
# ══════════════════════════════════════════════════════════════════════════════


def log(msg: str) -> None:
    entry = f"{time.ctime()}: {msg}\n"
    print(entry, end="")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(entry)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# Core Helpers
# ══════════════════════════════════════════════════════════════════════════════


def send_message(chat_id: str, text: str) -> None:
    """Send a Telegram message, sanitizing and chunking if needed."""
    err = telegram.send(BOT_TOKEN, chat_id, sanitize(text))
    if err:
        log(f"send failed: {err}")


def notify_all(text: str) -> None:
    """Send a notification to commander, full-log, and critical channels."""
    seen: set[str] = set()
    for cid in (DIGEST_CHAT_ID, FULL_LOG_CHAT_ID, CRITICAL_CHAT_ID):
        if cid and cid not in seen:
            seen.add(cid)
            send_message(cid, text)


# ── Wazuh token cache ────────────────────────────────────────────────────────
_wazuh_token: str | None = None
_wazuh_token_exp: float = 0


def get_wazuh_token() -> str | None:
    global _wazuh_token, _wazuh_token_exp
    if _wazuh_token and time.time() < _wazuh_token_exp:
        return _wazuh_token
    token = wazuh.get_token(WAZUH_API, WAZUH_USER, WAZUH_PASS)
    if token:
        _wazuh_token = token
        _wazuh_token_exp = time.time() + 840  # 14 min (tokens last ~15 min)
    return token


def wazuh_get(endpoint: str, token: str) -> dict:
    return wazuh.api_get(WAZUH_API, endpoint, token)


def indexer_search(query: dict) -> dict:
    return wazuh.indexer_search(INDEXER_URL, INDEXER_USER, INDEXER_PASS, query)


def get_lnd_headers() -> dict:
    macaroon = base64.b64decode(LND_MACAROON_B64).hex()
    return {"Grpc-Metadata-macaroon": macaroon}


def _alert_config() -> dict:
    """Return the alert_output config section."""
    return get_cfg().get("alert_output", {})


def _bitcoin_config() -> dict:
    """Return the bitcoin config section."""
    return get_cfg().get("bitcoin", {})


def score_channel_health(channels: list) -> tuple[str, str]:
    """Evaluate LND channel list and return (emoji, label).

    - Any inactive channels → 🔴 + count
    - Any channel with local ratio < min or > max → 🟡 + count/percentages
    - All active, ratios in range → 🟢 healthy
    """
    cfg = _bitcoin_config().get("channel_health", {})
    min_ratio = cfg.get("min_local_ratio", 0.15)
    max_ratio = cfg.get("max_local_ratio", 0.85)
    total = len(channels)

    inactive = sum(1 for c in channels if not c.get("active"))
    if inactive:
        return "\U0001f534", f"{inactive}/{total} channel{'s' if inactive != 1 else ''} offline"

    imbalanced = []
    for c in channels:
        capacity = int(c.get("capacity", 1))
        local = int(c.get("local_balance", 0))
        if capacity > 0:
            ratio = local / capacity
            if ratio < min_ratio or ratio > max_ratio:
                imbalanced.append(round(ratio * 100))

    if imbalanced:
        pcts = ", ".join(f"{p}%" for p in imbalanced)
        return "\U0001f7e1", f"{len(imbalanced)}/{total} need rebalancing ({pcts})"

    return "\U0001f7e2", f"{total} channel{'s' if total != 1 else ''} healthy"


def lnd_get(endpoint: str) -> dict:
    lnd_url = get_cfg()["integrations"]["lnd"]["rest_url"]
    try:
        r = requests.get(f"{lnd_url}{endpoint}", headers=get_lnd_headers(), verify=False, timeout=10)
        return r.json()
    except Exception:
        return {}


def mempool_get(endpoint: str, public: bool = False) -> dict | str:
    try:
        local_url = get_cfg()["integrations"]["bitcoin"]["mempool_local"]
        base = "https://mempool.space" if public else local_url
        # Skip SSL verification for local mempool (self-signed cert)
        r = requests.get(f"{base}{endpoint}", timeout=10, verify=public)
        if not r.ok:
            return "error"
        try:
            return r.json()
        except Exception:
            # Only return plain text (e.g. block height number), not HTML
            text = r.text.strip()
            if len(text) < 200 and "<" not in text:
                return text
            return "error"
    except Exception:
        return "error"


def get_uptime_kuma_status() -> tuple[list, list]:
    try:
        kuma_url = get_cfg()["integrations"]["uptime_kuma"]["url"]
        r = requests.get(kuma_url, timeout=10)
        data = r.json()
        monitors = data.get("publicGroupList", [])

        # Build id→name map
        id_name: dict[int, str] = {}
        for group in monitors:
            for monitor in group.get("monitorList", []):
                id_name[monitor.get("id")] = monitor.get("name", "?")

        # Fetch heartbeat data for actual up/down status
        heartbeat_url = kuma_url.replace("/api/status-page/", "/api/status-page/heartbeat/")
        hb = requests.get(heartbeat_url, timeout=10).json()
        hb_list = hb.get("heartbeatList", {})

        up, down = [], []
        for mid, name in id_name.items():
            beats = hb_list.get(str(mid), [])
            if beats and beats[-1].get("status") == 1:
                up.append(name)
            else:
                down.append(name)
        return up, down
    except Exception:
        return [], []


def format_table_row(rule_id, level, count, desc) -> str:
    """Format a rule as a compact 2-line list entry."""
    words = str(desc).split()
    line1, line2 = [], []
    length = 0
    for word in words:
        if length + len(word) + 1 <= 35:
            line1.append(word)
            length += len(word) + 1
        else:
            line2.append(word)

    desc_fmt = " ".join(line1)
    if line2:
        line2_str = " ".join(line2)
        if len(line2_str) > 35:
            line2_str = line2_str[:32].rsplit(" ", 1)[0] + "..."
        desc_fmt += "\n" + line2_str

    return f"<b>{esc(str(rule_id))}</b> (L{level}) \u00d7{count}\n{esc(desc_fmt)}\n\n"


# esc() imported from sentinel.telegram


# ══════════════════════════════════════════════════════════════════════════════
# System Info Helpers (shared by /status and /digest)
# ══════════════════════════════════════════════════════════════════════════════


def get_system_stats() -> dict:
    """Gather local system metrics."""
    load_str = subprocess.getoutput("cat /proc/loadavg | awk '{print $1, $2, $3}'")
    try:
        load_1m = float(load_str.split()[0])
    except (ValueError, IndexError):
        load_1m = 0.0
    try:
        nproc = int(subprocess.getoutput("nproc"))
    except ValueError:
        nproc = 1
    mem_pct_str = subprocess.getoutput("free | grep Mem | awk '{printf \"%.0f\", $3/$2 * 100}'")
    try:
        mem_pct = float(mem_pct_str)
    except ValueError:
        mem_pct = 0.0
    disk_pct_str = subprocess.getoutput("df / | tail -1 | awk '{print $5}'").rstrip("%")
    try:
        disk_pct = float(disk_pct_str)
    except ValueError:
        disk_pct = 0.0
    # CPU temperature — try thermal zones then lm-sensors
    cpu_temp = None
    try:
        temp_str = subprocess.getoutput(
            "cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | sort -rn | head -1"
        ).strip()
        if temp_str.isdigit():
            cpu_temp = int(temp_str) / 1000.0
    except Exception:
        pass
    if cpu_temp is None:
        try:
            raw = subprocess.getoutput(
                "sensors 2>/dev/null | grep -oP '\\+\\K[0-9.]+(?=°C)' | sort -rn | head -1"
            ).strip()
            if raw:
                cpu_temp = float(raw)
        except Exception:
            pass
    return {
        "uptime": subprocess.getoutput("uptime -p"),
        "load": load_str,
        "load_1m": load_1m,
        "nproc": nproc,
        "mem": subprocess.getoutput("free -h | grep Mem | awk '{print $3 \"/\" $2}'"),
        "mem_pct": mem_pct,
        "disk": subprocess.getoutput('df -h / | tail -1 | awk \'{print $5, "used (" $3 "/" $2 ")"}\''),
        "disk_pct": disk_pct,
        "cpu_temp": cpu_temp,
        "banned": subprocess.getoutput("iptables -L INPUT -n | grep -c DROP").strip(),
    }


def parse_ban_history() -> dict[str, int]:
    """Parse 24h ban history log and return {rule_id: count}."""
    ban_log = get_cfg()["active_response"]["ban_log"]
    ar_log = subprocess.getoutput(
        f"grep 'Banned' {ban_log} | awk -v d=\"$(date -d '24 hours ago' '+%Y/%m/%d %H:%M:%S')\" '$0 > d'"
    )
    rule_counts: dict[str, int] = {}
    for line in ar_log.splitlines():
        match = re.search(r"\(Rule (\w+)\)", line)
        if match:
            rid = match.group(1)
            rule_counts[rid] = rule_counts.get(rid, 0) + 1
    return rule_counts


def lookup_rules(rule_ids: list[str], token: str) -> dict[str, dict]:
    """Batch-fetch rule metadata from Wazuh API. Returns {id: {level, description}}."""
    if not rule_ids or not token:
        return {}
    ids_param = ",".join(rule_ids)
    data = wazuh_get(f"/rules?rule_ids={ids_param}", token)
    result: dict[str, dict] = {}
    for item in data.get("data", {}).get("affected_items", []):
        rid = str(item.get("id", ""))
        result[rid] = {
            "level": item.get("level", "?"),
            "description": item.get("description", "Unknown"),
        }
    return result


# ══════════════════════════════════════════════════════════════════════════════
# TOTP Authentication
# ══════════════════════════════════════════════════════════════════════════════


def verify_totp(code: str) -> bool:
    return pyotp.TOTP(TOTP_SECRET).verify(code, valid_window=1)


def require_totp(chat_id: str, arg: str) -> tuple[str | None, bool]:
    parts = arg.rsplit(" ", 1)
    if len(parts) < 2:
        log(f"totp: missing code (chat_id={chat_id})")
        send_message(chat_id, "⛔ TOTP required. Usage: /command [args] [totp]")
        return None, False
    actual_arg, code = parts[0], parts[1]
    if not verify_totp(code):
        log(f"totp: invalid code (chat_id={chat_id})")
        send_message(chat_id, "⛔ Invalid or expired TOTP code")
        return None, False
    return actual_arg, True


def require_totp_only(chat_id: str, arg: str) -> bool:
    code = arg.strip()
    if not code:
        log(f"totp: missing code (chat_id={chat_id})")
        send_message(chat_id, "⛔ TOTP required. Usage: /command [totp]")
        return False
    if not verify_totp(code):
        log(f"totp: invalid code (chat_id={chat_id})")
        send_message(chat_id, "⛔ Invalid or expired TOTP code")
        return False
    return True


# ══════════════════════════════════════════════════════════════════════════════
# Read-Only Commands
# ══════════════════════════════════════════════════════════════════════════════


def cmd_help(chat_id: str) -> None:
    text = f"<b>Homelab Sentinel</b> <i>v{VERSION}</i>\n\n"
    text += "<b>Read-Only:</b>\n"
    text += "/status - System overview + active response stats\n"
    text += "/event [id] [totp] - Full detail on a specific alert\n"
    text += "/agents - List all agents\n"
    text += "/alerts - Recent high-level alerts (Level 8+)\n"
    text += "/top - Top triggered rules (24h)\n"
    text += "/blocked [ip|page] - Blocked IPs + ban history\n"
    text += "/disk - Disk usage\n"
    text += "/uptime - System uptime\n"
    text += "/services - Docker container status\n"
    text += "/digest - Send daily digest now\n\n"
    text += "<b>Active Response (TOTP required):</b>\n"
    text += "/block [ip] [totp] - Block an IP\n"
    text += "/unblock [ip] [totp] - Unblock an IP\n"
    text += "/closeport [port] [totp] - Close a UFW port\n"
    text += "/openport [port] [totp] - Open a UFW port\n"
    text += "/lockdown [totp] - Deny all except SSH\n"
    text += "/restore [totp] - Restore normal firewall\n"
    text += "/restart [target] [totp] - Restart service or agent\n"
    text += "/syscheck [agent_id] [totp] - Run integrity scan\n"
    text += "/shutdown [totp] - Shutdown server\n\n"
    text += "/help - This menu"
    send_message(chat_id, text)


def cmd_status(chat_id: str) -> None:
    token = get_wazuh_token()
    if not token:
        send_message(chat_id, "Failed to authenticate with Wazuh API")
        return

    agents = wazuh_get("/agents/summary/status", token)
    agent_data = agents.get("data", {}).get("connection", {})
    active = agent_data.get("active", 0)
    disconnected = agent_data.get("disconnected", 0)
    total = agent_data.get("total", 0)

    stats = get_system_stats()
    rule_counts = parse_ban_history()

    rule_table = ""
    if rule_counts:
        rule_table = "\n<b>Active Response Events (24h)</b>\n\n"
        rules_meta = lookup_rules(list(rule_counts.keys()), token)
        for rid, count in sorted(rule_counts.items(), key=lambda x: -(rules_meta.get(x[0], {}).get("level", 0))):
            meta = rules_meta.get(rid, {})
            level = meta.get("level", "?")
            rule_table += f"<b>{rid}</b> (L{level}) \u00d7{count}\n"

    text = "<b>System Status</b>\n\n"
    text += f"<b>Uptime:</b> {esc(stats['uptime'])}\n"
    text += f"<b>Load (1m/5m/15m):</b> {esc(stats['load'])}\n"
    text += f"<b>Memory:</b> {esc(stats['mem'])}\n"
    text += f"<b>Disk:</b> {esc(stats['disk'])}\n\n"
    text += f"<b>Agents:</b> {active} active / {disconnected} disconnected / {total} total\n"
    text += f"<b>Banned IPs:</b> {esc(stats['banned'])} currently active\n"
    text += rule_table
    send_message(chat_id, text)


def cmd_event(chat_id: str, arg: str) -> None:
    alert_id, valid = require_totp(chat_id, arg)
    if not valid:
        return
    alert_id = alert_id.strip()
    if not alert_id:
        send_message(chat_id, "Usage: /event [alert_id] [totp]")
        return

    result = indexer_search({"query": {"term": {"id": alert_id}}})
    hits = result.get("hits", {}).get("hits", [])

    if not hits:
        send_message(chat_id, f"No alert found with ID: {alert_id}")
        return

    a = hits[0].get("_source", {})
    rule = a.get("rule", {})
    agent = a.get("agent", {})
    geo = a.get("GeoLocation", {})
    data_fields = a.get("data", {})
    full_log = a.get("full_log", "")

    text = "<b>Alert Detail</b>\n\n"
    text += f"<b>ID:</b> {a.get('id')}\n"
    text += f"<b>Level:</b> {rule.get('level')}\n"
    text += f"<b>Rule:</b> {rule.get('id')} - {rule.get('description')}\n"
    text += f"<b>Agent:</b> {agent.get('id', '?')}\n"
    text += f"<b>Time:</b> {a.get('timestamp', '')[:19]}\n"
    text += f"<b>Groups:</b> {', '.join(rule.get('groups', []))}\n"

    if geo:
        country = geo.get("country_name", "")
        loc = geo.get("location", {})
        text += f"<b>GeoLocation:</b> {country} ({loc.get('lat')}, {loc.get('lon')})\n"

    if data_fields:
        text += "\n<b>Data:</b>\n"
        for k, v in data_fields.items():
            text += f"  {esc(str(k))}: {esc(str(v))}\n"

    if full_log:
        text += f"\n<b>Log:</b> <pre>{esc(full_log[:150])}...</pre>"

    send_message(chat_id, text)


def cmd_agents(chat_id: str) -> None:
    token = get_wazuh_token()
    if not token:
        send_message(chat_id, "Failed to authenticate with Wazuh API")
        return

    data = wazuh_get("/agents?limit=50", token)
    agents = data.get("data", {}).get("affected_items", [])

    text = "<b>Agents</b>\n\n"
    for a in agents:
        emoji = "🟢" if a.get("status") == "active" else "🔴"
        name = a.get("name", "unknown")
        agent_id = a.get("id", "?")
        ip = a.get("ip", "?")
        os_name = a.get("os", {}).get("name", "?")
        text += f"{emoji} <b>{esc(name)}</b> (ID: {agent_id})\n"
        text += f"   IP: {ip} | OS: {esc(os_name)}\n"

    send_message(chat_id, text)


def cmd_alerts(chat_id: str) -> None:
    query = {"size": 10, "sort": [{"timestamp": {"order": "desc"}}], "query": {"range": {"rule.level": {"gte": 8}}}}
    result = indexer_search(query)
    hits = result.get("hits", {}).get("hits", [])

    if not hits:
        send_message(chat_id, "No recent high-level alerts")
        return

    text = "<b>Recent Alerts (Level 8+)</b>\n\n"
    for h in hits:
        a = h.get("_source", {})
        rule = a.get("rule", {})
        agent = a.get("agent", {})
        agent_id = agent.get("id", "?")
        text += f"L{rule.get('level')} | Agent {agent_id} | Rule {rule.get('id')} | {a.get('timestamp', '')[:19]}\n"
        text += f"Ref: <code>{a.get('id')}</code>\n\n"

    send_message(chat_id, text)


def cmd_top(chat_id: str) -> None:
    query = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": "now-24h"}}},
        "aggs": {
            "top_rules": {
                "terms": {"field": "rule.id", "size": 10, "order": {"_count": "desc"}},
                "aggs": {
                    "rule_desc": {"terms": {"field": "rule.description", "size": 1}},
                    "rule_level": {"terms": {"field": "rule.level", "size": 1}},
                },
            }
        },
    }
    result = indexer_search(query)
    buckets = result.get("aggregations", {}).get("top_rules", {}).get("buckets", [])

    if not buckets:
        send_message(chat_id, "No alert data found in last 24h")
        return

    text = "<b>Top Triggered Rules (24h)</b>\n\n"
    for bucket in buckets:
        rule_id = bucket.get("key", "?")
        count = bucket.get("doc_count", 0)
        desc_b = bucket.get("rule_desc", {}).get("buckets", [])
        level_b = bucket.get("rule_level", {}).get("buckets", [])
        desc = desc_b[0].get("key", "N/A") if desc_b else "N/A"
        level = level_b[0].get("key", "?") if level_b else "?"
        text += format_table_row(rule_id, level, count, desc)

    send_message(chat_id, text)


def cmd_blocked(chat_id: str, arg: str = "") -> None:
    arg = arg.strip()

    # IP lookup mode
    if arg and not arg.isdigit():
        try:
            ip = validated_ip(arg)
        except ValueError:
            send_message(chat_id, f"⛔ Invalid IP address: {esc(arg)}")
            return
        current = subprocess.getoutput(f"iptables -L INPUT -n | grep DROP | grep -F '{ip}'")
        history = subprocess.getoutput(f"grep -F '{ip}' /var/ossec/logs/ban-history.log | tail -20")
        send_message(
            chat_id,
            f"<b>Lookup: {esc(ip)}</b>\n\n"
            f"<b>Active rules:</b>\n<pre>{esc(current) or 'Not currently banned'}</pre>\n\n"
            f"<b>Ban history:</b>\n<pre>{esc(history) or 'No history found'}</pre>",
        )
        return

    # Pagination mode — default page 1, 20 per page
    page = max(1, int(arg)) if arg.isdigit() else 1
    per_page = 20
    skip = (page - 1) * per_page

    current = subprocess.getoutput(f"iptables -L INPUT -n | grep DROP | tail -n +{skip + 1} | head -{per_page}")
    total = subprocess.getoutput("iptables -L INPUT -n | grep -c DROP").strip()

    recent = subprocess.getoutput(f"tail -{per_page + skip} /var/ossec/logs/ban-history.log | head -{per_page}")

    send_message(chat_id, f"<b>Currently Banned (page {page}, {total} total)</b>\n<pre>{esc(current) or 'None'}</pre>")
    send_message(chat_id, f"<b>Recent Bans (page {page})</b>\n<pre>{esc(recent) or 'None'}</pre>")


def cmd_disk(chat_id: str) -> None:
    raw = subprocess.getoutput("df -h --exclude-type=tmpfs --exclude-type=devtmpfs")
    lines = raw.splitlines()
    out = [f"{'Drive':<10} {'Size':>5} {'Used':>5} {'Avail':>5} {'Use%':>5}  Mounted on"]
    for i, line in enumerate(lines[1:], 1):
        cols = line.split()
        if len(cols) >= 6:
            mount = " ".join(cols[5:])
            out.append(f"{'Drive ' + str(i):<10} {cols[1]:>5} {cols[2]:>5} {cols[3]:>5} {cols[4]:>5}  {mount}")
    send_message(chat_id, f"<b>Disk Usage</b>\n\n<pre>{esc(chr(10).join(out))}</pre>")


def cmd_uptime(chat_id: str) -> None:
    send_message(chat_id, f"<pre>{esc(subprocess.getoutput('uptime'))}</pre>")


def cmd_services(chat_id: str) -> None:
    result = subprocess.getoutput(
        "DOCKER_HOST=unix:///run/user/1001/docker.sock docker ps -a --format 'table {{.Names}}\t{{.Status}}' 2>&1"
    )
    summary = summarize_docker_output(result)
    send_message(chat_id, f"<b>Docker Services</b>\n\n{summary}")


# ══════════════════════════════════════════════════════════════════════════════
# Daily Digest
# ══════════════════════════════════════════════════════════════════════════════


def _rag(value: float, amber: float, red: float) -> str:
    """Return 🟢/🟡/🔴 based on value vs thresholds."""
    if value >= red:
        return "\U0001f534"
    if value >= amber:
        return "\U0001f7e1"
    return "\U0001f7e2"


def _simplify_service_name(name: str) -> str:
    """Strip common Uptime Kuma prefixes and URL parts for cleaner display."""
    for prefix in ("HTTP - ", "HTTPS - ", "TCP Port - ", "Ping - ", "Docker Container - ", "DNS - "):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    name = re.sub(r"^https?://", "", name)
    name = re.sub(r":\d+(/.*)?$", "", name)
    name = re.sub(r"\.(local|lan|home|internal)$", "", name, flags=re.IGNORECASE)
    return name


def _valid_height(h) -> bool:
    """Check if a mempool height response is a usable number."""
    return isinstance(h, (int, float)) or (isinstance(h, str) and h.isdigit())


def cmd_digest(chat_id: str) -> None:
    log("digest: starting")
    lines = ["<b>\u2600\ufe0f Daily Digest</b>\n"]
    cfg = get_cfg()

    # ── System ───────────────────────────────────────────────────────
    if cfg["digest"]["sections"]["system"]:
        stats = get_system_stats()
        th = cfg["digest"]["thresholds"]

        load_amber = th["load_per_core_amber"] * stats["nproc"]
        load_red = th["load_per_core_red"] * stats["nproc"]
        load_rag = _rag(stats["load_1m"], load_amber, load_red)
        mem_rag = _rag(stats["mem_pct"], th["memory_amber"], th["memory_red"])
        disk_rag = _rag(stats["disk_pct"], th["disk_amber"], th["disk_red"])

        lines.append("<b>\U0001f5a5 System</b>")
        lines.append(f"Uptime: {esc(stats['uptime'])}")
        lines.append(f"{load_rag} Load: {esc(stats['load'])}")
        lines.append(f"{mem_rag} Memory: {esc(stats['mem'])} ({stats['mem_pct']:.0f}%)")
        if stats["cpu_temp"] is not None:
            temp_rag = _rag(stats["cpu_temp"], th["cpu_temp_amber"], th["cpu_temp_red"])
            lines.append(f"{temp_rag} CPU temp: {stats['cpu_temp']:.0f}°C")
        lines.append(f"{disk_rag} Disk: {esc(stats['disk'])}\n")

    # ── Agents ───────────────────────────────────────────────────────
    if cfg["digest"]["sections"]["agents"]:
        token = get_wazuh_token()
        agent_data = {}
        disconnected_ids = []
        if token:
            agents = wazuh_get("/agents/summary/status", token)
            agent_data = agents.get("data", {}).get("connection", {})
            if agent_data.get("disconnected", 0):
                disc_resp = wazuh_get("/agents?status=disconnected", token)
                disconnected_ids = [a.get("id", "?") for a in disc_resp.get("data", {}).get("affected_items", [])]

        active_agents = agent_data.get("active", "?")
        disconnected = agent_data.get("disconnected", 0)
        if disconnected:
            ids = ", ".join(disconnected_ids) if disconnected_ids else str(disconnected)
            suffix = "s" if disconnected != 1 else ""
            agent_line = f"\U0001f7e1 Agents: {active_agents} active, {disconnected} disconnected (ID{suffix}: {ids})"
        else:
            agent_line = f"\U0001f7e2 Agents: {active_agents} active"
        lines.append(agent_line + "\n")

    # ── Security ─────────────────────────────────────────────────────
    if cfg["digest"]["sections"]["security"]:
        if not cfg["digest"]["sections"]["system"]:
            stats = get_system_stats()
        rule_counts = parse_ban_history()
        total_bans = sum(rule_counts.values())
        lines.append("<b>\U0001f6e1 Security</b>")
        lines.append(f"Bans (last 24h): {total_bans} | Active: {stats['banned']}")

        if not cfg["digest"]["sections"]["agents"]:
            token = get_wazuh_token()
        if rule_counts and token:
            all_rids = list(rule_counts.keys())
            rules_meta = lookup_rules(all_rids, token)
            sorted_rids = sorted(all_rids, key=lambda rid: -(rules_meta.get(rid, {}).get("level", 0)))[:5]
            for rid in sorted_rids:
                count = rule_counts[rid]
                meta = rules_meta.get(rid, {})
                level = meta.get("level", "?")
                desc = meta.get("description", "Unknown")
                if len(str(desc)) > 20:
                    desc = str(desc)[:17].rsplit(" ", 1)[0] + "..."
                lines.append(f"  <b>{esc(str(rid))}</b> (L{level}) \u00d7{count} \u2014 {esc(desc)}")

        # Level 10+ by level descending
        result = indexer_search(
            {
                "size": 0,
                "query": {
                    "bool": {
                        "must": [{"range": {"timestamp": {"gte": "now-24h"}}}, {"range": {"rule.level": {"gte": 10}}}]
                    }
                },
                "aggs": {
                    "by_level": {
                        "terms": {"field": "rule.level", "size": 10, "order": {"_key": "desc"}},
                        "aggs": {"by_rule": {"terms": {"field": "rule.description", "size": 1}}},
                    }
                },
            }
        )
        buckets = result.get("aggregations", {}).get("by_level", {}).get("buckets", [])

        if buckets:
            lines.append("  Critical alerts (24h):")
            for b in buckets:
                level = b.get("key", "?")
                count = b.get("doc_count", 0)
                rule_b = b.get("by_rule", {}).get("buckets", [])
                desc = rule_b[0].get("key", "Unknown") if rule_b else "Unknown"
                if len(desc) > 20:
                    desc = desc[:17].rsplit(" ", 1)[0] + "..."
                lines.append(f"  L{level} \u00d7{count} \u2014 {esc(desc)}")
        else:
            lines.append("  No Level 10+ alerts \u2705")

        lines.append("")

    # ── Services ─────────────────────────────────────────────────────
    if cfg["digest"]["sections"]["services"] and cfg["integrations"]["uptime_kuma"]["enabled"]:
        up_list, down_list = get_uptime_kuma_status()
        lines.append("<b>\U0001f4e1 Services</b>")
        if down_list:
            names = ", ".join(esc(_simplify_service_name(n)) for n in down_list)
            lines.append(f"\U0001f534 Down: {names}")
        else:
            lines.append(f"\U0001f7e2 All {len(up_list)} services up")
        lines.append("")

    # ── Bitcoin ──────────────────────────────────────────────────────
    if cfg["digest"]["sections"]["bitcoin"] and cfg["integrations"]["bitcoin"]["enabled"]:
        lines.append("<b>\u20bf Bitcoin</b>")

        local_height = mempool_get("/api/blocks/tip/height")
        public_height = mempool_get("/api/blocks/tip/height", public=True)

        lag_threshold = cfg["digest"]["bitcoin_lag_warning_blocks"]
        local_ok = _valid_height(local_height)
        public_ok = _valid_height(public_height)

        if local_ok and public_ok:
            lag = int(public_height) - int(local_height)
            if lag > lag_threshold:
                lines.append(f"\U0001f7e1 Block height: {local_height} (lagging {lag} blocks)")
            else:
                lines.append(f"\U0001f7e2 Block height: {local_height}")
        elif public_ok:
            lines.append(f"\U0001f7e1 Block height: {public_height} (local node unreachable)")
        elif local_ok:
            lines.append(f"\U0001f7e1 Block height: {local_height} (public API unreachable)")
        else:
            lines.append("\U0001f534 Block height: unavailable")

        fees = mempool_get("/api/v1/fees/recommended")
        if isinstance(fees, dict):
            lines.append(
                f"Fees: {fees.get('fastestFee')} / "
                f"{fees.get('halfHourFee')} / "
                f"{fees.get('hourFee')} sat/vB (fast/30m/1h)"
            )

        if cfg["integrations"]["lnd"]["enabled"]:
            lnd_info = lnd_get("/v1/getinfo")
            if lnd_info:
                synced = "\U0001f7e2" if lnd_info.get("synced_to_chain") else "\U0001f7e1 not synced"
                lines.append(f"LND: {synced}")
            else:
                lines.append("LND: \U0001f534 unreachable")

            channels = lnd_get("/v1/channels")
            if channels:
                ch_list = channels.get("channels", [])
                if ch_list:
                    emoji, label = score_channel_health(ch_list)
                    lines.append(f"Channels: {emoji} {label}")

    send_message(chat_id, "\n".join(lines))
    log("digest: sent")


# ══════════════════════════════════════════════════════════════════════════════
# Active Response Commands (TOTP required)
# ══════════════════════════════════════════════════════════════════════════════


def cmd_block(chat_id: str, arg: str) -> None:
    ip, valid = require_totp(chat_id, arg)
    if not valid:
        return
    try:
        ip = validated_ip(ip)
    except ValueError:
        send_message(chat_id, f"\u26d4 Invalid IP address: {esc(ip)}")
        return
    subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    log(f"block: manually blocked {ip}")
    send_message(chat_id, f"\U0001f6ab Blocked {ip}")


def cmd_unblock(chat_id: str, arg: str) -> None:
    ip, valid = require_totp(chat_id, arg)
    if not valid:
        return
    try:
        ip = validated_ip(ip)
    except ValueError:
        send_message(chat_id, f"\u26d4 Invalid IP address: {esc(ip)}")
        return
    result = subprocess.run(
        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
        text=True,
    )
    log(f"unblock: {ip}")
    send_message(chat_id, f"\u2705 Unblocked {ip}\n{result.stderr}")


def cmd_closeport(chat_id: str, arg: str) -> None:
    port, valid = require_totp(chat_id, arg)
    if not valid:
        return
    try:
        port = validated_port(port)
    except ValueError:
        send_message(chat_id, f"\u26d4 Invalid port: {esc(port)}")
        return
    result = subprocess.run(["ufw", "deny", port], capture_output=True, text=True)
    send_message(chat_id, f"\U0001f6ab Port {port} closed\n{result.stdout}")


def cmd_openport(chat_id: str, arg: str) -> None:
    port, valid = require_totp(chat_id, arg)
    if not valid:
        return
    try:
        port = validated_port(port)
    except ValueError:
        send_message(chat_id, f"\u26d4 Invalid port: {esc(port)}")
        return
    result = subprocess.run(["ufw", "allow", port], capture_output=True, text=True)
    send_message(chat_id, f"\u2705 Port {port} opened\n{result.stdout}")


def cmd_lockdown(chat_id: str, arg: str) -> None:
    if not require_totp_only(chat_id, arg):
        return
    subprocess.getoutput("cp /etc/ufw/user.rules /etc/ufw/user.rules.pre-lockdown")
    subprocess.getoutput("cp /etc/ufw/user6.rules /etc/ufw/user6.rules.pre-lockdown")
    subprocess.getoutput("ufw --force reset")
    subprocess.getoutput("ufw default deny incoming")
    subprocess.getoutput("ufw default deny outgoing")
    subprocess.getoutput("ufw allow in 22/tcp")
    subprocess.getoutput("ufw allow out 53")
    subprocess.getoutput("ufw allow out 443/tcp")
    subprocess.getoutput("ufw --force enable")
    log("lockdown: activated")
    send_message(
        chat_id,
        "\U0001f512 LOCKDOWN ACTIVE\nAll ports closed except SSH.\nUse /restore [totp] to return to normal.",
    )


def cmd_restore(chat_id: str, arg: str) -> None:
    if not require_totp_only(chat_id, arg):
        return
    if not os.path.exists("/etc/ufw/user.rules.pre-lockdown"):
        send_message(chat_id, "⛔ No pre-lockdown backup found. Cannot restore.")
        return
    subprocess.getoutput("cp /etc/ufw/user.rules.pre-lockdown /etc/ufw/user.rules")
    subprocess.getoutput("cp /etc/ufw/user6.rules.pre-lockdown /etc/ufw/user6.rules")
    subprocess.getoutput("ufw --force enable")
    log("lockdown: restored")
    send_message(chat_id, "\u2705 Firewall restored to pre-lockdown state")


def cmd_restart(chat_id: str, arg: str) -> None:
    target, valid = require_totp(chat_id, arg)
    if not valid:
        return
    if target == "manager":
        subprocess.getoutput("systemctl restart wazuh-manager")
        send_message(chat_id, "\u2705 Wazuh manager restarted")
    elif target:
        token = get_wazuh_token()
        if token:
            wazuh_get(f"/agents/{target}/restart", token)
            send_message(chat_id, f"\u2705 Restart signal sent to agent {target}")
    else:
        send_message(chat_id, "Usage: /restart manager [totp] or /restart [agent_id] [totp]")


def cmd_syscheck(chat_id: str, arg: str) -> None:
    agent_id, valid = require_totp(chat_id, arg)
    if not valid:
        return
    token = get_wazuh_token()
    if token:
        requests.put(
            f"{WAZUH_API}/syscheck/{agent_id}", headers={"Authorization": f"Bearer {token}"}, verify=False, timeout=10
        )
        send_message(chat_id, f"\u2705 Integrity scan started on agent {agent_id}")


def cmd_shutdown(chat_id: str, arg: str) -> None:
    if not require_totp_only(chat_id, arg):
        return
    log("shutdown: initiated via Telegram")
    send_message(chat_id, "\u2622\ufe0f SHUTDOWN INITIATED \u2014 Server going down now")
    time.sleep(2)
    subprocess.Popen(["shutdown", "-h", "+0"])


# ══════════════════════════════════════════════════════════════════════════════
# Update Dispatcher
# ══════════════════════════════════════════════════════════════════════════════

COMMANDS = {
    "/help": lambda c, a: cmd_help(c),
    "/start": lambda c, a: cmd_help(c),
    "/status": lambda c, a: cmd_status(c),
    "/event": cmd_event,
    "/agents": lambda c, a: cmd_agents(c),
    "/alerts": lambda c, a: cmd_alerts(c),
    "/top": lambda c, a: cmd_top(c),
    "/blocked": cmd_blocked,
    "/disk": lambda c, a: cmd_disk(c),
    "/uptime": lambda c, a: cmd_uptime(c),
    "/services": lambda c, a: cmd_services(c),
    "/digest": lambda c, a: cmd_digest(c),
    "/block": cmd_block,
    "/unblock": cmd_unblock,
    "/closeport": cmd_closeport,
    "/openport": cmd_openport,
    "/lockdown": cmd_lockdown,
    "/restore": cmd_restore,
    "/restart": cmd_restart,
    "/syscheck": cmd_syscheck,
    "/shutdown": cmd_shutdown,
}


def process_update(update: dict) -> None:
    message = update.get("message", {})
    chat_id = str(message.get("chat", {}).get("id", ""))
    user_id = str(message.get("from", {}).get("id", ""))
    text = message.get("text", "").strip()

    if user_id != AUTHORIZED_USER:
        log(f"auth: unauthorized access attempt from user_id={user_id}")
        send_message(chat_id, "Unauthorized")
        return

    parts = text.split(maxsplit=1)
    command = parts[0].lower() if parts else ""
    arg = parts[1].strip() if len(parts) > 1 else ""

    log(f"cmd: {command}")
    handler = COMMANDS.get(command)
    if handler:
        cmd_name = command.lstrip("/")
        enabled = get_cfg()["commands"]["enabled"]
        if cmd_name not in enabled:
            send_message(chat_id, f"Command disabled: {command}")
            return
        handler(chat_id, arg)
    else:
        send_message(chat_id, f"Unknown command: {command}\nType /help for available commands")


# ══════════════════════════════════════════════════════════════════════════════
# Main Loop
# ══════════════════════════════════════════════════════════════════════════════


def main() -> None:
    log("commander: starting")
    offset = 0
    digest_sent = None
    running = True

    def _shutdown(signum, frame):
        nonlocal running
        log(f"commander: received signal {signum}, shutting down")
        running = False

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    notify_all(f"\U0001f7e2 <b>Homelab Sentinel v{VERSION} started</b>")

    digest_time = get_cfg()["digest"]["time"]
    digest_h, digest_m = (int(x) for x in digest_time.split(":"))
    digest_minutes = digest_h * 60 + digest_m

    while running:
        try:
            now = time.localtime()
            today = (now.tm_year, now.tm_mon, now.tm_mday)
            now_minutes = now.tm_hour * 60 + now.tm_min
            if now_minutes >= digest_minutes and digest_sent != today:
                try:
                    cmd_digest(DIGEST_CHAT_ID)
                except Exception:
                    log(f"digest error: {traceback.format_exc()}")
                digest_sent = today

            url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
            r = requests.get(url, params={"offset": offset, "timeout": 30}, timeout=35)
            for update in r.json().get("result", []):
                offset = update["update_id"] + 1
                if "message" in update:
                    try:
                        process_update(update)
                    except Exception as e:
                        log(f"process_update error: {traceback.format_exc()}")
                        send_message(str(update.get("message", {}).get("chat", {}).get("id", "")), f"⛔ Error: {e!s}")
        except Exception:
            log(f"main loop error: {traceback.format_exc()}")
            time.sleep(5)

    notify_all(f"\U0001f534 <b>Homelab Sentinel v{VERSION} stopped</b>")
    log("commander: stopped")


if __name__ == "__main__":
    main()
