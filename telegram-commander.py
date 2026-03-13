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
from sentinel.sanitize import agent_alias, sanitize, summarize_docker_output
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
            if ratio < min_ratio:
                imbalanced.append(f"<{round(min_ratio * 100)}% local")
            elif ratio > max_ratio:
                imbalanced.append(f">{round(max_ratio * 100)}% local")

    if imbalanced:
        pcts = ", ".join(imbalanced)
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


def cmd_digest(chat_id: str, title: str = "\u2600\ufe0f Daily Digest") -> None:
    log("digest: starting")
    lines = [f"<b>{title}</b>\n"]
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
        rags = [load_rag, mem_rag, disk_rag]

        temp_rag = None
        if stats["cpu_temp"] is not None:
            temp_rag = _rag(stats["cpu_temp"], th["cpu_temp_amber"], th["cpu_temp_red"])
            rags.append(temp_rag)

        all_green = all(r == "\U0001f7e2" for r in rags)
        hdr = "<b>\U0001f5a5  System \U0001f7e2</b>" if all_green else "<b>System \U0001f5a5</b>"
        lines.append(hdr)
        lines.append(f"Uptime: {esc(stats['uptime'])}")
        if all_green:
            lines.append(f"Load: {esc(stats['load'])}")
            lines.append(f"Memory: {esc(stats['mem'])} ({stats['mem_pct']:.0f}%)")
            if temp_rag is not None:
                lines.append(f"CPU temp: {stats['cpu_temp']:.0f}°C")
            lines.append(f"Disk: {esc(stats['disk'])}\n")
        else:
            lines.append(f"{load_rag} Load: {esc(stats['load'])}")
            lines.append(f"{mem_rag} Memory: {esc(stats['mem'])} ({stats['mem_pct']:.0f}%)")
            if temp_rag is not None:
                lines.append(f"{temp_rag} CPU temp: {stats['cpu_temp']:.0f}°C")
            lines.append(f"{disk_rag} Disk: {esc(stats['disk'])}\n")

    # ── Agents ───────────────────────────────────────────────────────
    if cfg["digest"]["sections"]["agents"]:
        token = get_wazuh_token()
        agent_list = []
        if token:
            resp = wazuh_get("/agents?limit=50", token)
            agent_list = resp.get("data", {}).get("affected_items", [])

        critical = cfg["digest"].get("critical_agents", {})
        active = [a for a in agent_list if a.get("status") == "active"]
        disconnected = [a for a in agent_list if a.get("status") != "active"]

        # Check if any critical agent is disconnected
        disc_names = {a.get("name", "") for a in disconnected}
        red_down = any(sev == "red" and n in disc_names for n, sev in critical.items())

        if red_down:
            hdr_emoji = "\U0001f534"
        elif disconnected:
            hdr_emoji = "\U0001f7e1"
        else:
            hdr_emoji = "\U0001f7e2"

        lines.append(f"{hdr_emoji} <b>Agents:</b> {len(active)} active")
        if disconnected:
            for a in disconnected:
                name = a.get("name", "?")
                display = agent_alias(name)
                os_name = a.get("os", {}).get("name", "?")
                dot = "\U0001f534" if name in critical else "\U0001f7e1"
                lines.append(f"  {dot} {esc(display)} ({esc(os_name)})")
        for a in active:
            name = a.get("name", "?")
            display = agent_alias(name)
            os_name = a.get("os", {}).get("name", "?")
            lines.append(f"  \U0001f7e2 {esc(display)} ({esc(os_name)})")
        lines.append("")

    # ── Security ─────────────────────────────────────────────────────
    if cfg["digest"]["sections"]["security"]:
        if not cfg["digest"]["sections"]["system"]:
            stats = get_system_stats()
        rule_counts = parse_ban_history()
        total_bans = sum(rule_counts.values())
        lines.append("<b>\U0001f6e1 Security</b>")
        lines.append(f"Bans (24h): {total_bans} | Active: {stats['banned']}\n")

        if not cfg["digest"]["sections"]["agents"]:
            token = get_wazuh_token()
        if rule_counts and token:
            all_rids = list(rule_counts.keys())
            rules_meta = lookup_rules(all_rids, token)
            sorted_rids = sorted(all_rids, key=lambda rid: -(rules_meta.get(rid, {}).get("level", 0)))[:5]
            lines.append("<b>Active Response (24h):</b>")
            for rid in sorted_rids:
                count = rule_counts[rid]
                meta = rules_meta.get(rid, {})
                level = meta.get("level", "?")
                desc = meta.get("description", "Unknown")
                lines.append(f"  <b>{esc(str(rid))}</b> (L{level}) \u00d7{count}")
                lines.append(f"  {esc(str(desc))}")

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
            lines.append("\n<b>Critical Alerts (24h):</b>")
            for b in buckets:
                level = b.get("key", "?")
                count = b.get("doc_count", 0)
                rule_b = b.get("by_rule", {}).get("buckets", [])
                desc = rule_b[0].get("key", "Unknown") if rule_b else "Unknown"
                lines.append(f"  L{level} \u00d7{count}")
                lines.append(f"  {esc(desc)}")
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


def cmd_help(chat_id: str) -> None:
    text = f"<b>Homelab Sentinel</b> <i>v{VERSION}</i>\n\n"
    text += "\U0001f4cb /status — Full overview\n\n"
    text += "<b>\U0001f5a5 System</b>\n"
    text += "/system — Detailed system metrics\n"
    text += "/disk — Disk usage\n"
    text += "/uptime — System uptime\n\n"
    text += "<b>\U0001f6e1 Security</b>\n"
    text += "/security — Security deep dive\n"
    text += "/alerts — Recent alerts (Level 8+)\n"
    text += "/top — Top triggered rules (24h)\n"
    text += "/blocked [ip|page] — Blocked IPs & history\n"
    text += "/event [id] [totp] — Alert detail\n\n"
    text += "<b>\U0001f916 Agents</b>\n"
    text += "/agents — Agent list & status\n\n"
    text += "<b>\U0001f4e1 Services</b>\n"
    text += "/services — Docker & service status\n\n"
    text += "<b>\u20bf Bitcoin</b>\n"
    text += "/bitcoin — Bitcoin & Lightning detail\n\n"
    text += "<b>\U0001f512 Active Response</b> <i>(TOTP)</i>\n"
    text += "/block [ip] [totp]\n"
    text += "/unblock [ip] [totp]\n"
    text += "/closeport [port] [totp]\n"
    text += "/openport [port] [totp]\n"
    text += "/lockdown [totp]\n"
    text += "/restore [totp]\n"
    text += "/restart [target] [totp]\n"
    text += "/syscheck [agent_id] [totp]\n"
    text += "/shutdown [totp]"
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
    agent_name = agent.get('name', '')
    agent_display = agent_alias(agent_name) if agent_name else agent.get('id', '?')
    text += f"<b>Agent:</b> {esc(agent_display)}\n"
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
        display = agent_alias(name)
        agent_id = a.get("id", "?")
        ip = a.get("ip", "?")
        os_name = a.get("os", {}).get("name", "?")
        text += f"{emoji} <b>{esc(display)}</b> (ID: {agent_id})\n"
        text += f"   IP: <code>{ip}</code> | OS: {esc(os_name)}\n"

    send_message(chat_id, text)


def cmd_alerts(chat_id: str) -> None:
    query = {
        "size": 10,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"range": {"rule.level": {"gte": 8}}},
        "_source": ["id", "timestamp", "rule", "agent"],
    }
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
        agent_name = agent.get("name", "")
        agent_display = agent_alias(agent_name) if agent_name else agent.get("id", "?")
        desc = rule.get("description", "")
        text += f"L{rule.get('level')} | {esc(agent_display)} | Rule {rule.get('id')}\n"
        if desc:
            text += f"{esc(desc)}\n"
        text += f"{a.get('timestamp', '')[:19]} | Ref: <code>{a.get('id')}</code>\n\n"

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
            f"<b>Lookup: <code>{esc(ip)}</code></b>\n\n"
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
    lines = ["<b>\U0001f4e1 Services</b>\n"]

    # Docker containers
    result = subprocess.getoutput(
        "DOCKER_HOST=unix:///run/user/1001/docker.sock docker ps -a --format 'table {{.Names}}\t{{.Status}}' 2>&1"
    )
    summary = summarize_docker_output(result)
    lines.append(f"<b>Docker Containers</b>\n{summary}\n")

    # Uptime Kuma monitors
    cfg = get_cfg()
    if cfg["integrations"]["uptime_kuma"]["enabled"]:
        up_list, down_list = get_uptime_kuma_status()
        if down_list:
            lines.append("<b>Uptime Kuma</b>")
            for name in down_list:
                lines.append(f"  \U0001f534 {esc(_simplify_service_name(name))}")
            for name in up_list:
                lines.append(f"  \U0001f7e2 {esc(_simplify_service_name(name))}")
        elif up_list:
            lines.append(f"<b>Uptime Kuma</b>\n\U0001f7e2 All {len(up_list)} monitors up")
        else:
            lines.append("<b>Uptime Kuma</b>\n\U0001f7e1 No monitor data")

    send_message(chat_id, "\n".join(lines))


def cmd_system(chat_id: str) -> None:
    stats = get_system_stats()
    cfg = get_cfg()
    th = cfg["digest"]["thresholds"]

    load_amber = th["load_per_core_amber"] * stats["nproc"]
    load_red = th["load_per_core_red"] * stats["nproc"]
    load_rag = _rag(stats["load_1m"], load_amber, load_red)
    mem_rag = _rag(stats["mem_pct"], th["memory_amber"], th["memory_red"])
    disk_rag = _rag(stats["disk_pct"], th["disk_amber"], th["disk_red"])

    lines = ["<b>\U0001f5a5 System Detail</b>\n"]
    lines.append(f"Uptime: {esc(stats['uptime'])}")
    lines.append(f"{load_rag} Load: {esc(stats['load'])} ({stats['nproc']} cores)")
    lines.append(f"{mem_rag} Memory: {esc(stats['mem'])} ({stats['mem_pct']:.0f}%)")

    if stats["cpu_temp"] is not None:
        temp_rag = _rag(stats["cpu_temp"], th["cpu_temp_amber"], th["cpu_temp_red"])
        lines.append(f"{temp_rag} CPU temp: {stats['cpu_temp']:.0f}°C")

    lines.append(f"{disk_rag} Disk: {esc(stats['disk'])}")

    # Detailed disk breakdown
    raw = subprocess.getoutput("df -h --exclude-type=tmpfs --exclude-type=devtmpfs")
    disk_lines = raw.splitlines()
    if len(disk_lines) > 1:
        out = [f"{'Drive':<10} {'Size':>5} {'Used':>5} {'Avail':>5} {'Use%':>5}  Mounted on"]
        for i, line in enumerate(disk_lines[1:], 1):
            cols = line.split()
            if len(cols) >= 6:
                mount = " ".join(cols[5:])
                out.append(f"{'Drive ' + str(i):<10} {cols[1]:>5} {cols[2]:>5} {cols[3]:>5} {cols[4]:>5}  {mount}")
        lines.append(f"\n<pre>{esc(chr(10).join(out))}</pre>")

    # Top processes
    top_procs = subprocess.getoutput("ps -eo pid,pcpu,pmem,comm --sort=-pcpu --no-headers | head -5")
    if top_procs.strip():
        lines.append("\n<b>Top Processes (CPU)</b>")
        lines.append(f"<pre>{esc(top_procs.strip())}</pre>")

    send_message(chat_id, "\n".join(lines))


def cmd_security(chat_id: str) -> None:
    lines = ["<b>\U0001f6e1 Security Detail</b>\n"]
    stats = get_system_stats()

    # Active bans
    lines.append("<b>Firewall</b>")
    lines.append(f"Active bans: {stats['banned']}")

    # Ban history 24h
    rule_counts = parse_ban_history()
    total_bans = sum(rule_counts.values())
    lines.append(f"Bans in last 24h: {total_bans}")

    token = get_wazuh_token()

    # Active response breakdown
    if rule_counts and token:
        all_rids = list(rule_counts.keys())
        rules_meta = lookup_rules(all_rids, token)
        sorted_rids = sorted(all_rids, key=lambda rid: -(rules_meta.get(rid, {}).get("level", 0)))
        lines.append("\n<b>Active Response (24h)</b>")
        for rid in sorted_rids:
            count = rule_counts[rid]
            meta = rules_meta.get(rid, {})
            level = meta.get("level", "?")
            desc = meta.get("description", "Unknown")
            lines.append(f"  <b>{esc(str(rid))}</b> (L{level}) \u00d7{count}")
            lines.append(f"  {esc(str(desc))}")

    # Critical alerts (Level 10+)
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
                    "aggs": {"by_rule": {"terms": {"field": "rule.description", "size": 3}}},
                }
            },
        }
    )
    buckets = result.get("aggregations", {}).get("by_level", {}).get("buckets", [])

    if buckets:
        lines.append("\n<b>Critical Alerts (24h)</b>")
        for b in buckets:
            level = b.get("key", "?")
            count = b.get("doc_count", 0)
            rule_b = b.get("by_rule", {}).get("buckets", [])
            lines.append(f"  L{level} \u00d7{count}")
            for rb in rule_b:
                lines.append(f"    {esc(rb.get('key', 'Unknown'))} (\u00d7{rb.get('doc_count', 0)})")
    else:
        lines.append("\nNo Level 10+ alerts in 24h \u2705")

    # Top triggered rules
    top_result = indexer_search(
        {
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
    )
    top_buckets = top_result.get("aggregations", {}).get("top_rules", {}).get("buckets", [])

    if top_buckets:
        lines.append("\n<b>Top Triggered Rules (24h)</b>")
        for bucket in top_buckets:
            rule_id = bucket.get("key", "?")
            count = bucket.get("doc_count", 0)
            desc_b = bucket.get("rule_desc", {}).get("buckets", [])
            level_b = bucket.get("rule_level", {}).get("buckets", [])
            desc = desc_b[0].get("key", "N/A") if desc_b else "N/A"
            level = level_b[0].get("key", "?") if level_b else "?"
            lines.append(f"  <b>{esc(str(rule_id))}</b> (L{level}) \u00d7{count} — {esc(str(desc))}")

    send_message(chat_id, "\n".join(lines))


def cmd_bitcoin(chat_id: str) -> None:
    cfg = get_cfg()
    if not cfg["integrations"]["bitcoin"]["enabled"]:
        send_message(chat_id, "Bitcoin integration is disabled")
        return

    lines = ["<b>\u20bf Bitcoin Detail</b>\n"]

    # Block height
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
        lines.append(f"Public height: {public_height}")
    elif public_ok:
        lines.append(f"\U0001f7e1 Block height: {public_height} (local node unreachable)")
    elif local_ok:
        lines.append(f"\U0001f7e1 Block height: {local_height} (public API unreachable)")
    else:
        lines.append("\U0001f534 Block height: unavailable")

    # Fees
    fees = mempool_get("/api/v1/fees/recommended")
    if isinstance(fees, dict):
        lines.append("")
        lines.append("<b>Mempool Fees</b> (sat/vB)")
        lines.append(f"  Fastest:  {fees.get('fastestFee')}")
        lines.append(f"  30 min:   {fees.get('halfHourFee')}")
        lines.append(f"  1 hour:   {fees.get('hourFee')}")
        eco = fees.get("economyFee")
        if eco:
            lines.append(f"  Economy:  {eco}")
        minimum = fees.get("minimumFee")
        if minimum:
            lines.append(f"  Minimum:  {minimum}")

    # LND
    if cfg["integrations"]["lnd"]["enabled"]:
        lnd_info = lnd_get("/v1/getinfo")
        if lnd_info:
            lines.append("")
            lines.append("<b>Lightning (LND)</b>")
            synced = "\U0001f7e2 yes" if lnd_info.get("synced_to_chain") else "\U0001f7e1 no"
            lines.append(f"Synced: {synced}")
            alias = lnd_info.get("alias", "")
            if alias:
                lines.append(f"Alias: {esc(alias)}")
            version = lnd_info.get("version", "")
            if version:
                lines.append(f"Version: {esc(version)}")
            peers = lnd_info.get("num_peers", 0)
            lines.append(f"Peers: {peers}")
            block_height = lnd_info.get("block_height", "")
            if block_height:
                lines.append(f"LND block height: {block_height}")
        else:
            lines.append("\n\U0001f534 LND unreachable")

        # Channel detail
        channels = lnd_get("/v1/channels")
        ch_list = channels.get("channels", []) if channels else []
        if ch_list:
            emoji, label = score_channel_health(ch_list)
            lines.append(f"\nChannels: {emoji} {label}")
            for ch in ch_list:
                cap = int(ch.get("capacity", 0))
                local = int(ch.get("local_balance", 0))
                active = "\U0001f7e2" if ch.get("active") else "\U0001f534"
                alias = ch.get("peer_alias", ch.get("remote_pubkey", "?")[:12])
                ratio = (local / cap * 100) if cap > 0 else 0
                lines.append(f"  {active} {esc(str(alias))}")
                lines.append(f"    {local:,} / {cap:,} sat ({ratio:.0f}% local)")

        # Wallet balance
        balance = lnd_get("/v1/balance/channels")
        if balance:
            lb = balance.get("local_balance", 0)
            local_bal = int(lb.get("sat", 0)) if isinstance(lb, dict) else int(lb)
            rb = balance.get("remote_balance", 0)
            remote_bal = int(rb.get("sat", 0)) if isinstance(rb, dict) else int(rb)
            if local_bal or remote_bal:
                lines.append("\n<b>Channel Balance</b>")
                lines.append(f"  Local:  {local_bal:,} sat")
                lines.append(f"  Remote: {remote_bal:,} sat")

    send_message(chat_id, "\n".join(lines))


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
    send_message(chat_id, f"\U0001f6ab Blocked <code>{ip}</code>")


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
    send_message(chat_id, f"\u2705 Unblocked <code>{ip}</code>\n{result.stderr}")


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
    if not token:
        send_message(chat_id, "\u26d4 Failed to authenticate with Wazuh API")
        return
    resp = requests.put(
        f"{WAZUH_API}/syscheck",
        params={"agents_list": agent_id},
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
        timeout=10,
    )
    if resp.status_code != 200:
        send_message(chat_id, f"\u26d4 Failed to start syscheck: HTTP {resp.status_code}")
        return
    send_message(chat_id, f"\u23f3 Integrity scan started on agent {agent_id}, polling...")
    # Poll for completion (up to 5 minutes)
    for _ in range(30):
        time.sleep(10)
        token = get_wazuh_token()
        if not token:
            break
        scan = wazuh_get(f"/syscheck/{agent_id}/last_scan", token)
        status = scan.get("data", {}).get("affected_items", [{}])[0]
        if status.get("end"):
            end_time = status["end"]
            send_message(chat_id, f"\u2705 Syscheck completed on agent {agent_id} at {end_time}")
            return
    send_message(chat_id, f"\u23f3 Syscheck still running on agent {agent_id} (timeout waiting)")


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

BOT_MENU = [
    ("status", "Full overview"),
    ("system", "Detailed system metrics"),
    ("security", "Security deep dive"),
    ("agents", "Agent list & status"),
    ("services", "Docker & service status"),
    ("bitcoin", "Bitcoin & Lightning detail"),
    ("alerts", "Recent alerts (Level 8+)"),
    ("top", "Top triggered rules (24h)"),
    ("blocked", "Blocked IPs & ban history"),
    ("event", "Alert detail (TOTP)"),
    ("disk", "Disk usage"),
    ("uptime", "System uptime"),
    ("block", "Block an IP (TOTP)"),
    ("unblock", "Unblock an IP (TOTP)"),
    ("closeport", "Close a UFW port (TOTP)"),
    ("openport", "Open a UFW port (TOTP)"),
    ("lockdown", "Deny all except SSH (TOTP)"),
    ("restore", "Restore normal firewall (TOTP)"),
    ("restart", "Restart service or agent (TOTP)"),
    ("syscheck", "Run integrity scan (TOTP)"),
    ("shutdown", "Shutdown server (TOTP)"),
    ("help", "Show command menu"),
]

COMMANDS = {
    "/help": lambda c, a: cmd_help(c),
    "/start": lambda c, a: cmd_help(c),
    "/status": lambda c, a: cmd_digest(c, title="\U0001f4cb Status Report"),
    "/system": lambda c, a: cmd_system(c),
    "/security": lambda c, a: cmd_security(c),
    "/bitcoin": lambda c, a: cmd_bitcoin(c),
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


def register_commands() -> bool:
    """Register bot commands with Telegram for autocomplete menu.

    Returns True on success, False on failure.
    """
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/setMyCommands"
    commands = [{"command": cmd, "description": desc} for cmd, desc in BOT_MENU]
    try:
        resp = requests.post(url, json={"commands": commands}, timeout=10)
        body = resp.json()
        if body.get("ok"):
            log(f"register: {len(commands)} commands registered with Telegram")
            return True
        log(f"register: failed — {body.get('description', resp.status_code)}")
        return False
    except Exception as exc:
        log(f"register: error — {exc}")
        return False


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
    if len(sys.argv) > 1 and sys.argv[1] == "--register-commands":
        ok = register_commands()
        sys.exit(0 if ok else 1)
    main()
