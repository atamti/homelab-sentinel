"""Command handlers for the Homelab Sentinel Telegram bot.

All ``cmd_*`` functions, the ``COMMANDS`` dispatch table, ``BOT_MENU``,
``register_commands()``, and ``get_uptime_kuma_status()`` live here.

Runtime dependencies (``send_message``, ``log``, Wazuh helpers, TOTP
helpers, config strings) are injected at startup by
``telegram-commander.py`` via :func:`init`.
"""

import os
import re
import subprocess
import time
from collections.abc import Callable
from typing import Any

import requests

from sentinel.addons import (
    addon_commands,
    addon_digest_sections,
    addon_help,
    addon_init_hooks,
    addon_menu,
    addon_prompts,
)
from sentinel.config import VERSION, get_cfg
from sentinel.sanitize import abbreviate_os, agent_alias, summarize_docker_output
from sentinel.security import (
    clean_rule_desc,
    format_table_row,
    lookup_rules,
    parse_ban_history,
    query_critical_alerts,
    simplify_service_name,
)
from sentinel.system import format_system_rag_lines, get_system_stats
from sentinel.telegram import esc
from sentinel.validate import validated_ip, validated_port

# ══════════════════════════════════════════════════════════════════════════════
# Dependencies — set by telegram-commander.py via init()
# ══════════════════════════════════════════════════════════════════════════════

send_message: Any = None
log: Any = None
get_wazuh_token: Any = None
wazuh_get: Any = None
indexer_search: Any = None
require_totp: Any = None
require_totp_only: Any = None
BOT_TOKEN: Any = None
WAZUH_API: Any = None


def init(**deps: Any) -> None:
    """Wire up runtime dependencies from telegram-commander.py."""
    globals().update(deps)
    for hook in addon_init_hooks:
        hook(**deps)


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════


def get_uptime_kuma_status() -> tuple[list[str], list[str]]:
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

        up: list[str] = []
        down: list[str] = []
        for mid, name in id_name.items():
            beats = hb_list.get(str(mid), [])
            if beats and beats[-1].get("status") == 1:
                up.append(name)
            else:
                down.append(name)
        return up, down
    except Exception:
        return [], []


# ══════════════════════════════════════════════════════════════════════════════
# Read-Only Commands
# ══════════════════════════════════════════════════════════════════════════════


def cmd_digest(chat_id: str, title: str = "\u2600\ufe0f Daily Digest") -> None:
    log("digest: starting")
    lines = [f"<b>{title}</b>\n"]
    cfg = get_cfg()
    stats: dict[str, Any] = {}
    token: str | None = None

    # ── System ───────────────────────────────────────────────────────
    if cfg["digest"]["sections"]["system"]:
        stats = get_system_stats()
        th = cfg["digest"]["thresholds"]
        lines.extend(format_system_rag_lines(stats, th, compact=True))
        lines.append("→ /system")
        lines.append("")

    # ── Agents ───────────────────────────────────────────────────────
    if cfg["digest"]["sections"]["agents"]:
        token = get_wazuh_token()
        agent_list: list[dict[str, Any]] = []
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
                os_name = abbreviate_os(a.get("os", {}).get("name", "?"))
                dot = "\U0001f534" if name in critical else "\U0001f7e1"
                lines.append(f"  {dot} {esc(display)} ({esc(os_name)})")
        for a in active:
            name = a.get("name", "?")
            display = agent_alias(name)
            os_name = abbreviate_os(a.get("os", {}).get("name", "?"))
            lines.append(f"  \U0001f7e2 {esc(display)} ({esc(os_name)})")
        lines.append("→ /agents")
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
            rules_meta = lookup_rules(all_rids, token, wazuh_get)
            sorted_rids = sorted(all_rids, key=lambda rid: -(rules_meta.get(rid, {}).get("level", 0)))[:5]
            lines.append("<b>Active Response (24h):</b>")
            for rid in sorted_rids:
                count = rule_counts[rid]
                meta = rules_meta.get(rid, {})
                level = meta.get("level", "?")
                desc = clean_rule_desc(meta.get("description", "Unknown"))
                lines.append(f"  <b>{esc(str(rid))}</b> (L{level}) \u00d7{count}")
                lines.append(f"  {esc(str(desc))}")

        # Level 10+ by level descending
        buckets = query_critical_alerts(indexer_search, top_rules_per_level=1)

        if buckets:
            lines.append("\n<b>Critical Alerts (24h):</b>")
            for b in buckets:
                level = b.get("key", "?")
                count = b.get("doc_count", 0)
                rule_b = b.get("by_rule", {}).get("buckets", [])
                desc = clean_rule_desc(rule_b[0].get("key", "Unknown")) if rule_b else "Unknown"
                lines.append(f"  L{level} \u00d7{count}")
                lines.append(f"  {esc(desc)}")
        else:
            lines.append("  No Level 10+ alerts \u2705")

        lines.append("→ /security  /blocked")
        lines.append("")

    # ── Services ─────────────────────────────────────────────────────
    if cfg["digest"]["sections"]["services"] and cfg["integrations"]["uptime_kuma"]["enabled"]:
        up_list, down_list = get_uptime_kuma_status()
        lines.append("<b>\U0001f4e1 Services</b>")
        if down_list:
            names = ", ".join(esc(simplify_service_name(n)) for n in down_list)
            lines.append(f"\U0001f534 Down: {names}")
        else:
            lines.append(f"\U0001f7e2 All {len(up_list)} services up")
        lines.append("→ /services")
        lines.append("")

    # ── Addon digest sections ────────────────────────────────────────
    for _order, section_func in addon_digest_sections:
        section_func(cfg, lines)

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
    for block in addon_help:
        text += block + "\n"
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
        os_name = abbreviate_os(a.get("os", {}).get("name", "?"))
        text += f"{emoji} <b>{esc(display)}</b> (ID: {agent_id})\n"
        text += f"   OS: {esc(os_name)}\n"

    send_message(chat_id, text)


def cmd_alerts(chat_id: str) -> None:
    query: dict[str, Any] = {
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
    query: dict[str, Any] = {
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
        desc = clean_rule_desc(desc_b[0].get("key", "N/A")) if desc_b else "N/A"
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
        result = subprocess.run(
            ["iptables", "-L", "INPUT", "-n"],
            capture_output=True, text=True,
        )
        ip_re = re.compile(r"\b" + re.escape(ip) + r"\b")
        current = "\n".join(line for line in result.stdout.splitlines() if "DROP" in line and ip_re.search(line))
        ban_log = get_cfg()["active_response"]["ban_log"]
        history = ""
        try:
            with open(ban_log) as f:
                history = "\n".join(line.rstrip() for line in f if ip_re.search(line))[-2000:]
        except FileNotFoundError:
            pass
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

    result = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True)
    drop_lines = [line for line in result.stdout.splitlines() if "DROP" in line]
    total = str(len(drop_lines))
    current = "\n".join(drop_lines[skip : skip + per_page])

    ban_log = get_cfg()["active_response"]["ban_log"]
    recent = ""
    try:
        with open(ban_log) as f:
            all_lines = f.read().splitlines()
            recent = "\n".join(all_lines[-(per_page + skip) :][:per_page])
    except FileNotFoundError:
        pass

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
                lines.append(f"  \U0001f534 {esc(simplify_service_name(name))}")
            for name in up_list:
                lines.append(f"  \U0001f7e2 {esc(simplify_service_name(name))}")
        elif up_list:
            lines.append(f"<b>Uptime Kuma</b>\n\U0001f7e2 All {len(up_list)} monitors up")
        else:
            lines.append("<b>Uptime Kuma</b>\n\U0001f7e1 No monitor data")

    send_message(chat_id, "\n".join(lines))


def cmd_system(chat_id: str) -> None:
    stats = get_system_stats()
    cfg = get_cfg()
    th = cfg["digest"]["thresholds"]

    lines = ["<b>\U0001f5a5 System Detail</b>\n"]
    lines.extend(format_system_rag_lines(stats, th))

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
        rules_meta = lookup_rules(all_rids, token, wazuh_get)
        sorted_rids = sorted(all_rids, key=lambda rid: -(rules_meta.get(rid, {}).get("level", 0)))
        lines.append("\n<b>Active Response (24h)</b>")
        for rid in sorted_rids:
            count = rule_counts[rid]
            meta = rules_meta.get(rid, {})
            level = meta.get("level", "?")
            desc = clean_rule_desc(meta.get("description", "Unknown"))
            lines.append(f"  <b>{esc(str(rid))}</b> (L{level}) \u00d7{count}")
            lines.append(f"  {esc(str(desc))}")

    # Critical alerts (Level 10+)
    buckets = query_critical_alerts(indexer_search, top_rules_per_level=3)

    if buckets:
        lines.append("\n<b>Critical Alerts (24h)</b>")
        for b in buckets:
            level = b.get("key", "?")
            count = b.get("doc_count", 0)
            rule_b = b.get("by_rule", {}).get("buckets", [])
            lines.append(f"  L{level} \u00d7{count}")
            for rb in rule_b:
                lines.append(f"    {esc(clean_rule_desc(rb.get('key', 'Unknown')))} (\u00d7{rb.get('doc_count', 0)})")
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
            desc = clean_rule_desc(desc_b[0].get("key", "N/A")) if desc_b else "N/A"
            level = level_b[0].get("key", "?") if level_b else "?"
            lines.append(f"  <b>{esc(str(rule_id))}</b> (L{level}) \u00d7{count} — {esc(str(desc))}")

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
# Dispatch Table & Registration
# ══════════════════════════════════════════════════════════════════════════════

BOT_MENU = [
    ("status", "Full overview"),
    ("system", "Detailed system metrics"),
    ("security", "Security deep dive"),
    ("agents", "Agent list & status"),
    ("services", "Docker & service status"),
    *addon_menu,
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

COMMANDS: dict[str, Callable[[str, str], None]] = {
    "/help": lambda c, a: cmd_help(c),
    "/start": lambda c, a: cmd_help(c),
    "/status": lambda c, a: cmd_digest(c, title="\U0001f4cb Status Report"),
    "/system": lambda c, a: cmd_system(c),
    "/security": lambda c, a: cmd_security(c),
    **addon_commands,
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

# ══════════════════════════════════════════════════════════════════════════════
# Interactive Prompts — step-by-step arg collection for action commands
# ══════════════════════════════════════════════════════════════════════════════

COMMAND_PROMPTS: dict[str, list[str]] = {
    "/block": ["Enter IP address to block:", "Enter TOTP code:"],
    "/unblock": ["Enter IP address to unblock:", "Enter TOTP code:"],
    "/closeport": ["Enter port to close:", "Enter TOTP code:"],
    "/openport": ["Enter port to open:", "Enter TOTP code:"],
    "/restart": ["Enter 'manager' or agent ID:", "Enter TOTP code:"],
    "/syscheck": ["Enter agent ID:", "Enter TOTP code:"],
    "/lockdown": ["Enter TOTP code:"],
    "/restore": ["Enter TOTP code:"],
    "/shutdown": ["Enter TOTP code:"],
    **addon_prompts,
}

_pending: dict[str, dict[str, Any]] = {}


def start_prompt(chat_id: str, command: str) -> None:
    """Begin an interactive prompt sequence for a command."""
    prompts = COMMAND_PROMPTS[command]
    _pending[chat_id] = {
        "command": command,
        "step": 0,
        "args": [],
        "prompts": prompts,
    }
    send_message(chat_id, prompts[0])


def handle_pending(chat_id: str, text: str) -> bool:
    """Process the next answer in a pending prompt sequence.

    Returns True if a pending prompt was active (and handled), False otherwise.
    """
    if chat_id not in _pending:
        return False
    state = _pending[chat_id]
    state["args"].append(text.strip())
    state["step"] += 1
    if state["step"] < len(state["prompts"]):
        send_message(chat_id, state["prompts"][state["step"]])
        return True
    # All args collected — execute the command
    command: str = state["command"]
    arg = " ".join(state["args"])
    del _pending[chat_id]
    handler = COMMANDS[command]
    handler(chat_id, arg)
    return True


def cancel_pending(chat_id: str) -> None:
    """Cancel any pending prompt sequence for a chat."""
    _pending.pop(chat_id, None)


def register_commands() -> bool:
    """Register bot commands with Telegram for autocomplete menu.

    Returns True on success, False on failure.
    """
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/setMyCommands"
    cmds = [{"command": cmd, "description": desc} for cmd, desc in BOT_MENU]
    try:
        resp = requests.post(url, json={"commands": cmds}, timeout=10)
        body = resp.json()
        if body.get("ok"):
            log(f"register: {len(cmds)} commands registered with Telegram")
            return True
        log(f"register: failed — {body.get('description', resp.status_code)}")
        return False
    except Exception as exc:
        log(f"register: error — {exc}")
        return False
