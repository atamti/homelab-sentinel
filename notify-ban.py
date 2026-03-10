#!/usr/bin/env python3
"""
notify-ban.py - Wazuh Active Response + Telegram Notification Script
======================================================================
Deployed as a Wazuh active response binary. Handles the two-phase
firewall-drop handshake, bans the offending IP via iptables, sends
a Telegram notification, and writes to the ban history log.

Deployment:
  sudo cp notify-ban.py /var/ossec/active-response/bin/notify-ban.py
  sudo chmod 750 /var/ossec/active-response/bin/notify-ban.py
  sudo chown root:wazuh /var/ossec/active-response/bin/notify-ban.py

Environment variables are loaded from /etc/homelab-sentinel.env
(injected via systemd EnvironmentFile or sourced at runtime).
"""

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.environ.get(
    "SENTINEL_LIB", os.path.dirname(os.path.abspath(__file__))))

from sentinel import telegram
from sentinel.config import env, load_env_file, SILENT_RULES
from sentinel.validate import validated_ip

# ── Load config from environment ────────────────────────────────────────────
# Active response scripts are spawned by Wazuh directly (not via systemd),
# so the EnvironmentFile isn't inherited.  Load it explicitly.
load_env_file()

BOT_TOKEN        = env("TELEGRAM_BOT_TOKEN")
FULL_LOG_CHAT_ID = env("TELEGRAM_FULL_LOG_CHAT_ID")
CRITICAL_CHAT_ID = env("TELEGRAM_CRITICAL_CHAT_ID")

BAN_LOG          = "/var/ossec/logs/ban-history.log"
DEBUG_LOG        = None   # set to "/tmp/ar_debug.log" to enable


# ── Helpers ──────────────────────────────────────────────────────────────────

def debug_log(msg: str) -> None:
    if DEBUG_LOG:
        with open(DEBUG_LOG, "a") as f:
            f.write(f"{time.ctime()}: {msg}\n")


def send_telegram(chat_id: str, message: str) -> None:
    err = telegram.send(BOT_TOKEN, chat_id, message)
    if err:
        debug_log(f"send failed: {err}")


def write_ban_log(ip: str, rule_id: str) -> None:
    try:
        with open(BAN_LOG, "a") as f:
            f.write(f"{time.strftime('%Y/%m/%d %H:%M:%S')} Banned {ip} (Rule {rule_id})\n")
    except Exception as e:
        debug_log(f"Ban log write error: {e}")


def lockfile_path(ip: str) -> str:
    return f"/tmp/ar_ban_{ip.replace('.', '_')}.lock"


def is_duplicate(ip: str, ttl: int = 10) -> bool:
    """Return True if this IP was already processed within ttl seconds."""
    path = lockfile_path(ip)
    if os.path.exists(path):
        if time.time() - os.path.getmtime(path) < ttl:
            return True
        # Stale lock — remove before recreating
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(time.time()).encode())
        os.close(fd)
    except FileExistsError:
        return True
    return False


def is_already_banned(ip: str) -> bool:
    """Return True if a DROP rule for this IP already exists in iptables INPUT chain."""
    try:
        result = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception as e:
        debug_log(f"iptables -C check failed for {ip}: {e}")
        return False  # fail open — proceed with handshake


def deduplicate_iptables() -> int:
    """Remove duplicate DROP rules from iptables INPUT chain.

    Returns count of duplicates removed.
    Reads current rules via iptables-save, deduplicates, restores.
    Intended for manual / cron use, not called in the main flow.
    """
    try:
        raw = subprocess.run(
            ["iptables-save"], capture_output=True, text=True, check=True,
        ).stdout
        seen: set[str] = set()
        deduped_lines: list[str] = []
        removed = 0
        for line in raw.splitlines():
            if line.startswith("-A INPUT") and "-j DROP" in line:
                if line in seen:
                    removed += 1
                    continue
                seen.add(line)
            deduped_lines.append(line)
        if removed:
            subprocess.run(
                ["iptables-restore"],
                input="\n".join(deduped_lines) + "\n",
                text=True,
                check=True,
            )
            debug_log(f"deduplicate_iptables: removed {removed} duplicate(s)")
        return removed
    except Exception as e:
        debug_log(f"deduplicate_iptables error: {e}")
        return 0


def run_firewall_drop(alert_json: str) -> None:
    """
    Execute firewall-drop via two-phase stdin/stdout handshake.
    Phase 1: send alert JSON to firewall-drop
    Phase 2: receive check_keys request, respond 'continue'
    """
    fw_bin = "/var/ossec/active-response/bin/firewall-drop"
    try:
        proc = subprocess.Popen(
            [fw_bin],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        proc.stdin.write(alert_json.encode())
        proc.stdin.flush()

        # Read check_keys request
        response = proc.stdout.readline()
        debug_log(f"firewall-drop check_keys: {response.decode().strip()}")

        # Send continue
        proc.stdin.write(b"continue\n")
        proc.stdin.flush()
        proc.stdin.close()

        stdout, stderr = proc.communicate(timeout=10)
        debug_log(f"firewall-drop stdout: {stdout.decode().strip()}")
        if stderr:
            debug_log(f"firewall-drop stderr: {stderr.decode().strip()}")
    except Exception as e:
        debug_log(f"firewall-drop error: {e}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    try:
        raw = sys.stdin.read()
        debug_log(f"stdin: {raw[:500]}")
        data = json.loads(raw)
    except Exception as e:
        debug_log(f"JSON parse error: {e}")
        sys.exit(1)

    action     = data.get("command", "")
    alert      = data.get("parameters", {}).get("alert", {})
    rule       = alert.get("rule", {})
    agent      = alert.get("agent", {})
    geo        = alert.get("GeoLocation", {})
    src_data   = alert.get("data", {})

    ip        = src_data.get("srcip", "")
    rule_id   = str(rule.get("id", ""))
    rule_desc = rule.get("description", "Unknown rule")
    rule_lvl  = rule.get("level", 0)
    agent_name = agent.get("name", "unknown")

    country     = geo.get("country_name", "")
    country_str = f" [{country}]" if country else ""

    if not ip:
        debug_log("No srcip found, exiting")
        sys.exit(0)

    # Validate IP before any iptables interaction (fail open on bad input)
    try:
        ip = validated_ip(ip)
    except ValueError:
        debug_log(f"Invalid IP from alert: {ip}")
        sys.exit(1)

    # ── Firewall drop (skip if IP already has a DROP rule) ───────────
    if not is_already_banned(ip):
        run_firewall_drop(raw)
    else:
        debug_log(f"{ip} already in iptables, skipping firewall-drop")

    # ── Handle add (new ban) ─────────────────────────────────────────
    if action == "add":
        if is_duplicate(ip):
            debug_log(f"Duplicate suppressed for {ip}")
            sys.exit(0)

        write_ban_log(ip, rule_id)

        message = (
            f"🔨 <b>Active Response: Banned</b>\n"
            f"<b>IP:</b> {ip}{country_str}\n"
            f"<b>Rule:</b> {rule_id} - {rule_desc}\n"
            f"<b>Agent:</b> {agent_name}"
        )

        send_telegram(FULL_LOG_CHAT_ID, message)

        if rule_id not in SILENT_RULES:
            send_telegram(CRITICAL_CHAT_ID, f"🚨 {message}")

    # ── Handle delete (ban expiry) ───────────────────────────────────
    elif action == "delete":
        message = (
            f"✅ <b>Active Response: Unbanned</b>\n"
            f"<b>IP:</b> {ip}{country_str}\n"
            f"<b>Rule:</b> {rule_id}\n"
            f"<b>Agent:</b> {agent_name}"
        )
        send_telegram(FULL_LOG_CHAT_ID, message)

    else:
        debug_log(f"Unknown action: {action}")


if __name__ == "__main__":
    main()
