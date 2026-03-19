#!/usr/bin/env python3
"""
custom-telegram.py - Wazuh Integration: Telegram Alert Forwarder
=================================================================
Receives alert JSON from Wazuh integration, formats it, and routes
to the appropriate Telegram channels based on alert level and rule ID.

Wazuh ossec.conf integration block:
  <integration>
    <name>custom-telegram</name>
    <alert_format>json</alert_format>
    <level>7</level>
  </integration>

Deployment:
  sudo cp custom-telegram.py /var/ossec/integrations/custom-telegram
  sudo chmod 750 /var/ossec/integrations/custom-telegram
  sudo chown root:wazuh /var/ossec/integrations/custom-telegram
"""

import json
import os
import re
import sys

sys.path.insert(0, os.environ.get("SENTINEL_LIB", os.path.dirname(os.path.abspath(__file__))))

from sentinel import telegram
from sentinel.config import env, get_cfg, load_env_file
from sentinel.sanitize import agent_alias
from sentinel.telegram import esc

# ── Configuration ─────────────────────────────────────────────────────────────
# Wazuh spawns integrations directly (not via systemd), so load env explicitly.
load_env_file()

BOT_TOKEN = env("TELEGRAM_BOT_TOKEN")
FULL_LOG_CHAT_ID = env("TELEGRAM_FULL_LOG_CHAT_ID")
CRITICAL_CHAT_ID = env("TELEGRAM_CRITICAL_CHAT_ID")


def send_telegram(chat_id: str, message: str) -> None:
    err = telegram.send(BOT_TOKEN, chat_id, message)
    if err:
        sys.stderr.write(f"send failed: {err}\n")


def _parse_port_change(full_log: str) -> tuple[str, str]:
    """Extract port number and direction (opened/closed) from rule 533 full_log.

    Returns (port, direction) where direction is 'opened' or 'closed'.
    Falls back to ('unknown', 'changed') if parsing fails.
    """
    # Look for port number in common syscollector / netstat patterns
    port_match = re.search(r"\b(\d{1,5})(?:/(?:tcp|udp))?\b", full_log)
    port = port_match.group(1) if port_match else "unknown"

    lower = full_log.lower()
    if "new" in lower or "open" in lower or "listening" in lower:
        direction = "opened"
    elif "closed" in lower or "inactive" in lower or "removed" in lower:
        direction = "closed"
    else:
        direction = "changed"

    return port, direction


def format_alert(alert: dict) -> tuple[str, int, str]:
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    level = rule.get("level", 0)
    description = rule.get("description", "N/A")
    rule_id = str(rule.get("id", "N/A"))
    agent_name = agent.get("name", "unknown")
    agent_display = agent_alias(agent_name)
    timestamp = alert.get("timestamp", "N/A")
    src_ip = alert.get("data", {}).get("srcip", "")
    alert_id = alert.get("id", "N/A")

    msg = f"<b>Wazuh Alert (Level {level})</b>\n"
    msg += f"<b>Rule:</b> {esc(str(rule_id))} - {esc(description)}\n"
    msg += f"<b>Time:</b> {esc(timestamp[:19])}\n"
    if src_ip:
        msg += f"<b>Source IP:</b> <code>{esc(src_ip)}</code>\n"
    msg += f"<b>Agent:</b> {esc(agent_display)}\n"

    # Enrich port change alerts with port and direction details
    if rule_id == "100200":
        full_log = alert.get("full_log", "")
        port, direction = _parse_port_change(full_log)
        msg += f"<b>Port:</b> {esc(port)} | <b>Status:</b> {esc(direction)}\n"

    msg += f"<b>Ref:</b> <code>{esc(str(alert_id))}</code>\n"  # <code> tag = tappable on mobile

    return msg, level, rule_id


def main() -> None:
    alert_file = sys.argv[1]
    with open(alert_file) as f:
        alert = json.load(f)

    message, level, rule_id = format_alert(alert)

    alerts_cfg = get_cfg()["alerts"]
    critical_level = alerts_cfg["critical_level"]
    silent_rules = set(str(r) for r in alerts_cfg["silent_rules"])

    # Always send to full log channel (muted, Level 7+)
    send_telegram(FULL_LOG_CHAT_ID, message)

    # Send critical+ to critical channel, excluding high-volume rules
    if level >= critical_level and rule_id not in silent_rules:
        send_telegram(CRITICAL_CHAT_ID, "🚨 " + message)


if __name__ == "__main__":
    main()
