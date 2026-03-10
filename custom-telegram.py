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
import sys

sys.path.insert(0, os.environ.get(
    "SENTINEL_LIB", os.path.dirname(os.path.abspath(__file__))))

from sentinel import telegram
from sentinel.config import env, SILENT_RULES

# ── Configuration ─────────────────────────────────────────────────────────────
BOT_TOKEN        = env("TELEGRAM_BOT_TOKEN")
FULL_LOG_CHAT_ID = env("TELEGRAM_FULL_LOG_CHAT_ID")
CRITICAL_CHAT_ID = env("TELEGRAM_CRITICAL_CHAT_ID")


def send_telegram(chat_id: str, message: str) -> None:
    telegram.send(BOT_TOKEN, chat_id, message)


def format_alert(alert: dict) -> tuple[str, int, str]:
    rule        = alert.get("rule", {})
    agent       = alert.get("agent", {})
    level       = rule.get("level", 0)
    description = rule.get("description", "N/A")
    rule_id     = rule.get("id", "N/A")
    agent_name  = agent.get("name", "N/A")
    timestamp   = alert.get("timestamp", "N/A")
    src_ip      = alert.get("data", {}).get("srcip", "")
    alert_id    = alert.get("id", "N/A")

    msg  = f"<b>Wazuh Alert (Level {level})</b>\n"
    msg += f"<b>Rule:</b> {rule_id} - {description}\n"
    msg += f"<b>Time:</b> {timestamp[:19]}\n"
    if src_ip:
        msg += f"<b>Source IP:</b> {src_ip}\n"
    msg += f"<b>Ref:</b> <code>{alert_id}</code>\n"  # <code> tag = tappable on mobile

    return msg, level, rule_id


def main() -> None:
    alert_file = sys.argv[1]
    with open(alert_file) as f:
        alert = json.load(f)

    message, level, rule_id = format_alert(alert)

    # Always send to full log channel (muted, Level 7+)
    send_telegram(FULL_LOG_CHAT_ID, message)

    # Send Level 10+ to critical channel, excluding high-volume rules
    if level >= 10 and rule_id not in SILENT_RULES:
        send_telegram(CRITICAL_CHAT_ID, "🚨 " + message)


if __name__ == "__main__":
    main()
