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

import os
import signal
import subprocess
import sys
import time
import traceback

sys.path.insert(0, os.environ.get("SENTINEL_LIB", os.path.dirname(os.path.abspath(__file__))))

from typing import Any

import pyotp
import requests

from sentinel import telegram, wazuh
from sentinel.config import VERSION, env, get_cfg, require_env
from sentinel.sanitize import sanitize
from sentinel.security import clean_rule_desc, format_table_row, simplify_service_name
from sentinel.system import rag
from sentinel.telegram import esc

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


def wazuh_get(endpoint: str, token: str) -> dict[str, Any]:
    return wazuh.api_get(WAZUH_API, endpoint, token)


def indexer_search(query: dict[str, Any]) -> dict[str, Any]:
    return wazuh.indexer_search(INDEXER_URL, INDEXER_USER, INDEXER_PASS, query)


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
# Command Handlers (sentinel.commands)
# ══════════════════════════════════════════════════════════════════════════════

from sentinel import commands  # noqa: E402

# Load optional addons before init() so they can register commands/menus
if get_cfg()["integrations"]["bitcoin"]["enabled"]:
    import sentinel.addons.bitcoin  # noqa: E402, F401

commands.init(
    send_message=send_message,
    log=log,
    get_wazuh_token=get_wazuh_token,
    wazuh_get=wazuh_get,
    indexer_search=indexer_search,
    require_totp=require_totp,
    require_totp_only=require_totp_only,
    BOT_TOKEN=BOT_TOKEN,
    WAZUH_API=WAZUH_API,
)

from sentinel.commands import (  # noqa: E402
    BOT_MENU,
    COMMAND_PROMPTS,
    COMMANDS,
    cancel_pending,
    cmd_agents,
    cmd_alerts,
    cmd_block,
    cmd_blocked,
    cmd_closeport,
    cmd_digest,
    cmd_disk,
    cmd_event,
    cmd_help,
    cmd_lockdown,
    cmd_openport,
    cmd_restart,
    cmd_restore,
    cmd_security,
    cmd_services,
    cmd_shutdown,
    cmd_syscheck,
    cmd_system,
    cmd_top,
    cmd_unblock,
    cmd_uptime,
    get_uptime_kuma_status,
    handle_pending,
    register_commands,
    start_prompt,
)


# ══════════════════════════════════════════════════════════════════════════════
# Update Dispatcher
# ══════════════════════════════════════════════════════════════════════════════


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

    # Non-command text — check for a pending interactive prompt
    if not command.startswith("/"):
        if handle_pending(chat_id, text):
            return
        send_message(chat_id, f"Unknown command: {command}\nType /help for available commands")
        return

    # New command — cancel any in-progress prompt
    cancel_pending(chat_id)

    log(f"cmd: {command}")
    handler = COMMANDS.get(command)
    if handler:
        cmd_name = command.lstrip("/")
        enabled_sections = get_cfg()["commands"]["enabled"]
        # Flatten grouped dict into a set, supporting legacy flat lists too
        if isinstance(enabled_sections, dict):
            enabled = {c for cmds in enabled_sections.values() for c in cmds}
        else:
            enabled = set(enabled_sections)
        if cmd_name not in enabled:
            send_message(chat_id, f"Command disabled: {command}")
            return
        # No args and command supports interactive prompts — start prompting
        if not arg and command in COMMAND_PROMPTS:
            start_prompt(chat_id, command)
            return
        handler(chat_id, arg)
    else:
        send_message(chat_id, f"Unknown command: {command}\nType /help for available commands")


# ══════════════════════════════════════════════════════════════════════════════
# Main Loop
# ══════════════════════════════════════════════════════════════════════════════


DIGEST_STATE_FILE = os.path.join(os.path.dirname(LOG_FILE), ".digest-sent")


def _read_digest_state() -> tuple | None:
    """Read persisted digest date from disk."""
    try:
        with open(DIGEST_STATE_FILE) as f:
            parts = f.read().strip().split(",")
            if len(parts) == 3:
                return (int(parts[0]), int(parts[1]), int(parts[2]))
    except (FileNotFoundError, ValueError):
        pass
    return None


def _write_digest_state(date_tuple: tuple) -> None:
    """Persist digest date to disk so restarts don't re-send."""
    try:
        with open(DIGEST_STATE_FILE, "w") as f:
            f.write(f"{date_tuple[0]},{date_tuple[1]},{date_tuple[2]}")
    except OSError:
        pass


def main() -> None:
    log("commander: starting")
    offset = 0
    digest_sent = _read_digest_state()
    last_sweep: float = 0
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
                _write_digest_state(today)

            # Sweep expired bans every 60 seconds
            now_ts = time.time()
            if now_ts - last_sweep >= 60:
                last_sweep = now_ts
                try:
                    script = os.path.join(
                        os.path.dirname(os.path.abspath(__file__)), "notify-ban.py"
                    )
                    subprocess.run(
                        [sys.executable, script, "--sweep"],
                        capture_output=True,
                        timeout=30,
                    )
                except Exception:
                    log(f"sweep error: {traceback.format_exc()}")

            url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
            r = requests.get(url, params={"offset": offset, "timeout": 30}, timeout=35)
            for update in r.json().get("result", []):
                offset = update["update_id"] + 1
                if "message" in update:
                    try:
                        process_update(update)
                    except Exception:
                        log(f"process_update error: {traceback.format_exc()}")
                        chat_id = str(update.get("message", {}).get("chat", {}).get("id", ""))
                        send_message(chat_id, "⛔ Internal error — check server logs")
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
