#!/usr/bin/env python3
"""
notify-ban.py - Wazuh Active Response + Telegram Notification Script
======================================================================
Deployed as a Wazuh active response binary. Bans/unbans the offending
IP directly via iptables, sends a Telegram notification, and writes
to the ban history log.

DESIGN PRINCIPLE: The firewall action MUST succeed even if everything
else (Telegram, config loading, logging) is broken.  ban_ip()/unban_ip()
execute first with only the raw stdin JSON.  All notification and
logging is best-effort and wrapped in try/except so it can never
prevent the security action.

Deployment:
  sudo cp notify-ban.py /var/ossec/active-response/bin/notify-ban.py
  sudo chmod 750 /var/ossec/active-response/bin/notify-ban.py
  sudo chown root:wazuh /var/ossec/active-response/bin/notify-ban.py

Environment variables are loaded from /etc/homelab-sentinel.env
(injected via systemd EnvironmentFile or sourced at runtime).
"""

import contextlib
import json
import os
import subprocess
import sys
import time

AR_ERROR_LOG = "/var/ossec/logs/ar-errors.log"
DEBUG_LOG = None  # set to "/tmp/ar_debug.log" to enable verbose trace

# sentinel/ lives under /var/ossec/integrations/ when deployed, but this
# script lives under /var/ossec/active-response/bin/.  Set the path once
# so all late imports find the library.
_SENTINEL_LIB = os.environ.get("SENTINEL_LIB", "/var/ossec/integrations")
if _SENTINEL_LIB not in sys.path:
    sys.path.insert(0, _SENTINEL_LIB)

from sentinel.ban_state import load_state, record_ban, remove_ban_record, save_state
from sentinel.firewall import ban_ip, deduplicate_iptables, is_already_banned, unban_ip


# ── Helpers ──────────────────────────────────────────────────────────────────


def _log_error(msg: str) -> None:
    """Append to the persistent AR error log.  Never raises."""
    try:
        with open(AR_ERROR_LOG, "a") as f:
            f.write(f"{time.strftime('%Y/%m/%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass


def debug_log(msg: str) -> None:
    if DEBUG_LOG:
        with open(DEBUG_LOG, "a") as f:
            f.write(f"{time.ctime()}: {msg}\n")


def send_telegram(chat_id: str, message: str) -> None:
    """Best-effort Telegram send.  Never raises."""
    try:
        # Late imports — sentinel library may be broken; that must never
        # prevent the firewall ban that already ran before this point.
        from sentinel import telegram
        from sentinel.config import env, load_env_file

        load_env_file()
        token = env("TELEGRAM_BOT_TOKEN")
        err = telegram.send(token, chat_id, message)
        if err:
            _log_error(f"Telegram send failed (chat {chat_id}): {err}")
            debug_log(f"send failed: {err}")
    except Exception as exc:
        _log_error(f"Telegram send error (chat {chat_id}): {exc}")
        debug_log(f"send exception: {exc}")


def write_ban_log(ip: str, rule_id: str, action: str = "Banned") -> None:
    """Best-effort ban log write.  Never raises."""
    try:
        from sentinel.config import get_cfg

        ban_log = get_cfg()["active_response"]["ban_log"]
    except Exception:
        ban_log = "/var/ossec/logs/ban-history.log"
    try:
        with open(ban_log, "a") as f:
            f.write(f"{time.strftime('%Y/%m/%d %H:%M:%S')} {action} {ip} (Rule {rule_id})\n")
    except Exception as e:
        _log_error(f"Ban log write error ({ban_log}): {e}")
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
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(time.time()).encode())
        os.close(fd)
    except FileExistsError:
        return True
    return False


# ── Ban state tracking ───────────────────────────────────────────────────────


def _schedule_at_unban(ip: str, ttl: int) -> None:
    """Best-effort: schedule an at-job to auto-unban after ttl seconds."""
    try:
        script = os.path.abspath(__file__)
        minutes = max(1, (ttl + 59) // 60)  # round up to nearest minute
        at_cmd = f"python3 {script} --unban {ip}\n"
        subprocess.run(
            ["at", f"now + {minutes} minutes"],
            input=at_cmd,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        debug_log(f"at: scheduled unban for {ip} in {minutes}m")
    except Exception as e:
        # at(1) may not be installed — the sweep is the real safety net
        debug_log(f"at: scheduling failed (non-fatal): {e}")


def sweep_expired_bans() -> list[str]:
    """Unban any IPs whose TTL has expired.  Returns list of IPs unbanned."""
    state = load_state()
    now = time.time()
    expired = []

    for ip, info in list(state.items()):
        banned_at = info.get("banned_at", 0)
        ttl = info.get("ttl", 600)
        if now - banned_at >= ttl:
            expired.append(ip)

    if not expired:
        debug_log("sweep: no expired bans")
        return []

    unbanned = []
    for ip in expired:
        if unban_ip(ip):
            unbanned.append(ip)
            rule_id = state[ip].get("rule_id", "?")
            write_ban_log(ip, rule_id, action="Unbanned (sweep)")
        del state[ip]

    save_state(state)

    # Best-effort notification
    if unbanned:
        try:
            from sentinel.config import env, get_cfg, load_env_file

            load_env_file()
            ar_cfg = get_cfg()["active_response"]
            if ar_cfg.get("notify_on_expire", True):
                full_log_chat = env("TELEGRAM_FULL_LOG_CHAT_ID")
                ip_list = ", ".join(f"<code>{ip}</code>" for ip in unbanned)
                message = f"\U0001f9f9 <b>Sweep: unbanned {len(unbanned)} expired IP(s)</b>\n{ip_list}"
                send_telegram(full_log_chat, message)
        except Exception as exc:
            debug_log(f"sweep notification error: {exc}")

    debug_log(f"sweep: unbanned {len(unbanned)} IP(s)")
    return unbanned


def cli_unban(ip: str) -> None:
    """CLI handler for --unban: remove iptables rule, clean state, log, notify."""
    from sentinel.validate import validated_ip

    ip = validated_ip(ip)
    if not ip:
        print(f"Invalid IP: {sys.argv[2]}")
        sys.exit(1)

    state = load_state()
    rule_id = state.get(ip, {}).get("rule_id", "?")

    unban_ip(ip)
    remove_ban_record(ip)
    write_ban_log(ip, rule_id, action="Unbanned (at-job)")

    try:
        from sentinel.config import env, get_cfg, load_env_file

        load_env_file()
        ar_cfg = get_cfg()["active_response"]
        if ar_cfg.get("notify_on_expire", True):
            full_log_chat = env("TELEGRAM_FULL_LOG_CHAT_ID")
            message = (
                f"\u2705 <b>Auto-expiry: Unbanned</b>\n"
                f"<b>IP:</b> <code>{ip}</code>\n"
                f"<b>Rule:</b> {rule_id}"
            )
            send_telegram(full_log_chat, message)
    except Exception as exc:
        debug_log(f"cli_unban notification error: {exc}")


def _extract_ip(data: dict) -> str:
    """Pull srcip from the alert JSON, or return empty string."""
    return data.get("parameters", {}).get("alert", {}).get("data", {}).get("srcip", "")


def _validate_ip(ip: str) -> str | None:
    """Validate and return normalized IP, or None on failure."""
    try:
        from sentinel.validate import validated_ip

        return validated_ip(ip)
    except Exception:
        # Fallback: basic sanity check (IPv4 dotted quad)
        parts = ip.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return ip
        return None


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    # ── Phase 1: Read stdin (fatal if this fails — nothing to do) ────
    try:
        raw = sys.stdin.readline()
        debug_log(f"stdin: {raw[:500]}")
        data = json.loads(raw)
    except Exception as e:
        _log_error(f"JSON parse error: {e}")
        debug_log(f"JSON parse error: {e}")
        sys.exit(1)

    action = data.get("command", "")
    ip = _extract_ip(data)

    if not ip:
        debug_log("No srcip found, exiting")
        sys.exit(0)

    ip = _validate_ip(ip)
    if not ip:
        debug_log("Invalid IP from alert, exiting")
        sys.exit(1)

    # ── Phase 2: FIREWALL ACTION — runs before any config/notification ──
    # This block uses ONLY stdlib.  No sentinel imports, no env loading,
    # no YAML config, no Telegram.  If it fails, it's a real OS-level
    # problem (iptables broken / permissions).
    if action == "add":
        if not is_already_banned(ip):
            ban_ip(ip)
        else:
            debug_log(f"{ip} already in iptables, skipping ban")
    elif action == "delete":
        unban_ip(ip)

    # ── Phase 3: Notification & logging (best-effort) ────────────────
    # Everything below is wrapped so failures can never retroactively
    # undo the firewall action above.
    try:
        _notify(action, ip, data)
    except Exception as exc:
        _log_error(f"Notification phase failed for {ip}: {exc}")
        debug_log(f"Notification phase error: {exc}")


def _notify(action: str, ip: str, data: dict) -> None:
    """Handle logging and Telegram notifications.  Called after the ban."""
    from sentinel.config import env, get_cfg, load_env_file

    load_env_file()

    full_log_chat = env("TELEGRAM_FULL_LOG_CHAT_ID")
    critical_chat = env("TELEGRAM_CRITICAL_CHAT_ID")

    alert = data.get("parameters", {}).get("alert", {})
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    geo = alert.get("GeoLocation", {})

    rule_id = str(rule.get("id", ""))
    rule_desc = rule.get("description", "Unknown rule")
    agent_name = agent.get("name", "unknown")

    from sentinel.sanitize import agent_alias

    agent_display = agent_alias(agent_name)

    country = geo.get("country_name", "")
    country_str = f" [{country}]" if country else ""

    ar_cfg = get_cfg()["active_response"]
    silent_rules = set(str(r) for r in get_cfg()["alerts"]["silent_rules"])
    extra_whitelist = ar_cfg.get("extra_whitelist", [])

    if ip in extra_whitelist:
        debug_log(f"Whitelisted IP {ip}, skipping notifications")
        return

    # ── Handle add (new ban) ─────────────────────────────────────────
    if action == "add":
        if is_duplicate(ip):
            debug_log(f"Duplicate suppressed for {ip}")
            return

        write_ban_log(ip, rule_id)
        ttl = record_ban(ip, rule_id)
        _schedule_at_unban(ip, ttl)

        message = (
            f"🔨 <b>Active Response: Banned</b>\n"
            f"<b>IP:</b> <code>{ip}</code>{country_str}\n"
            f"<b>Rule:</b> {rule_id} - {rule_desc}\n"
            f"<b>Agent:</b> {agent_display}"
        )

        send_telegram(full_log_chat, message)

        if rule_id not in silent_rules:
            send_telegram(critical_chat, f"🚨 {message}")

    # ── Handle delete (ban expiry) ───────────────────────────────────
    elif action == "delete":
        remove_ban_record(ip)
        write_ban_log(ip, rule_id, action="Unbanned")

        if ar_cfg.get("notify_on_expire", True):
            message = (
                f"✅ <b>Active Response: Unbanned</b>\n"
                f"<b>IP:</b> <code>{ip}</code>{country_str}\n"
                f"<b>Rule:</b> {rule_id}\n"
                f"<b>Agent:</b> {agent_display}"
            )
            send_telegram(full_log_chat, message)

    else:
        debug_log(f"Unknown action: {action}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--sweep":
        expired = sweep_expired_bans()
        print(f"Swept {len(expired)} expired ban(s)")
        sys.exit(0)
    if len(sys.argv) > 2 and sys.argv[1] == "--unban":
        cli_unban(sys.argv[2])
        sys.exit(0)
    main()
