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
            ["iptables-save"],
            capture_output=True,
            text=True,
            check=True,
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


def ban_ip(ip: str) -> bool:
    """Ban an IP via iptables.  Returns True on success."""
    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
        )
        debug_log(f"iptables: banned {ip}")
        return True
    except Exception as e:
        _log_error(f"iptables ban failed for {ip}: {e}")
        debug_log(f"iptables ban error: {e}")
        return False


def unban_ip(ip: str) -> bool:
    """Remove iptables DROP rule for IP.  Returns True on success."""
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
        )
        debug_log(f"iptables: unbanned {ip}")
        return True
    except Exception as e:
        _log_error(f"iptables unban failed for {ip}: {e}")
        debug_log(f"iptables unban error: {e}")
        return False


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
    main()
