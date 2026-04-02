"""Active-ban state persistence (JSON file with file locking)."""

import contextlib
import fcntl
import json
import os
import time
from typing import Any

from sentinel.config import get_cfg


def _state_path() -> str:
    """Return the path to the active-bans JSON state file."""
    try:
        return get_cfg()["active_response"]["ban_state_file"]
    except Exception:
        return "/var/ossec/logs/active-bans.json"


def load_state() -> dict[str, Any]:
    """Load active-bans state from disk. Returns {} on any error."""
    path = _state_path()
    try:
        with open(path) as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            data = json.load(f)
            fcntl.flock(f, fcntl.LOCK_UN)
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    except Exception:
        return {}


def save_state(state: dict[str, Any]) -> None:
    """Atomically write active-bans state to disk."""
    path = _state_path()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            json.dump(state, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
            fcntl.flock(f, fcntl.LOCK_UN)
        os.replace(tmp, path)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def record_ban(ip: str, rule_id: str, ttl: int | None = None) -> int:
    """Record a ban in the state file. Returns the effective TTL used."""
    if ttl is None:
        try:
            ttl = int(get_cfg()["active_response"]["ban_timeout_seconds"])
        except Exception:
            ttl = 600

    state = load_state()
    state[ip] = {
        "banned_at": time.time(),
        "ttl": ttl,
        "rule_id": rule_id,
    }
    save_state(state)
    return ttl


def remove_ban_record(ip: str) -> None:
    """Remove an IP from the state file."""
    state = load_state()
    if ip in state:
        del state[ip]
        save_state(state)
