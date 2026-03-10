"""Shared configuration helpers and constants."""

import os

VERSION = "0.1.0"

# Rules that trigger bans but skip the critical notification channel
SILENT_RULES = {"31151", "5710", "5711"}

ENV_FILE = "/etc/homelab-sentinel.env"


def load_env_file(path: str = ENV_FILE) -> None:
    """Parse a shell-style KEY=VALUE env file into os.environ.

    Skips blank lines, comments, and already-set variables.
    """
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if key and key not in os.environ:
                    os.environ[key] = value
    except FileNotFoundError:
        pass


def require_env(key: str) -> str:
    """Get a required environment variable or raise."""
    val = os.environ.get(key)
    if not val:
        raise RuntimeError(f"Required environment variable not set: {key}")
    return val


def env(key: str, default: str = "") -> str:
    """Get an optional environment variable with a default."""
    return os.environ.get(key, default)
