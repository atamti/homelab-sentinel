"""Shared configuration helpers and constants."""

import os

# Rules that trigger bans but skip the critical notification channel
SILENT_RULES = {"31151", "5710", "5711"}


def require_env(key: str) -> str:
    """Get a required environment variable or raise."""
    val = os.environ.get(key)
    if not val:
        raise RuntimeError(f"Required environment variable not set: {key}")
    return val


def env(key: str, default: str = "") -> str:
    """Get an optional environment variable with a default."""
    return os.environ.get(key, default)
