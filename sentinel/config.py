"""Shared configuration helpers and constants."""

import os

import yaml

VERSION = "0.1.0"

ENV_FILE = "/etc/homelab-sentinel.env"

# ── YAML configuration ──────────────────────────────────────────────────────

_CONFIG_PATHS = [
    "/etc/homelab-sentinel.yaml",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "homelab-sentinel.yaml"),
]

_DEFAULTS = {
    "alerts": {
        "full_log_level": 7,
        "critical_level": 10,
        "silent_rules": ["31151", "5710", "5711"],
        "silent_groups": [],
    },
    "active_response": {
        "ban_log": "/var/ossec/logs/ban-history.log",
        "ban_state_file": "/var/ossec/logs/active-bans.json",
        "ban_timeout_seconds": 600,
        "notify_on_expire": True,
        "extra_whitelist": [],
    },
    "commands": {
        "enabled": {
            "system": [
                "status",
                "system",
                "disk",
                "uptime",
            ],
            "security": [
                "security",
                "alerts",
                "top",
                "blocked",
                "event",
            ],
            "agents": [
                "agents",
            ],
            "services": [
                "services",
            ],
            "bitcoin": [
                "bitcoin",
            ],
            "active_response": [
                "block",
                "unblock",
                "closeport",
                "openport",
                "lockdown",
                "restore",
                "restart",
                "syscheck",
                "shutdown",
            ],
            "general": [
                "help",
                "start",
                "digest",
            ],
        },
        "totp_required": [
            "block",
            "unblock",
            "closeport",
            "openport",
            "lockdown",
            "restore",
            "restart",
            "syscheck",
            "shutdown",
        ],
    },
    "digest": {
        "time": "06:30",
        "sections": {
            "system": True,
            "agents": True,
            "security": True,
            "services": True,
            "bitcoin": True,
        },
        "critical_agents": {},
        "bitcoin_lag_warning_blocks": 6,
        "thresholds": {
            "load_per_core_amber": 1.0,
            "load_per_core_red": 2.0,
            "memory_amber": 70,
            "memory_red": 90,
            "disk_amber": 70,
            "disk_red": 90,
            "cpu_temp_amber": 70,
            "cpu_temp_red": 85,
        },
    },
    "integrations": {
        "bitcoin": {
            "enabled": True,
            "mempool_local": "https://minibolt.local:4081",
            "mempool_public_fallback": True,
        },
        "lnd": {
            "enabled": True,
            "rest_url": "https://minibolt.local:8080",
        },
        "uptime_kuma": {
            "enabled": True,
            "url": "http://localhost:3001/api/status-page/default",
        },
    },
    "sanitization": {},
    "alert_output": {},
    "bitcoin": {
        "channel_health": {
            "min_local_ratio": 0.15,
            "max_local_ratio": 0.85,
        },
    },
    "wazuh": {
        "unexpected_port_level": 12,
        "expected_port_rule_level": 3,
        "port_whitelist": {
            "masterserver": [
                {"port": 22, "proto": "tcp", "service": "SSH"},
                {"port": 80, "proto": "tcp", "service": "HTTP"},
                {"port": 443, "proto": "tcp", "service": "HTTPS"},
                {"port": 55000, "proto": "tcp", "service": "Wazuh API"},
                {"port": 9200, "proto": "tcp", "service": "OpenSearch"},
                {"port": 9300, "proto": "tcp", "service": "OpenSearch transport"},
                {"port": 3001, "proto": "tcp", "service": "Uptime Kuma"},
                {"port": 1514, "proto": "tcp", "service": "Wazuh agent"},
                {"port": 1515, "proto": "tcp", "service": "Wazuh enrollment"},
            ],
            "minibolt": [
                {"port": 22, "proto": "tcp", "service": "SSH"},
                {"port": 8080, "proto": "tcp", "service": "LND REST"},
                {"port": 4081, "proto": "tcp", "service": "mempool"},
                {"port": 9735, "proto": "tcp", "service": "LND P2P"},
                {"port": 18333, "proto": "tcp", "service": "Bitcoin testnet RPC"},
                {"port": 18334, "proto": "tcp", "service": "Bitcoin testnet P2P"},
                {"port": 3002, "proto": "tcp", "service": "Uptime Kuma"},
            ],
        },
    },
}

_raw_config: dict | None = None


def _deep_merge(defaults: dict, overrides: dict) -> dict:
    """Recursively merge overrides into defaults (overrides win)."""
    result = dict(defaults)
    for key, val in overrides.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _load_yaml() -> dict:
    """Load raw YAML config from disk. Returns empty dict on failure."""
    global _raw_config
    if _raw_config is not None:
        return _raw_config
    for path in _CONFIG_PATHS:
        try:
            with open(path) as f:
                _raw_config = yaml.safe_load(f) or {}
                return _raw_config
        except (FileNotFoundError, PermissionError):
            continue
    _raw_config = {}
    return _raw_config


def load_config() -> dict:
    """Return the full config dict, merged with defaults."""
    return _deep_merge(_DEFAULTS, _load_yaml())


def reload_config() -> None:
    """Force a config reload (useful after config changes or in tests)."""
    global _raw_config, cfg
    _raw_config = None
    cfg = None


# Convenience accessor
cfg = None  # Will be a dict; initialized lazily


def get_cfg() -> dict:
    """Return the cached config, loading on first access."""
    global cfg
    if cfg is None:
        cfg = load_config()
    return cfg


# Legacy constant — kept for backward compatibility during transition
_alerts: dict = _DEFAULTS["alerts"]  # type: ignore[assignment]
SILENT_RULES = set(_alerts["silent_rules"])


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
