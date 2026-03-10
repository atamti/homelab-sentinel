"""Shared fixtures and helpers for the test suite."""

import importlib
import json
import os
import sys
import types
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Environment fixtures — provide a complete fake env so both modules can be
# imported without hitting real services or crashing on missing vars.
# ---------------------------------------------------------------------------

FAKE_ENV = {
    "TELEGRAM_BOT_TOKEN": "111111:FAKE-TOKEN",
    "TELEGRAM_AUTHORIZED_USER": "999",
    "TOTP_SECRET": "JBSWY3DPEHPK3PXP",
    "TELEGRAM_FULL_LOG_CHAT_ID": "-100111",
    "TELEGRAM_CRITICAL_CHAT_ID": "-100222",
    "WAZUH_API_URL": "https://127.0.0.1:55000",
    "WAZUH_API_USER": "testuser",
    "WAZUH_API_PASS": "testpass",
    "INDEXER_URL": "https://localhost:9200",
    "INDEXER_USER": "admin",
    "INDEXER_PASS": "admin",
    "LND_READONLY_MACAROON_B64": "dGVzdA==",  # base64("test")
    "COMMANDER_LOG": "/tmp/test-commander.log",
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    """Inject fake env vars, reset config cache, and temp paths for every test."""
    for key, val in FAKE_ENV.items():
        monkeypatch.setenv(key, val)
    # Point ban log at a temp file so tests don't touch /var/ossec
    monkeypatch.setenv("COMMANDER_LOG", str(tmp_path / "commander.log"))
    # Reset YAML config cache so tests get fresh defaults
    from sentinel.config import reload_config

    reload_config()


# ---------------------------------------------------------------------------
# Module-import helpers — import the scripts as Python modules on demand.
# Each fixture reloads the module so env patches take effect.
# ---------------------------------------------------------------------------


def _add_project_root():
    """Ensure the repo root is on sys.path."""
    root = os.path.dirname(os.path.dirname(__file__))
    if root not in sys.path:
        sys.path.insert(0, root)


def _import_script(name: str, monkeypatch) -> types.ModuleType:
    """Import (or re-import) a top-level script as a module.

    Handles hyphens in filenames by mapping them via importlib.
    Forces sentinel sub-modules to reimport so they pick up fresh mocks.
    """
    _add_project_root()
    # Clear cached sentinel modules so they pick up active patches
    for key in list(sys.modules):
        if key.startswith("sentinel"):
            del sys.modules[key]
    # Python module names can't have hyphens; use importlib path trick
    module_name = name.replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(
        module_name,
        os.path.join(os.path.dirname(os.path.dirname(__file__)), name),
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def notify_ban(monkeypatch, tmp_path):
    """Import notify-ban.py with mocked externals.

    Returns the loaded module.  ``requests.post`` and ``subprocess``
    calls are pre-mocked so nothing leaves the test process.
    """
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", FAKE_ENV["TELEGRAM_BOT_TOKEN"])
    monkeypatch.setenv("TELEGRAM_FULL_LOG_CHAT_ID", FAKE_ENV["TELEGRAM_FULL_LOG_CHAT_ID"])
    monkeypatch.setenv("TELEGRAM_CRITICAL_CHAT_ID", FAKE_ENV["TELEGRAM_CRITICAL_CHAT_ID"])

    ban_log = tmp_path / "ban-history.log"
    ban_log.touch()

    with patch("requests.post") as mock_post:
        from sentinel.config import _DEFAULTS, _deep_merge, reload_config

        reload_config()
        mod = _import_script("notify-ban.py", monkeypatch)
        # Override ban_log path via config to use temp file
        test_cfg = _deep_merge(_DEFAULTS, {"active_response": {"ban_log": str(ban_log)}})
        monkeypatch.setattr("sentinel.config.cfg", test_cfg)
        mod.DEBUG_LOG = str(tmp_path / "debug.log")
        mod._mock_post = mock_post
        mod._ban_log = str(ban_log)
        yield mod


@pytest.fixture()
def commander(monkeypatch, tmp_path):
    """Import telegram-commander.py with mocked externals.

    Returns the loaded module.  HTTP calls and subprocess are
    pre-mocked.
    """
    with (
        patch("requests.post") as mock_post,
        patch("requests.get") as mock_get,
        patch("subprocess.getoutput", return_value="") as mock_getoutput,
        patch("subprocess.run") as mock_run,
    ):
        mod = _import_script("telegram-commander.py", monkeypatch)
        mod._mock_post = mock_post
        mod._mock_get = mock_get
        mod._mock_getoutput = mock_getoutput
        mod._mock_run = mock_run
        yield mod


@pytest.fixture()
def custom_telegram(monkeypatch, tmp_path):
    """Import custom-telegram.py with mocked externals."""
    with patch("requests.post") as mock_post:
        mod = _import_script("custom-telegram.py", monkeypatch)
        mod._mock_post = mock_post
        yield mod


# ---------------------------------------------------------------------------
# Reusable test data builders
# ---------------------------------------------------------------------------


def make_ar_input(
    *,
    action="add",
    srcip="1.2.3.4",
    rule_id="5710",
    rule_desc="sshd brute force",
    rule_level=10,
    agent_name="server1",
    country="Germany",
):
    """Build a Wazuh active-response JSON payload."""
    return json.dumps(
        {
            "command": action,
            "parameters": {
                "alert": {
                    "rule": {
                        "id": rule_id,
                        "description": rule_desc,
                        "level": rule_level,
                    },
                    "agent": {"name": agent_name},
                    "GeoLocation": {"country_name": country},
                    "data": {"srcip": srcip},
                }
            },
        }
    )


def make_telegram_update(text: str, user_id: str = "999", chat_id: str = "999", update_id: int = 1):
    """Build a minimal Telegram Bot API update object."""
    return {
        "update_id": update_id,
        "message": {
            "chat": {"id": int(chat_id)},
            "from": {"id": int(user_id)},
            "text": text,
        },
    }
