"""Tests for the Bitcoin & Lightning addon (sentinel.addons.bitcoin)."""

from typing import Any
from unittest.mock import MagicMock

import pytest

from sentinel.addons.bitcoin import cmd_bitcoin, score_channel_health, valid_height


# ── valid_height ─────────────────────────────────────────────────────────────


class TestValidHeight:
    def test_int_is_valid(self):
        assert valid_height(876543) is True

    def test_numeric_string_is_valid(self):
        assert valid_height("876543") is True

    def test_error_string_is_invalid(self):
        assert valid_height("error") is False

    def test_empty_dict_is_invalid(self):
        assert valid_height({}) is False


# ── score_channel_health ─────────────────────────────────────────────────────


class TestScoreChannelHealth:
    def test_all_active_balanced(self):
        channels: list[dict[str, Any]] = [
            {"active": True, "capacity": "1000000", "local_balance": "500000"},
            {"active": True, "capacity": "2000000", "local_balance": "600000"},
        ]
        emoji, label = score_channel_health(channels)
        assert emoji == "\U0001f7e2"
        assert "healthy" in label
        assert "2 channels" in label

    def test_inactive_channel(self):
        channels: list[dict[str, Any]] = [
            {"active": True, "capacity": "1000000", "local_balance": "500000"},
            {"active": False, "capacity": "1000000", "local_balance": "500000"},
        ]
        emoji, label = score_channel_health(channels)
        assert "\U0001f534" in emoji
        assert "offline" in label
        assert "1/2" in label

    def test_needs_rebalancing_low(self):
        channels: list[dict[str, Any]] = [
            {"active": True, "capacity": "1000000", "local_balance": "50000"},  # 5% ratio
        ]
        emoji, label = score_channel_health(channels)
        assert "\U0001f7e1" in emoji
        assert "rebalancing" in label
        assert "<15% local" in label

    def test_needs_rebalancing_high(self):
        channels: list[dict[str, Any]] = [
            {"active": True, "capacity": "1000000", "local_balance": "950000"},  # 95% ratio
        ]
        emoji, label = score_channel_health(channels)
        assert "\U0001f7e1" in emoji
        assert "rebalancing" in label
        assert ">85% local" in label

    def test_rebalancing_shows_count_and_pcts(self):
        channels: list[dict[str, Any]] = [
            {"active": True, "capacity": "1000000", "local_balance": "50000"},  # 5%
            {"active": True, "capacity": "1000000", "local_balance": "500000"},  # 50% OK
            {"active": True, "capacity": "1000000", "local_balance": "950000"},  # 95%
        ]
        emoji, label = score_channel_health(channels)
        assert "\U0001f7e1" in emoji
        assert "2/3" in label
        assert "<15%" in label
        assert ">85%" in label


# ── cmd_bitcoin disabled ─────────────────────────────────────────────────────


class TestCmdBitcoin:
    def test_bitcoin_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from sentinel.config import _DEFAULTS, _deep_merge, reload_config  # pyright: ignore[reportPrivateUsage]

        reload_config()
        test_cfg = _deep_merge(_DEFAULTS, {"integrations": {"bitcoin": {"enabled": False}}})
        import sentinel.config

        monkeypatch.setattr(sentinel.config, "cfg", test_cfg)

        import sentinel.addons.bitcoin as btc

        mock_send = MagicMock()
        monkeypatch.setattr(btc, "send_message", mock_send)
        cmd_bitcoin("123")
        text = mock_send.call_args[0][1]
        assert "disabled" in text
