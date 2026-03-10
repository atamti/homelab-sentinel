"""Tests for custom-telegram.py."""

import json
from unittest.mock import patch


class TestFormatAlert:
    def test_formats_basic_alert(self, custom_telegram):
        alert = {
            "rule": {"id": "5710", "level": 10, "description": "SSH brute force"},
            "agent": {"name": "server1"},
            "timestamp": "2026-03-09T10:00:00",
            "data": {"srcip": "1.2.3.4"},
            "id": "abc-123",
        }
        msg, level, rule_id = custom_telegram.format_alert(alert)
        assert "Level 10" in msg
        assert "5710" in msg
        assert "SSH brute force" in msg
        assert "server1" not in msg  # agent name stripped
        assert "1.2.3.4" in msg
        assert "abc-123" in msg
        assert "Ref:" in msg
        assert level == 10
        assert rule_id == "5710"

    def test_formats_alert_without_srcip(self, custom_telegram):
        alert = {
            "rule": {"id": "100", "level": 7, "description": "test"},
            "agent": {"name": "a"},
            "timestamp": "2026-01-01T00:00:00",
            "data": {},
            "id": "x",
        }
        msg, _level, _rule_id = custom_telegram.format_alert(alert)
        assert "Source IP" not in msg

    def test_handles_missing_fields(self, custom_telegram):
        alert = {}
        msg, level, _rule_id = custom_telegram.format_alert(alert)
        assert "N/A" in msg
        assert level == 0

    def test_unexpected_port_change_includes_details(self, custom_telegram):
        alert = {
            "rule": {"id": "100200", "level": 12, "description": "Unexpected port change"},
            "agent": {"id": "002", "name": "minibolt"},
            "timestamp": "2026-03-09T10:00:00",
            "data": {},
            "id": "port-1",
            "full_log": "New listening port 9090/tcp detected",
        }
        msg, _level, _rule_id = custom_telegram.format_alert(alert)
        assert "Agent:</b> 002" in msg
        assert "Port:</b> 9090" in msg
        assert "Status:</b> opened" in msg
        assert "minibolt" not in msg

    def test_unexpected_port_closed(self, custom_telegram):
        alert = {
            "rule": {"id": "100200", "level": 12, "description": "Unexpected port change"},
            "agent": {"id": "001", "name": "masterserver"},
            "timestamp": "2026-03-09T10:00:00",
            "data": {},
            "id": "port-2",
            "full_log": "Previously active port 8080/tcp became inactive",
        }
        msg, _level, _rule_id = custom_telegram.format_alert(alert)
        assert "Agent:</b> 001" in msg
        assert "Port:</b> 8080" in msg
        assert "Status:</b> closed" in msg

    def test_unexpected_port_unparseable_log(self, custom_telegram):
        alert = {
            "rule": {"id": "100200", "level": 12, "description": "Unexpected port change"},
            "agent": {"id": "003"},
            "timestamp": "2026-03-09T10:00:00",
            "data": {},
            "id": "port-3",
            "full_log": "",
        }
        msg, _level, _rule_id = custom_telegram.format_alert(alert)
        assert "Agent:</b> 003" in msg
        assert "Port:</b> unknown" in msg
        assert "Status:</b> changed" in msg


class TestMain:
    def test_sends_to_full_log(self, custom_telegram, tmp_path):
        alert = {
            "rule": {"id": "5710", "level": 8, "description": "test"},
            "agent": {"name": "s1"},
            "timestamp": "t",
            "data": {},
            "id": "1",
        }
        alert_file = tmp_path / "alert.json"
        alert_file.write_text(json.dumps(alert))

        with patch("sys.argv", ["custom-telegram", str(alert_file)]):
            custom_telegram.main()

        # Level 8 < 10, so only full log channel (1 call)
        assert custom_telegram._mock_post.call_count == 1

    def test_sends_to_both_channels_for_critical(self, custom_telegram, tmp_path):
        alert = {
            "rule": {"id": "99999", "level": 12, "description": "critical"},
            "agent": {"name": "s1"},
            "timestamp": "t",
            "data": {},
            "id": "2",
        }
        alert_file = tmp_path / "alert.json"
        alert_file.write_text(json.dumps(alert))

        with patch("sys.argv", ["custom-telegram", str(alert_file)]):
            custom_telegram.main()

        # Level 12 >= 10, non-silent rule -> both channels
        assert custom_telegram._mock_post.call_count == 2

    def test_silent_rule_skips_critical(self, custom_telegram, tmp_path):
        alert = {
            "rule": {"id": "5710", "level": 12, "description": "noisy"},
            "agent": {"name": "s1"},
            "timestamp": "t",
            "data": {},
            "id": "3",
        }
        alert_file = tmp_path / "alert.json"
        alert_file.write_text(json.dumps(alert))

        with patch("sys.argv", ["custom-telegram", str(alert_file)]):
            custom_telegram.main()

        # 5710 is in SILENT_RULES -> only full log (1 call)
        assert custom_telegram._mock_post.call_count == 1
