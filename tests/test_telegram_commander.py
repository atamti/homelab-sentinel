"""Tests for telegram-commander.py."""

from unittest.mock import MagicMock, patch

import pyotp
from conftest import FAKE_ENV, make_telegram_update

# ── Pure helpers ─────────────────────────────────────────────────────────────


class TestEsc:
    def test_escapes_html_entities(self, commander):
        assert commander.esc("a < b & c > d") == "a &lt; b &amp; c &gt; d"

    def test_noop_on_clean_string(self, commander):
        assert commander.esc("hello world") == "hello world"


class TestFormatTableRow:
    def test_basic_formatting(self, commander):
        result = commander.format_table_row("5710", 8, 42, "SSH brute force")
        assert "<b>5710</b>" in result
        assert "\u00d742" in result
        assert "L8" in result
        assert "SSH brute force" in result


class TestRag:
    def test_green_below_amber(self, commander):
        assert commander._rag(0.5, 1.0, 2.0) == "\U0001f7e2"

    def test_amber_between(self, commander):
        assert commander._rag(1.5, 1.0, 2.0) == "\U0001f7e1"

    def test_red_above(self, commander):
        assert commander._rag(3.0, 1.0, 2.0) == "\U0001f534"

    def test_exact_amber_threshold(self, commander):
        assert commander._rag(1.0, 1.0, 2.0) == "\U0001f7e1"

    def test_exact_red_threshold(self, commander):
        assert commander._rag(2.0, 1.0, 2.0) == "\U0001f534"


class TestSimplifyServiceName:
    def test_strips_http_prefix(self, commander):
        assert commander._simplify_service_name("HTTP - myservice.local") == "myservice"

    def test_strips_url_protocol(self, commander):
        assert commander._simplify_service_name("https://myapp.local:8080/health") == "myapp"

    def test_strips_tcp_prefix(self, commander):
        assert commander._simplify_service_name("TCP Port - 10.0.0.1:22") == "10.0.0.1"

    def test_plain_name_unchanged(self, commander):
        assert commander._simplify_service_name("My Web App") == "My Web App"


class TestValidHeight:
    def test_int_is_valid(self, commander):
        assert commander._valid_height(876543) is True

    def test_numeric_string_is_valid(self, commander):
        assert commander._valid_height("876543") is True

    def test_error_string_is_invalid(self, commander):
        assert commander._valid_height("error") is False

    def test_empty_dict_is_invalid(self, commander):
        assert commander._valid_height({}) is False


# ── Send message / chunking ─────────────────────────────────────────────────


class TestSendMessage:
    def test_single_chunk(self, commander):
        commander.send_message("123", "short message")
        commander._mock_post.assert_called_once()
        payload = commander._mock_post.call_args[1]["json"]
        assert payload["chat_id"] == "123"
        assert payload["text"] == "short message"

    def test_long_message_chunked(self, commander):
        long_text = "x" * 9000  # > 4000, should produce 3 chunks
        commander.send_message("123", long_text)
        assert commander._mock_post.call_count == 3


# ── TOTP ─────────────────────────────────────────────────────────────────────


class TestTOTP:
    def test_verify_valid_code(self, commander):
        code = pyotp.TOTP(FAKE_ENV["TOTP_SECRET"]).now()
        assert commander.verify_totp(code) is True

    def test_verify_invalid_code(self, commander):
        assert commander.verify_totp("000000") is False

    def test_require_totp_splits_arg_and_verifies(self, commander):
        code = pyotp.TOTP(FAKE_ENV["TOTP_SECRET"]).now()
        result, valid = commander.require_totp("123", f"1.2.3.4 {code}")
        assert valid is True
        assert result == "1.2.3.4"

    def test_require_totp_rejects_missing_code(self, commander):
        result, valid = commander.require_totp("123", "1.2.3.4")
        assert valid is False
        assert result is None

    def test_require_totp_only_valid(self, commander):
        code = pyotp.TOTP(FAKE_ENV["TOTP_SECRET"]).now()
        assert commander.require_totp_only("123", code) is True

    def test_require_totp_only_invalid(self, commander):
        assert commander.require_totp_only("123", "000000") is False


# ── Authorization ────────────────────────────────────────────────────────────


class TestProcessUpdate:
    def test_unauthorized_user_rejected(self, commander):
        update = make_telegram_update("/help", user_id="666")
        commander.process_update(update)
        commander._mock_post.assert_called_once()
        assert "Unauthorized" in commander._mock_post.call_args[1]["json"]["text"]

    def test_unknown_command(self, commander):
        update = make_telegram_update("/nonexistent", user_id="999")
        commander.process_update(update)
        commander._mock_post.assert_called_once()
        assert "Unknown command" in commander._mock_post.call_args[1]["json"]["text"]

    def test_help_command(self, commander):
        update = make_telegram_update("/help", user_id="999")
        commander.process_update(update)
        commander._mock_post.assert_called_once()
        text = commander._mock_post.call_args[1]["json"]["text"]
        assert "Homelab Sentinel" in text
        assert "/status" in text


# ── Read-only commands ───────────────────────────────────────────────────────


class TestScoreChannelHealth:
    def test_all_active_balanced(self, commander):
        channels = [
            {"active": True, "capacity": "1000000", "local_balance": "500000"},
            {"active": True, "capacity": "2000000", "local_balance": "600000"},
        ]
        emoji, label = commander.score_channel_health(channels)
        assert emoji == "\U0001f7e2"
        assert "healthy" in label
        assert "2 channels" in label

    def test_inactive_channel(self, commander):
        channels = [
            {"active": True, "capacity": "1000000", "local_balance": "500000"},
            {"active": False, "capacity": "1000000", "local_balance": "500000"},
        ]
        emoji, label = commander.score_channel_health(channels)
        assert "\U0001f534" in emoji
        assert "offline" in label
        assert "1/2" in label

    def test_needs_rebalancing_low(self, commander):
        channels = [
            {"active": True, "capacity": "1000000", "local_balance": "50000"},  # 5% ratio
        ]
        emoji, label = commander.score_channel_health(channels)
        assert "\U0001f7e1" in emoji
        assert "rebalancing" in label
        assert "<15% local" in label

    def test_needs_rebalancing_high(self, commander):
        channels = [
            {"active": True, "capacity": "1000000", "local_balance": "950000"},  # 95% ratio
        ]
        emoji, label = commander.score_channel_health(channels)
        assert "\U0001f7e1" in emoji
        assert "rebalancing" in label
        assert ">85% local" in label

    def test_rebalancing_shows_count_and_pcts(self, commander):
        channels = [
            {"active": True, "capacity": "1000000", "local_balance": "50000"},  # 5%
            {"active": True, "capacity": "1000000", "local_balance": "500000"},  # 50% OK
            {"active": True, "capacity": "1000000", "local_balance": "950000"},  # 95%
        ]
        emoji, label = commander.score_channel_health(channels)
        assert "\U0001f7e1" in emoji
        assert "2/3" in label
        assert "<15%" in label
        assert ">85%" in label


class TestCmdUptime:
    def test_sends_uptime_output(self, commander):
        commander._mock_getoutput.return_value = "up 5 days, 3:22"
        commander.cmd_uptime("123")
        text = commander._mock_post.call_args[1]["json"]["text"]
        assert "up 5 days" in text


class TestCmdDisk:
    def test_sends_disk_output(self, commander):
        commander._mock_getoutput.return_value = (
            "Filesystem  Size  Used Avail Use% Mounted\n/dev/sda1    50G   20G   28G  42% /"
        )
        commander.cmd_disk("123")
        text = commander._mock_post.call_args[1]["json"]["text"]
        assert "Disk Usage" in text
        assert "Drive 1" in text
        assert "/dev/sda1" not in text


class TestCmdServices:
    def test_sends_docker_output(self, commander):
        commander._mock_getoutput.return_value = "NAMES  STATUS\nnginx  Up 2 days"
        commander.cmd_services("123")
        text = commander._mock_post.call_args[1]["json"]["text"]
        assert "Docker Services" in text


class TestCmdBlocked:
    def test_displays_ban_info(self, commander):
        commander._mock_getoutput.side_effect = [
            "DROP  all  -- 1.2.3.4  0.0.0.0/0",  # iptables page
            "5",  # total count
            "2026/03/09 Banned 1.2.3.4 (Rule 5710)",  # ban log page
        ]
        commander.cmd_blocked("123")
        assert commander._mock_post.call_count == 2

    def test_ip_lookup(self, commander):
        commander._mock_getoutput.side_effect = [
            "DROP  all  -- 1.2.3.4  0.0.0.0/0",  # iptables grep
            "2026/03/09 Banned 1.2.3.4 (Rule 5710)",  # history grep
        ]
        commander.cmd_blocked("123", "1.2.3.4")
        text = commander._mock_post.call_args[1]["json"]["text"]
        assert "Lookup" in text
        assert "1.2.3.4" in text

    def test_invalid_ip_rejected(self, commander):
        commander.cmd_blocked("123", "not-an-ip")
        text = commander._mock_post.call_args[1]["json"]["text"]
        assert "Invalid IP" in text


class TestCmdAlerts:
    def test_displays_alerts(self, commander):
        search_resp = MagicMock()
        search_resp.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "id": "abc123",
                            "timestamp": "2026-03-09T10:00:00",
                            "rule": {"id": "5710", "level": 10, "description": "SSH brute force"},
                            "agent": {"id": "001", "name": "server1"},
                        }
                    }
                ]
            }
        }
        commander._mock_post.return_value = search_resp
        commander.cmd_alerts("123")
        sent = [c for c in commander._mock_post.call_args_list if "sendMessage" in str(c)]
        assert len(sent) >= 1
        text = sent[0][1]["json"]["text"]
        assert "server1" in text
        assert "Rule 5710" in text


class TestCmdEvent:
    def test_missing_totp_shows_error(self, commander):
        commander.cmd_event("123", "some-alert-id")
        text = commander._mock_post.call_args[1]["json"]["text"]
        assert "TOTP required" in text

    def test_missing_arg_shows_usage(self, commander):
        code = pyotp.TOTP(FAKE_ENV["TOTP_SECRET"]).now()
        commander.cmd_event("123", f" {code}")
        text = commander._mock_post.call_args[1]["json"]["text"]
        assert "Usage" in text

    def test_not_found(self, commander):
        search_resp = MagicMock()
        search_resp.json.return_value = {"hits": {"hits": []}}
        commander._mock_post.return_value = search_resp
        code = pyotp.TOTP(FAKE_ENV["TOTP_SECRET"]).now()
        commander.cmd_event("123", f"nonexistent {code}")
        sent = [c for c in commander._mock_post.call_args_list if "sendMessage" in str(c)]
        assert any("No alert found" in str(c) for c in sent)

    def test_truncates_full_log(self, commander):
        long_log = "A" * 300
        search_resp = MagicMock()
        search_resp.json.return_value = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "id": "abc123",
                            "timestamp": "2026-03-09T10:00:00",
                            "rule": {"id": "5710", "level": 10, "description": "test", "groups": ["sshd"]},
                            "agent": {"id": "001", "name": "server1"},
                            "data": {},
                            "full_log": long_log,
                        }
                    }
                ]
            }
        }
        commander._mock_post.return_value = search_resp
        code = pyotp.TOTP(FAKE_ENV["TOTP_SECRET"]).now()
        commander.cmd_event("123", f"abc123 {code}")
        sent = [c for c in commander._mock_post.call_args_list if "sendMessage" in str(c)]
        text = sent[-1][1]["json"]["text"]
        # full_log should be truncated to 150 + "..."
        assert "A" * 150 in text
        assert "A" * 151 not in text
        assert "..." in text
        assert "<b>Agent:</b> server1" in text


# ── Active response commands ─────────────────────────────────────────────────


class TestCmdBlock:
    def test_rejects_without_totp(self, commander):
        commander.cmd_block("123", "1.2.3.4")
        text = commander._mock_post.call_args[1]["json"]["text"]
        assert "TOTP required" in text

    def test_blocks_with_valid_totp(self, commander):
        code = pyotp.TOTP(FAKE_ENV["TOTP_SECRET"]).now()
        commander.cmd_block("123", f"1.2.3.4 {code}")
        sent = [c for c in commander._mock_post.call_args_list if "sendMessage" in str(c)]
        assert any("Blocked" in str(c) for c in sent)


class TestCmdUnblock:
    def test_unblocks_with_valid_totp(self, commander):
        code = pyotp.TOTP(FAKE_ENV["TOTP_SECRET"]).now()
        commander.cmd_unblock("123", f"1.2.3.4 {code}")
        sent = [c for c in commander._mock_post.call_args_list if "sendMessage" in str(c)]
        assert any("Unblocked" in str(c) for c in sent)


class TestCmdLockdown:
    def test_rejects_without_totp(self, commander):
        commander.cmd_lockdown("123", "")
        text = commander._mock_post.call_args[1]["json"]["text"]
        assert "TOTP required" in text

    def test_activates_with_valid_totp(self, commander):
        code = pyotp.TOTP(FAKE_ENV["TOTP_SECRET"]).now()
        commander.cmd_lockdown("123", code)
        sent = [c for c in commander._mock_post.call_args_list if "sendMessage" in str(c)]
        assert any("LOCKDOWN" in str(c) for c in sent)


class TestCmdRestore:
    def test_fails_without_backup(self, commander):
        code = pyotp.TOTP(FAKE_ENV["TOTP_SECRET"]).now()
        with patch("os.path.exists", return_value=False):
            commander.cmd_restore("123", code)
        sent = [c for c in commander._mock_post.call_args_list if "sendMessage" in str(c)]
        assert any("No pre-lockdown backup" in str(c) for c in sent)


class TestCmdSyscheck:
    def test_rejects_without_totp(self, commander):
        commander.cmd_syscheck("123", "001")
        text = commander._mock_post.call_args[1]["json"]["text"]
        assert "TOTP required" in text

    def test_polls_until_complete(self, commander):
        code = pyotp.TOTP(FAKE_ENV["TOTP_SECRET"]).now()
        # Mock the PUT (start) and GET (poll) responses
        put_resp = MagicMock()
        put_resp.status_code = 200
        # Wazuh token response
        token_resp = MagicMock()
        token_resp.json.return_value = {"data": {"token": "fake-token"}}
        token_resp.status_code = 200
        # Poll response — scan finished
        scan_resp = MagicMock()
        scan_resp.json.return_value = {
            "data": {"affected_items": [{"start": "2026-03-10T10:00:00Z", "end": "2026-03-10T10:05:00Z"}]}
        }
        scan_resp.status_code = 200
        # requests.put returns the put_resp; requests.get returns token then scan
        import requests as req_mod

        with (
            patch.object(req_mod, "put", return_value=put_resp),
            patch.object(req_mod, "get", return_value=scan_resp),
            patch.object(commander, "get_wazuh_token", return_value="fake-token"),
            patch.object(commander, "wazuh_get", return_value=scan_resp.json.return_value),
            patch("time.sleep"),
        ):
            commander.cmd_syscheck("123", f"001 {code}")
        sent = [c for c in commander._mock_post.call_args_list if "sendMessage" in str(c)]
        texts = [c[1]["json"]["text"] for c in sent]
        assert any("started" in t for t in texts)
        assert any("completed" in t for t in texts)

    def test_timeout_message(self, commander):
        code = pyotp.TOTP(FAKE_ENV["TOTP_SECRET"]).now()
        put_resp = MagicMock()
        put_resp.status_code = 200
        # Poll response — scan never finishes (no "end")
        scan_data = {"data": {"affected_items": [{"start": "2026-03-10T10:00:00Z"}]}}
        import requests as req_mod

        with (
            patch.object(req_mod, "put", return_value=put_resp),
            patch.object(commander, "get_wazuh_token", return_value="fake-token"),
            patch.object(commander, "wazuh_get", return_value=scan_data),
            patch("time.sleep"),
        ):
            commander.cmd_syscheck("123", f"001 {code}")
        sent = [c for c in commander._mock_post.call_args_list if "sendMessage" in str(c)]
        texts = [c[1]["json"]["text"] for c in sent]
        assert any("still running" in t for t in texts)
