"""Tests for notify-ban.py."""

import json
import os
import subprocess
import time
from unittest.mock import MagicMock, patch

import pytest
from conftest import make_ar_input

# ── Helpers ──────────────────────────────────────────────────────────────────


class TestSendTelegram:
    def test_sends_post_to_correct_url(self, notify_ban):
        notify_ban.send_telegram("-100111", "hello")
        notify_ban._mock_post.assert_called_once()
        call_args = notify_ban._mock_post.call_args
        assert "/sendMessage" in call_args[0][0]
        assert call_args[1]["json"]["chat_id"] == "-100111"
        assert call_args[1]["json"]["text"] == "hello"

    def test_noop_when_token_missing(self, notify_ban, monkeypatch):
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        notify_ban.send_telegram("-100111", "hello")
        notify_ban._mock_post.assert_not_called()

    def test_noop_when_chat_id_missing(self, notify_ban):
        notify_ban.send_telegram("", "hello")
        notify_ban._mock_post.assert_not_called()

    def test_swallows_network_error(self, notify_ban):
        notify_ban._mock_post.side_effect = Exception("network down")
        # Should not raise
        notify_ban.send_telegram("-100111", "hello")


class TestWriteBanLog:
    def test_appends_to_file(self, notify_ban):
        notify_ban.write_ban_log("1.2.3.4", "5710")
        with open(notify_ban._ban_log) as f:
            content = f.read()
        assert "Banned 1.2.3.4" in content
        assert "Rule 5710" in content

    def test_unban_action(self, notify_ban):
        notify_ban.write_ban_log("1.2.3.4", "5710", action="Unbanned")
        with open(notify_ban._ban_log) as f:
            content = f.read()
        assert "Unbanned 1.2.3.4" in content
        assert "Rule 5710" in content

    def test_multiple_entries_append(self, notify_ban):
        notify_ban.write_ban_log("1.1.1.1", "100")
        notify_ban.write_ban_log("2.2.2.2", "200")
        with open(notify_ban._ban_log) as f:
            lines = f.read().strip().splitlines()
        assert len(lines) == 2


class TestIsDuplicate:
    def test_first_call_not_duplicate(self, notify_ban, tmp_path):
        # Use a unique IP so no leftover lockfiles
        assert notify_ban.is_duplicate("10.0.0.1") is False

    def test_second_call_is_duplicate(self, notify_ban, tmp_path):
        notify_ban.is_duplicate("10.0.0.2")
        assert notify_ban.is_duplicate("10.0.0.2") is True

    def test_expired_lock_is_not_duplicate(self, notify_ban, tmp_path):
        notify_ban.is_duplicate("10.0.0.3")
        lf = notify_ban.lockfile_path("10.0.0.3")
        # Back-date the lockfile
        old_time = time.time() - 20
        os.utime(lf, (old_time, old_time))
        assert notify_ban.is_duplicate("10.0.0.3") is False


# ── Main flow ────────────────────────────────────────────────────────────────


class TestMainAdd:
    """Test the main() function with action=add."""

    def test_ban_sends_to_full_log(self, notify_ban):
        payload = make_ar_input(action="add", srcip="5.5.5.5", rule_id="5710")
        with (
            patch("sys.stdin") as mock_stdin,
            patch.object(notify_ban, "ban_ip"),
            patch.object(notify_ban, "is_duplicate", return_value=False),
            patch.object(notify_ban, "is_already_banned", return_value=False),
        ):
            mock_stdin.readline.return_value = payload
            notify_ban.main()

        # Should have sent at least one Telegram message (full log)
        assert notify_ban._mock_post.call_count >= 1
        first_call = notify_ban._mock_post.call_args_list[0]
        assert "Banned" in first_call[1]["json"]["text"]

    def test_silent_rule_skips_critical_channel(self, notify_ban):
        payload = make_ar_input(action="add", srcip="6.6.6.6", rule_id="5710")
        with (
            patch("sys.stdin") as mock_stdin,
            patch.object(notify_ban, "ban_ip"),
            patch.object(notify_ban, "is_duplicate", return_value=False),
            patch.object(notify_ban, "is_already_banned", return_value=False),
        ):
            mock_stdin.readline.return_value = payload
            notify_ban.main()

        # 5710 is in SILENT_RULES -> only 1 message (full log), not 2
        assert notify_ban._mock_post.call_count == 1

    def test_non_silent_rule_sends_to_critical(self, notify_ban):
        payload = make_ar_input(action="add", srcip="7.7.7.7", rule_id="99999")
        with (
            patch("sys.stdin") as mock_stdin,
            patch.object(notify_ban, "ban_ip"),
            patch.object(notify_ban, "is_duplicate", return_value=False),
            patch.object(notify_ban, "is_already_banned", return_value=False),
        ):
            mock_stdin.readline.return_value = payload
            notify_ban.main()

        # Non-silent -> 2 messages: full log + critical
        assert notify_ban._mock_post.call_count == 2

    def test_duplicate_suppressed(self, notify_ban):
        payload = make_ar_input(action="add", srcip="8.8.8.8")
        with (
            patch("sys.stdin") as mock_stdin,
            patch.object(notify_ban, "ban_ip"),
            patch.object(notify_ban, "is_duplicate", return_value=True),
            patch.object(notify_ban, "is_already_banned", return_value=False),
        ):
            mock_stdin.readline.return_value = payload
            notify_ban.main()

        # Duplicate -> no Telegram calls
        notify_ban._mock_post.assert_not_called()


class TestMainDelete:
    def test_unban_sends_message(self, notify_ban):
        payload = make_ar_input(action="delete", srcip="9.9.9.9")
        with (
            patch("sys.stdin") as mock_stdin,
            patch.object(notify_ban, "unban_ip") as mock_unban,
        ):
            mock_stdin.readline.return_value = payload
            notify_ban.main()

        mock_unban.assert_called_once_with("9.9.9.9")
        assert notify_ban._mock_post.call_count == 1
        text = notify_ban._mock_post.call_args[1]["json"]["text"]
        assert "Unbanned" in text

    def test_unban_logs_to_ban_history(self, notify_ban):
        payload = make_ar_input(action="delete", srcip="9.9.9.9")
        with (
            patch("sys.stdin") as mock_stdin,
            patch.object(notify_ban, "unban_ip"),
        ):
            mock_stdin.readline.return_value = payload
            notify_ban.main()

        with open(notify_ban._ban_log) as f:
            content = f.read()
        assert "Unbanned 9.9.9.9" in content

    def test_unban_calls_iptables_delete(self, notify_ban):
        payload = make_ar_input(action="delete", srcip="9.9.9.9")
        with (
            patch("sys.stdin") as mock_stdin,
            patch.object(notify_ban, "unban_ip", return_value=True) as mock_unban,
        ):
            mock_stdin.readline.return_value = payload
            notify_ban.main()

        mock_unban.assert_called_once_with("9.9.9.9")


class TestMainEdgeCases:
    def test_no_srcip_exits_cleanly(self, notify_ban):
        payload = json.dumps(
            {
                "command": "add",
                "parameters": {"alert": {"rule": {}, "agent": {}, "data": {}}},
            }
        )
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.readline.return_value = payload
            with pytest.raises(SystemExit):
                notify_ban.main()

    def test_ban_runs_even_when_notify_crashes(self, notify_ban):
        """The core robustness guarantee: ban fires before notification."""
        payload = make_ar_input(action="add", srcip="3.3.3.3", rule_id="5710")
        with (
            patch("sys.stdin") as mock_stdin,
            patch.object(notify_ban, "ban_ip") as mock_ban,
            patch.object(notify_ban, "_notify", side_effect=Exception("sentinel broken")),
            patch.object(notify_ban, "is_already_banned", return_value=False),
        ):
            mock_stdin.readline.return_value = payload
            # Should NOT raise — the exception in _notify is caught
            notify_ban.main()

        # Ban MUST have been called despite notification failure
        mock_ban.assert_called_once()

    def test_error_log_written_when_notify_crashes(self, notify_ban, tmp_path):
        """Notification failures are logged to ar-errors.log."""
        payload = make_ar_input(action="add", srcip="4.4.4.4", rule_id="5710")
        with (
            patch("sys.stdin") as mock_stdin,
            patch.object(notify_ban, "ban_ip"),
            patch.object(notify_ban, "_notify", side_effect=RuntimeError("yaml broken")),
            patch.object(notify_ban, "is_already_banned", return_value=False),
        ):
            mock_stdin.readline.return_value = payload
            notify_ban.main()

        with open(notify_ban.AR_ERROR_LOG) as f:
            content = f.read()
        assert "yaml broken" in content
        assert "4.4.4.4" in content


# ── iptables dedup ───────────────────────────────────────────────────────────────


class TestIsAlreadyBanned:
    def test_returns_true_when_rule_exists(self, notify_ban):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert notify_ban.is_already_banned("1.2.3.4") is True
            mock_run.assert_called_once_with(
                ["iptables", "-C", "INPUT", "-s", "1.2.3.4", "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    def test_returns_false_when_rule_missing(self, notify_ban):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            assert notify_ban.is_already_banned("1.2.3.4") is False

    def test_fails_open_on_exception(self, notify_ban):
        with patch("subprocess.run", side_effect=OSError("no iptables")):
            assert notify_ban.is_already_banned("1.2.3.4") is False


class TestAlreadyBannedSkipsBan:
    def test_skips_ban_when_already_banned(self, notify_ban):
        payload = make_ar_input(action="add", srcip="3.3.3.3", rule_id="5710")
        with (
            patch("sys.stdin") as mock_stdin,
            patch.object(notify_ban, "ban_ip") as mock_ban,
            patch.object(notify_ban, "is_duplicate", return_value=False),
            patch.object(notify_ban, "is_already_banned", return_value=True),
        ):
            mock_stdin.readline.return_value = payload
            notify_ban.main()

        # ban_ip should NOT have been called
        mock_ban.assert_not_called()
        # But Telegram notification should still be sent
        assert notify_ban._mock_post.call_count >= 1

    def test_calls_ban_when_not_banned(self, notify_ban):
        payload = make_ar_input(action="add", srcip="4.4.4.4", rule_id="5710")
        with (
            patch("sys.stdin") as mock_stdin,
            patch.object(notify_ban, "ban_ip") as mock_ban,
            patch.object(notify_ban, "is_duplicate", return_value=False),
            patch.object(notify_ban, "is_already_banned", return_value=False),
        ):
            mock_stdin.readline.return_value = payload
            notify_ban.main()

        mock_ban.assert_called_once()


class TestDeduplicateIptables:
    def test_removes_duplicates(self, notify_ban):
        iptables_output = (
            "*filter\n"
            ":INPUT ACCEPT [0:0]\n"
            "-A INPUT -s 1.2.3.4/32 -j DROP\n"
            "-A INPUT -s 1.2.3.4/32 -j DROP\n"
            "-A INPUT -s 5.6.7.8/32 -j DROP\n"
            "COMMIT\n"
        )
        mock_save = MagicMock(stdout=iptables_output)
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [mock_save, MagicMock()]  # save, restore
            removed = notify_ban.deduplicate_iptables()
        assert removed == 1
        # iptables-restore should have been called with deduped content
        restore_call = mock_run.call_args_list[1]
        assert "-A INPUT -s 1.2.3.4/32 -j DROP" in restore_call[1]["input"]
        # Only one copy of the 1.2.3.4 rule in the restore input
        assert restore_call[1]["input"].count("-A INPUT -s 1.2.3.4/32 -j DROP") == 1

    def test_noop_when_no_duplicates(self, notify_ban):
        iptables_output = "*filter\n-A INPUT -s 1.2.3.4/32 -j DROP\nCOMMIT\n"
        mock_save = MagicMock(stdout=iptables_output)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = mock_save
            removed = notify_ban.deduplicate_iptables()
        assert removed == 0
        # Only iptables-save called, no restore needed
        assert mock_run.call_count == 1

    def test_returns_zero_on_error(self, notify_ban):
        with patch("subprocess.run", side_effect=OSError("fail")):
            assert notify_ban.deduplicate_iptables() == 0

    def test_bad_json_exits(self, notify_ban):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.readline.return_value = "NOT JSON"
            with pytest.raises(SystemExit):
                notify_ban.main()


# ── Ban state tracking ───────────────────────────────────────────────────────


class TestBanState:
    def test_load_empty_state(self, notify_ban):
        assert notify_ban.load_state() == {}

    def test_save_and_load(self, notify_ban):
        notify_ban.save_state({"1.2.3.4": {"banned_at": 100, "ttl": 600, "rule_id": "5763"}})
        state = notify_ban.load_state()
        assert "1.2.3.4" in state
        assert state["1.2.3.4"]["ttl"] == 600

    def test_record_ban_writes_state(self, notify_ban):
        with patch.object(notify_ban, "_schedule_at_unban"):
            notify_ban.record_ban("10.0.0.1", "5763", ttl=300)
        state = notify_ban.load_state()
        assert "10.0.0.1" in state
        assert state["10.0.0.1"]["ttl"] == 300
        assert state["10.0.0.1"]["rule_id"] == "5763"

    def test_record_ban_schedules_at(self, notify_ban):
        with patch.object(notify_ban, "_schedule_at_unban") as mock_at:
            notify_ban.record_ban("10.0.0.2", "5710", ttl=600)
        mock_at.assert_called_once_with("10.0.0.2", 600)

    def test_remove_ban_record(self, notify_ban):
        with patch.object(notify_ban, "_schedule_at_unban"):
            notify_ban.record_ban("10.0.0.3", "100")
        notify_ban.remove_ban_record("10.0.0.3")
        state = notify_ban.load_state()
        assert "10.0.0.3" not in state

    def test_remove_nonexistent_is_noop(self, notify_ban):
        notify_ban.remove_ban_record("99.99.99.99")  # should not raise


class TestScheduleAt:
    def test_calls_at_command(self, notify_ban):
        with patch("subprocess.run") as mock_run:
            notify_ban._schedule_at_unban("1.2.3.4", 600)
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args == ["at", "now + 10 minutes"]
        assert "--unban 1.2.3.4" in mock_run.call_args[1]["input"]

    def test_rounds_up_minutes(self, notify_ban):
        with patch("subprocess.run") as mock_run:
            notify_ban._schedule_at_unban("1.2.3.4", 61)
        args = mock_run.call_args[0][0]
        assert args == ["at", "now + 2 minutes"]

    def test_minimum_one_minute(self, notify_ban):
        with patch("subprocess.run") as mock_run:
            notify_ban._schedule_at_unban("1.2.3.4", 5)
        args = mock_run.call_args[0][0]
        assert args == ["at", "now + 1 minutes"]

    def test_swallows_error_when_at_missing(self, notify_ban):
        with patch("subprocess.run", side_effect=FileNotFoundError("at not found")):
            notify_ban._schedule_at_unban("1.2.3.4", 600)  # should not raise


class TestSweepExpiredBans:
    def test_unbans_expired_ips(self, notify_ban):
        # Plant a ban that expired 10 seconds ago
        notify_ban.save_state({
            "1.1.1.1": {"banned_at": time.time() - 700, "ttl": 600, "rule_id": "5763"},
        })
        with patch.object(notify_ban, "unban_ip", return_value=True) as mock_unban:
            result = notify_ban.sweep_expired_bans()
        mock_unban.assert_called_once_with("1.1.1.1")
        assert result == ["1.1.1.1"]
        # State file should be empty now
        assert notify_ban.load_state() == {}

    def test_keeps_active_bans(self, notify_ban):
        notify_ban.save_state({
            "2.2.2.2": {"banned_at": time.time(), "ttl": 600, "rule_id": "100"},
        })
        with patch.object(notify_ban, "unban_ip") as mock_unban:
            result = notify_ban.sweep_expired_bans()
        mock_unban.assert_not_called()
        assert result == []
        assert "2.2.2.2" in notify_ban.load_state()

    def test_mixed_expired_and_active(self, notify_ban):
        now = time.time()
        notify_ban.save_state({
            "3.3.3.3": {"banned_at": now - 1000, "ttl": 600, "rule_id": "A"},
            "4.4.4.4": {"banned_at": now, "ttl": 600, "rule_id": "B"},
        })
        with patch.object(notify_ban, "unban_ip", return_value=True):
            result = notify_ban.sweep_expired_bans()
        assert result == ["3.3.3.3"]
        state = notify_ban.load_state()
        assert "3.3.3.3" not in state
        assert "4.4.4.4" in state

    def test_sweep_logs_to_ban_history(self, notify_ban):
        notify_ban.save_state({
            "5.5.5.5": {"banned_at": time.time() - 700, "ttl": 600, "rule_id": "5763"},
        })
        with patch.object(notify_ban, "unban_ip", return_value=True):
            notify_ban.sweep_expired_bans()
        with open(notify_ban._ban_log) as f:
            content = f.read()
        assert "Unbanned (sweep) 5.5.5.5" in content

    def test_sweep_sends_telegram(self, notify_ban):
        notify_ban.save_state({
            "6.6.6.6": {"banned_at": time.time() - 700, "ttl": 600, "rule_id": "100"},
        })
        with patch.object(notify_ban, "unban_ip", return_value=True):
            notify_ban.sweep_expired_bans()
        assert notify_ban._mock_post.call_count >= 1
        text = notify_ban._mock_post.call_args[1]["json"]["text"]
        assert "Sweep" in text
        assert "6.6.6.6" in text

    def test_noop_on_empty_state(self, notify_ban):
        result = notify_ban.sweep_expired_bans()
        assert result == []


class TestMainRecordsBan:
    """Verify main() records bans in the state file."""

    def test_add_records_ban(self, notify_ban):
        payload = make_ar_input(action="add", srcip="7.7.7.7", rule_id="5763")
        with (
            patch("sys.stdin") as mock_stdin,
            patch.object(notify_ban, "ban_ip"),
            patch.object(notify_ban, "is_duplicate", return_value=False),
            patch.object(notify_ban, "is_already_banned", return_value=False),
            patch.object(notify_ban, "_schedule_at_unban"),
        ):
            mock_stdin.readline.return_value = payload
            notify_ban.main()
        state = notify_ban.load_state()
        assert "7.7.7.7" in state
        assert state["7.7.7.7"]["rule_id"] == "5763"

    def test_delete_removes_ban_record(self, notify_ban):
        # Pre-populate state
        notify_ban.save_state({
            "8.8.8.8": {"banned_at": time.time(), "ttl": 600, "rule_id": "5710"},
        })
        payload = make_ar_input(action="delete", srcip="8.8.8.8", rule_id="5710")
        with (
            patch("sys.stdin") as mock_stdin,
            patch.object(notify_ban, "unban_ip"),
        ):
            mock_stdin.readline.return_value = payload
            notify_ban.main()
        state = notify_ban.load_state()
        assert "8.8.8.8" not in state
