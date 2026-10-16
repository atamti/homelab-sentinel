"""Tests for the sentinel shared library."""

import time
from unittest.mock import MagicMock, patch

import pytest


class TestConfig:
    def test_require_env_returns_value(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "test_value")
        from sentinel.config import require_env

        assert require_env("TEST_KEY") == "test_value"

    def test_require_env_raises_on_missing(self, monkeypatch):
        monkeypatch.delenv("NONEXISTENT_KEY", raising=False)
        from sentinel.config import require_env

        with pytest.raises(RuntimeError, match="NONEXISTENT_KEY"):
            require_env("NONEXISTENT_KEY")

    def test_env_returns_default(self, monkeypatch):
        monkeypatch.delenv("NONEXISTENT_KEY", raising=False)
        from sentinel.config import env

        assert env("NONEXISTENT_KEY", "fallback") == "fallback"

    def test_env_returns_value(self, monkeypatch):
        monkeypatch.setenv("TEST_KEY", "real")
        from sentinel.config import env

        assert env("TEST_KEY", "fallback") == "real"

    def test_load_env_file(self, tmp_path, monkeypatch):
        env_file = tmp_path / "test.env"
        env_file.write_text("# comment\nNEW_VAR=hello\nEXISTING=old\n\nSPACED = world\n")
        monkeypatch.setenv("EXISTING", "keep")
        monkeypatch.delenv("NEW_VAR", raising=False)
        monkeypatch.delenv("SPACED", raising=False)
        from sentinel.config import load_env_file

        load_env_file(str(env_file))
        import os

        assert os.environ["NEW_VAR"] == "hello"
        assert os.environ["EXISTING"] == "keep"  # not overwritten
        assert os.environ["SPACED"] == "world"

    def test_load_env_file_missing(self):
        from sentinel.config import load_env_file

        load_env_file("/nonexistent/path")  # should not raise

    def test_load_env_file_strips_quotes(self, tmp_path, monkeypatch):
        env_file = tmp_path / "quoted.env"
        env_file.write_text('DQ_VAR="double-quoted"\nSQ_VAR=\'single-quoted\'\nNO_QUOTE=plain\n')
        monkeypatch.delenv("DQ_VAR", raising=False)
        monkeypatch.delenv("SQ_VAR", raising=False)
        monkeypatch.delenv("NO_QUOTE", raising=False)
        from sentinel.config import load_env_file

        load_env_file(str(env_file))
        import os

        assert os.environ["DQ_VAR"] == "double-quoted"
        assert os.environ["SQ_VAR"] == "single-quoted"
        assert os.environ["NO_QUOTE"] == "plain"


class TestTelegram:
    def test_send_posts_to_api(self):
        with patch("requests.post") as mock_post:
            from sentinel.telegram import send

            send("TOKEN", "CHAT", "hello")
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert "TOKEN" in call_args[0][0]
            assert call_args[1]["json"]["chat_id"] == "CHAT"
            assert call_args[1]["json"]["text"] == "hello"

    def test_send_noop_without_token(self):
        with patch("requests.post") as mock_post:
            from sentinel.telegram import send

            send("", "CHAT", "hello")
            mock_post.assert_not_called()

    def test_send_noop_without_chat_id(self):
        with patch("requests.post") as mock_post:
            from sentinel.telegram import send

            send("TOKEN", "", "hello")
            mock_post.assert_not_called()

    def test_send_chunks_long_messages(self):
        with patch("requests.post") as mock_post:
            from sentinel.telegram import send

            send("TOKEN", "CHAT", "x" * 9000)
            assert mock_post.call_count == 3

    def test_esc_escapes_html(self):
        from sentinel.telegram import esc

        assert esc("<b>&</b>") == "&lt;b&gt;&amp;&lt;/b&gt;"


class TestWazuh:
    def test_get_token_returns_jwt(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"token": "jwt-123"}}
        with patch("requests.post", return_value=mock_resp):
            from sentinel.wazuh import get_token

            assert get_token("https://api", "user", "pass") == "jwt-123"

    def test_get_token_returns_none_on_error(self):
        with patch("requests.post", side_effect=Exception("fail")):
            from sentinel.wazuh import get_token

            assert get_token("https://api", "user", "pass") is None

    def test_api_get_returns_json(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": {"agents": []}}
        with patch("requests.get", return_value=mock_resp):
            from sentinel.wazuh import api_get

            result = api_get("https://api", "/agents", "token")
            assert result == {"data": {"agents": []}}

    def test_api_get_returns_empty_on_error(self):
        with patch("requests.get", side_effect=Exception("fail")):
            from sentinel.wazuh import api_get

            assert api_get("https://api", "/agents", "token") == {}

    def test_indexer_search_returns_json(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"hits": {"hits": []}}
        with patch("requests.post", return_value=mock_resp):
            from sentinel.wazuh import indexer_search

            result = indexer_search("https://idx", "user", "pass", {"query": {}})
            assert result == {"hits": {"hits": []}}

    def test_indexer_search_returns_empty_on_error(self):
        with patch("requests.post", side_effect=Exception("fail")):
            from sentinel.wazuh import indexer_search

            assert indexer_search("https://idx", "user", "pass", {}) == {}


class TestValidate:
    def test_valid_ipv4(self):
        from sentinel.validate import validated_ip

        assert validated_ip("1.2.3.4") == "1.2.3.4"

    def test_valid_ipv6(self):
        from sentinel.validate import validated_ip

        assert validated_ip("::1") == "::1"

    def test_invalid_ip_raises(self):
        from sentinel.validate import validated_ip

        with pytest.raises(ValueError):
            validated_ip("not-an-ip")

    def test_ip_with_semicolon_raises(self):
        from sentinel.validate import validated_ip

        with pytest.raises(ValueError):
            validated_ip("1.2.3.4; rm -rf /")

    def test_valid_port(self):
        from sentinel.validate import validated_port

        assert validated_port("443") == "443"

    def test_port_zero_raises(self):
        from sentinel.validate import validated_port

        with pytest.raises(ValueError):
            validated_port("0")

    def test_port_too_high_raises(self):
        from sentinel.validate import validated_port

        with pytest.raises(ValueError):
            validated_port("70000")

    def test_port_injection_raises(self):
        from sentinel.validate import validated_port

        with pytest.raises(ValueError):
            validated_port("80; whoami")


# ---------------------------------------------------------------------------
# sentinel.system
# ---------------------------------------------------------------------------


class TestRag:
    def test_green(self):
        from sentinel.system import rag

        assert rag(10, 70, 90) == "\U0001f7e2"

    def test_amber(self):
        from sentinel.system import rag

        assert rag(75, 70, 90) == "\U0001f7e1"

    def test_red(self):
        from sentinel.system import rag

        assert rag(95, 70, 90) == "\U0001f534"

    def test_exact_amber_boundary(self):
        from sentinel.system import rag

        assert rag(70, 70, 90) == "\U0001f7e1"

    def test_exact_red_boundary(self):
        from sentinel.system import rag

        assert rag(90, 70, 90) == "\U0001f534"


class TestFormatSystemRagLines:
    STATS = {
        "uptime": "up 1 day",
        "load": "0.50 0.40 0.30",
        "load_1m": 0.5,
        "nproc": 4,
        "mem": "1.5G/4.0G",
        "mem_pct": 42.0,
        "disk": "30% used (30G/100G)",
        "disk_pct": 30.0,
        "cpu_temp": 55.0,
        "banned": "0",
    }
    TH = {
        "load_per_core_amber": 1.0,
        "load_per_core_red": 2.0,
        "memory_amber": 70,
        "memory_red": 90,
        "disk_amber": 70,
        "disk_red": 90,
        "cpu_temp_amber": 70,
        "cpu_temp_red": 85,
    }

    def test_all_green_compact(self):
        from sentinel.system import format_system_rag_lines

        lines = format_system_rag_lines(self.STATS, self.TH, compact=True)
        assert any("System" in l for l in lines)
        # Compact all-green should NOT have emoji per line
        assert not any(l.startswith("\U0001f7e2 Load") for l in lines)

    def test_all_green_verbose(self):
        from sentinel.system import format_system_rag_lines

        lines = format_system_rag_lines(self.STATS, self.TH, compact=False)
        assert any("\U0001f7e2 Load" in l for l in lines)

    def test_amber_memory(self):
        from sentinel.system import format_system_rag_lines

        stats = {**self.STATS, "mem_pct": 75.0}
        lines = format_system_rag_lines(stats, self.TH, compact=True)
        assert any("\U0001f7e1" in l for l in lines)

    def test_no_cpu_temp(self):
        from sentinel.system import format_system_rag_lines

        stats = {**self.STATS, "cpu_temp": None}
        lines = format_system_rag_lines(stats, self.TH)
        assert not any("CPU temp" in l for l in lines)


class TestGetSystemStats:
    def test_parses_normal_output(self):
        from sentinel.system import get_system_stats

        outputs = {
            "cat /proc/loadavg": "0.50 0.40 0.30 1/200 12345",
            "nproc": "4",
            "free | grep Mem": "42",
            "df / | tail": "30",
            "cat /sys/class/thermal": "55000",
            "uptime -p": "up 1 day",
            "free -h": "1.5G/4.0G",
            "df -h /": "30% used",
            "iptables -L": "3",
        }

        def fake_getoutput(cmd: str) -> str:
            for key, val in outputs.items():
                if key in cmd:
                    return val
            return ""

        with patch("sentinel.system.subprocess.getoutput", side_effect=fake_getoutput):
            stats = get_system_stats()
        assert stats["load_1m"] == 0.5
        assert stats["nproc"] == 4
        assert stats["mem_pct"] == 42.0
        assert stats["disk_pct"] == 30.0
        assert stats["cpu_temp"] == 55.0

    def test_handles_parse_failures(self):
        from sentinel.system import get_system_stats

        with patch("sentinel.system.subprocess.getoutput", return_value="garbage"):
            stats = get_system_stats()
        assert stats["load_1m"] == 0.0
        assert stats["nproc"] == 1
        assert stats["mem_pct"] == 0.0
        assert stats["disk_pct"] == 0.0


# ---------------------------------------------------------------------------
# sentinel.security
# ---------------------------------------------------------------------------


class TestCleanRuleDesc:
    def test_strips_variables(self):
        from sentinel.security import clean_rule_desc

        assert clean_rule_desc("Attack from $(srcip) on $(dstport)") == "Attack from on"

    def test_collapses_spaces(self):
        from sentinel.security import clean_rule_desc

        assert clean_rule_desc("too  many   spaces") == "too many spaces"

    def test_clean_passthrough(self):
        from sentinel.security import clean_rule_desc

        assert clean_rule_desc("Normal description") == "Normal description"


class TestSimplifyServiceName:
    @pytest.mark.parametrize(
        "input_name,expected",
        [
            ("HTTP - myservice.local", "myservice"),
            ("HTTPS - myservice.lan:8443/health", "myservice"),
            ("TCP Port - myhost:3000", "myhost"),
            ("Ping - myrouter.home", "myrouter"),
            ("Docker Container - redis", "redis"),
            ("DNS - ns1.internal", "ns1"),
            ("https://grafana.local:3000/api", "grafana"),
            ("plain-name", "plain-name"),
        ],
    )
    def test_simplification(self, input_name: str, expected: str):
        from sentinel.security import simplify_service_name

        assert simplify_service_name(input_name) == expected


class TestFormatTableRow:
    def test_short_desc(self):
        from sentinel.security import format_table_row

        result = format_table_row("5710", 5, 3, "sshd login attempt")
        assert "<b>5710</b>" in result
        assert "(L5)" in result
        assert "\u00d73" in result

    def test_long_desc_wraps(self):
        from sentinel.security import format_table_row

        desc = "This is a very long rule description that exceeds the thirty-five char limit"
        result = format_table_row("100", 10, 1, desc)
        lines = result.strip().split("\n")
        assert len(lines) >= 2


class TestLookupRules:
    def test_empty_ids_returns_empty(self):
        from sentinel.security import lookup_rules

        assert lookup_rules([], "token", MagicMock()) == {}

    def test_empty_token_returns_empty(self):
        from sentinel.security import lookup_rules

        assert lookup_rules(["5710"], "", MagicMock()) == {}

    def test_normal_response(self):
        from sentinel.security import lookup_rules

        mock_get = MagicMock(return_value={
            "data": {"affected_items": [
                {"id": "5710", "level": 5, "description": "sshd login attempt"},
            ]}
        })
        result = lookup_rules(["5710"], "tok", mock_get)
        assert "5710" in result
        assert result["5710"]["level"] == 5


class TestQueryCriticalAlerts:
    def test_normal_buckets(self):
        from sentinel.security import query_critical_alerts

        mock_search = MagicMock(return_value={
            "aggregations": {"by_level": {"buckets": [
                {"key": 12, "doc_count": 5, "by_rule": {"buckets": [{"key": "brute force", "doc_count": 5}]}},
            ]}}
        })
        buckets = query_critical_alerts(mock_search)
        assert len(buckets) == 1
        assert buckets[0]["key"] == 12

    def test_empty_response(self):
        from sentinel.security import query_critical_alerts

        mock_search = MagicMock(return_value={})
        assert query_critical_alerts(mock_search) == []


class TestParseBanHistory:
    def test_parses_recent_bans(self, tmp_path):
        from sentinel.security import parse_ban_history

        log_file = tmp_path / "ban-history.log"
        recent_ts = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime())
        log_file.write_text(
            f"{recent_ts} Banned 1.2.3.4 (Rule 5710)\n"
            f"{recent_ts} Banned 5.6.7.8 (Rule 5710)\n"
            f"{recent_ts} Banned 9.0.1.2 (Rule 31151)\n"
            f"{recent_ts} Unbanned 1.2.3.4\n"
        )
        with patch("sentinel.security.get_cfg", return_value={"active_response": {"ban_log": str(log_file)}}):
            counts = parse_ban_history()
        assert counts["5710"] == 2
        assert counts["31151"] == 1
        assert "Unbanned" not in str(counts)

    def test_missing_file_returns_empty(self):
        from sentinel.security import parse_ban_history

        with patch("sentinel.security.get_cfg", return_value={"active_response": {"ban_log": "/nonexistent"}}):
            assert parse_ban_history() == {}
