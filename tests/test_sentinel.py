"""Tests for the sentinel shared library."""

from unittest.mock import patch, MagicMock

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

    def test_silent_rules_is_set(self):
        from sentinel.config import SILENT_RULES
        assert isinstance(SILENT_RULES, set)
        assert "31151" in SILENT_RULES
        assert "5710" in SILENT_RULES

    def test_load_env_file(self, tmp_path, monkeypatch):
        env_file = tmp_path / "test.env"
        env_file.write_text(
            "# comment\n"
            "NEW_VAR=hello\n"
            "EXISTING=old\n"
            "\n"
            "SPACED = world\n"
        )
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
