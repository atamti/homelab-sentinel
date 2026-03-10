"""Tests for sentinel/sanitize.py."""

from unittest.mock import patch

import pytest
import yaml

from sentinel import config as _sentinel_config
from sentinel import sanitize


@pytest.fixture(autouse=True)
def _reset_config():
    """Reset cached config before each test."""
    sanitize.reload_config()
    yield
    sanitize.reload_config()


def _write_config(tmp_path, cfg: dict) -> str:
    path = tmp_path / "homelab-sentinel.yaml"
    path.write_text(yaml.dump(cfg))
    return str(path)


def _patch_config(tmp_path, cfg: dict):
    """Return a patch context that makes sanitize load cfg from tmp_path."""
    path = _write_config(tmp_path, cfg)
    sanitize.reload_config()
    return patch.object(_sentinel_config, "_CONFIG_PATHS", [path])


# ── scrub_hostnames ──────────────────────────────────────────────────────────


class TestScrubHostnames:
    def test_replaces_configured_hostnames(self, tmp_path):
        cfg = {"sanitization": {"internal_hostnames": ["masterserver", "minibolt"]}}
        with _patch_config(tmp_path, cfg):
            result, count = sanitize.scrub_hostnames("Agent: masterserver | Target: minibolt")
        assert result == "Agent: [host] | Target: [host]"
        assert count == 2

    def test_case_insensitive(self, tmp_path):
        cfg = {"sanitization": {"internal_hostnames": ["MasterServer"]}}
        with _patch_config(tmp_path, cfg):
            result, _ = sanitize.scrub_hostnames("host is MASTERSERVER")
        assert "[host]" in result

    def test_preserves_html_tags(self, tmp_path):
        cfg = {"sanitization": {"internal_hostnames": ["myhost"]}}
        with _patch_config(tmp_path, cfg):
            result, _ = sanitize.scrub_hostnames("<b>Agent:</b> myhost is up")
        assert "<b>Agent:</b>" in result
        assert "myhost" not in result

    def test_no_config_returns_unchanged(self, tmp_path):
        cfg = {"sanitization": {}}
        with _patch_config(tmp_path, cfg):
            result, count = sanitize.scrub_hostnames("masterserver")
        assert result == "masterserver"
        assert count == 0


# ── scrub_internal_ips ───────────────────────────────────────────────────────


class TestScrubInternalIPs:
    def test_scrubs_rfc1918_class_a(self, tmp_path):
        cfg = {"sanitization": {}}
        with _patch_config(tmp_path, cfg):
            result, count = sanitize.scrub_internal_ips("IP: 10.0.0.1")
        assert result == "IP: [internal]"
        assert count == 1

    def test_scrubs_rfc1918_class_b(self, tmp_path):
        cfg = {"sanitization": {}}
        with _patch_config(tmp_path, cfg):
            result, _ = sanitize.scrub_internal_ips("target 172.16.0.5")
        assert "[internal]" in result

    def test_scrubs_rfc1918_class_c(self, tmp_path):
        cfg = {"sanitization": {}}
        with _patch_config(tmp_path, cfg):
            result, _ = sanitize.scrub_internal_ips("192.168.1.100")
        assert result == "[internal]"

    def test_preserves_public_ips(self, tmp_path):
        cfg = {"sanitization": {}}
        with _patch_config(tmp_path, cfg):
            result, count = sanitize.scrub_internal_ips("attacker: 45.33.22.11")
        assert "45.33.22.11" in result
        assert count == 0

    def test_preserves_html_tags(self, tmp_path):
        cfg = {"sanitization": {}}
        with _patch_config(tmp_path, cfg):
            result, _ = sanitize.scrub_internal_ips('<a href="10.0.0.1">link</a> ip=10.0.0.1')
        # Tag content preserved, text content scrubbed
        assert "10.0.0.1" in result  # inside tag
        assert result.endswith("ip=[internal]")


# ── scrub_paths ──────────────────────────────────────────────────────────────


class TestScrubPaths:
    def test_shortens_long_paths(self, tmp_path):
        cfg = {"sanitization": {}}
        with _patch_config(tmp_path, cfg):
            result, count = sanitize.scrub_paths("file at /var/ossec/logs/alerts.log")
        assert "/.../alerts.log" in result
        assert count == 1

    def test_preserves_short_paths(self, tmp_path):
        cfg = {"sanitization": {}}
        with _patch_config(tmp_path, cfg):
            result, count = sanitize.scrub_paths("in /tmp/foo")
        assert result == "in /tmp/foo"
        assert count == 0

    def test_preserves_html_tags(self, tmp_path):
        cfg = {"sanitization": {}}
        with _patch_config(tmp_path, cfg):
            result, _ = sanitize.scrub_paths("<pre>/var/ossec/logs/test.log</pre>")
        assert "<pre>" in result
        assert "</pre>" in result


# ── scrub_custom ─────────────────────────────────────────────────────────────


class TestScrubCustom:
    def test_applies_custom_replacements(self, tmp_path):
        cfg = {"sanitization": {"custom_replacements": {"dockerdaemon": "[service-user]"}}}
        with _patch_config(tmp_path, cfg):
            result, count = sanitize.scrub_custom("user: dockerdaemon")
        assert result == "user: [service-user]"
        assert count == 1

    def test_case_insensitive(self, tmp_path):
        cfg = {"sanitization": {"custom_replacements": {"Secret": "[redacted]"}}}
        with _patch_config(tmp_path, cfg):
            result, _ = sanitize.scrub_custom("found SECRET value")
        assert "[redacted]" in result

    def test_empty_config(self, tmp_path):
        cfg = {"sanitization": {}}
        with _patch_config(tmp_path, cfg):
            result, count = sanitize.scrub_custom("nothing to scrub")
        assert result == "nothing to scrub"
        assert count == 0


# ── summarize_docker_output ──────────────────────────────────────────────────


class TestSummarizeDockerOutput:
    def test_formats_running_containers(self):
        raw = "NAMES\tSTATUS\nvaultwarden\tUp 3 days\nnextcloud\tUp 3 days"
        result = sanitize.summarize_docker_output(raw)
        assert "\U0001f7e2 vaultwarden" in result
        assert "Up 3 days" in result
        assert "NAMES" not in result

    def test_formats_stopped_containers(self):
        raw = "NAMES\tSTATUS\nuptime-kuma\tExited (1) 2 hours ago"
        result = sanitize.summarize_docker_output(raw)
        assert "\U0001f534 uptime-kuma" in result

    def test_mixed_status(self):
        raw = "NAMES\tSTATUS\nfoo\tUp 1 day\nbar\tExited (0) 5m ago"
        result = sanitize.summarize_docker_output(raw)
        lines = result.strip().splitlines()
        assert len(lines) == 2

    def test_empty_input(self):
        assert sanitize.summarize_docker_output("") == "No containers found"

    def test_header_only(self):
        assert sanitize.summarize_docker_output("NAMES\tSTATUS") == "No containers found"


# ── sanitize (main entry point) ──────────────────────────────────────────────


class TestSanitize:
    def test_disabled_returns_unchanged(self, tmp_path):
        cfg = {"sanitization": {"enabled": False, "internal_hostnames": ["myhost"]}}
        with _patch_config(tmp_path, cfg):
            result = sanitize.sanitize("myhost is up on 10.0.0.1")
        assert "myhost" in result
        assert "10.0.0.1" in result

    def test_enabled_scrubs_all(self, tmp_path):
        cfg = {
            "sanitization": {
                "enabled": True,
                "internal_hostnames": ["masterserver"],
                "scrub_internal_ips": True,
                "scrub_paths": True,
            }
        }
        with _patch_config(tmp_path, cfg):
            result = sanitize.sanitize("Agent: masterserver at 192.168.1.5 file /var/ossec/logs/test.log")
        assert "masterserver" not in result
        assert "192.168.1.5" not in result
        assert "[host]" in result
        assert "[internal]" in result
        assert "/.../test.log" in result

    def test_dry_run_returns_original(self, tmp_path):
        cfg = {
            "sanitization": {
                "enabled": True,
                "dry_run": True,
                "internal_hostnames": ["myhost"],
            }
        }
        with _patch_config(tmp_path, cfg):
            result = sanitize.sanitize("myhost is here")
        assert result == "myhost is here"

    def test_preserves_public_ips_and_rule_ids(self, tmp_path):
        cfg = {
            "sanitization": {
                "enabled": True,
                "internal_hostnames": ["masterserver"],
                "scrub_internal_ips": True,
            }
        }
        with _patch_config(tmp_path, cfg):
            result = sanitize.sanitize("Rule 5710 (L8) attacker 45.33.22.11 from masterserver")
        assert "5710" in result
        assert "L8" in result
        assert "45.33.22.11" in result
        assert "masterserver" not in result

    def test_no_config_file_returns_unchanged(self):
        # With no config file at all, sanitize is disabled by default
        sanitize.reload_config()
        with patch.object(_sentinel_config, "_CONFIG_PATHS", ["/nonexistent/path.yaml"]):
            result = sanitize.sanitize("masterserver 10.0.0.1")
        assert result == "masterserver 10.0.0.1"
