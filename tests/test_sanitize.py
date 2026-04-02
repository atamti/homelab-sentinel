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
    def test_redacts_null_value_hostnames(self, tmp_path):
        cfg = {"sanitization": {"hostnames": {"masterserver": None, "minibolt": None}}}
        with _patch_config(tmp_path, cfg):
            result, count = sanitize.scrub_hostnames("Agent: masterserver | Target: minibolt")
        assert result == "Agent: [host] | Target: [host]"
        assert count == 2

    def test_codename_replacement(self, tmp_path):
        cfg = {"sanitization": {"hostnames": {"masterserver": "sentinel", "minibolt": "node"}}}
        with _patch_config(tmp_path, cfg):
            result, count = sanitize.scrub_hostnames("Agent: masterserver | Target: minibolt")
        assert result == "Agent: sentinel | Target: node"
        assert count == 2

    def test_case_insensitive(self, tmp_path):
        cfg = {"sanitization": {"hostnames": {"MasterServer": None}}}
        with _patch_config(tmp_path, cfg):
            result, _ = sanitize.scrub_hostnames("host is MASTERSERVER")
        assert "[host]" in result

    def test_preserves_html_tags(self, tmp_path):
        cfg = {"sanitization": {"hostnames": {"myhost": None}}}
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


# ── agent_alias ──────────────────────────────────────────────────────────────


class TestAgentAlias:
    def test_returns_codename(self, tmp_path):
        cfg = {"sanitization": {"hostnames": {"masterserver": "sentinel"}}}
        with _patch_config(tmp_path, cfg):
            assert sanitize.agent_alias("masterserver") == "sentinel"

    def test_case_insensitive(self, tmp_path):
        cfg = {"sanitization": {"hostnames": {"MasterServer": "sentinel"}}}
        with _patch_config(tmp_path, cfg):
            assert sanitize.agent_alias("masterserver") == "sentinel"

    def test_null_value_returns_original(self, tmp_path):
        cfg = {"sanitization": {"hostnames": {"masterserver": None}}}
        with _patch_config(tmp_path, cfg):
            assert sanitize.agent_alias("masterserver") == "masterserver"

    def test_unknown_host_returns_host(self, tmp_path):
        cfg = {"sanitization": {"hostnames": {"other": "alias"}}}
        with _patch_config(tmp_path, cfg):
            assert sanitize.agent_alias("masterserver") == "host"

    def test_no_config_returns_host(self, tmp_path):
        cfg = {"sanitization": {}}
        with _patch_config(tmp_path, cfg):
            assert sanitize.agent_alias("masterserver") == "host"

    def test_old_list_format_returns_host(self, tmp_path):
        cfg = {"sanitization": {"hostnames": ["masterserver"]}}
        with _patch_config(tmp_path, cfg):
            assert sanitize.agent_alias("masterserver") == "host"


# ── abbreviate_os ────────────────────────────────────────────────────────────


class TestAbbreviateOS:
    def test_windows_pro(self):
        assert sanitize.abbreviate_os("Microsoft Windows 11 Pro") == "Windows 11"

    def test_windows_10(self):
        assert sanitize.abbreviate_os("Microsoft Windows 10 Enterprise") == "Windows 10"

    def test_windows_server(self):
        assert sanitize.abbreviate_os("Microsoft Windows Server 2022") == "Win Server 2022"

    def test_windows_server_r2(self):
        assert sanitize.abbreviate_os("Microsoft Windows Server 2008 R2") == "Win Server 2008 R2"

    def test_ubuntu_lts(self):
        assert sanitize.abbreviate_os("Ubuntu 24.04.2 LTS") == "Ubuntu 24.04"

    def test_ubuntu_short(self):
        assert sanitize.abbreviate_os("Ubuntu 22.04.5 LTS") == "Ubuntu 22.04"

    def test_debian(self):
        assert sanitize.abbreviate_os("Debian GNU/Linux 12") == "Debian 12"

    def test_rhel(self):
        assert sanitize.abbreviate_os("Red Hat Enterprise Linux 9") == "RHEL 9"

    def test_centos(self):
        assert sanitize.abbreviate_os("CentOS Linux 8") == "CentOS 8"

    def test_rocky(self):
        assert sanitize.abbreviate_os("Rocky Linux 9") == "Rocky 9"

    def test_alma(self):
        assert sanitize.abbreviate_os("AlmaLinux 9") == "AlmaLinux 9"

    def test_fedora(self):
        assert sanitize.abbreviate_os("Fedora 40") == "Fedora 40"

    def test_arch(self):
        assert sanitize.abbreviate_os("Arch Linux") == "Arch"

    def test_macos(self):
        assert sanitize.abbreviate_os("macOS 14.0") == "macOS 14.0"

    def test_opensuse(self):
        assert sanitize.abbreviate_os("openSUSE Leap 15.6") == "openSUSE 15.6"

    def test_sles(self):
        assert sanitize.abbreviate_os("SUSE Linux Enterprise Server 15") == "SLES 15"

    def test_amazon(self):
        assert sanitize.abbreviate_os("Amazon Linux 2023") == "Amazon Linux 2023"

    def test_raspbian(self):
        assert sanitize.abbreviate_os("Raspbian 12 (bookworm)") == "Raspbian 12"

    def test_kali(self):
        assert sanitize.abbreviate_os("Kali GNU/Linux 2024.1") == "Kali 2024"

    def test_unknown_passes_through(self):
        assert sanitize.abbreviate_os("SomeUnknownOS 1.0") == "SomeUnknownOS 1.0"

    def test_question_mark_passes_through(self):
        assert sanitize.abbreviate_os("?") == "?"


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
        cfg = {"sanitization": {"enabled": False, "hostnames": {"myhost": None}}}
        with _patch_config(tmp_path, cfg):
            result = sanitize.sanitize("myhost is up on 10.0.0.1")
        assert "myhost" in result
        assert "10.0.0.1" in result

    def test_enabled_scrubs_all(self, tmp_path):
        cfg = {
            "sanitization": {
                "enabled": True,
                "hostnames": {"masterserver": None},
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

    def test_codename_in_full_sanitize(self, tmp_path):
        cfg = {
            "sanitization": {
                "enabled": True,
                "hostnames": {"masterserver": "sentinel"},
            }
        }
        with _patch_config(tmp_path, cfg):
            result = sanitize.sanitize("Agent: masterserver is up")
        assert "masterserver" not in result
        assert "sentinel" in result

    def test_dry_run_returns_original(self, tmp_path):
        cfg = {
            "sanitization": {
                "enabled": True,
                "dry_run": True,
                "hostnames": {"myhost": None},
            }
        }
        with _patch_config(tmp_path, cfg):
            result = sanitize.sanitize("myhost is here")
        assert result == "myhost is here"

    def test_preserves_public_ips_and_rule_ids(self, tmp_path):
        cfg = {
            "sanitization": {
                "enabled": True,
                "hostnames": {"masterserver": None},
                "scrub_internal_ips": True,
            }
        }
        with _patch_config(tmp_path, cfg):
            result = sanitize.sanitize("Rule 5710 (L8) attacker 45.33.22.11 from masterserver")
        assert "5710" in result
        assert "L8" in result
        assert "45.33.22.11" in result
        assert "masterserver" not in result

    def test_backward_compat_list_format(self, tmp_path):
        """Old list format under hostnames key still works."""
        cfg = {"sanitization": {"enabled": True, "hostnames": ["masterserver"]}}
        with _patch_config(tmp_path, cfg):
            result = sanitize.sanitize("Agent: masterserver")
        assert "masterserver" not in result
        assert "[host]" in result

    def test_backward_compat_internal_hostnames_key(self, tmp_path):
        """Old internal_hostnames key still works."""
        cfg = {"sanitization": {"enabled": True, "internal_hostnames": ["masterserver"]}}
        with _patch_config(tmp_path, cfg):
            result = sanitize.sanitize("Agent: masterserver")
        assert "masterserver" not in result
        assert "[host]" in result

    def test_no_config_file_returns_unchanged(self):
        # With no config file at all, sanitize is disabled by default
        sanitize.reload_config()
        with patch.object(_sentinel_config, "_CONFIG_PATHS", ["/nonexistent/path.yaml"]):
            result = sanitize.sanitize("masterserver 10.0.0.1")
        assert result == "masterserver 10.0.0.1"
