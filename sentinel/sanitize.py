"""Output sanitization for Telegram messages.

Scrubs internal hostnames, RFC1918 addresses, filesystem paths,
and custom terms before sending output through Telegram.

Configuration is loaded from homelab-sentinel.yaml (sanitization section).
"""

import re

# ── Config loading ───────────────────────────────────────────────────────────
from sentinel.config import _load_yaml
from sentinel.config import reload_config as _reload_config


def _load_config() -> dict:
    """Load raw YAML config. Delegates to sentinel.config."""
    result: dict = _load_yaml()
    return result


def _san_config() -> dict:
    """Return the sanitization sub-config."""
    result: dict = _load_config().get("sanitization", {})
    return result


def reload_config() -> None:
    """Force a config reload (useful after config changes or in tests)."""
    _reload_config()


# ── HTML-safe regex helper ───────────────────────────────────────────────────

# Matches HTML tags so we can skip them during replacement
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _replace_outside_tags(text: str, pattern: re.Pattern, replacement: str) -> tuple[str, int]:
    """Replace pattern matches in text, but skip anything inside HTML tags.
    Returns (new_text, replacement_count)."""
    result = []
    count = 0
    last_end = 0
    for tag_match in _HTML_TAG_RE.finditer(text):
        # Process text before this tag
        segment = text[last_end : tag_match.start()]
        segment, n = pattern.subn(replacement, segment)
        count += n
        result.append(segment)
        # Preserve the tag as-is
        result.append(tag_match.group())
        last_end = tag_match.end()
    # Process remaining text after last tag
    segment = text[last_end:]
    segment, n = pattern.subn(replacement, segment)
    count += n
    result.append(segment)
    return "".join(result), count


# ── Scrub functions ──────────────────────────────────────────────────────────

_RFC1918_RE = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r")\b"
)

_PATH_RE = re.compile(r"(?:/[\w.@-]+){3,}")


def scrub_hostnames(text: str) -> tuple[str, int]:
    """Replace internal hostnames with generic labels.
    Returns (scrubbed_text, replacement_count)."""
    cfg = _san_config()
    hostnames = cfg.get("internal_hostnames") or []
    count = 0
    for hostname in hostnames:
        if not hostname:
            continue
        pattern = re.compile(re.escape(hostname), re.IGNORECASE)
        text, n = _replace_outside_tags(text, pattern, "[host]")
        count += n
    return text, count


def scrub_internal_ips(text: str) -> tuple[str, int]:
    """Replace RFC1918 addresses with [internal].
    Returns (scrubbed_text, replacement_count)."""
    return _replace_outside_tags(text, _RFC1918_RE, "[internal]")


def scrub_paths(text: str) -> tuple[str, int]:
    """Replace long filesystem paths with shortened versions.
    Returns (scrubbed_text, replacement_count)."""

    def _shorten(m: "re.Match[str]") -> str:
        path = m.group()
        parts = path.strip("/").split("/")
        if len(parts) <= 2:
            return path
        return f"/.../{parts[-1]}"

    count = 0
    result = []
    last_end = 0
    for tag_match in _HTML_TAG_RE.finditer(text):
        segment = text[last_end : tag_match.start()]
        segment, n = _PATH_RE.subn(_shorten, segment)
        count += n
        result.append(segment)
        result.append(tag_match.group())
        last_end = tag_match.end()
    segment = text[last_end:]
    segment, n = _PATH_RE.subn(_shorten, segment)
    count += n
    result.append(segment)
    return "".join(result), count


def scrub_custom(text: str) -> tuple[str, int]:
    """Apply custom replacement rules from config.
    Returns (scrubbed_text, replacement_count)."""
    cfg = _san_config()
    replacements = cfg.get("custom_replacements") or {}
    count = 0
    for find, replace in replacements.items():
        if not find:
            continue
        pattern = re.compile(re.escape(find), re.IGNORECASE)
        text, n = _replace_outside_tags(text, pattern, replace)
        count += n
    return text, count


def summarize_docker_output(text: str) -> str:
    """Replace raw docker ps output with a clean status summary.

    Expects docker ps --format 'table {{.Names}}\\t{{.Status}}\\t{{.Ports}}'
    or similar tabular output. Returns emoji-prefixed lines.
    """
    lines = text.strip().splitlines()
    if not lines:
        return "No containers found"

    summaries = []
    for line in lines:
        # Skip the header row
        lower = line.lower()
        if lower.startswith("names") or lower.startswith("name"):
            continue
        parts = line.split("\t") if "\t" in line else line.split(None, 2)
        if not parts:
            continue

        name = parts[0].strip()
        status = parts[1].strip() if len(parts) > 1 else "unknown"

        status_lower = status.lower()
        emoji = "\U0001f7e2" if status_lower.startswith("up") else "\U0001f534"

        summaries.append(f"{emoji} {name} — {status}")

    return "\n".join(summaries) if summaries else "No containers found"


# ── Main sanitize entry point ────────────────────────────────────────────────


def sanitize(text: str) -> str:
    """Apply all enabled scrub passes to text.

    Reads sanitization config to decide which passes to run.
    Returns the scrubbed text.
    """
    cfg = _san_config()

    if not cfg.get("enabled", False):
        return text

    dry_run = cfg.get("dry_run", False)
    original = text
    total = 0

    text, n = scrub_hostnames(text)
    total += n

    if cfg.get("scrub_internal_ips", True):
        text, n = scrub_internal_ips(text)
        total += n

    if cfg.get("scrub_paths", True):
        text, n = scrub_paths(text)
        total += n

    text, n = scrub_custom(text)
    total += n

    if dry_run:
        return original

    return text
