"""Low-level iptables helpers for firewall management."""

import subprocess


def ban_ip(ip: str) -> bool:
    """Insert a DROP rule for *ip* in the INPUT chain. Returns True on success."""
    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
        )
        return True
    except Exception:
        return False


def unban_ip(ip: str) -> bool:
    """Remove the DROP rule for *ip* from the INPUT chain. Returns True on success."""
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
        )
        return True
    except Exception:
        return False


def is_already_banned(ip: str) -> bool:
    """Return True if a DROP rule for *ip* already exists in iptables INPUT chain."""
    try:
        result = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception:
        return False


def deduplicate_iptables() -> int:
    """Remove duplicate DROP rules from iptables INPUT chain.

    Returns count of duplicates removed.
    """
    try:
        raw = subprocess.run(
            ["iptables-save"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        seen: set[str] = set()
        deduped_lines: list[str] = []
        removed = 0
        for line in raw.splitlines():
            if line.startswith("-A INPUT") and "-j DROP" in line:
                if line in seen:
                    removed += 1
                    continue
                seen.add(line)
            deduped_lines.append(line)
        if removed:
            subprocess.run(
                ["iptables-restore"],
                input="\n".join(deduped_lines) + "\n",
                text=True,
                check=True,
            )
        return removed
    except Exception:
        return 0
