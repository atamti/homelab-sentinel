"""Input validation helpers for active response commands."""

import ipaddress
import re

_PORT_RE = re.compile(r"^\d{1,5}(/(?:tcp|udp))?$")


def validated_ip(value: str) -> str:
    """Return the IP string if valid, or raise ValueError."""
    addr = ipaddress.ip_address(value.strip())
    return str(addr)


def validated_port(value: str) -> str:
    """Return the port string if it looks like a valid port spec, or raise ValueError."""
    value = value.strip()
    if not _PORT_RE.match(value):
        raise ValueError(f"Invalid port specification: {value}")
    port_num = int(value.split("/")[0])
    if not 1 <= port_num <= 65535:
        raise ValueError(f"Port out of range: {port_num}")
    return value
