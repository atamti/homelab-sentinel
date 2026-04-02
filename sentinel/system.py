"""System metrics and RAG (Red/Amber/Green) display helpers."""

import subprocess
from typing import Any

from sentinel.telegram import esc


def get_system_stats() -> dict[str, Any]:
    """Gather local system metrics."""
    load_str = subprocess.getoutput("cat /proc/loadavg | awk '{print $1, $2, $3}'")
    try:
        load_1m = float(load_str.split()[0])
    except (ValueError, IndexError):
        load_1m = 0.0
    try:
        nproc = int(subprocess.getoutput("nproc"))
    except ValueError:
        nproc = 1
    mem_pct_str = subprocess.getoutput("free | grep Mem | awk '{printf \"%.0f\", $3/$2 * 100}'")
    try:
        mem_pct = float(mem_pct_str)
    except ValueError:
        mem_pct = 0.0
    disk_pct_str = subprocess.getoutput("df / | tail -1 | awk '{print $5}'").rstrip("%")
    try:
        disk_pct = float(disk_pct_str)
    except ValueError:
        disk_pct = 0.0
    # CPU temperature — try thermal zones then lm-sensors
    cpu_temp = None
    try:
        temp_str = subprocess.getoutput(
            "cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | sort -rn | head -1"
        ).strip()
        if temp_str.isdigit():
            cpu_temp = int(temp_str) / 1000.0
    except Exception:
        pass
    if cpu_temp is None:
        try:
            raw = subprocess.getoutput(
                "sensors 2>/dev/null | grep -oP '\\+\\K[0-9.]+(?=°C)' | sort -rn | head -1"
            ).strip()
            if raw:
                cpu_temp = float(raw)
        except Exception:
            pass
    return {
        "uptime": subprocess.getoutput("uptime -p"),
        "load": load_str,
        "load_1m": load_1m,
        "nproc": nproc,
        "mem": subprocess.getoutput("free -h | grep Mem | awk '{print $3 \"/\" $2}'"),
        "mem_pct": mem_pct,
        "disk": subprocess.getoutput('df -h / | tail -1 | awk \'{print $5, "used (" $3 "/" $2 ")"}\''),
        "disk_pct": disk_pct,
        "cpu_temp": cpu_temp,
        "banned": subprocess.getoutput("iptables -L INPUT -n | grep -c DROP").strip(),
    }


def rag(value: float, amber: float, red: float) -> str:
    """Return 🟢/🟡/🔴 based on value vs thresholds."""
    if value >= red:
        return "\U0001f534"
    if value >= amber:
        return "\U0001f7e1"
    return "\U0001f7e2"


def format_system_rag_lines(stats: dict[str, Any], th: dict[str, Any], *, compact: bool = False) -> list[str]:
    """Return RAG-colored system stats lines.

    compact=True omits the section header and collapses all-green output.
    """
    load_amber = th["load_per_core_amber"] * stats["nproc"]
    load_red = th["load_per_core_red"] * stats["nproc"]
    load_rag = rag(stats["load_1m"], load_amber, load_red)
    mem_rag = rag(stats["mem_pct"], th["memory_amber"], th["memory_red"])
    disk_rag = rag(stats["disk_pct"], th["disk_amber"], th["disk_red"])
    rags = [load_rag, mem_rag, disk_rag]

    temp_rag = None
    if stats["cpu_temp"] is not None:
        temp_rag = rag(stats["cpu_temp"], th["cpu_temp_amber"], th["cpu_temp_red"])
        rags.append(temp_rag)

    lines: list[str] = []
    all_green = all(r == "\U0001f7e2" for r in rags)

    if compact:
        hdr = "<b>\U0001f7e2 \U0001f5a5  System</b>" if all_green else "<b>System \U0001f5a5</b>"
        lines.append(hdr)

    lines.append(f"Uptime: {esc(stats['uptime'])}")
    if compact and all_green:
        lines.append(f"Load: {esc(stats['load'])}")
        lines.append(f"Memory: {esc(stats['mem'])} ({stats['mem_pct']:.0f}%)")
        if temp_rag is not None:
            lines.append(f"CPU temp: {stats['cpu_temp']:.0f}°C")
        lines.append(f"Disk: {esc(stats['disk'])}")
    else:
        lines.append(f"{load_rag} Load: {esc(stats['load'])}")
        lines.append(f"{mem_rag} Memory: {esc(stats['mem'])} ({stats['mem_pct']:.0f}%)")
        if temp_rag is not None:
            lines.append(f"{temp_rag} CPU temp: {stats['cpu_temp']:.0f}°C")
        lines.append(f"{disk_rag} Disk: {esc(stats['disk'])}")
    return lines
