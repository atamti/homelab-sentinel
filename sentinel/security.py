"""Security, alert, and ban-history helpers."""

import re
import time
from collections.abc import Callable
from typing import Any

from sentinel.config import get_cfg
from sentinel.telegram import esc


def clean_rule_desc(desc: str) -> str:
    """Strip Wazuh template variables like $(srcip) from rule descriptions."""
    cleaned = re.sub(r"\$\(\w+\)", "", desc)
    return re.sub(r"  +", " ", cleaned).strip()


def parse_ban_history() -> dict[str, int]:
    """Parse 24h ban history log and return {rule_id: count}."""
    ban_log = get_cfg()["active_response"]["ban_log"]
    cutoff = time.time() - 86400
    rule_counts: dict[str, int] = {}
    try:
        with open(ban_log) as f:
            for line in f:
                if "Banned" not in line:
                    continue
                ts_str = line[:19]
                try:
                    ts = time.mktime(time.strptime(ts_str, "%Y/%m/%d %H:%M:%S"))
                except ValueError:
                    continue
                if ts < cutoff:
                    continue
                match = re.search(r"\(Rule (\w+)\)", line)
                if match:
                    rid = match.group(1)
                    rule_counts[rid] = rule_counts.get(rid, 0) + 1
    except FileNotFoundError:
        pass
    return rule_counts


def lookup_rules(rule_ids: list[str], token: str, wazuh_get: Callable[..., dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Batch-fetch rule metadata from Wazuh API.

    Returns {id: {level, description}}.
    wazuh_get: callable(endpoint, token) -> dict
    """
    if not rule_ids or not token:
        return {}
    ids_param = ",".join(rule_ids)
    data: dict[str, Any] = wazuh_get(f"/rules?rule_ids={ids_param}", token)
    result: dict[str, dict[str, Any]] = {}
    for item in data.get("data", {}).get("affected_items", []):
        rid = str(item.get("id", ""))
        result[rid] = {
            "level": item.get("level", "?"),
            "description": item.get("description", "Unknown"),
        }
    return result


def query_critical_alerts(indexer_search: Callable[..., dict[str, Any]], top_rules_per_level: int = 1) -> list[dict[str, Any]]:
    """Query OpenSearch for Level 10+ alert aggregations in the last 24h.

    Returns list of bucket dicts with keys: key (level), doc_count, by_rule.
    indexer_search: callable(query) -> dict
    """
    result: dict[str, Any] = indexer_search(
        {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": "now-24h"}}},
                        {"range": {"rule.level": {"gte": 10}}},
                    ]
                }
            },
            "aggs": {
                "by_level": {
                    "terms": {"field": "rule.level", "size": 10, "order": {"_key": "desc"}},
                    "aggs": {"by_rule": {"terms": {"field": "rule.description", "size": top_rules_per_level}}},
                }
            },
        }
    )
    return result.get("aggregations", {}).get("by_level", {}).get("buckets", [])


def format_table_row(rule_id: str, level: str | int, count: int, desc: str) -> str:
    """Format a rule as a compact 2-line list entry."""
    words = str(clean_rule_desc(desc)).split()
    line1: list[str] = []
    line2: list[str] = []
    length = 0
    for word in words:
        if length + len(word) + 1 <= 35:
            line1.append(word)
            length += len(word) + 1
        else:
            line2.append(word)

    desc_fmt = " ".join(line1)
    if line2:
        line2_str = " ".join(line2)
        if len(line2_str) > 35:
            line2_str = line2_str[:32].rsplit(" ", 1)[0] + "..."
        desc_fmt += "\n" + line2_str

    return f"<b>{esc(str(rule_id))}</b> (L{level}) \u00d7{count}\n{esc(desc_fmt)}\n\n"


def simplify_service_name(name: str) -> str:
    """Strip common Uptime Kuma prefixes and URL parts for cleaner display."""
    for prefix in ("HTTP - ", "HTTPS - ", "TCP Port - ", "Ping - ", "Docker Container - ", "DNS - "):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    name = re.sub(r"^https?://", "", name)
    name = re.sub(r":\d+(/.*)?$", "", name)
    name = re.sub(r"\.(local|lan|home|internal)$", "", name, flags=re.IGNORECASE)
    return name
