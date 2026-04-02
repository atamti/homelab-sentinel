"""Bitcoin and Lightning Network helpers."""

import base64
from typing import Any

import requests

from sentinel.config import env, get_cfg


def _bitcoin_config() -> dict[str, Any]:
    """Return the bitcoin config section."""
    return get_cfg().get("bitcoin", {})


def get_lnd_headers() -> dict[str, str]:
    """Build LND gRPC-gateway auth headers from the macaroon env var."""
    macaroon_b64 = env("LND_READONLY_MACAROON_B64")
    macaroon = base64.b64decode(macaroon_b64).hex()
    return {"Grpc-Metadata-macaroon": macaroon}


def score_channel_health(channels: list[dict[str, Any]]) -> tuple[str, str]:
    """Evaluate LND channel list and return (emoji, label).

    - Any inactive channels → 🔴 + count
    - Any channel with local ratio < min or > max → 🟡 + count/percentages
    - All active, ratios in range → 🟢 healthy
    """
    ch_cfg: dict[str, Any] = _bitcoin_config().get("channel_health", {})
    min_ratio: float = ch_cfg.get("min_local_ratio", 0.15)
    max_ratio: float = ch_cfg.get("max_local_ratio", 0.85)
    total = len(channels)

    inactive = sum(1 for c in channels if not c.get("active"))
    if inactive:
        return "\U0001f534", f"{inactive}/{total} channel{'s' if inactive != 1 else ''} offline"

    imbalanced: list[str] = []
    for c in channels:
        capacity = int(c.get("capacity", 1))
        local = int(c.get("local_balance", 0))
        if capacity > 0:
            ratio = local / capacity
            if ratio < min_ratio:
                imbalanced.append(f"<{round(min_ratio * 100)}% local")
            elif ratio > max_ratio:
                imbalanced.append(f">{round(max_ratio * 100)}% local")

    if imbalanced:
        pcts = ", ".join(imbalanced)
        return "\U0001f7e1", f"{len(imbalanced)}/{total} need rebalancing ({pcts})"

    return "\U0001f7e2", f"{total} channel{'s' if total != 1 else ''} healthy"


def lnd_get(endpoint: str) -> dict[str, Any]:
    """GET a JSON endpoint from the local LND REST API."""
    lnd_url: str = get_cfg()["integrations"]["lnd"]["rest_url"]
    try:
        r = requests.get(f"{lnd_url}{endpoint}", headers=get_lnd_headers(), verify=False, timeout=10)
        return r.json()
    except Exception:
        return {}


def mempool_get(endpoint: str, public: bool = False) -> dict[str, Any] | str:
    """GET a JSON (or plain-text) endpoint from mempool."""
    try:
        local_url: str = get_cfg()["integrations"]["bitcoin"]["mempool_local"]
        base = "https://mempool.space" if public else local_url
        r = requests.get(f"{base}{endpoint}", timeout=10, verify=public)
        if not r.ok:
            return "error"
        try:
            return r.json()
        except Exception:
            text = r.text.strip()
            if len(text) < 200 and "<" not in text:
                return text
            return "error"
    except Exception:
        return "error"


def valid_height(h: object) -> bool:
    """Check if a mempool height response is a usable number."""
    return isinstance(h, (int, float)) or (isinstance(h, str) and h.isdigit())
