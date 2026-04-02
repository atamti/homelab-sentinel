"""Bitcoin & Lightning Network addon for Homelab Sentinel.

Provides ``/bitcoin`` command, digest section, and all LND/mempool helpers.
Ships disabled by default — enable via config:

.. code-block:: yaml

    integrations:
      bitcoin:
        enabled: true
        mempool_local: "https://minibolt.local:4081"
      lnd:
        enabled: true
        rest_url: "https://minibolt.local:8080"
"""

import base64
from typing import Any

import requests

from sentinel.addons import (
    register_command,
    register_digest_section,
    register_help,
    register_init_hook,
    register_menu,
)
from sentinel.config import env, get_cfg


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════


def _bitcoin_config() -> dict[str, Any]:
    """Return the bitcoin config section."""
    return get_cfg().get("bitcoin", {})


def get_lnd_headers() -> dict[str, str]:
    """Build LND gRPC-gateway auth headers from the macaroon env var."""
    macaroon_b64 = env("LND_READONLY_MACAROON_B64")
    macaroon = base64.b64decode(macaroon_b64).hex()
    return {"Grpc-Metadata-macaroon": macaroon}


def score_channel_health(channels: list[dict[str, Any]]) -> tuple[str, str]:
    """Evaluate LND channel list and return (emoji, label)."""
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


# ══════════════════════════════════════════════════════════════════════════════
# Command handler
# ══════════════════════════════════════════════════════════════════════════════

# send_message is injected by commands.init() via the addon init hook
send_message: Any = None


def _init_hook(**deps: Any) -> None:
    global send_message
    send_message = deps.get("send_message")


def cmd_bitcoin(chat_id: str, _arg: str = "") -> None:
    cfg = get_cfg()
    if not cfg["integrations"]["bitcoin"]["enabled"]:
        send_message(chat_id, "Bitcoin integration is disabled")
        return

    lines = ["<b>\u20bf Bitcoin Detail</b>\n"]

    # Block height
    local_height = mempool_get("/api/blocks/tip/height")
    public_height = mempool_get("/api/blocks/tip/height", public=True)
    lag_threshold = cfg["digest"]["bitcoin_lag_warning_blocks"]
    local_ok = valid_height(local_height)
    public_ok = valid_height(public_height)

    if local_ok and public_ok:
        lag = int(str(public_height)) - int(str(local_height))
        if lag > lag_threshold:
            lines.append(f"\U0001f7e1 Block height: {local_height} (lagging {lag} blocks)")
        else:
            lines.append(f"\U0001f7e2 Block height: {local_height}")
    elif public_ok:
        lines.append(f"\U0001f7e1 Block height: {public_height} (local node unreachable)")
    elif local_ok:
        lines.append(f"\U0001f7e1 Block height: {local_height} (public API unreachable)")
    else:
        lines.append("\U0001f534 Block height: unavailable")

    # Fees
    fees = mempool_get("/api/v1/fees/recommended")
    if isinstance(fees, dict):
        lines.append("")
        lines.append("<b>Mempool Fees</b> (sat/vB)")
        lines.append(f"  Fastest:  {fees.get('fastestFee')}")
        lines.append(f"  30 min:   {fees.get('halfHourFee')}")
        lines.append(f"  1 hour:   {fees.get('hourFee')}")
        eco = fees.get("economyFee")
        if eco:
            lines.append(f"  Economy:  {eco}")
        minimum = fees.get("minimumFee")
        if minimum:
            lines.append(f"  Minimum:  {minimum}")

    # LND
    if cfg["integrations"]["lnd"]["enabled"]:
        lnd_info = lnd_get("/v1/getinfo")
        if lnd_info:
            lines.append("")
            lines.append("<b>Lightning (LND)</b>")
            synced = "\U0001f7e2 yes" if lnd_info.get("synced_to_chain") else "\U0001f7e1 no"
            lines.append(f"Synced: {synced}")
            peers = lnd_info.get("num_peers", 0)
            lines.append(f"Peers: {peers}")
        else:
            lines.append("\n\U0001f534 LND unreachable")

        # Channel detail
        channels = lnd_get("/v1/channels")
        ch_list: list[dict[str, Any]] = channels.get("channels", []) if channels else []
        if ch_list:
            btc_cfg = get_cfg().get("bitcoin", {}).get("channel_health", {})
            min_ratio = btc_cfg.get("min_local_ratio", 0.15)
            max_ratio = btc_cfg.get("max_local_ratio", 0.85)
            emoji, label = score_channel_health(ch_list)
            lines.append(f"\nChannels: {emoji} {label}")
            for ch in ch_list:
                cap = int(ch.get("capacity", 0))
                local = int(ch.get("local_balance", 0))
                ratio = (local / cap) if cap > 0 else 0
                pct = ratio * 100
                if not ch.get("active"):
                    dot = "\U0001f534"
                elif ratio < min_ratio or ratio > max_ratio:
                    dot = "\U0001f7e1"
                else:
                    dot = "\U0001f7e2"
                lines.append(f"  {dot} {pct:.0f}% local")

        # Wallet balance
        balance = lnd_get("/v1/balance/channels")
        if balance:
            lb: Any = balance.get("local_balance", 0)
            local_bal = int(lb.get("sat", 0)) if hasattr(lb, "get") else int(lb)
            rb: Any = balance.get("remote_balance", 0)
            remote_bal = int(rb.get("sat", 0)) if hasattr(rb, "get") else int(rb)
            total_bal = local_bal + remote_bal
            if total_bal > 0:
                local_pct = local_bal / total_bal * 100
                lines.append(f"\nBalance: {local_pct:.0f}% local / {100 - local_pct:.0f}% remote")

    send_message(chat_id, "\n".join(lines))


# ══════════════════════════════════════════════════════════════════════════════
# Digest section
# ══════════════════════════════════════════════════════════════════════════════


def digest_bitcoin(cfg: dict[str, Any], lines: list[str]) -> None:
    """Render the Bitcoin section of the daily digest."""
    if not cfg["digest"]["sections"].get("bitcoin"):
        return
    if not cfg["integrations"]["bitcoin"]["enabled"]:
        return

    lines.append("<b>\u20bf Bitcoin</b>")

    local_height = mempool_get("/api/blocks/tip/height")
    public_height = mempool_get("/api/blocks/tip/height", public=True)
    lag_threshold = cfg["digest"]["bitcoin_lag_warning_blocks"]
    local_ok = valid_height(local_height)
    public_ok = valid_height(public_height)

    if local_ok and public_ok:
        lag = int(str(public_height)) - int(str(local_height))
        if lag > lag_threshold:
            lines.append(f"\U0001f7e1 Block height: {local_height} (lagging {lag} blocks)")
        else:
            lines.append(f"\U0001f7e2 Block height: {local_height}")
    elif public_ok:
        lines.append(f"\U0001f7e1 Block height: {public_height} (local node unreachable)")
    elif local_ok:
        lines.append(f"\U0001f7e1 Block height: {local_height} (public API unreachable)")
    else:
        lines.append("\U0001f534 Block height: unavailable")

    fees = mempool_get("/api/v1/fees/recommended")
    if isinstance(fees, dict):
        lines.append(
            f"Fees: {fees.get('fastestFee')} / "
            f"{fees.get('halfHourFee')} / "
            f"{fees.get('hourFee')} sat/vB (fast/30m/1h)"
        )

    if cfg["integrations"]["lnd"]["enabled"]:
        lnd_info = lnd_get("/v1/getinfo")
        if lnd_info:
            synced = "\U0001f7e2" if lnd_info.get("synced_to_chain") else "\U0001f7e1 not synced"
            lines.append(f"LND: {synced}")
        else:
            lines.append("LND: \U0001f534 unreachable")

        channels = lnd_get("/v1/channels")
        if channels:
            ch_list = channels.get("channels", [])
            if ch_list:
                emoji, label = score_channel_health(ch_list)
                lines.append(f"Channels: {emoji} {label}")

    lines.append("\u2192 /bitcoin")


# ══════════════════════════════════════════════════════════════════════════════
# Registration
# ══════════════════════════════════════════════════════════════════════════════

register_command("/bitcoin", cmd_bitcoin)
register_menu("bitcoin", "Bitcoin & Lightning detail")
register_help("<b>\u20bf Bitcoin</b>\n/bitcoin \u2014 Bitcoin & Lightning detail\n")
register_digest_section(50, digest_bitcoin)
register_init_hook(_init_hook)
