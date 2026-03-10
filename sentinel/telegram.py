"""Telegram messaging helpers."""

import time

import requests


def send(token: str, chat_id: str, text: str) -> str | None:
    """Send a Telegram message, auto-chunking if over 4000 chars.

    Returns None on success, or an error description string on failure.
    """
    if not token or not chat_id:
        return "missing token or chat_id"
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    chunks = [text[i:i + 4000] for i in range(0, len(text), 4000)]
    for chunk in chunks:
        try:
            resp = requests.post(
                url,
                json={"chat_id": chat_id, "text": chunk, "parse_mode": "HTML"},
                timeout=10,
            )
            body = resp.json()
            if not body.get("ok"):
                return body.get("description", f"HTTP {resp.status_code}")
            if len(chunks) > 1:
                time.sleep(0.5)
        except Exception as exc:
            return str(exc)
    return None


def esc(s: str) -> str:
    """Escape HTML entities for Telegram HTML parse mode."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
