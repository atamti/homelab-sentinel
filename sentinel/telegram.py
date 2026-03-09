"""Telegram messaging helpers."""

import time

import requests


def send(token: str, chat_id: str, text: str) -> None:
    """Send a Telegram message, auto-chunking if over 4000 chars."""
    if not token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    chunks = [text[i:i + 4000] for i in range(0, len(text), 4000)]
    for chunk in chunks:
        try:
            requests.post(
                url,
                json={"chat_id": chat_id, "text": chunk, "parse_mode": "HTML"},
                timeout=10,
            )
            if len(chunks) > 1:
                time.sleep(0.5)
        except Exception:
            pass


def esc(s: str) -> str:
    """Escape HTML entities for Telegram HTML parse mode."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
