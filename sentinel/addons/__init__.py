"""Addon registration for Homelab Sentinel.

Addons extend the bot with extra commands, digest sections, and help text.
Each addon calls the ``register_*`` helpers at import time to plug itself in.
"""

from collections.abc import Callable
from typing import Any

# Registered addon commands: {"/bitcoin": handler, ...}
addon_commands: dict[str, Callable[[str, str], None]] = {}

# Registered BOT_MENU entries: [("bitcoin", "Bitcoin & Lightning detail"), ...]
addon_menu: list[tuple[str, str]] = []

# Registered help-text blocks: ["<b>₿ Bitcoin</b>\n/bitcoin — detail\n", ...]
addon_help: list[str] = []

# Registered digest section callables: [(order, section_func), ...]
# section_func(cfg, lines) -> None — appends lines in-place
addon_digest_sections: list[tuple[int, Callable[[dict[str, Any], list[str]], None]]] = []

# Registered interactive prompt definitions
addon_prompts: dict[str, list[str]] = {}

# Init hooks — called when commands.init() wires up dependencies
addon_init_hooks: list[Callable[..., None]] = []


def register_command(name: str, handler: Callable[[str, str], None]) -> None:
    """Register a slash command (e.g. ``"/bitcoin"``)."""
    addon_commands[name] = handler


def register_menu(command: str, description: str) -> None:
    """Register a BOT_MENU entry for Telegram autocomplete."""
    addon_menu.append((command, description))


def register_help(text: str) -> None:
    """Register a help-text block shown in /help output."""
    addon_help.append(text)


def register_digest_section(order: int, func: Callable[[dict[str, Any], list[str]], None]) -> None:
    """Register a digest section renderer.

    ``order`` controls position (lower = earlier). Core sections
    use 10/20/30/40; addons should use 50+.
    ``func`` receives ``(cfg, lines)`` and appends to ``lines``.
    """
    addon_digest_sections.append((order, func))
    addon_digest_sections.sort(key=lambda t: t[0])


def register_prompts(command: str, prompts: list[str]) -> None:
    """Register interactive prompt steps for a command."""
    addon_prompts[command] = prompts


def register_init_hook(func: Callable[..., None]) -> None:
    """Register a callback invoked during ``commands.init(**deps)``."""
    addon_init_hooks.append(func)
