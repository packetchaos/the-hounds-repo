"""Single source of truth for The Hounds version.

Scheme: ``1.<number of agents>.<build>``
  * major  — 1 (stable line)
  * agents — count of registered, non-hidden agents (auto-derived from discovery)
  * build  — bumped by hand on every change from here on

Bump ``BUILD`` each time we cut a change/release.
"""
MAJOR = 1
BUILD = 456

# Fallback used only if discovery can't run (keeps the string well-formed).
_AGENTS_FALLBACK = 40


def agent_count() -> int:
    """Number of registered, non-hidden agents (the version's middle number)."""
    try:
        from core.discovery import discover
        n = sum(1 for r in discover() if not (r.get("meta") or {}).get("hidden"))
        return n or _AGENTS_FALLBACK
    except Exception:
        return _AGENTS_FALLBACK


def version_string() -> str:
    return f"{MAJOR}.{agent_count()}.{BUILD}"
