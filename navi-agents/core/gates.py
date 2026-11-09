"""Strict approval gates shared by every write / send / remove / apply / run action.

``confirmed(p)`` is the ONLY way an action should check the human's approval: it is True
for a JSON ``true`` and nothing else. The old ``if not p.get("confirm")`` treated the
strings "false" / "0" / "no" (truthy in Python) as approval.

The request context records whether the HTTP caller is this machine (loopback). The
launcher sets it around every dispatch; Settings uses it to keep the gate switches and the
navi.db path local-only. In-process callers (tests, the MCP server, scripts) have no HTTP
peer and count as local.
"""
import contextvars

_CLIENT = contextvars.ContextVar("hounds_client", default=None)


def confirmed(p) -> bool:
    """True only when the payload carries confirm === true (a JSON boolean)."""
    return isinstance(p, dict) and p.get("confirm") is True


def flag(p, key) -> bool:
    """Strict boolean for other safety switches (armed / force / send): JSON true only."""
    return isinstance(p, dict) and p.get(key) is True


def set_client(peer_addr=None, http=False):
    """Bind the current request's peer for the duration of a dispatch. Returns a reset token."""
    return _CLIENT.set({"http": bool(http), "peer": peer_addr})


def reset_client(tok):
    try:
        _CLIENT.reset(tok)
    except Exception:
        pass


def client_is_loopback() -> bool:
    c = _CLIENT.get()
    if not c or not c.get("http"):
        return True                        # in-process caller (no HTTP peer)
    from core import security
    return security.is_loopback_peer(c.get("peer"))
