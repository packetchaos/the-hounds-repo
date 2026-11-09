"""External downloads — one registry + one switch for every hound that fetches data
from outside Tenable / navi.db (MITRE's ATT&CK→CVE CSV, CISA's KEV catalog, …).

By default a hound asks a human to approve each external download (the "Human
approval — external download" card). Settings → **Auto-approve downloads**
(``NAVI_AUTO_APPROVE_DOWNLOADS=1``) skips that card: the hound shows a one-line
"Auto-approved download: <url> (Settings)" note and fetches straight away. Either
way the download is read-only and still falls back to the bundled snapshot offline.

Adding a source (see CONTRIBUTING.md → "External downloads"):

    from core import downloads
    downloads.register("myfeed", "My feed", ["https://example.org/feed.json"],
                       agent="myagent", purpose="what it adds", fallback="bundled snapshot")

    # in the action that downloads:
    live, by = downloads.allowed(p)        # p = the request payload
    data = fetch(allow_live=live)          # live=False → snapshot only, no network

and on the page:  ``if(await downloadsAutoApproved('myfeed')) …run… else …show the card…``
(the card's approve button sends ``approved:true``).
"""
import os
import threading

ENV = "NAVI_AUTO_APPROVE_DOWNLOADS"
_TRUE = ("1", "true", "yes", "on", "y", "t", "enabled")

_LOCK = threading.Lock()
_SOURCES = {}          # id -> record (insertion-ordered)


def register(id, name, urls, agent, purpose="", fallback="", approval=True):
    """Register (or replace) an external source. Call at import time of the module that
    owns the URL. approval=False marks a source that has no approval step of its own
    (fetched only by an explicit user action), so the setting does not change it."""
    if isinstance(urls, str):
        urls = [urls]
    rec = {"id": str(id), "name": str(name), "urls": [str(u) for u in (urls or [])],
           "agent": str(agent), "purpose": str(purpose or ""), "fallback": str(fallback or ""),
           "approval": bool(approval)}
    with _LOCK:
        _SOURCES[rec["id"]] = rec
    return rec


def get(id):
    with _LOCK:
        r = _SOURCES.get(str(id or ""))
        return dict(r) if r else None


def sources():
    with _LOCK:
        return [dict(r) for r in _SOURCES.values()]


def auto_approve() -> bool:
    """True when Settings → Auto-approve downloads is ON. Read live from the environment
    (the Settings page / config store set it), so a change applies immediately."""
    return (os.environ.get(ENV) or "").strip().lower() in _TRUE


def allowed(payload=None):
    """Server-side gate for an action that downloads. Returns (live_ok, approved_by):
    approved_by is 'settings' (auto-approve ON), 'user' (the page sent approved:true
    after the human clicked Approve) or '' (not approved → use the snapshot, no network)."""
    if auto_approve():
        return True, "settings"
    if isinstance(payload, dict) and payload.get("approved") is True:
        return True, "user"
    return False, ""


def status(id=None) -> dict:
    """What the Settings page and downloadsAutoApproved() read: the switch + the sources."""
    out = {"ok": True, "auto_approve": auto_approve(), "env": ENV, "sources": sources()}
    if id:
        out["source"] = get(id)
    return out
