"""Tag scope — run a hound over ONE tag's assets instead of the whole estate (build 489).

A hound opts in through its manifest:

    "tag_scope": {"actions": ["run", "drill", "tag"],   # honour the request's tag_scope
                  "ignore":  ["source", "nl"]}           # scope is irrelevant: dropped

The page calls mountTagScope() (web/assets/console.js): the bar at the top of the page picks a
tag; the page's address becomes ?tk=<key>&tv=<value>, and every POST the page sends to its own
hound carries {tag_scope: {key, value}} — its own parameter, because tag_key / tag_value already
mean "the tag to write / remove / search" in several hounds (Certania, Garmr, Basset, Gabriel…). The launcher (core/launcher.dispatch → check()) refuses a
scoped request to an action the manifest doesn't list — no action can silently ignore a scope
the operator thinks is applied. Writes from a scoped view stay inside the scope: the hound
re-reads the tag's assets from navi.db on the server, never from the browser.

Caching needs nothing new: a scoped page is its own page-cache entry (core/pagecache keys on
path + query), its ▶ Run detaches to the job queue like any other (core/launcher._detached), and
the read cache keys on the payload. pagecache keeps the newest MAX_TAGS tag variants per hound,
and never prunes the whole-estate page.

Helpers for a hound:
    k, v = tagscope.parse(p)                 # (None, None) = whole estate
    frag, args = tagscope.sql(k, v, "a.uuid")  # " AND a.uuid IN (SELECT asset_uuid FROM tags …)"
    s = tagscope.uuids(k, v)                 # the set, for Python-side filtering
    tagscope.describe(k, v)                  # {"key","value","label","assets"} — put it in a result as "scope"
"""
import json
import os
import threading
import time
import urllib.parse

from core import db

MAX_TAGS = 5
MAX_LEN = 200
_LOCK = threading.Lock()
_POLICY = {}


def parse(p):
    """(key, value) of the request's tag_scope, or (None, None) for the whole estate."""
    ts = p.get("tag_scope") if isinstance(p, dict) else None
    if not isinstance(ts, dict):
        return None, None
    k, v = ts.get("key"), ts.get("value")
    k = k.strip() if isinstance(k, str) else ""
    v = v.strip() if isinstance(v, str) else ""
    return (k, v) if (k and v) else (None, None)


def label(k, v):
    return f"{k} : {v}" if k else "Whole estate"


def _has_tags(path=None):
    try:
        return bool(db.query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='tags'", path=path))
    except Exception:
        return False


def sql(k, v, col="asset_uuid"):
    """WHERE fragment (starts with ' AND ') + params scoping `col` (an asset uuid column) to the
    tag. ('', ()) for the whole estate. Exact tag_key / tag_value match, like Sköll's filter."""
    if not (k and v):
        return "", ()
    return f" AND {col} IN (SELECT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?)", (k, v)


def uuids(k, v, path=None):
    """The set of asset uuids carrying the tag (empty for none / no tags table)."""
    if not (k and v) or not _has_tags(path):
        return set()
    return {r["asset_uuid"] for r in db.query(
        "SELECT DISTINCT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", (k, v), path=path) if r["asset_uuid"]}


def count(k, v, path=None):
    if not (k and v) or not _has_tags(path):
        return 0
    try:
        return int(db.scalar("SELECT COUNT(DISTINCT asset_uuid) FROM tags WHERE tag_key=? AND tag_value=?",
                             (k, v), path=path) or 0)
    except Exception:
        return 0


def describe(k, v, path=None):
    """What a scoped result says about its scope (None for the whole estate)."""
    if not (k and v):
        return None
    return {"key": k, "value": v, "label": label(k, v), "assets": count(k, v, path)}


def keys(path=None, top=300):
    if not _has_tags(path):
        return []
    rows = db.query("SELECT tag_key k, COUNT(DISTINCT asset_uuid) n FROM tags WHERE tag_key IS NOT NULL "
                    "AND TRIM(tag_key)<>'' GROUP BY tag_key ORDER BY n DESC, tag_key LIMIT ?", (int(top),), path=path)
    return [{"key": r["k"], "assets": r["n"]} for r in rows]


def values(key, path=None, top=500):
    if not key or not _has_tags(path):
        return []
    rows = db.query("SELECT tag_value v, COUNT(DISTINCT asset_uuid) n FROM tags WHERE tag_key=? AND tag_value IS NOT NULL "
                    "AND TRIM(tag_value)<>'' GROUP BY tag_value ORDER BY n DESC, tag_value LIMIT ?",
                    (key, int(top)), path=path)
    return [{"value": r["v"], "assets": r["n"]} for r in rows]


# ── the manifest contract, enforced by the launcher ─────────────────────────────────────────
def policy(agent_id):
    """The hound's manifest "tag_scope" block, or None when it has no tag filter."""
    if agent_id not in _POLICY:
        pol = None
        try:
            from core import discovery
            with open(os.path.join(discovery.AGENTS_DIR, agent_id, "manifest.json"), encoding="utf-8") as f:
                ts = json.load(f).get("tag_scope")
            if isinstance(ts, dict):
                pol = {"actions": set(ts.get("actions") or []), "ignore": set(ts.get("ignore") or [])}
        except Exception:
            pol = None
        _POLICY[agent_id] = pol
    return _POLICY[agent_id]


def check(agent_id, action, payload):
    """None when the request may go on (a scope on an `ignore` action is dropped from payload in
    place), else an (error body, status) tuple. Called for every request by the launcher."""
    if not isinstance(payload, dict) or "tag_scope" not in payload:
        return None
    ts = payload.get("tag_scope")
    if ts in (None, "", {}):                                 # an explicit "whole estate"
        payload.pop("tag_scope", None)
        return None
    if not isinstance(ts, dict):
        return {"ok": False, "error": "tag_scope must be {key, value}"}, 400
    k, v = ts.get("key"), ts.get("value")
    pol = policy(agent_id)
    if pol is None:
        return {"ok": False, "error": f"'{agent_id}' has no tag filter — open it without one"}, 400
    if action in pol["ignore"]:
        payload.pop("tag_scope", None)
        return None
    if action not in pol["actions"]:
        return {"ok": False, "error": f"'{agent_id}/{action}' doesn't support a tag filter yet — "
                                      "clear the filter (🌐 Whole estate) to use it"}, 400
    if not (isinstance(k, str) and isinstance(v, str) and k.strip() and v.strip()
            and len(k) <= MAX_LEN and len(v) <= MAX_LEN):
        return {"ok": False, "error": "tag_scope needs a key and a value (text, at most 200 characters)"}, 400
    payload["tag_scope"] = {"key": k.strip(), "value": v.strip()}
    try:
        remember(agent_id, k.strip(), v.strip())
    except Exception:
        pass
    return None


# ── recent tags per hound (the switcher) ─────────────────────────────────────────────────────
def _recent_path(agent_id):
    from core import snapcache
    d = os.path.join(snapcache.CACHE_DIR, "tagscope")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return os.path.join(d, "".join(c for c in agent_id if c.isalnum() or c == "_") + ".json")


def recent(agent_id):
    try:
        with open(_recent_path(agent_id), encoding="utf-8") as f:
            r = json.load(f)
        return [x for x in r if isinstance(x, dict) and x.get("key") and x.get("value")][:MAX_TAGS]
    except Exception:
        return []


def remember(agent_id, k, v):
    with _LOCK:
        r = [x for x in recent(agent_id) if not (x["key"] == k and x["value"] == v)]
        r.insert(0, {"key": k, "value": v, "at": time.time()})
        p = _recent_path(agent_id)
        tmp = p + ".tmp.%d" % threading.get_ident()
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(r[:MAX_TAGS], f)
        os.replace(tmp, p)


def page_query(k, v):
    """The page address' query for a scope — exactly what console.js tagScopeHref() builds
    (encodeURIComponent), so the server finds the same page-cache entry."""
    q = lambda s: urllib.parse.quote(s, safe="-_.!~*'()")
    return f"?tk={q(k)}&tv={q(v)}"


def scopes(agent_id, key=None, path=None):
    """The switcher: the whole estate + this hound's recent tags (each with the time its last
    run was kept in the page cache), the tag keys, and the values of `key`."""
    from core import pagecache
    page = f"/agents/{agent_id}/page.html"
    # a hound with its OWN cache (its page turns the page cache off) may define
    # api.scope_cached_at(key, value) -> epoch ms | None  (key None = the whole estate)
    hook = None
    try:
        import importlib
        hook = getattr(importlib.import_module(f"agents.{agent_id}.api"), "scope_cached_at", None)
    except Exception:
        hook = None

    def _at(k, v):
        if hook:
            try:
                return hook(k, v)
            except Exception:
                return None
        try:
            m = pagecache.meta(page + (page_query(k, v) if k else ""), path)
            return (m or {}).get("at")
        except Exception:
            return None

    out = [{"key": None, "value": None, "label": "Whole estate", "cached_at": _at(None, None)}]
    for r in recent(agent_id):
        out.append({"key": r["key"], "value": r["value"], "label": label(r["key"], r["value"]),
                    "assets": count(r["key"], r["value"], path), "cached_at": _at(r["key"], r["value"])})
    res = {"agent": agent_id, "scopes": out, "keys": keys(path), "max": MAX_TAGS,
           "enabled": policy(agent_id) is not None}
    if key:
        res["values"] = values(key, path)
    return res
