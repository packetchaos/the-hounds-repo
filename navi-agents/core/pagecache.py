"""Server-side page cache — where every hound page keeps its last run.

The page cache in web/assets/console.js (the `HC` block) used to live only in the
browser's IndexedDB. It now lives here, on disk under data/cache/pages/ (git-ignored),
so it survives a browser change, is shared by every browser on this console, and can
be filled by the SERVER: Release the Hounds (core/release.py) runs each hound and
writes the same entry a browser would have written, so opening the page later shows
the run straight away.

An entry is the HC record for one page (key = path + query string):
    {key, at (ms), title, steps:[{id, inputs}], final, resp:{"POST /api/a/b {...}": {status, body}},
     released?: {by, id, at, sig}, db}
Two files per page:
    <hash>.json.gz    the whole entry (responses can be tens of MB)
    <hash>.meta.json  {key, at, title, released, db, size, final?, steps?} — read by the
                      listing, and the target of patch(): typing in a field after a run
                      updates `final` here instead of re-uploading every response.
`db` ties an entry to the navi.db it was computed from: a page opened against another
navi.db gets nothing (its own run is not someone else's data).
Reads/writes go through the hub agent (agents/hub/api.py: pc_get / pc_put / pc_patch /
pc_del), which the launcher never caches.
"""
import gzip
import hashlib
import json
import os
import threading
import time

from core import snapcache
from core.security import private_open as _popen

MAX_BYTES = int(os.environ.get("NAVI_PAGECACHE_MAX_BYTES", str(64 * 1024 * 1024)))   # one entry, raw JSON
MAX_PAGES = int(os.environ.get("NAVI_PAGECACHE_MAX_PAGES", "200"))
_LOCK = threading.Lock()


def _dir():
    d = os.path.join(snapcache.CACHE_DIR, "pages")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def _base(key):
    return os.path.join(_dir(), hashlib.sha1(str(key).encode("utf-8")).hexdigest()[:24])


def _path(key):
    return _base(key) + ".json.gz"


def _meta_path(key):
    return _base(key) + ".meta.json"


def valid_key(key):
    k = str(key or "")
    return k.startswith("/agents/") and len(k) < 2000 and "\x00" not in k


def db_id(db_path=None):
    """Which navi.db an entry belongs to (its resolved path)."""
    try:
        return os.path.realpath(snapcache.db_file(db_path))
    except Exception:
        return ""


def _read_meta(key):
    try:
        with open(_meta_path(key), encoding="utf-8") as f:
            m = json.load(f)
        return m if m.get("key") == key else None
    except Exception:
        return None


def _write_json(path, obj):
    tmp = path + ".tmp.%d.%d" % (os.getpid(), threading.get_ident())
    with _popen(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, default=str, separators=(",", ":"))
    os.replace(tmp, path)


def get(key, db_path=None):
    """The entry for `key` computed from the current navi.db, or None."""
    if not valid_key(key):
        return None
    try:
        with gzip.open(_path(key), "rt", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception:
        return None
    if doc.get("key") != key:
        return None
    if doc.get("db") and doc["db"] != db_id(db_path):
        return None                                  # computed from another navi.db
    m = _read_meta(key)
    if m and (m.get("at") or 0) >= (doc.get("at") or 0):
        for k in ("final", "steps", "at", "title"):  # field edits after the run (patch())
            if k in m:
                doc[k] = m[k]
    return doc


def meta(key, db_path=None):
    """The small metadata of an entry (no responses) — cheap."""
    m = _read_meta(key) if valid_key(key) else None
    if m and m.get("db") and m["db"] != db_id(db_path):
        return None
    return m


def put(key, entry, db_path=None):
    """Store one page's entry. Returns (ok, error)."""
    if not valid_key(key) or not isinstance(entry, dict):
        return False, "bad key or entry"
    entry = dict(entry, key=key, db=db_id(db_path))
    raw = json.dumps(entry, default=str, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_BYTES:
        # a stale smaller copy must not be replayed in its place (it has the steps but
        # not these responses, so every read would go live on each open)
        delete(key)
        return False, "entry too large (%s, limit %s)" % (_size(len(raw)), _size(MAX_BYTES))
    p = _path(key)
    tmp = p + ".tmp.%d.%d" % (os.getpid(), threading.get_ident())
    with _LOCK:
        with _popen(tmp, "wb") as f:
            f.write(gzip.compress(raw, 5))
        os.replace(tmp, p)
        _write_json(_meta_path(key), {"key": key, "at": entry.get("at"), "title": entry.get("title"),
                                      "released": entry.get("released"), "db": entry["db"],
                                      "size": os.path.getsize(p)})
    _prune()
    return True, None


def patch(key, fields, db_path=None):
    """Update an entry's small fields (final, steps, at, title) without rewriting its
    responses. Returns (ok, error); not-found → the caller sends the whole entry."""
    m = meta(key, db_path)
    if not m or not os.path.exists(_path(key)):
        return False, "not found"
    for k in ("final", "steps", "at", "title"):
        if k in (fields or {}):
            m[k] = fields[k]
    if (fields or {}).get("released") is None and "released" in (fields or {}):
        m["released"] = None
    raw = json.dumps(m, default=str).encode("utf-8")
    if len(raw) > 4 * 1024 * 1024:
        return False, "fields too large"
    with _LOCK:
        _write_json(_meta_path(key), m)
    return True, None


def delete(key):
    ok = False
    for fp in (_path(key), _meta_path(key)):
        try:
            os.remove(fp)
            ok = True
        except OSError:
            pass
    return ok


def clear_all():
    n = 0
    for f in os.listdir(_dir()):
        if f.endswith((".json.gz", ".meta.json")) or ".tmp." in f:
            try:
                os.remove(os.path.join(_dir(), f))
                n += f.endswith(".json.gz")
            except OSError:
                pass
    return n


def listing(db_path=None):
    """[{key, at, title, released, size}] newest first — for the hub and Settings. Reads
    only the small .meta.json files."""
    out, me = [], db_id(db_path)
    for f in os.listdir(_dir()):
        if not f.endswith(".meta.json"):
            continue
        try:
            with open(os.path.join(_dir(), f), encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception:
            continue
        if d.get("db") and d["db"] != me:
            continue
        out.append({"key": d.get("key"), "at": d.get("at"), "title": d.get("title"),
                    "released": d.get("released"), "size": d.get("size")})
    return sorted(out, key=lambda x: -(x.get("at") or 0))


def _prune():
    try:
        d = _dir()
        names = os.listdir(d)
        now = time.time()
        for n in names:                    # leftovers of a crash mid-write
            if ".tmp." in n:
                fp = os.path.join(d, n)
                try:
                    if now - os.path.getmtime(fp) > 3600:
                        os.remove(fp)
                except OSError:
                    pass
        fs = sorted((os.path.join(d, n) for n in names if n.endswith(".json.gz")),
                    key=os.path.getmtime, reverse=True)
        for fp in fs[MAX_PAGES:]:
            for x in (fp, fp[:-len(".json.gz")] + ".meta.json"):
                try:
                    os.remove(x)
                except OSError:
                    pass
    except Exception:
        pass


def _size(n):
    return ("%.1f MB" % (n / 1048576.0)) if n >= 1048576 else ("%.1f KB" % (n / 1024.0))


def now_ms():
    return int(time.time() * 1000)
