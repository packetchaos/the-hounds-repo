"""Sköll — the SLA Adherence agent.

Named for the Norse wolf that eternally chases the sun across the sky: Sköll chases
the SLA clock. It measures two things, segmented by owner/tag:
  • remediation — were CLOSED findings fixed inside their SLA window (Pass/Fail),
  • open aging  — how OPEN findings are aging against the per-severity SLA window.
Plus navi's own Pass/Fail verdict as the headline, the SLA-owner metrics (due soon,
MTTR, crown jewels, worst assets/plugins/owners) and a monthly trend reconstructed from
finding dates. All read-only over navi.db — the computation lives in core.sla.

Snapshot cache (same pattern as Exposure Routes): the full dashboard for one view
(segment key + filter value) is cached on disk as gzipped JSON under data/cache/, keyed
by navi.db's signature (size + mtime of the db and its -wal) AND the SLA thresholds. A
navi update or an SLA change invalidates it; a new day makes it stale (ages moved), so
the next ▶ Run recomputes. Builds run on the job queue, so leaving the page doesn't stop
them, and opening the page only peeks — it never computes.
"""
import datetime
import gzip
import hashlib
import json as _json
import os
import threading
import time as _time

from core import db, sla as _sla
from core.agents.base import Agent
from core.security import private_open as _popen

CACHE_DIR = os.environ.get("NAVI_CACHE_DIR") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "cache")
SNAP_VERSION = 1
_MEM_MAX = 12
_SNAP_MEM = {}            # file key -> snapshot dict (small LRU)
_BUILDING = {}            # file key -> {"job_id", "started", "view"}
_SLOCK = threading.Lock()


def _cache_path(name):
    os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
    return os.path.join(CACHE_DIR, name)


def _atomic_write(path, data: bytes):
    tmp = path + ".tmp"
    with _popen(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _db_file(db_path=None):
    try:
        return os.path.abspath(db_path or db.db_path())
    except Exception:
        return ""


def db_signature(db_path=None) -> str:
    """size:mtime of navi.db and its -wal — changes on every navi update."""
    p = _db_file(db_path)
    parts = []
    for fp in (p, p + "-wal"):
        try:
            st = os.stat(fp)
            parts.append(f"{st.st_size}:{st.st_mtime_ns}")
        except OSError:
            parts.append("-")
    return "|".join(parts)


_CFG_MEM = {}              # (db file, signature) -> config signature


def _read_thresholds(db_path=None):
    """The `sla` table, read on a bare read-only connection (no query-profiler entry, so a
    peek doesn't add a line to the Runs log)."""
    try:
        con = db.connect(db_path)
        try:
            row = con.execute("SELECT critical, high, medium, low FROM sla").fetchone()
        finally:
            con.close()
    except Exception:
        return None
    if not row:
        return None

    def _i(v):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return None
    out = {s: _i(v) for s, v in zip(_sla.SEVERITIES, tuple(row))}
    return out if any(v is not None for v in out.values()) else None


def config_signature(db_path=None, sig=None) -> str:
    """The SLA policy the numbers depend on (thresholds + engine version). Changing the
    SLA days (Settings ▸ SLA policy) changes this, so the cache is never reused across it.
    Thresholds live in navi.db, so they're re-read only when its signature moves."""
    sig = sig or db_signature(db_path)
    k = (_db_file(db_path), sig)
    if k not in _CFG_MEM:
        _CFG_MEM.clear()
        _CFG_MEM[k] = _json.dumps({"th": _read_thresholds(db_path), "engine": _sla.ENGINE_VERSION,
                                   "crown": _sla.CROWN_ACR, "due": list(_sla.DUE_WINDOWS)},
                                  sort_keys=True)
    return _CFG_MEM[k]


def _view(tag_key=None, tag_value=None):
    return {"tag_key": (tag_key or "").strip() or None, "tag_value": (tag_value or "").strip() or None}


def _dbkey(db_path=None):
    return hashlib.sha1(_db_file(db_path).encode()).hexdigest()[:12]


def _file_key(db_path=None, tag_key=None, tag_value=None):
    v = _view(tag_key, tag_value)
    vh = hashlib.sha1(_json.dumps(v, sort_keys=True).encode()).hexdigest()[:10]
    return f"sla_{_dbkey(db_path)}_{vh}"


def _iso(ts):
    try:
        return datetime.datetime.fromtimestamp(float(ts)).astimezone().isoformat(timespec="seconds")
    except Exception:
        return None


def _today():
    return datetime.date.today().isoformat()


def _mem_put(key, s):
    _SNAP_MEM.pop(key, None)
    _SNAP_MEM[key] = s
    while len(_SNAP_MEM) > _MEM_MAX:
        _SNAP_MEM.pop(next(iter(_SNAP_MEM)))


def _valid(s, sig, cfg):
    m = (s or {}).get("meta") or {}
    return m.get("v") == SNAP_VERSION and m.get("sig") == sig and m.get("cfg") == cfg


def _load_snapshot(key, sig, cfg):
    s = _SNAP_MEM.get(key)
    if s and _valid(s, sig, cfg):
        return s
    try:
        with gzip.open(_cache_path(key + ".json.gz"), "rt", encoding="utf-8") as f:
            s = _json.load(f)
    except Exception:
        return None
    if not _valid(s, sig, cfg):
        return None
    _mem_put(key, s)
    return s


def _prune(db_path=None):
    """Drop this navi.db's cached views written before its current version — their
    signature can no longer match, so they're dead weight in data/cache/."""
    try:
        cutoff = max(os.stat(fp).st_mtime for fp in (_db_file(db_path), _db_file(db_path) + "-wal")
                     if os.path.exists(fp))
        pre = f"sla_{_dbkey(db_path)}_"
        for n in os.listdir(CACHE_DIR):
            fp = os.path.join(CACHE_DIR, n)
            if n.startswith(pre) and n.endswith(".json.gz") and os.stat(fp).st_mtime < cutoff:
                os.remove(fp)
    except Exception:
        pass


def _save_snapshot(key, s, db_path=None):
    _mem_put(key, s)
    try:
        _prune(db_path)
        _atomic_write(_cache_path(key + ".json.gz"),
                      gzip.compress(_json.dumps(s, default=list).encode("utf-8"), 5))
    except Exception:
        pass


def build_snapshot(db_path=None, tag_key=None, tag_value=None, record_history=True) -> dict:
    """Compute the dashboard for one view and cache it. An unscoped build also writes the
    day's point to the trend store (core.history) — exactly as ▶ Run always did."""
    t0 = _time.time()
    sig = db_signature(db_path)
    cfg = config_signature(db_path, sig)
    res = _sla.dashboard(path=db_path, tag_key=tag_key, tag_value=tag_value)
    snap = {"result": res,
            "meta": {"v": SNAP_VERSION, "sig": sig, "cfg": cfg, "db": _db_file(db_path),
                     "view": _view(tag_key, tag_value), "day": _today(),
                     "built_at": _iso(t0), "build_sec": round(_time.time() - t0, 2)}}
    _save_snapshot(_file_key(db_path, tag_key, tag_value), snap, db_path)
    # also file it under the RESOLVED view (default segment key filled in, a stale filter
    # value dropped), so a peek that names the view explicitly finds the same result
    rk = _file_key(db_path, res.get("tag_key"), res.get("tag_value"))
    if rk != _file_key(db_path, tag_key, tag_value):
        _save_snapshot(rk, {**snap, "meta": {**snap["meta"], "view": _view(res.get("tag_key"), res.get("tag_value"))}}, db_path)
    if record_history and not res.get("scoped"):
        try:
            from core import history
            history.record("sla", _sla.snapshot_metrics(res), dims={"tag_key": res.get("tag_key")})
        except Exception:
            pass
    return snap


def snapshot_state(db_path=None, tag_key=None, tag_value=None) -> dict:
    """What the page can show right now without computing anything. `stale` = valid for
    this navi.db + SLA policy, but built on an earlier day (open ages have moved since)."""
    key = _file_key(db_path, tag_key, tag_value)
    sig = db_signature(db_path)
    s = _load_snapshot(key, sig, config_signature(db_path, sig))
    with _SLOCK:
        bld = dict(_BUILDING.get(key) or {})
    stale = bool(s) and (s.get("meta") or {}).get("day") != _today()
    return {"snap": s, "stale": stale, "building": bld or None, "key": key}


def start_build(submit, db_path=None, tag_key=None, tag_value=None) -> dict:
    """Start (or join) the background build for one view. `submit(fn)` puts fn on the job
    queue and returns the job stub. One build per (navi.db, view) at a time."""
    key = _file_key(db_path, tag_key, tag_value)
    with _SLOCK:
        if key in _BUILDING:
            return dict(_BUILDING[key])

        def _work():
            try:
                s = build_snapshot(db_path, tag_key, tag_value)
                m = s["meta"]
                return {"ok": True, "ready": True, "build_sec": m["build_sec"],
                        "message": f"SLA snapshot built in {m['build_sec']}s"}
            finally:
                with _SLOCK:
                    _BUILDING.pop(key, None)
        job = submit(_work)
        _BUILDING[key] = {"job_id": job.get("id"), "started": _iso(_time.time()),
                          "view": _view(tag_key, tag_value)}
        return dict(_BUILDING[key])


def cached_or_compute(db_path=None, tag_key=None, tag_value=None) -> tuple:
    """(snapshot, from_cache) — synchronous; used by the legacy `run` action."""
    st = snapshot_state(db_path, tag_key, tag_value)
    if st["snap"] and not st["stale"]:
        return st["snap"], True
    return build_snapshot(db_path, tag_key, tag_value), False


class SkollAgent(Agent):
    id = "sla"
    name = "SLA Adherence"
    icon = "⏱"
    description = ("Sköll — chases the SLA clock. Remediation adherence on closed findings "
                   "and open-vuln aging vs the per-severity SLA window, by owner/tag. Records "
                   "a daily snapshot for the trend view.")

    def summary(self):
        r = self.result or {}
        oa = r.get("open_aging") or {}
        vd = r.get("verdict") or {}
        return {"adherence_pct": vd.get("adherence_pct"),
                "open": oa.get("open"), "open_breached": oa.get("breached")}

    def _run(self, db_path=None, tag_key=None, tag_value=None, **kwargs):
        snap, _hit = cached_or_compute(db_path, tag_key, tag_value)
        return snap["result"]
