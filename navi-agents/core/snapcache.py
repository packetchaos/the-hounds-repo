"""Snapshot cache — the reusable form of the pattern Exposure Routes and SLA introduced.

A heavy, read-only result is built once, gzipped to disk (``data/cache/``, git-ignored) and
kept in memory, keyed by navi.db's signature (size + mtime of the db and its ``-wal``) plus
whatever else changes the answer (weights, thresholds, a view). Builds run on the job queue,
so a user can leave the page; opening the page only *peeks* (shows the cached result or
re-attaches to a running build) and never computes.

    SNAP = snapcache.Snapshots("fused")                 # one per agent
    st = SNAP.state(extra={"w": weights})               # {"snap", "building", "key"}
    SNAP.start(submit, lambda: build(...), extra=...)   # background build (joins a running one)
    SNAP.build(lambda: build(...), extra=...)           # synchronous build + save

A snapshot is ``{"result": <your dict>, "meta": {"sig", "built_at", "build_sec", "extra"}}``.
"""
import datetime
import gzip
import hashlib
import json
import os
import threading
import time

from core import db
from core.security import private_open as _popen

CACHE_DIR = os.environ.get("NAVI_CACHE_DIR") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "cache")


def db_file(db_path=None):
    try:
        return os.path.abspath(db_path or db.db_path())
    except Exception:
        return ""


def db_signature(db_path=None) -> str:
    """Changes whenever navi.db (or its write-ahead log) is written."""
    p = db_file(db_path)
    parts = []
    for fp in (p, p + "-wal"):
        try:
            st = os.stat(fp)
            parts.append(f"{st.st_size}:{st.st_mtime_ns}")
        except OSError:
            parts.append("-")
    return "|".join(parts)


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


class Snapshots:
    def __init__(self, name, version=1, keep=4):
        self.name, self.version, self.keep = name, version, keep
        self._mem = {}
        self._building = {}
        self._lock = threading.Lock()
        self._mlock = threading.Lock()          # guards _mem (request + worker threads)

    # ---- keys / files
    def key(self, db_path=None, extra=None):
        # readers match '<prefix>-<category>' test-run tags too (core/tagname.py), so a new
        # phrase must not be answered from a snapshot built with the old one
        try:
            from core import tagname
            tp = tagname.configured_prefix()
        except Exception:
            tp = ""
        raw = json.dumps({"db": db_file(db_path), "x": extra or {}, "v": self.version, **({"tp": tp} if tp else {})},
                         sort_keys=True, default=str)
        return hashlib.sha1(raw.encode()).hexdigest()[:16]

    def _path(self, key):
        os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
        return os.path.join(CACHE_DIR, f"{self.name}_{key}.json.gz")

    def load(self, key, sig):
        with self._mlock:
            s = self._mem.get(key)
        if s and s["meta"].get("sig") == sig:
            return s
        try:
            with gzip.open(self._path(key), "rt", encoding="utf-8") as f:
                s = json.load(f)
        except Exception:
            return None
        if s.get("meta", {}).get("sig") != sig:
            return None
        self._remember(key, s)
        return s

    def _remember(self, key, s):
        with self._mlock:
            self._mem.pop(key, None)
            self._mem[key] = s                               # newest last
            while len(self._mem) > self.keep:                # bounded memory
                self._mem.pop(next(iter(self._mem)))

    def save(self, key, s):
        try:
            self._remember(key, s)
            p = self._path(key)
            tmp = p + ".tmp.%d.%d" % (os.getpid(), threading.get_ident())
            with _popen(tmp, "wb") as f:
                f.write(gzip.compress(json.dumps(s, default=list).encode("utf-8"), 5))
            os.replace(tmp, p)
            self._prune()
        except Exception:
            pass

    def _prune(self):
        """Keep the newest `keep` files for this snapshot name (different weights/views)."""
        try:
            fs = sorted((os.path.join(CACHE_DIR, n) for n in os.listdir(CACHE_DIR)
                         if n.startswith(self.name + "_") and n.endswith(".json.gz")),
                        key=os.path.getmtime, reverse=True)
            for fp in fs[self.keep:]:
                os.remove(fp)
        except Exception:
            pass

    # ---- the three calls an agent makes
    def state(self, db_path=None, extra=None):
        key, sig = self.key(db_path, extra), db_signature(db_path)
        with self._lock:
            bld = dict(self._building.get(key) or {})
        return {"snap": self.load(key, sig), "building": bld or None, "key": key}

    def build(self, fn, db_path=None, extra=None):
        t0 = time.time()
        sig = db_signature(db_path)
        result = fn()
        snap = {"result": result, "meta": {"sig": sig, "built_at": _iso(t0),
                                           "build_sec": round(time.time() - t0, 2), "extra": extra or {}}}
        self.save(self.key(db_path, extra), snap)
        return snap

    def start(self, submit, fn, db_path=None, extra=None, label=None):
        """Start (or join) a background build for this key. `submit(work)` puts work on the
        job queue and returns the job stub (see core.jobq.submit)."""
        key = self.key(db_path, extra)
        with self._lock:
            if key in self._building:
                return dict(self._building[key])
            entry = {"job_id": None, "started": _iso(time.time())}
            self._building[key] = entry             # claimed before submit: no double builds

        def _work():
            try:
                s = self.build(fn, db_path, extra)
                return {"ok": True, "ready": True, "build_sec": s["meta"]["build_sec"],
                        "message": f"{label or self.name} snapshot built in {s['meta']['build_sec']}s"}
            finally:
                with self._lock:
                    self._building.pop(key, None)

        try:
            job = submit(_work)                     # outside the lock — a queue may run it at once
        except Exception:
            with self._lock:
                self._building.pop(key, None)
            raise
        with self._lock:
            entry["job_id"] = job.get("id")
            return dict(entry)
