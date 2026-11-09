"""Release the Hounds — run every hound in the left-sidebar order, in the background, so
each page is already populated when a human opens it.

Recipes (core/release_recipes.json) say what each hound's ▶ Run does:
  page      — the run button(s) and the read requests they send. The requests are run
              here through the launcher (exactly as the page would send them) and saved
              as that page's cache entry (core/pagecache.py). Opening the page replays the
              click and every read is answered from the entry — the page shows the run.
  snapshot  — the hound keeps its own server snapshot (Exposure Routes, SLA, Exposure
              Score): build it; the page peeks it on open.
  live      — the page loads its live list on open; nothing to pre-run.
On the Scent (insights) is first in the sidebar but runs LAST (kind snapshot, action `scent`):
it summarises every other hound's released result. The final state is persisted to
CACHE_DIR/release_last.json (last() / record()), with the snapshot file each snapshot hound left.
Reads only — Release never tags, applies or sends anything. External catalog downloads
(MITRE ATT&CK map, CISA KEV list) run only when approved (Settings → Auto-approve
downloads, or the box in the Release dialog); otherwise those hounds are skipped.

One release at a time, on its own thread (it waits on snapshot builds that run on the
job queue, so it must not occupy a queue worker). Cancel stops before the next request.
"""
import json
import os
import threading
import time

from core import db, pagecache, snapcache
from core.security import private_open as _popen

HERE = os.path.dirname(os.path.abspath(__file__))
RECIPES_PATH = os.path.join(HERE, "release_recipes.json")
_LOCK = threading.Lock()
_STATE = {"id": None, "status": "idle"}
_THREAD = None
MIN_HIST_S = 0.5            # runs faster than this (or cached) don't replace the estimate basis


def recipes():
    with open(RECIPES_PATH, encoding="utf-8") as f:
        return json.load(f)


def _hist_path():
    return os.path.join(snapcache.CACHE_DIR, "release_history.json")


def _history():
    try:
        with open(_hist_path(), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_history(h):
    try:
        os.makedirs(snapcache.CACHE_DIR, mode=0o700, exist_ok=True)
        tmp = _hist_path() + ".tmp"
        with _popen(tmp, "w", encoding="utf-8") as f:
            json.dump(h, f)
        os.replace(tmp, _hist_path())
    except Exception:
        pass


def _vuln_rows():
    try:
        return int(db.scalar("SELECT COUNT(*) FROM vulns", budget=0) or 0)
    except Exception:
        return 0


def _deployed():
    try:
        from core import launcher
        return set(launcher.DISPATCH)
    except Exception:
        return set()


def _auto_approve():
    try:
        from core import downloads
        return bool(downloads.auto_approve())
    except Exception:
        return False


def plan(approve_downloads=None):
    """What a release would run, in order, with a time estimate per hound.
    Estimate = the last release's time for that hound (scaled to today's navi.db size),
    else a first-run guess from the recipe's seconds-per-million-vulns-rows."""
    rc = recipes()
    rows = _vuln_rows()
    hist = _history()
    dep = _deployed()
    auto = _auto_approve()
    approve = auto if approve_downloads is None else bool(approve_downloads)
    items, total = [], 0.0
    for r in rc["pages"]:
        a = r["agent"]
        it = {"agent": a, "label": r["label"], "kind": r["kind"], "page": "/agents/%s/page.html" % a}
        if a not in dep:
            it.update(run=False, note="not installed")
        elif r["kind"] == "live":
            it.update(run=False, note="loads its live list when you open it")
        elif r.get("download") and not approve:
            it.update(run=False, note="needs the catalog download approved", download=r["download"])
        else:
            h = hist.get(a)
            first = max(r.get("min_s", 1), r.get("rate_s_per_mrow", 5) * rows / 1e6)
            if h and h.get("sec") is not None and h.get("rows"):
                scale = rows / h["rows"]
                est = max(r.get("min_s", 1), h["sec"] * max(0.25, scale))
                basis = "last release"
            elif h and h.get("sec") is not None:      # old entry with no row count — can't scale it
                est = max(first, h["sec"])
                basis = "last release"
            else:
                est = first
                basis = "first-run estimate"
            it.update(run=True, est_s=round(est, 1), basis=basis, download=r.get("download"))
            total += est
        items.append(it)
    return {"ok": True, "items": items, "total_s": round(total, 1), "vuln_rows": rows,
            "auto_approve_downloads": auto, "approve_downloads": approve,
            "excluded": rc.get("excluded", {}), "state": state()}


def state():
    with _LOCK:
        s = json.loads(json.dumps(_STATE, default=str))
    return s


def _last_path():
    return os.path.join(snapcache.CACHE_DIR, "release_last.json")


def last(db_path=None):
    """The final state of the last finished (or cancelled) release, persisted to
    CACHE_DIR/release_last.json so a restart still knows which hounds errored or were
    skipped. None when there is none for this navi.db (`db` = pagecache.db_id())."""
    try:
        with open(_last_path(), encoding="utf-8") as f:
            s = json.load(f)
    except Exception:
        return None
    if not isinstance(s, dict) or (s.get("db") and s["db"] != pagecache.db_id(db_path)):
        return None
    return s


def record(db_path=None):
    """The release that describes this navi.db's caches: the one running / just run in this
    process if it was for this navi.db, else the persisted last one. None if neither."""
    s = state()
    if s.get("id") and (not s.get("db") or s["db"] == pagecache.db_id(db_path)):
        return s
    return last(db_path)


def _save_last(s):
    try:
        os.makedirs(snapcache.CACHE_DIR, mode=0o700, exist_ok=True)
        tmp = _last_path() + ".tmp"
        with _popen(tmp, "w", encoding="utf-8") as f:
            json.dump(s, f, default=str)
        os.replace(tmp, _last_path())
    except Exception:
        pass


def cancel():
    with _LOCK:
        if _STATE.get("status") == "running":
            _STATE["cancel"] = True
            return True
    return False


def start(approve_downloads=None):
    """Start a release (or return the one already running)."""
    global _THREAD
    pl = plan(approve_downloads)
    with _LOCK:
        if _STATE.get("status") == "running":
            return {"ok": True, "already_running": True, "state": json.loads(json.dumps(_STATE, default=str))}
        rid = time.strftime("%Y%m%d-%H%M%S")
        _STATE.clear()
        _STATE.update({"id": rid, "status": "running", "started": time.time(), "finished": None,
                       "db": pagecache.db_id(),
                       "cancel": False, "approve_downloads": pl["approve_downloads"],
                       "est_total_s": pl["total_s"], "vuln_rows": pl["vuln_rows"],
                       "items": [dict(i, status=("pending" if i.get("run") else "skipped")) for i in pl["items"]]})
    _THREAD = threading.Thread(target=_run, args=(rid,), name="release-the-hounds", daemon=True)
    _THREAD.start()
    return {"ok": True, "state": state()}


# ---------------------------------------------------------------- the run
def _stable(o):
    """The page cache's request key body — mirrors stable() in console.js (sorted keys, no
    spaces, non-ASCII kept)."""
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def req_key(agent, action, body, ignore=()):
    """ignore = body keys the page leaves out of its cache key (its data-cache-ignore —
    e.g. the AI page's per-browser fingerprint list)."""
    k = {x: v for x, v in (body or {}).items()
         if x not in ("_label", "_nocache", "_run", "refresh") and x not in set(ignore or ())}
    return "POST /api/%s/%s %s" % (agent, action, _stable(k))


def _set_item(rid, agent, **kw):
    with _LOCK:
        if _STATE.get("id") != rid:
            return
        for it in _STATE.get("items", []):
            if it["agent"] == agent:
                it.update(kw)


def _cancelled(rid):
    with _LOCK:
        return _STATE.get("id") != rid or bool(_STATE.get("cancel"))


def _dispatch(agent, action, body):
    from core import launcher
    out = launcher._dispatch(agent, action, dict(body, _nocache=True, _label="Release · %s" % action))
    if isinstance(out, tuple) and len(out) == 2:
        return out
    return out, 200


def _newer_user_run(key, started_ms):
    """A run the user made on this page after the release started (not a release's own)."""
    m = pagecache.meta(key)
    return bool(m and not m.get("released") and (m.get("at") or 0) >= started_ms)


def _run_page(rid, r, approve, started_ms=0):
    key = "/agents/%s/page.html" % r["agent"]
    entry = {"key": key, "at": pagecache.now_ms(), "title": r["label"],
             "steps": [{"id": s, "inputs": {}} for s in r["steps"]], "final": None, "resp": {}}
    # a download hound: if the page shows its approval card on ▶ Run (approved for this
    # release only, or auto-approve turned off since), the replay clicks ✓ Approve as well.
    # optional → skipped when the card isn't showing.
    if r.get("download"):
        entry["steps"].append({"id": "approveBtn", "inputs": {}, "optional": True})
    ign = r.get("key_ignore") or ()
    errs = []
    for q in r["requests"]:
        if _cancelled(rid):
            return "cancelled", None
        body, status = _dispatch(q["agent"], q["action"], q.get("body") or {})
        if status < 400 and not (isinstance(body, dict) and body.get("ok") is False):
            entry["resp"][req_key(q["agent"], q["action"], q.get("body") or {}, ign)] = {"status": status, "body": body}
        else:
            errs.append((isinstance(body, dict) and (body.get("error") or body.get("message"))) or ("HTTP %s" % status))
    if _cancelled(rid):
        return "cancelled", None
    if not entry["resp"]:
        return "error", "; ".join(str(e) for e in errs[:2]) or "no results"
    if _newer_user_run(key, started_ms):
        return "done", "kept your newer run on this page"
    entry["released"] = {"by": "release", "id": rid, "at": entry["at"], "sig": snapcache.db_signature()}
    ok, err = pagecache.put(entry["key"], entry)
    if not ok:
        return "error", err
    return "done", ("%d of %d reads" % (len(entry["resp"]), len(r["requests"])) if errs else None)


# snapshot hounds → the file prefix their snapcache uses in CACHE_DIR (On the Scent reads them)
SNAP_PREFIX = {"fused_score": "fused", "exproute": "exproute", "sla": "sla"}


def snap_file(agent, snap):
    """The CACHE_DIR file holding `snap` (a {result|…, meta:{built_at, sig}} snapshot), found
    by its meta among that hound's snapshot files — or None. Reads files only, never navi.db."""
    pre = SNAP_PREFIX.get(agent)
    m = (snap or {}).get("meta") if isinstance(snap, dict) else None
    if not pre or not isinstance(m, dict) or not m.get("built_at"):
        return None
    try:
        names = [n for n in os.listdir(snapcache.CACHE_DIR) if n.startswith(pre + "_") and n.endswith(".json.gz")]
    except OSError:
        return None
    import gzip
    for n in sorted(names, key=lambda n: -os.path.getmtime(os.path.join(snapcache.CACHE_DIR, n))):
        try:
            with gzip.open(os.path.join(snapcache.CACHE_DIR, n), "rt", encoding="utf-8") as f:
                fm = (json.load(f) or {}).get("meta") or {}
        except Exception:
            continue
        if fm.get("built_at") == m.get("built_at") and fm.get("sig") == m.get("sig") \
                and (fm.get("view") or {}) == (m.get("view") or {}):
            return n
    return None


def _snap_ref(agent, body):
    """After a snapshot step: which file it left (peeks the hound — a cache read)."""
    if agent not in SNAP_PREFIX:
        return None
    try:
        snap = (body or {}).get("result") if isinstance(body, dict) else None
        if not (isinstance(snap, dict) and snap.get("meta")):
            body, _ = _dispatch(agent, "snapshot", {"peek": True})
            snap = (body or {}).get("result") if isinstance(body, dict) else None
        n = snap_file(agent, snap)
        if n:
            m = snap["meta"]
            return {"file": n, "built_at": m.get("built_at"), "sig": m.get("sig")}
    except Exception:
        pass
    return None


def _run_snapshot(rid, r):
    from core import jobq
    body, status = _dispatch(r["agent"], r["action"], r.get("body") or {})
    if status >= 400 or (isinstance(body, dict) and body.get("ok") is False):
        return "error", (isinstance(body, dict) and (body.get("error") or body.get("message"))) or "failed"
    b = (body or {}).get("building") if isinstance(body, dict) else None
    if not b or not b.get("job_id"):
        _set_item(rid, r["agent"], snap=_snap_ref(r["agent"], body))
        return "done", ("cached" if isinstance(body, dict) and body.get("cached") else None)
    jid = b["job_id"]
    while True:
        if _cancelled(rid):
            return "cancelled", "the build keeps running in the background"
        j = jobq.get(jid)
        if not j:
            return "done", None
        if j.get("status") == "done":
            _set_item(rid, r["agent"], snap=_snap_ref(r["agent"], None))
            return "done", None
        if j.get("status") == "error":
            return "error", j.get("message") or "build failed"
        time.sleep(0.5)


def _run(rid):
    rc = {r["agent"]: r for r in recipes()["pages"]}
    rows = _vuln_rows()
    hist = _history()
    with _LOCK:
        items = [dict(i) for i in _STATE.get("items", [])]
        approve = _STATE.get("approve_downloads")
        started_ms = int((_STATE.get("started") or time.time()) * 1000)
    for it in items:
        if not it.get("run"):
            continue
        if _cancelled(rid):
            break
        r = rc[it["agent"]]
        _set_item(rid, it["agent"], status="running", started=time.time())
        t0 = time.time()
        try:
            if r["kind"] == "snapshot":
                st, note = _run_snapshot(rid, r)
            else:
                st, note = _run_page(rid, r, approve, started_ms)
        except Exception as e:                          # one hound failing never stops the pack
            st, note = "error", "%s: %s" % (type(e).__name__, e)
        sec = round(time.time() - t0, 2)
        _set_item(rid, it["agent"], status=st, sec=sec, note=note)
        # a cached snapshot or a near-instant run says nothing about the real cost — keep
        # the previous measurement (or the first-run rate) for the next estimate
        if st == "done" and note != "cached" and sec >= MIN_HIST_S and rows > 0:
            hist[it["agent"]] = {"sec": sec, "rows": rows, "at": time.time()}
            _save_history(hist)                         # saved per hound: survives a restart
        if st == "cancelled":
            break
    _save_history(hist)
    with _LOCK:
        if _STATE.get("id") == rid:
            for it in _STATE.get("items", []):
                if it["status"] in ("pending", "running"):
                    it["status"] = "cancelled"
            _STATE["status"] = "cancelled" if _STATE.get("cancel") else "done"
            _STATE["finished"] = time.time()
            final = json.loads(json.dumps(_STATE, default=str))
        else:
            final = None
    if final:
        _save_last(final)       # survives a restart: which hounds errored / were skipped
