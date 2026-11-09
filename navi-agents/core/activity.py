"""Per-hound activity — "what has this hound already done?"

Feeds the "Done so far" panel at the top of every agent page. Two sources:

  • the Hounds log (tag_jobs.db, written by core.tagq) — what THIS install did:
    every tag / remove / ACR / mail / push job with its agent, category, value,
    outcome and time; plus a `runs` table (added here) recording every agent run,
    so read-only hounds have a durable "last run" too (the Runs log in core.jobq is
    memory-only and resets on restart).
  • navi.db's `tags` table — what is on assets RIGHT NOW (as of the last navi sync),
    so the panel can say "66 Mitre values on 1,204 assets" and flag values that were
    applied but haven't shown up yet (awaiting sync).

Tags in a hound's categories that this install never applied (navi CLI, the
Tenable UI, another install) are reported separately as "already in navi.db" — the
panel never claims them as the hound's own work.
"""
import os
import sqlite3
import threading
import time

from . import db, tagname, tagq

# Well-known categories per hound — used only to surface tags already in navi.db for a
# hound this install hasn't logged yet. What a hound DID always comes from the log.
DEFAULT_CATEGORIES = {
    "mitre": ["Mitre"], "cisakev": ["CISA KEV", "CISA KEV Due"], "eol": ["Lifecycle", "Lifecycle EOL"],
    "certificate": ["Cert failure", "Cert Issue"], "customapp": ["Custom App"],
    "classify": ["Asset Inventory"], "agentgroup": ["Agent Group"],
    "attackpath": ["Attack Path"], "fused_score": ["Priority"], "scan_eval": ["Scan Health"],
    "postquantum": ["Post-Quantum", "PQC Priority", "PQC Harvest-Now", "PQC Risk",
                    "PQC Transport", "PQC Agility"],
    "compliance": ["Audit Owner"], "compliance_asset": ["Audit-Vuln Link"],
    "asset_ownership": ["Business Owner", "Asset Owner"], "ai": ["AI", "AI Role", "AI ACR Raise", "AI Exposed", "AI Priority", "AI Egress", "AI ATLAS", "AI Software"],
    "identity": ["Identity", "NHI", "Machine ID", "Owner", "Identity Risk", "Identity Coverage"], "software": ["Software", "Software EOL", "Software Outdated", "Software Risk", "Crown Jewel"], "iot_squad": ["IoT"],
}


def allowed_category(agent, category) -> bool:
    """Server-side guard: a fixed-button agent may only write the categories it owns, so a
    crafted request can't make it tag e.g. 'Business Unit'."""
    # Settings → Test run: '<phrase>-<category>' is the same category (core.tagname)
    return tagname.base(category or "") in DEFAULT_CATEGORIES.get(agent, [])


# The "Done so far" panel is for TAGGING hounds only — its job is to show whether they've
# already tagged. Driven by the manifest: category Tagging or Discovery shows the panel;
# anything else (Risk, Explore, Views, …) doesn't. A manifest may override with
# "status_panel": true/false.
PANEL_CATEGORIES = {"Tagging", "Discovery"}
_PANEL = {}


def shows_panel(agent) -> bool:
    if agent in _PANEL:
        return _PANEL[agent]
    ok = False
    try:
        import json
        p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "agents", agent, "manifest.json")
        with open(p, encoding="utf-8") as f:
            m = json.load(f)
        ok = bool(m["status_panel"]) if "status_panel" in m else (m.get("category") in PANEL_CATEGORIES)
    except Exception:
        ok = False
    _PANEL[agent] = ok
    return ok


# agents whose runs are bookkeeping, not a hound run
_NO_RUNS = {"explore", "settings", "hub", "jobs", "profile"}
_RUNS_MAX = int(os.environ.get("NAVI_RUN_LOG_MAX", "20000"))
_LOCK = threading.Lock()
_READY = None


def _con():
    con = sqlite3.connect(tagq._DBPATH, timeout=5.0)
    con.row_factory = sqlite3.Row
    return con


def _ensure():
    global _READY
    if _READY is not None:
        return _READY
    try:
        con = _con()
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                        "agent TEXT, action TEXT, ok INTEGER, ms REAL, at REAL, cached INTEGER)")
            if "rid" not in [r[1] for r in con.execute("PRAGMA table_info(runs)")]:
                con.execute("ALTER TABLE runs ADD COLUMN rid TEXT")     # one id per ▶ Run / Run all
            con.execute("CREATE INDEX IF NOT EXISTS runs_agent_at ON runs(agent, at)")
            con.execute("CREATE INDEX IF NOT EXISTS jobs_agent ON jobs(agent)")
            con.commit()
        finally:
            con.close()
        _READY = True
    except Exception:
        _READY = False
    return _READY


def note_run(agent, action, ok=True, ms=0.0, cached=False, rid=None):
    """Record one agent run (best-effort; never raises)."""
    if not agent or agent in _NO_RUNS or not _ensure():
        return
    try:
        with _LOCK:
            con = _con()
            try:
                cur = con.execute("INSERT INTO runs(agent,action,ok,ms,at,cached,rid) VALUES(?,?,?,?,?,?,?)",
                                  (agent, action, 1 if ok else 0, float(ms or 0), time.time(),
                                   1 if cached else 0, str(rid)[:40] if rid else None))
                if cur.lastrowid and cur.lastrowid % 500 == 0:     # occasional trim
                    con.execute("DELETE FROM runs WHERE id <= ?", (cur.lastrowid - _RUNS_MAX,))
                con.commit()
            finally:
                con.close()
    except Exception:
        pass


def _q(sql, params=()):
    con = _con()
    try:
        return [dict(r) for r in con.execute(sql, params).fetchall()]
    finally:
        con.close()


def summary(agent: str) -> dict:
    agent = (agent or "").strip()
    out = {"ok": True, "agent": agent, "runs": {}, "ops": [], "tags": [], "other": [],
           "kpi": {}, "navi_db": True, "log": _ensure()}
    if not agent:
        return {"ok": False, "error": "agent required"}
    if not shows_panel(agent):
        return {"ok": True, "agent": agent, "show": False}
    out["show"] = True

    # ---- runs (durable) ----
    if out["log"]:
        try:
            # a ▶ Run all (or one click that fires several reads) shares one rid = one run
            r = _q("SELECT COUNT(DISTINCT COALESCE(rid, 'id'||id)) n, MAX(at) last, "
                   "COUNT(DISTINCT CASE WHEN cached=0 THEN COALESCE(rid, 'id'||id) END) fresh "
                   "FROM runs WHERE agent=?", (agent,))[0]
            last = _q("SELECT action, ok, ms, at, cached, rid FROM runs WHERE agent=? ORDER BY at DESC LIMIT 1",
                      (agent,))
            if last and last[0].get("rid"):
                steps = _q("SELECT action, MIN(ok) ok FROM runs WHERE agent=? AND rid=? GROUP BY action ORDER BY MIN(at)",
                           (agent, last[0]["rid"]))
                last[0]["steps"] = [x["action"] for x in steps]
                last[0]["ok"] = min([x["ok"] for x in steps] or [last[0]["ok"]])
            out["runs"] = {"count": r["n"] or 0, "fresh": r["fresh"] or 0, "last_at": r["last"],
                           "last": last[0] if last else None}
        except Exception:
            pass

    # ---- the Hounds log: writes this hound made ----
    log = []
    if out["log"]:
        try:
            log = _q("SELECT CASE WHEN selector LIKE 'acr %' THEN 'acr' ELSE COALESCE(NULLIF(op,''),'tag') END op, "
                     "category, value, COUNT(*) n, SUM(CASE WHEN ok=1 THEN 1 ELSE 0 END) okn, "
                     "SUM(CASE WHEN ok=0 THEN 1 ELSE 0 END) errn, "
                     "SUM(CASE WHEN status IN ('queued','running') THEN 1 ELSE 0 END) busy, "
                     "MAX(COALESCE(finished, created)) last FROM jobs WHERE agent=? "
                     "GROUP BY 1, category, value", (agent,))
        except Exception:
            log = []
    ops = {}
    for r in log:
        o = ops.setdefault(r["op"] or "tag", {"op": r["op"] or "tag", "jobs": 0, "ok": 0, "errors": 0,
                                            "busy": 0, "last": None, "values": 0})
        o["jobs"] += r["n"] or 0; o["ok"] += r["okn"] or 0; o["errors"] += r["errn"] or 0
        o["busy"] += r["busy"] or 0; o["values"] += 1
        o["last"] = max(o["last"] or 0, r["last"] or 0) or None
    out["ops"] = sorted(ops.values(), key=lambda o: -(o["jobs"]))

    tag_rows = [r for r in log if (r["op"] or "tag") == "tag" and r["category"]]
    # well-known categories match both the plain and the test-run name (core.tagname)
    cats = sorted({r["category"] for r in tag_rows} | set(tagname.names(*DEFAULT_CATEGORIES.get(agent, []))))

    # ---- navi.db: what's on assets now, for those categories ----
    counts = {}
    try:   # a missing / empty navi.db must read as "can't check", not "0 assets"
        out["navi_db"] = bool(db.query("SELECT name FROM sqlite_master WHERE type='table' AND name='tags';"))
    except Exception:
        out["navi_db"] = False
    if cats and out["navi_db"]:
        try:
            ph = ",".join("?" * len(cats))
            for r in db.query(f"SELECT tag_key, tag_value, COUNT(DISTINCT asset_uuid) n FROM tags "
                              f"WHERE tag_key IN ({ph}) GROUP BY tag_key, tag_value;", tuple(cats)):
                counts[(r.get("tag_key"), r.get("tag_value"))] = r.get("n") or 0
        except Exception:
            out["navi_db"] = False

    # removals by ANY hound (usually Tag Removal) — a removed value isn't "awaiting sync"
    removed = {}
    if tag_rows and out["log"]:
        try:
            for r in _q("SELECT category, value, MAX(COALESCE(finished, created)) t FROM jobs "
                        "WHERE op='remove' AND ok=1 GROUP BY category, value"):
                removed[(r["category"], r["value"])] = r["t"] or 0
        except Exception:
            pass
    # when navi.db was last rebuilt — a value applied BEFORE that and still on 0 assets
    # matched nothing (it isn't waiting on a sync)
    try:
        synced = os.path.getmtime(db.db_path())
    except Exception:
        synced = None
    out["navi_db_synced"] = synced

    mine = set()
    for r in tag_rows:
        k = (r["category"], r["value"]); mine.add(k)
        n = counts.get(k, 0)
        rm = removed.get(k)
        status = ("running" if r["busy"] else
                  "failed" if (r["okn"] or 0) == 0 and (r["errn"] or 0) else
                  "applied" if not out["navi_db"] else          # can't check navi.db — don't guess
                  "on assets" if n else
                  "removed" if rm and rm >= (r["last"] or 0) else
                  "no assets" if synced and r["last"] and synced > r["last"] + 60 else
                  "awaiting sync")
        out["tags"].append({"category": r["category"], "value": r["value"], "assets": n,
                            "applied": r["okn"] or 0, "errors": r["errn"] or 0,
                            "last": r["last"], "status": status})
    out["tags"].sort(key=lambda t: (-(t["assets"] or 0), t["category"], str(t["value"])))
    out["other"] = sorted([{"category": k[0], "value": k[1], "assets": n}
                           for k, n in counts.items() if k not in mine],
                          key=lambda t: -(t["assets"] or 0))[:500]

    # ---- distinct tagged assets (mine), one query ----
    tagged_assets = 0
    if mine and out["navi_db"]:
        try:
            ph = " OR ".join("(tag_key=? AND tag_value=?)" for _ in mine)
            args = tuple(x for k in mine for x in k)
            if len(mine) <= 400:
                tagged_assets = (db.query(f"SELECT COUNT(DISTINCT asset_uuid) n FROM tags WHERE {ph};",
                                          args) or [{}])[0].get("n") or 0
            else:
                tagged_assets = sum(t["assets"] for t in out["tags"])     # upper bound
        except Exception:
            pass

    t = out["tags"]
    out["kpi"] = {
        "values_applied": len(t),
        "values_on_assets": sum(1 for x in t if x["assets"]),
        "assets_tagged": tagged_assets,
        "awaiting_sync": sum(1 for x in t if x["status"] == "awaiting sync"),
        "failed": sum(1 for x in t if x["status"] == "failed"),
        "removed": sum(1 for x in t if x["status"] == "removed"),
        "no_assets": sum(1 for x in t if x["status"] == "no assets"),
        "running": sum(1 for x in t if x["status"] == "running"),
        "last_write": max([o["last"] or 0 for o in out["ops"]] or [0]) or None,
        "other_values": len(out["other"]),
        "other_assets": sum(x["assets"] for x in out["other"]),
        "categories": cats,
    }
    return out
