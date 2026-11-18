"""Heimdall / Post-Quantum Cipher Analysis — self-contained HTTP actions.

  run          — one pass: the quantum-vulnerable surface, certificate crypto, transport +
                 agility, the migration roadmap and the headline metrics
  tag          — tag those plugins' assets Post-Quantum:Cipher Analysis (gated)
  roadmap      — correlate cert crypto + transport + agility, weighted by ACR +
                 KEV, into a ranked crown-jewel migration roadmap (read-only)
  roadmap_tag  — tag the roadmap hit-list PQC Priority:<value> (gated)

Build 489 — tag filter: every action the page calls honours `tag_scope` {key, value}
(core/tagscope). With no scope the code paths below are exactly the pre-489 ones. With a scope,
every query is limited to the tag's assets (each asset keeps its whole-estate facts), the
result says so ("scope"), the module-level AGENT (the hub's status card) is NOT touched, and
writes re-read their set from navi.db inside the tag — browser UUID lists are refused.
"""
from core import activity, navi_cli, db, tagscope
from .agent import (PostQuantumAgent, tag_all, roadmap, ROADMAP_CAT,
                    cert_analysis, transport_analysis, overview, discover, select_uuids, _w)
from core.gates import confirmed

AGENT = PostQuantumAgent()


def _scope(p):
    """(key, value) of the request's tag scope, or None for the whole estate."""
    k, v = tagscope.parse(p)
    return (k, v) if k else None


def _with_scope(body, sc):
    if sc:
        body["scope"] = tagscope.describe(*sc)
    return body


def cert(p):
    sc = _scope(p)
    if not sc:
        return {"ok": True, "result": cert_analysis()}, 200
    return _with_scope({"ok": True, "result": cert_analysis(scope=sc)}, sc), 200


def transport(p):
    sc = _scope(p)
    if not sc:
        return {"ok": True, "result": transport_analysis()}, 200
    return _with_scope({"ok": True, "result": transport_analysis(scope=sc)}, sc), 200


def tag_uuids(p):
    """Generic gated tag of an explicit uuid set — powers the per-algorithm, harvest-now,
    transport-signal and agility-tier tag buttons. {category, value, uuids}."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    category = (p.get("category") or "PQC Risk").strip() or "PQC Risk"
    if not activity.allowed_category("postquantum", category):
        return {"ok": False, "error": f"category '{category}' is not one this agent writes"}, 400
    value = (p.get("value") or "Vulnerable").strip() or "Vulnerable"
    sc = _scope(p)
    if sc:
        # a tag view: the set is recomputed here from the page's selection, inside the tag —
        # any `uuids` the browser sent are ignored
        uu, err = select_uuids(p.get("select"), sc)
        if err:
            return {"ok": False, "error": err}, 400
        if not uu:
            return {"ok": False, "error": "nothing to tag among the assets tagged " + tagscope.label(*sc),
                    "scope": tagscope.describe(*sc)}, 200
    else:
        uu = [u for u in (p.get("uuids") or []) if u]
    if not uu:
        return {"ok": False, "error": "no asset uuids supplied"}, 400
    sm = navi_cli.jobs_summary(navi_cli.tag_uuids_batched(category, value, uu, agent="postquantum"))
    body = {"ok": bool(sm["result"].get("ok", True)), "category": category, "value": value,
            "count": len(uu), "result": sm["result"], "jobs": sm["jobs"], "job_ids": sm["job_ids"],
            "writes_enabled": navi_cli.writes_enabled()}
    return _with_scope(body, sc), 200


def tag_signal(p):
    """Gated: tag one transport signal's hosts PQC Transport : <signal>. Only the signal KEY
    comes from the page; the set is the signal's own SQL (agent.PQT_SIGNALS), computed here and
    paged (≤1,999 per navi job) — the page never posts a UUID list."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    from .agent import PQT_SIGNALS, TRANSPORT_CAT
    key = (p.get("key") or "").strip()
    sig = next((s for s in PQT_SIGNALS if s["key"] == key), None)
    if sig is None:
        return {"ok": False, "error": "unknown transport signal"}, 400
    sc = _scope(p)
    if sc:   # a tag view: the signal's own SQL, limited to the tag's assets
        sql, args = _w(sig["sql"], sc)
        try:
            n = db.scalar("SELECT COUNT(*) FROM (" + sql + ")", args) or 0
        except Exception:
            n = 0
        if not n:
            return {"ok": False, "error": f"no assets tagged {tagscope.label(*sc)} show '{key}'",
                    "scope": tagscope.describe(*sc)}, 200
        sm = navi_cli.jobs_summary(navi_cli.tag_set(TRANSPORT_CAT, key, sql=sql, params=args, agent="postquantum"))
        return _with_scope({"ok": bool(sm["result"].get("ok", True)), "category": TRANSPORT_CAT, "value": key,
                            "count": n, "result": sm["result"], "jobs": sm["jobs"], "job_ids": sm["job_ids"],
                            "writes_enabled": navi_cli.writes_enabled()}, sc), 200
    try:
        n = db.scalar("SELECT COUNT(*) FROM (" + sig["sql"] + ")") or 0
    except Exception:
        n = 0
    if not n:
        return {"ok": False, "error": f"no assets show '{key}'"}, 200
    sm = navi_cli.jobs_summary(navi_cli.tag_set(TRANSPORT_CAT, key, sql=sig["sql"], agent="postquantum"))
    return {"ok": bool(sm["result"].get("ok", True)), "category": TRANSPORT_CAT, "value": key, "count": n,
            "result": sm["result"], "jobs": sm["jobs"], "job_ids": sm["job_ids"],
            "writes_enabled": navi_cli.writes_enabled()}, 200


def run(p):
    """One ▶ Run: the surface (kept at the top level — the Contract and the hub read
    `plugins` / `assets`) plus certificates, transport, agility, roadmap and metrics."""
    sc = _scope(p)
    if sc:
        return _run_scoped(sc)
    res = AGENT.run()
    try:
        ov = overview()
        res = {**res, **{k: v for k, v in ov.items() if k not in ("surface", "ok")}}
    except Exception as e:
        res = {**res, "overview_error": f"analysis failed: {e}"}
    return {"ok": True, "agent": AGENT.meta(), "result": res}, 200


def _run_scoped(sc):
    """▶ Run over one tag's assets. Same shape as the estate run, plus "scope". The module-level
    AGENT (the hub's status card, the estate's last result) is left alone."""
    res = discover(scope=sc)
    res["ok"] = True
    try:
        ov = overview(scope=sc)
        res = {**res, **{k: v for k, v in ov.items() if k not in ("surface", "ok")}}
    except Exception as e:
        res = {**res, "overview_error": f"analysis failed: {e}"}
    res["scope"] = tagscope.describe(*sc)
    return {"ok": True, "agent": AGENT.meta(), "result": res, "scope": res["scope"]}, 200


def tag(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    sc = _scope(p)
    if sc:
        res = tag_all(scope=sc)
        if not res:
            return {"ok": False, "error": "no quantum-vulnerable surface among the assets tagged " + tagscope.label(*sc),
                    "scope": tagscope.describe(*sc)}, 200
        return _with_scope({"ok": True, "queued": len(res), "results": res,
                            "count": int(res[0].get("assets") or 0),
                            "writes_enabled": navi_cli.writes_enabled()}, sc), 200
    res = tag_all()
    return {"ok": True, "queued": len(res), "results": res,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def roadmap_run(p):
    sc = _scope(p)
    if sc:
        return _with_scope({"ok": True, "agent": AGENT.meta(), "result": roadmap(scope=sc)}, sc), 200
    return {"ok": True, "agent": AGENT.meta(), "result": roadmap()}, 200


def roadmap_tag(p):
    """Tag an explicit list of asset UUIDs under PQC Priority:<value>.

    value defaults to 'Crown Jewel'. Used both for the crown-jewel bulk tag and
    per-row 'Migrate' tags from the roadmap table.
    """
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    uu = [u for u in (p.get("uuids") or []) if u]
    if not uu:
        return {"ok": False, "error": "nothing to tag — build the roadmap first"}, 400
    value = p.get("value") or "Crown Jewel"
    # roadmap scores are computed in Python → ≤1,999-UUID batches (add-only)
    sm = navi_cli.jobs_summary(navi_cli.tag_uuids_batched(ROADMAP_CAT, value, uu, agent="postquantum"))
    return {"ok": True, "category": ROADMAP_CAT, "value": value, "count": len(uu),
            "result": sm["result"], "jobs": sm["jobs"], "job_ids": sm["job_ids"],
            "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"run": run, "tag": tag, "tag_uuids": tag_uuids, "tag_signal": tag_signal,
           "cert": cert, "transport": transport,
           "roadmap": roadmap_run, "roadmap_tag": roadmap_tag}
