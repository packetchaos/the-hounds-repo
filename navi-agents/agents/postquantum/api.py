"""Heimdall / Post-Quantum Cipher Analysis — self-contained HTTP actions.

  run          — one pass: the quantum-vulnerable surface, certificate crypto, transport +
                 agility, the migration roadmap and the headline metrics
  tag          — tag those plugins' assets Post-Quantum:Cipher Analysis (gated)
  roadmap      — correlate cert crypto + transport + agility, weighted by ACR +
                 KEV, into a ranked crown-jewel migration roadmap (read-only)
  roadmap_tag  — tag the roadmap hit-list PQC Priority:<value> (gated)
"""
from core import activity, navi_cli, db
from .agent import (PostQuantumAgent, tag_all, roadmap, ROADMAP_CAT,
                    cert_analysis, transport_analysis, overview)
from core.gates import confirmed

AGENT = PostQuantumAgent()


def cert(p):
    return {"ok": True, "result": cert_analysis()}, 200


def transport(p):
    return {"ok": True, "result": transport_analysis()}, 200


def tag_uuids(p):
    """Generic gated tag of an explicit uuid set — powers the per-algorithm, harvest-now,
    transport-signal and agility-tier tag buttons. {category, value, uuids}."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    category = (p.get("category") or "PQC Risk").strip() or "PQC Risk"
    if not activity.allowed_category("postquantum", category):
        return {"ok": False, "error": f"category '{category}' is not one this agent writes"}, 400
    value = (p.get("value") or "Vulnerable").strip() or "Vulnerable"
    uu = [u for u in (p.get("uuids") or []) if u]
    if not uu:
        return {"ok": False, "error": "no asset uuids supplied"}, 400
    inlist = ",".join("'" + str(u).replace("'", "''") + "'" for u in uu)
    q = "SELECT uuid AS asset_uuid FROM assets WHERE uuid IN (" + inlist + ")"
    r = navi_cli.tag(category, value, query=q, remove=False, agent="postquantum")
    return {"ok": bool(r.get("ok", True)), "category": category, "value": value,
            "count": len(uu), "result": r, "writes_enabled": navi_cli.writes_enabled()}, 200


def run(p):
    """One ▶ Run: the surface (kept at the top level — the Contract and the hub read
    `plugins` / `assets`) plus certificates, transport, agility, roadmap and metrics."""
    res = AGENT.run()
    try:
        ov = overview()
        res = {**res, **{k: v for k, v in ov.items() if k not in ("surface", "ok")}}
    except Exception as e:
        res = {**res, "overview_error": f"analysis failed: {e}"}
    return {"ok": True, "agent": AGENT.meta(), "result": res}, 200


def tag(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    res = tag_all()
    return {"ok": True, "queued": len(res), "results": res,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def roadmap_run(p):
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
    inlist = ",".join("'" + str(u).replace("'", "''") + "'" for u in uu)
    q = "SELECT uuid AS asset_uuid FROM assets WHERE uuid IN (" + inlist + ")"
    r = navi_cli.tag(ROADMAP_CAT, value, query=q, remove=False, agent="postquantum")
    return {"ok": True, "category": ROADMAP_CAT, "value": value, "count": len(uu),
            "result": r, "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"run": run, "tag": tag, "tag_uuids": tag_uuids, "cert": cert, "transport": transport,
           "roadmap": roadmap_run, "roadmap_tag": roadmap_tag}
