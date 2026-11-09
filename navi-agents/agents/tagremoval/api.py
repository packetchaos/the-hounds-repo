"""Garmr / Tag Removal — self-contained HTTP actions.

`run`             — list the tags navi can remove: navi.db's tags table + asset counts.
`asset_delta`     — navi.db assets vs Tenable licensed (why some live tags are out of reach).
`remove`          — gated; queue a `-remove` for each chosen tag (shows in the Tagging
                    log as op=remove). Each removal strips the category:value from the
                    assets that currently carry it in navi.db.
`add_to_contract` — merge the chosen tags into the AI Contract's removal phase (the
                    contract removes them first, pauses, runs navi update, then re-tags).
"""
from core import navi_cli
from core.gates import confirmed

AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import TagRemovalAgent
        AGENT = TagRemovalAgent()
    return AGENT


def run(p):
    return {"ok": True, "agent": _agent().meta(), "result": _agent().run()}, 200


def remove(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to remove tags"}, 400
    tags = p.get("tags") or []
    if not tags:
        return {"ok": False, "error": "no tags selected"}, 400
    results, skipped = [], []
    in_navi = _navi_tag_counts()
    for t in tags:
        cat = (t.get("category") or "").strip()
        val = (t.get("value") or "").strip()
        if not cat or not val:
            continue
        # strictly navi.db: -remove only reaches assets navi.db says carry the tag, so a tag
        # with none there would "succeed" and change nothing in Tenable
        if in_navi is not None and not in_navi.get((cat.lower(), val.lower())):
            skipped.append({"category": cat, "value": val,
                            "reason": "not in navi.db (no navi.db asset carries it) — navi can't remove it from here"})
            continue
        # Strip the tag off every asset that carries it, keeping the tag itself (UUID
        # intact). No selector — just `navi enrich tag --c <cat> --v <val> -remove`.
        r = navi_cli.tag(cat, val, remove=True, op="remove", agent="tagremoval")
        results.append({"category": cat, "value": val, **r})
    return {"ok": True, "queued": len(results), "results": results, "skipped": skipped,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def _navi_tag_counts():
    """{(category.lower(), value.lower()): assets} from navi.db's tags table, or None if
    navi.db can't be read (then nothing is filtered — the removal verdict still reports)."""
    try:
        from core import db
        rows = db.query("SELECT tag_key AS k, tag_value AS v, COUNT(DISTINCT asset_uuid) AS n "
                        "FROM tags GROUP BY tag_key, tag_value")
    except Exception:
        return None
    return {((r.get("k") or "").strip().lower(), (r.get("v") or "").strip().lower()): r.get("n") or 0
            for r in rows}


def add_to_contract(p):
    tags = p.get("tags") or []
    if not tags:
        return {"ok": False, "error": "no tags selected"}, 400
    from core import contract
    out = contract.add_removals([{"category": t.get("category"), "value": t.get("value")}
                                 for t in tags])
    return {"ok": True, **out}, 200


def asset_delta(p):
    """navi.db assets vs Tenable licensed + stale assets — why some live tags are out of
    navi's reach (read-only; one `navi explore info licensed` call)."""
    from core import asset_delta as ad
    return ad.delta(days=p.get("days", ad.DEFAULT_DAYS), live=p.get("live", True) is not False), 200


ACTIONS = {"run": run, "remove": remove, "add_to_contract": add_to_contract, "asset_delta": asset_delta}
