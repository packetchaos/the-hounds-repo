"""Hub orchestration — powers the "Release the Hounds" page.

Two cross-agent actions, both built on the Covenant contract engine
(core.contract), so there is ONE place that knows how to run every agent and
apply its tags:

  run_all — run discovery for every tagging agent (plan only; NO writes).
  trust   — "I trust you": run every tagging agent AND apply the proposed tags
            live (gated). ACR is never run; agents that need human input (an owner
            name or mapping — they default off in the contract) are skipped. The
            skipped list comes from roster() so the page's confirm text is exact.
"""
from core import contract, navi_cli
from core.gates import confirmed

# Agents the pack autopilot will NOT run automatically (need human input).
# ACR is not in contract.TAGGERS at all, so it is never auto-run either.
SKIP = {"exproute"}


def _pack_contract():
    """A one-shot contract: all taggers enabled EXCEPT the human-input ones,
    no ACR rules, no inter-agent wait."""
    c = contract.default_contract()
    for aid in SKIP:
        if aid in c.get("agents", {}):
            c["agents"][aid]["enabled"] = False
    c["acr"] = []
    c["wait_minutes"] = 0
    return c


def roster(p):
    """Which agents the pack orchestration will run, for the UI to badge cards."""
    # agents that need human input (an owner name, an owner mapping) default OFF in the
    # contract — they're not auto-run either
    dflt = contract.default_contract().get("agents", {})
    tg = [a for a in contract.TAGGERS if a not in SKIP and (dflt.get(a) or {}).get("enabled", True)]
    return {"ok": True, "taggers": tg, "skipped": sorted(set(contract.TAGGERS) - set(tg)),
            "writes_enabled": navi_cli.writes_enabled()}, 200


def run_all(p):
    """Run all ready — discovery for every tagging agent (plan only, no writes)."""
    pl = contract.plan(_pack_contract())
    total = sum(b.get("selected", 0) for b in pl.get("agents", []))
    return {"ok": True, "plan": pl, "total_selected": total,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def trust(p):
    """I trust you — run every tagging agent and APPLY the proposed tags (gated)."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — this applies tags live"}, 400
    c = _pack_contract()
    c["armed"] = True                        # execute() only writes when armed
    out = contract.execute(c, enforce_pause=False)    # a click, not the paced loop
    skipped = sorted(set(contract.TAGGERS) - {a for a, v in (c.get("agents") or {}).items()
                                              if isinstance(v, dict) and v.get("enabled")})
    return {"ok": True, "queued_tags": out.get("queued_tags", 0),
            "plan": out.get("plan", {}), "skipped": skipped,
            "writes_enabled": navi_cli.writes_enabled()}, 200


# ---------------------------------------------------------------- page cache (server side)
# Every hound page's last run (the console.js HC block) is stored here instead of only in
# the browser — shared by every browser, and fillable by Release the Hounds.
def pc_get(p):
    from core import pagecache
    return {"ok": True, "entry": pagecache.get(p.get("key"))}, 200


def pc_put(p):
    from core import pagecache
    ok, err = pagecache.put(p.get("key"), p.get("entry"))
    return ({"ok": True}, 200) if ok else ({"ok": False, "error": err}, 400)


def pc_patch(p):
    from core import pagecache
    ok, err = pagecache.patch(p.get("key"), p.get("fields") or {})
    return {"ok": ok, "error": err}, 200


def pc_del(p):
    from core import pagecache
    if p.get("all"):
        return {"ok": True, "cleared": pagecache.clear_all()}, 200
    return {"ok": True, "deleted": pagecache.delete(p.get("key"))}, 200


def pc_list(p):
    from core import pagecache
    return {"ok": True, "pages": pagecache.listing()}, 200


# ---------------------------------------------------------------- Release the Hounds
# Run every hound (reads only) in the left-sidebar order, in the background, so each page
# is populated when it's opened. plan → estimate; start → background; status; cancel.
def release_plan(p):
    from core import release
    ap = p.get("approve_downloads")
    return release.plan(None if ap is None else bool(ap)), 200


def release_start(p):
    from core import release
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to release the hounds"}, 400
    ap = p.get("approve_downloads")
    ag = p.get("agents")
    if ag is not None and not (isinstance(ag, list) and len(ag) <= 64 and all(isinstance(a, str) and len(a) < 40 for a in ag)):
        return {"ok": False, "error": "agents must be a list of hound keys"}, 400
    r = release.start(None if ap is None else bool(ap), agents=ag)
    return r, (200 if r.get("ok") else 400)


def release_status(p):
    from core import release
    return {"ok": True, "state": release.state()}, 200


def release_cancel(p):
    from core import release
    return {"ok": True, "cancelled": release.cancel(), "state": release.state()}, 200


# ---------------------------------------------------------------- ⚙ settings status light (build 468)
def config_status(p):
    """The header gear's light. red = a KEY configuration is missing (navi.db unreadable, no
    assets or no findings — no hound can run); amber = OPTIONAL data / setup is missing (some
    hounds run with less: certs, software, routes / paths, WAS, compliance, SLA, Fixed, EPSS,
    ⚡ Optimize, an AI model); purple = all set. Cheap: EXISTS probes + the Optimize catalog."""
    from core import release, db
    items = []                       # {level, label, fix, href}
    try:
        ok_db = bool(db.scalar("SELECT 1", budget=0) == 1)
    except Exception as e:
        ok_db = False
        items.append({"level": "red", "label": "navi.db can't be read", "fix": str(e)[:160],
                      "href": "/web/settings.html"})
    if ok_db:
        seen = set()
        for c in release.PREFLIGHT:
            if c["key"] in seen or c.get("only_if") or c["key"] == "compliance_ap":
                continue
            seen.add(c["key"])
            if c["key"] == "indexes":
                try:
                    from core import hx_optimize
                    st = hx_optimize.status()
                    sm = st.get("summary") or {}
                    good = bool(st.get("optimized")) and (not sm.get("applies") or bool(sm.get("fresh")))
                except Exception:
                    good = True
            else:
                got = [release._has_rows(t) for t in c["tables"]]
                good = any(got) if c.get("any") else all(got)
            if not good:
                key = c["key"] in ("vulns", "assets")
                items.append({"level": "red" if key else "amber", "label": c["label"], "fix": c["fix"],
                              "href": c["settings"], "why": c["why"]})
    try:
        from core import llm
        if not llm.available():
            items.append({"level": "amber", "label": "AI model", "fix": "set a model and key in Settings",
                          "href": "/web/settings.html", "why": "the plain-English boxes and AI summaries are off"})
    except Exception:
        pass
    level = "red" if any(i["level"] == "red" for i in items) else ("amber" if items else "ok")
    title = {"red": "Key configurations required", "amber": "Optional configurations missing", "ok": "All set"}[level]
    return {"ok": True, "level": level, "title": title, "items": items}, 200


ACTIONS = {"roster": roster, "run_all": run_all, "trust": trust, "config_status": config_status,
           "pc_get": pc_get, "pc_put": pc_put, "pc_patch": pc_patch, "pc_del": pc_del, "pc_list": pc_list,
           "release_plan": release_plan, "release_start": release_start,
           "release_status": release_status, "release_cancel": release_cancel}
