"""Scan Evaluations (Chronos) — self-contained HTTP actions.

`run` — scanner / policy / scan performance (plugin 19506) plus scan coverage: credential
        health per asset (the Target Credential Status / Issues plugin family), scan freshness,
        agent vs network, scanner plugin-feed currency, crown-jewel blind spots. Read-only.
`tag` — gated. The page sends only a KEY; the server re-runs the evaluation and tags the EXACT
        asset set behind it (by uuid), so a crafted request can't pick a category, value or
        selector. Category is always `Scan Health`.
          {key:'status:failed'}         -> Scan Health : Cred Failure
          {key:'status:insufficient'}   -> Scan Health : Insufficient Privilege
          {key:'status:intermittent'}   -> Scan Health : Intermittent Auth
          {key:'status:uncredentialed'} -> Scan Health : Uncredentialed
          {key:'patch:failed'}          -> Scan Health : Patch Assessment Failed
          {key:'fresh:31-90'}           -> Scan Health : Stale Scan 30d+
          {key:'fresh:90+'}             -> Scan Health : Stale Scan 90d+
          {key:'fresh:never'}           -> Scan Health : Never Scanned
          {key:'slow'}                  -> Scan Health : Slow Scan
          {key:'crown:blind'}           -> Scan Health : Crown Jewel Blind Spot
          {key:'scanner', name}         -> Scan Health : Scanner : <ip>
          {key:'policy',  name}         -> Scan Health : Policy : <name>
          {key:'scan',    name}         -> Scan Health : Scan : <name>
"""
from core import navi_cli, payload, scan_eval
from core.gates import confirmed

AGENT = None
CATEGORY = "Scan Health"
VALUES = {
    "status:failed": "Cred Failure", "status:insufficient": "Insufficient Privilege",
    "status:intermittent": "Intermittent Auth", "status:uncredentialed": "Uncredentialed",
    "patch:failed": "Patch Assessment Failed", "fresh:31-90": "Stale Scan 30d+",
    "fresh:90+": "Stale Scan 90d+", "fresh:never": "Never Scanned", "slow": "Slow Scan",
    "crown:blind": "Crown Jewel Blind Spot",
}
DIM_PREFIX = {"scanner": "Scanner : ", "policy": "Policy : ", "scan": "Scan : "}


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import ScanEvalAgent
        AGENT = ScanEvalAgent()
    return AGENT


# ── payload contract (build 464) ──────────────────────────────────────────────────────────────
# Every asset row is stored server-side (core.payload's result store); the run ships the
# metrics + dimension tables + page 1, and the asset table's states / metric-card filters /
# search page on the server (`drill`). Tags were already keys. (Before: the page got the first
# 20,000 asset rows + every credential-failure asset — 11 MB at 150k assets — and the table
# and its CSV stopped at row 20,000.)
_BLIND = ("failed", "insufficient", "intermittent", "uncredentialed")
FLAGS = {"st:" + s for s in ("failed", "insufficient", "intermittent", "uncredentialed", "ok", "unknown")} | {
    "f:failed", "f:insufficient", "f:intermittent", "f:uncredentialed", "f:blind", "f:patch", "f:stale30",
    "f:stale90", "f:never", "f:slow", "f:crownblind", "f:crown", "f:agent", "f:network"}
SECTIONS = {"assets": {"sorts": {}, "flags": FLAGS}}
CSV_COLS = ["host", "ip", "acr", "credentials", "patch_assessment", "last_scan", "age_days", "type", "scanner",
            "policy", "scan", "duration_sec"]
_ST_LABEL = {"failed": "Failed", "insufficient": "Insufficient privilege", "intermittent": "Intermittent",
             "uncredentialed": "Uncredentialed", "ok": "Credentialed OK", "unknown": "No scan data"}


def _flags(x, slow_sec):
    st, fr = x.get("status"), x.get("fresh")
    f = ["st:" + str(st)]
    if st in _BLIND:
        f += ["f:" + st, "f:blind"]
    if x.get("patch") == "failed":
        f.append("f:patch")
    if fr in ("31-90", "90+"):
        f.append("f:stale30")
    if fr == "90+":
        f.append("f:stale90")
    if fr == "never":
        f.append("f:never")
    if (x.get("dur") or 0) > slow_sec:
        f.append("f:slow")
    if x.get("crown"):
        f.append("f:crown")
        if st in _BLIND or fr in ("90+", "never"):
            f.append("f:crownblind")
    if x.get("type") == "Agent":
        f.append("f:agent")
    elif x.get("type") == "Network":
        f.append("f:network")
    return f


def _publish(res):
    W = payload.STORE.begin("scan_eval")
    W.section("assets")
    slow = res.get("slow_sec") or 3600
    try:
        for x in res.get("assets") or []:
            W.add("assets", x, uid=x.get("asset_uuid"), rk=x.get("asset_uuid"), flags=_flags(x, slow),
                  text=" ".join(str(x.get(k) or "") for k in ("host", "ip", "scanner", "policy", "scan", "type")))
    except BaseException:
        W.close(ok=False)
        raise
    W.close()
    return W.run


def run(p):
    try:
        res = scan_eval.evaluate(all_rows=True)
    except Exception as e:
        return {"ok": False, "error": f"scan evaluation failed: {e}"}, 200
    runid = _publish(res)
    first, _c = payload.drill("scan_eval", {"run": runid, "section": "assets", "limit": 50}, SECTIONS)
    small = {k: v for k, v in res.items() if k != "assets"}
    small["assets_total"] = len(res.get("assets") or [])
    small["assets_truncated"] = False
    cred = dict(small.get("credential") or {})
    cred.pop("assets", None)                  # the per-asset list stays server-side (counts kept)
    small["credential"] = cred
    return payload.response(summary=res.get("metrics") or {}, top=first.get("top") or [],
                            total_=first.get("total"), page=first.get("page"),
                            drill={"action": "drill", "run": runid, "section": "assets"},
                            agent=_agent().meta(), result=small), 200


def drill(p):
    return payload.drill("scan_eval", p, SECTIONS)


def export(p):
    """The asset table as CSV — EVERY row of the current view (state / metric filter / search),
    streamed from the stored run. An explicit download, not a page payload."""
    import csv
    import io
    run = (p or {}).get("run")
    if not payload.STORE.run_info(run, "scan_eval"):
        return {"ok": False, "expired": True, "error": "this run is no longer on the server — press ▶ Run again"}, 200
    flt = (p or {}).get("filter") or []
    if isinstance(flt, str):
        flt = [flt]
    if not isinstance(flt, list) or len(flt) > 6 or not all(isinstance(f, str) and f in FLAGS for f in flt):
        return {"ok": False, "error": "bad filter"}, 400
    q = (p or {}).get("q") if isinstance((p or {}).get("q"), str) else ""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLS)
    n = 0
    for x in payload.STORE.iter_rows(run, "assets", flt, q.strip()[:200]):
        vals = [x.get("host"), x.get("ip") or "", "" if x.get("acr") is None else x.get("acr"),
                _ST_LABEL.get(x.get("status"), x.get("status")), x.get("patch") or "", x.get("last_scan") or "",
                "" if x.get("age_days") is None else x.get("age_days"), x.get("type") or "", x.get("scanner") or "",
                x.get("policy") or "", x.get("scan") or "", "" if x.get("dur") is None else round(x.get("dur"))]
        # spreadsheet-formula injection guard (a host / policy name starting with = + - @)
        w.writerow([("'" + v) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v for v in vals])
        n += 1
    return {"ok": True, "rows": n, "csv": buf.getvalue()}, 200


def _open_only():
    vc = scan_eval._cols("vulns")
    return " AND lower(COALESCE(state,'open')) IN ('open','reopened')" if "state" in vc else ""


# Keys whose set IS a navi.db condition (no Python parsing) are selected by that SQL; every
# other key is computed from parsed plugin-19506 output / worst-state ranking in Python. Either
# way the set is computed HERE and paged by core.navi_cli.tag_set (≤1,999 UUIDs per navi job).
def _predicate(key):
    if key == "patch:failed":     # evaluate(): patch == 'failed' ⇔ an open 21745 finding
        return "SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='21745'" + _open_only()
    return ""


def tag_target(key, name="", ev=None):
    """(value, sorted asset uuids, error) for one Scan Health key. Shared by tag() and the AI
    Contract adapter so both write the same set."""
    if key in VALUES:
        value = VALUES[key]
        q = _predicate(key)
        if q:
            return value, navi_cli.collect_uuids(q), None
        ev = ev or scan_eval.evaluate(keep_uuids=True)
        uuids = ev["_sets"].get(key, set())
    elif key in DIM_PREFIX:
        ev = ev or scan_eval.evaluate(keep_uuids=True)
        uuids = ev["_dim_uuids"][key].get(name)
        if uuids is None:
            return None, [], f"no {key} named '{name}' in navi.db"
        value = DIM_PREFIX[key] + name
    else:
        return None, [], "unknown tag key"
    return value, sorted(u for u in uuids if u), None


def tag(p):
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    key = (p.get("key") or "").strip()
    value, uu, err = tag_target(key, (p.get("name") or "").strip())
    if err:
        return {"ok": False, "error": err}, 400
    if not uu:
        return {"ok": False, "error": f"no assets for {value}"}, 200
    jobs = navi_cli.tag_set(CATEGORY, value, uuids=uu, agent="scan_eval")
    ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    return {"ok": True, "category": CATEGORY, "value": value, "count": len(uu), "jobs": len(ids),
            "job_ids": ids, "series": (jobs[0].get("series") if jobs else None),
            "result": (jobs[0] if jobs else {}),
            "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"run": run, "drill": drill, "export": export, "tag": tag}
