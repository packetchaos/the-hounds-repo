"""Certificate agent — self-contained HTTP actions. Deterministic; no free-form LLM
reasoning (ad-hoc certificate questions go through the MCP).

`run`         — expired certs by month (last 12 months + older), certs failing in the
                next 12 months, the expiry timeline, metrics, crown jewels, cert-issue
                plugins and the IoT/app cache.
`tags_apply`  — gated; tags the ASSETS behind each chosen expiry date
                Cert failure : <Mon>-<DD>-<YYYY>. Jobs go to the Tagging log.
`tags_issues` — gated; tags the assets a cert-issue plugin fired on
                Cert Issue : <plugin name> (navi --plugin <id>).
`drill`       — read; pages / searches / filters the run's certificate, crown-jewel and
                IoT/app lists (core.payload — the page never receives the full lists).
`dates`       — read; the expiry dates (tag values) in a filtered view and how many
                certificates / assets a set of dates covers — what "Select shown" and the
                selection counter use instead of the full certificate list.

Payload contract (build 455): `run` returns the decision data — every metric, the
timeline, the cert-issue matrix, the top crown jewels, IoT counts and the first page
of certificates — plus `drill` (the run id) for everything else; no UUID arrays.

Tag filter (build 489): every action honours the request's `tag_scope` {key, value} (its own
parameter; this hound's tag_key / tag_value never meant a scope). Scoped = the certificates ON
the assets carrying that tag, and the cert-issue plugin hits on those assets. A scoped run keeps
its result in its own cache (_TAG_RESULTS, newest 5 tags) and its drill rows under its own
store hound (agent.TAG_HOUND), so it never replaces or prunes the whole estate's. drill / dates
only read a run of the same scope. Writes from a tag view re-read the tag's assets from navi.db
on the server and tag only those. No scope = exactly the pre-489 behaviour.
"""
import collections
import threading

from core import navi_cli, db, payload, tagname, tagscope
from .agent import CertificateAgent, TAG_HOUND, TAG_STORE
from core.gates import confirmed

AGENT = CertificateAgent()
CATEGORIES = ["Cert failure", "Cert Issue"]

# build 489: the last scoped results, per tag — never AGENT.result (the estate / hub card)
_TAG_RESULTS = collections.OrderedDict()
_TAG_LOCK = threading.Lock()


def _tag_result(k, v, fresh=False):
    """The scoped run of (k, v): the cached one, or a fresh run over navi.db."""
    with _TAG_LOCK:
        res = None if fresh else _TAG_RESULTS.get((k, v))
    if res is None:
        res = AGENT._run(None, scope=(k, v))
        with _TAG_LOCK:
            _TAG_RESULTS[(k, v)] = res
            _TAG_RESULTS.move_to_end((k, v))
            while len(_TAG_RESULTS) > tagscope.MAX_TAGS:
                _TAG_RESULTS.popitem(last=False)
    return res


def _no_assets(k, v):
    return {"ok": False, "error": f"no asset in navi.db carries the tag {tagscope.label(k, v)} — "
                                  "pick another tag, or run a navi update assets"}, 200


def _run_ok(run, k, v):
    """The run's store info when it belongs to the request's scope (estate run for no scope,
    the same tag's run for a scope), else None — a tag view never pages another view's rows."""
    if not k:
        return payload.STORE.run_info(run, "certificate")
    info = TAG_STORE.run_info(run, TAG_HOUND)
    sc = ((info or {}).get("meta") or {}).get("scope") or {}
    return info if (sc.get("key") == k and sc.get("value") == v) else None


def _gate():
    return {"writes_enabled": navi_cli.writes_enabled(), "write_gate_reason": navi_cli.write_gate_reason()}


# drill sections: sorts are (ascending) store key columns; flags are the filter tokens
_MONTH = lambda f: f.startswith("m:") and (f == "m:older" or (len(f) == 9 and f[2:6].isdigit() and f[7:].isdigit()))
_CERT_FLAGS = {"expired", "failing", "last12", "older", "due30", "due90", "crown", "weak", "self"}
SECTIONS = {
    "certs": {"sorts": {"near": ("s1", "s2")}, "flags": lambda f: f in _CERT_FLAGS or _MONTH(f)},
    "crown": {"sorts": {}, "flags": set()},
    "iot": {"sorts": {"type": ("s1", "s2")}, "flags": {"t:IoT", "t:Application", "t:Unknown"}},
}


def run(p):
    k, v = tagscope.parse(p)
    if k and not tagscope.count(k, v):
        return _no_assets(k, v)
    res = _tag_result(k, v, fresh=True) if k else AGENT.run()
    runid = res.get("run")
    first, nxt = [], None
    if runid:
        b, _c = payload.drill(TAG_HOUND if k else "certificate",
                              {"run": runid, "section": "certs", "sort": "near", "limit": 50}, SECTIONS,
                              store=TAG_STORE if k else None)
        first, nxt = b.get("top") or [], (b.get("page") or {}).get("next")
    m = res.get("metrics") or {}
    small = {k: v for k, v in res.items() if k != "tag_actions"}       # tag_actions stay server-side
    # "applied" ground truth: which of our tags exist in navi.db right now
    extra = {"scope": tagscope.describe(k, v)} if k else {}
    return payload.response(
        summary=m, top=first,
        total_=payload.total((m.get("expired") or 0) + (m.get("failing") or 0)),
        page={"next": nxt, "start": 0, "limit": 50},
        drill={"action": "drill", "run": runid, "section": "certs", "sections": sorted(SECTIONS)},
        tag={"key": "dates", "count": len(res.get("tag_actions") or [])},
        agent=AGENT.meta(), result=small,
        # plain + Settings → Test run names; `base` lets the page match either
        tags_present=[dict(t, base=tagname.base(t.get("tag_key")))
                      for t in db.tags_present(tagname.names(*CATEGORIES))], **extra), 200


def drill(p):
    k, v = tagscope.parse(p)
    if not k:
        return payload.drill("certificate", p, SECTIONS)
    if not _run_ok((p or {}).get("run"), k, v):
        return {"ok": False, "expired": True,
                "error": f"this run isn't a run of {tagscope.label(k, v)} — press ▶ Run again"}, 200
    b, c = payload.drill(TAG_HOUND, p, SECTIONS, store=TAG_STORE)
    if isinstance(b, dict) and b.get("ok", True) is not False:
        b["scope"] = tagscope.describe(k, v)
    return b, c


def dates(p):
    """Read: the tag values (expiry dates) of a filtered certificate view ({run, filter, q}) —
    capped at 5,000 dates — or, for {run, values}, how many certificates and assets those
    dates cover. Dates are strings, never asset uuids."""
    run = (p or {}).get("run")
    k, v = tagscope.parse(p)
    if not _run_ok(run, k, v):
        return {"ok": False, "expired": True, "error": "this run is gone — press ▶ Run again"}, 200
    st = TAG_STORE if k else payload.STORE
    sc = {"scope": tagscope.describe(k, v)} if k else {}
    vals = p.get("values")
    if isinstance(vals, list):
        vals = [str(x) for x in vals if isinstance(x, str) and len(x) < 40][:5000]
        n, assets = st.count_any(run, "certs", ["v:" + x for x in vals])
        return {"ok": True, "values": len(vals), "certs": n, "assets": assets, **sc}, 200
    flt = p.get("filter") or []
    if isinstance(flt, str):
        flt = [flt]
    ok = SECTIONS["certs"]["flags"]
    if not isinstance(flt, list) or not all(isinstance(f, str) and ok(f) for f in flt):
        return {"ok": False, "error": "unknown filter"}, 400
    q = p.get("q") if isinstance(p.get("q"), str) else ""
    out = st.distinct_keys(run, "certs", flt, q[:200].strip(), cap=5000)
    return {"ok": True, "values": out["keys"], "truncated": out["truncated"], **sc}, 200


def tags_apply(p):
    """Tag the assets behind each selected expiry date. Returns a compact summary —
    per-job detail lives in the Tagging log."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to apply tags"}, 400
    want = [x for x in (p.get("values") or []) if x]
    if not want:
        return {"ok": False, "error": "no expiry dates selected"}, 400
    k, v = tagscope.parse(p)
    if k and not tagscope.count(k, v):
        return _no_assets(k, v)
    # recompute server-side if the cache is cold; a tag view uses that tag's own run
    res = _tag_result(k, v) if k else (AGENT.result or AGENT.run())
    # scope: the tag's assets are re-read from navi.db inside the set query (never from the page)
    frag, args = tagscope.sql(k, v, "uuid")
    actions = {a["value"]: a for a in res.get("tag_actions", [])}
    queued, missing = 0, []
    for x in want:
        a = actions.get(x)
        if not a:
            missing.append(x)
            continue
        # the date's set (raw not_valid_after strings → assets), computed here and paged
        if k:
            js = navi_cli.tag_set(a["category"], a["value"], sql=a["query"].rstrip(";") + frag, params=args,
                                  agent="certificate")
        else:
            js = navi_cli.tag_set(a["category"], a["value"], sql=a["query"].rstrip(";"), agent="certificate")
        if any(j.get("job_id") is not None or j.get("ok") for j in js):
            queued += 1
    sc = {"scope": tagscope.describe(k, v)} if k else {}
    return {"ok": queued > 0, "queued": queued, "requested": len(want), "missing": missing,
            "error": None if queued else ("none of those dates match a certificate in navi.db"
                                          + (f" on the assets tagged {tagscope.label(k, v)}" if k else "")),
            **sc, **_gate()}, 200


def tags_issues(p):
    """Tag the assets each selected cert-issue plugin fired on: Cert Issue : <plugin name>."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to apply tags"}, 400
    k, v = tagscope.parse(p)
    if k and not tagscope.count(k, v):
        return _no_assets(k, v)
    res = _tag_result(k, v) if k else (AGENT.result or AGENT.run())
    known = {str(m.get("plugin_id")): m.get("plugin_name") for m in res.get("cert_issue_matrix", [])}
    frag, args = tagscope.sql(k, v, "asset_uuid")
    queued, bad = 0, 0
    for it in p.get("issues", []):
        pid = str(it.get("plugin_id") or "").strip()
        nm = (known.get(pid) or "").strip()          # only certificate plugins, named by the server
        if not pid or not nm:
            bad += 1
            continue
        if k:
            # a tag view: the plugin's assets INSIDE the tag, computed here and paged (navi
            # --plugin would tag every asset in the estate the plugin fired on)
            js = navi_cli.tag_set("Cert Issue", nm, sql="SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id=?" + frag,
                                  params=(pid,) + tuple(args), agent="certificate")
            if any(j.get("job_id") is not None or j.get("ok") for j in js):
                queued += 1
            continue
        j = navi_cli.tag("Cert Issue", nm, plugin=pid, remove=False, agent="certificate")
        if j.get("job_id") is not None or j.get("ok"):
            queued += 1
    sc = {"scope": tagscope.describe(k, v)} if k else {}
    return {"ok": queued > 0, "queued": queued, "skipped": bad,
            "error": None if queued else "no valid plugins selected", **sc, **_gate()}, 200


ACTIONS = {"run": run, "drill": drill, "dates": dates, "tags_apply": tags_apply, "tags_issues": tags_issues}
