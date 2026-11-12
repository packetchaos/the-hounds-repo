"""Identity Inventory — self-contained HTTP actions.

`run`       — discover NHI/human/service identities (read-only) + asset_uuids + URLs.
`tag`       — gated; tag the hosting assets via navi tag-by-query. Accepts either a
              single {category,value,asset_uuids} or a list of such under `items`.
`interpret` — natural-language tagging: turn an instruction + the discovered
              identities into per-identity {category,value} assignments (LLM).
"""
import re

from core import identity, navi_cli, payload
from core.gates import confirmed

try:
    from core import llm
except Exception:
    llm = None

AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import IdentityAgent
        AGENT = IdentityAgent()
    return AGENT


CROWN_ACR = 7
RISK = ("privileged", "non-expiring pw", "ssh password auth", "weak pw policy", "guest enabled",
        "default/blank cred", "AD attack path", "default secret", "write (private)")


def _enrich(res):
    """Page metrics: crown-jewel exposure (max ACR of the hosts behind each identity),
    credential coverage, and per-signal counts. Read-only; best-effort."""
    from core import db
    accts = res.get("accounts") or []
    uu = sorted({u for a in accts for u in (a.get("asset_uuids") or [])})
    acr = {}
    if uu:
        try:
            for part in navi_cli.uuid_batches(uu, size=900):    # bounded SQL per statement
                for r in db.query("SELECT uuid, acr FROM assets WHERE uuid IN (" + ",".join("?" * len(part)) + ")",
                                  tuple(part)):
                    try:
                        acr[r["uuid"]] = float(r.get("acr") or 0)
                    except (TypeError, ValueError):
                        pass
        except Exception:
            pass
    try:
        total = db.scalar("SELECT COUNT(*) FROM assets") or 0
    except Exception:
        total = 0
    for a in accts:
        vals = [acr.get(u, 0) for u in a.get("asset_uuids") or []]
        a["max_acr"] = max(vals) if vals else None
        a["crown_hosts"] = sum(1 for v in vals if v >= CROWN_ACR)
        a["reused"] = max([int(re.search(r"×(\d+)", f).group(1)) for f in a.get("flags", [])
                           if f.startswith("account reuse ×")] or [0])
        a["risky"] = [f for f in a.get("flags", []) if f != "scan credential"]
    has = lambda a, f: f in (a.get("flags") or [])
    people = [a for a in accts if a.get("klass") != "machine"]
    c = res.get("counts") or {}
    cred, blind = res.get("credentialed") or 0, res.get("blind") or 0
    res["metrics"] = {
        "estate": total,
        "identity_hosts": res.get("identity_hosts") or 0,
        "credentialed": cred, "blind": blind,
        "coverage_pct": round(100.0 * cred / (cred + blind), 1) if (cred + blind) else None,
        "privileged": sum(1 for a in accts if has(a, "privileged")),
        "privileged_hosts": len({u for a in accts if has(a, "privileged") for u in a["asset_uuids"]}),
        "nonexpiring": sum(1 for a in accts if has(a, "non-expiring pw")),
        "reused": c.get("reused", 0), "reused_hosts": c.get("reused_hosts", 0),
        "max_reuse": max([a["reused"] for a in accts] or [0]),
        "on_kev": sum(1 for a in people if has(a, "on KEV host")),
        "on_crit": sum(1 for a in people if has(a, "on critical host")),
        "crown_ids": sum(1 for a in people if a["crown_hosts"]),
        "crown_priv": sum(1 for a in people if a["crown_hosts"] and has(a, "privileged")),
        "priv_exploitable": sum(1 for a in people if has(a, "privileged")
                                and (has(a, "on KEV host") or has(a, "on critical host"))),
        "scan_creds": len(res.get("scan_creds") or []),
        "signals": {k: len(v) for k, v in (res.get("host_sets") or {}).items()},
    }
    return res


def scan_full():
    """The engine's full result (every identity with its asset uuids + the host sets) — what the
    AI Contract adapter plans from. The page's `run` ships the paged contract payload instead."""
    res = identity.scan()
    try:
        res = _enrich(res)
    except Exception as e:
        res["metrics_error"] = f"metrics failed: {e}"
    return res


# ── payload contract (build 464) ──────────────────────────────────────────────────────────────
# A big estate has 200k+ identities, each carrying the uuids of every host it was seen on, plus
# host sets of 100k+ uuids for the tag buttons: 22 MB at 150k assets. The run now stores every
# identity server-side (core.payload's result store) and ships the decision data + page 1; the
# table, its filters and search page on the server (`drill`), and every tag button sends a KEY
# ({set:{run, kind, …}}) that the server turns back into the exact hosts (_resolve).
def _has(a, f):
    return f in (a.get("flags") or [])


def _reused(a):
    return any(str(f).startswith("account reuse") for f in a.get("flags") or [])


def _grp(k):
    return "human" if k == "human" else ("machine" if k == "machine" else "service")


# the page's metric-card filters (FILTERS in page.html), evaluated once per identity
_FILTERS = {
    "privileged": lambda a: _has(a, "privileged"),
    "nonexp": lambda a: _has(a, "non-expiring pw"),
    "reused": _reused,
    "kev": lambda a: a.get("klass") != "machine" and _has(a, "on KEV host"),
    "crit": lambda a: a.get("klass") != "machine" and _has(a, "on critical host"),
    "crown": lambda a: a.get("klass") != "machine" and (a.get("crown_hosts") or 0) > 0,
    "privexp": lambda a: a.get("klass") != "machine" and _has(a, "privileged")
    and (_has(a, "on KEV host") or _has(a, "on critical host")),
    "ssh": lambda a: _has(a, "ssh password auth"),
    "dflt": lambda a: _has(a, "default/blank cred") or _has(a, "default secret"),
    "ad": lambda a: _has(a, "AD attack path"),
}
_GROUPS = ("human", "service", "machine", "reused", "flagged")
SIGNAL_KEYS = ("ssh password auth", "weak pw policy", "default/blank cred", "AD attack path", "on KEV host")
HOSTS_SHOWN = 12


def _flag_ok(f):
    if f in ("flagged", "reused"):
        return True
    k, _, v = f.partition(":")
    return (k == "g" and v in _GROUPS) or (k == "f" and v in _FILTERS) or (k == "k" and 0 < len(v) < 40)


SECTIONS = {"ids": {"sorts": {}, "flags": _flag_ok}, "reuse": {"sorts": {}, "flags": set()}}


def _slim(a, rk):
    hosts = a.get("hosts") or []
    return {"rk": rk, "user": a.get("user"), "klass": a.get("klass"), "authority": a.get("authority"),
            "flags": a.get("flags") or [], "risky": a.get("risky") or [], "hosts": hosts[:HOSTS_SHOWN],
            "hosts_n": len(hosts), "assets_n": len(a.get("asset_uuids") or []), "max_acr": a.get("max_acr"),
            "crown_hosts": a.get("crown_hosts") or 0, "reused": a.get("reused") or 0,
            "reuse_n": len(a.get("reuse_uuids") or []), "plugins": a.get("plugins") or [], "url": a.get("url"),
            "scan_credential": a.get("scan_credential")}


def _publish(res):
    accts = res.get("accounts") or []
    W = payload.STORE.begin("identity")
    W.section("ids")
    W.section("reuse")
    flag_top, auth_ids = {}, {k: 0 for k in SIGNAL_KEYS}
    try:
        for i, a in enumerate(accts):
            rk = "i%d" % i
            fl = ["g:" + _grp(a.get("klass")), "k:" + str(a.get("klass") or "")]
            if a.get("risky"):
                fl.append("flagged")
            if _reused(a):
                fl.append("reused")
            fl += ["f:" + k for k, fn in _FILTERS.items() if fn(a)]
            row = _slim(a, rk)
            W.add("ids", row, rk=rk, flags=fl,
                  text=" ".join([str(a.get("user") or ""), str(a.get("klass") or ""), " ".join(a.get("flags") or []),
                                 " ".join(str(h) for h in (a.get("hosts") or [])[:200])]))
            W.members("id:" + rk, a.get("asset_uuids") or [])
            if a.get("reuse_uuids"):
                W.members("ru:" + rk, a.get("reuse_uuids"))
            for f in a.get("risky") or []:
                key = "account reuse ≥ 5 hosts" if str(f).startswith("account reuse") else f
                flag_top[key] = flag_top.get(key, 0) + 1
            if a.get("klass") != "machine":
                for k in SIGNAL_KEYS:
                    if _has(a, k):
                        auth_ids[k] += 1
        for i, a in sorted(((i, a) for i, a in enumerate(accts) if _reused(a)), key=lambda t: -(t[1].get("reused") or 0)):
            W.add("reuse", _slim(a, "i%d" % i), rk="i%d" % i)
        for k, uu in (res.get("host_sets") or {}).items():
            W.members("hs:" + k, uu or [])
    except BaseException:
        W.close(ok=False)
        raise
    W.close()
    view = {"flag_top": sorted(flag_top.items(), key=lambda t: -t[1])[:6], "auth_ids": auth_ids,
            "host_sets": {k: len(v or []) for k, v in (res.get("host_sets") or {}).items()},
            "classes": {k: sum(1 for a in accts if a.get("klass") == k) for k in ("nhi", "human", "service", "machine")}}
    return W.run, view


def run(p):
    try:
        res = scan_full()
    except Exception as e:
        return {"ok": False, "error": f"identity scan failed: {e}"}, 200
    runid, view = _publish(res)
    first, _c = payload.drill("identity", {"run": runid, "section": "ids", "limit": 50}, SECTIONS)
    small = {k: v for k, v in res.items() if k not in ("accounts", "host_sets")}
    small["view"] = view
    small["accounts_total"] = len(res.get("accounts") or [])
    return payload.response(summary=res.get("metrics") or {}, top=first.get("top") or [],
                            total_=first.get("total"), page=first.get("page"),
                            drill={"action": "drill", "run": runid, "section": "ids"},
                            agent=_agent().meta(), result=small,
                            llm_available=bool(llm and llm.available())), 200


def drill(p):
    return payload.drill("identity", p, SECTIONS)


def _idcat(k):
    return "NHI" if k == "nhi" else ("Machine ID" if k == "machine" else "Identity")


def _view_args(st):
    flt = st.get("filter") or []
    if isinstance(flt, str):
        flt = [flt]
    if not isinstance(flt, list) or len(flt) > 6 or not all(isinstance(f, str) and _flag_ok(f) for f in flt):
        raise ValueError("bad filter")
    q = st.get("q") if isinstance(st.get("q"), str) else ""
    return flt, q.strip()[:200]


def _resolve(p):
    """A tag KEY → [(category, value, uuids)] rebuilt from the stored run. Kinds:
      id {rk}            one identity's hosts            (category/value from the request)
      union {filter, q}  every shown identity's hosts, one tag
      each {filter, q, category?}  one tag per shown identity (value = account, category by class)
      reuse {rk?}        one account's reuse hosts, or every reused account's
      hs {key}           a host signal's hosts (auth weakness / uncredentialed)
      assign {list:[{user, category, value}]}   the model's proposals, by account name"""
    st = p.get("set")
    if not isinstance(st, dict):
        raise ValueError("set must be an object")
    run, kind = st.get("run"), st.get("kind")
    S = payload.STORE
    if not S.run_info(run, "identity"):
        raise LookupError("expired")
    cat, val = (p.get("category") or "Identity").strip(), (p.get("value") or "").strip()
    rk = st.get("rk") if isinstance(st.get("rk"), str) and re.fullmatch(r"i\d{1,9}", st.get("rk") or "") else None
    if kind == "id":
        if not rk:
            raise ValueError("rk required")
        r = S.row(run, "ids", rk) or {}
        return [(cat, val or r.get("user") or "", S.group(run, "id:" + rk))]
    if kind == "reuse":
        if rk:
            return [(cat, val, S.group(run, "ru:" + rk))]
        uu = sorted({u for _k, u in S.row_members(run, "reuse", "ru:")})
        return [(cat, val, uu)]
    if kind == "hs":
        key = st.get("key")
        if not isinstance(key, str) or not (key in SIGNAL_KEYS or key == "uncredentialed"):
            raise ValueError("unknown host signal")
        return [(cat, val, S.group(run, "hs:" + key))]
    if kind in ("union", "each"):
        flt, q = _view_args(st)
        if kind == "union":
            return [(cat, val, sorted({u for _k, u in S.row_members(run, "ids", "id:", flt, q)}))]
        by = {}
        for k, u in S.row_members(run, "ids", "id:", flt, q):
            by.setdefault(k, []).append(u)
        out = []
        for r in S.iter_rows(run, "ids", flt, q):
            uu = by.get(r.get("rk"))
            if uu:
                out.append((st.get("category") or _idcat(r.get("klass")), r.get("user") or "", uu))
        return out
    if kind == "assign":
        lst = st.get("list")
        if not isinstance(lst, list) or len(lst) > 5000:
            raise ValueError("list required")
        users = {}
        for r in S.iter_rows(run, "ids"):
            users.setdefault(r.get("user"), r)
        out = []
        for x in lst:
            if not isinstance(x, dict):
                continue
            r = users.get(x.get("user"))
            if not r:
                continue
            out.append((str(x.get("category") or _idcat(r.get("klass"))), str(x.get("value") or x.get("user")),
                        S.group(run, "id:" + r["rk"])))
        return out
    raise ValueError("unknown set kind")


def _tag_one(category, value, asset_uuids):
    """Identity → host mapping is computed in Python (accounts parsed from plugin output), so
    the set goes as ≤1,999-UUID batches (core.navi_cli.tag_uuids_batched, add-only)."""
    uu = [u for u in (asset_uuids or []) if u]
    if not uu:
        return {"ok": False, "message": "no asset_uuids for this identity"}
    jobs = navi_cli.tag_uuids_batched(category or "Identity", value, uu, agent="identity")
    sm = navi_cli.jobs_summary(jobs)
    return {**(sm["result"] or {}), "jobs": sm["jobs"], "job_ids": sm["job_ids"]}


def tag(p):
    p = p or {}
    if p.get("set") is not None:
        # build 464: a KEY — the server rebuilds the hosts. dry=true (read-only, no confirm) just
        # counts, so the page's confirm dialog can name exactly what will be written.
        try:
            plan = [(c, v, u) for c, v, u in _resolve(p) if u and v]
        except LookupError:
            return {"ok": False, "expired": True,
                    "error": "this run's identities are no longer on the server — press ▶ Run again"}, 400
        except ValueError as e:
            return {"ok": False, "error": str(e)}, 400
        n_assets = len({u for _c, _v, uu in plan for u in uu})
        if p.get("dry") is True:
            return {"ok": True, "dry": True, "tags": len(plan), "assets": n_assets,
                    "categories": sorted({c for c, _v, _u in plan}),
                    "sample": [c + " : " + v for c, v, _u in plan[:3]]}, 200
        if not confirmed(p):
            return {"ok": False, "error": "confirm=true required to write tags"}, 400
        if not plan:
            return {"ok": False, "error": "nothing to tag"}, 400
        results = []
        for c, v, uu in plan:
            r = _tag_one(c, v, uu)
            results.append({"value": v, "category": c, **r})
        ok = sum(1 for r in results if r.get("ok", r.get("job_id") is not None))
        return {"ok": ok > 0, "applied": ok, "total": len(results), "count": n_assets,
                "error": None if ok else "no tags queued", "results": results[:50],
                "writes_enabled": navi_cli.writes_enabled()}, 200
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    items = p.get("items")
    if items:
        results = []
        for it in items:
            r = _tag_one(it.get("category", "Identity"), it.get("value", ""), it.get("asset_uuids"))
            results.append({"value": it.get("value"), "category": it.get("category", "Identity"), **r})
        ok = sum(1 for r in results if r.get("ok", r.get("job_id") is not None))
        return {"ok": ok > 0, "applied": ok, "error": None if ok else "no tags queued",
                "total": len(results), "results": results,
                "writes_enabled": navi_cli.writes_enabled()}, 200
    value = (p.get("value") or "").strip()
    if not value:
        return {"ok": False, "error": "value required"}, 400
    r = _tag_one(p.get("category", "Identity"), value, p.get("asset_uuids"))
    return {"ok": r.get("ok", True) is not False, "result": r, "count": len(p.get("asset_uuids") or []),
            "error": r.get("message") if r.get("ok") is False else None,
            "writes_enabled": navi_cli.writes_enabled()}, 200


def interpret(p):
    prompt = (p.get("prompt") or "").strip()
    accounts = p.get("accounts") or []
    if not accounts and p.get("run"):
        # build 464: the identities come from the stored run, not a 20 MB upload from the page
        if not payload.STORE.run_info(p.get("run"), "identity"):
            return {"ok": False, "error": "this run's identities are no longer on the server — press ▶ Run again"}, 200
        accounts = [{"user": r.get("user"), "klass": r.get("klass")} for r in payload.STORE.iter_rows(p["run"], "ids")]
    if not prompt:
        return {"ok": False, "error": "prompt required"}, 200
    if llm is None or not llm.available():
        return {"ok": False, "needs_key": True,
                "error": "natural-language tagging needs the model (set ANTHROPIC_API_KEY); "
                         "use the per-row Tag buttons instead"}, 200
    out = llm.identity_plan(prompt, accounts)
    if not out.get("ok"):
        return {"ok": False, "error": out.get("message", "LLM failed")}, 200
    return {"ok": True, "assignments": out.get("assignments", [])}, 200


ACTIONS = {"run": run, "drill": drill, "tag": tag, "interpret": interpret}
