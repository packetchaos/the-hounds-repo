"""Asset Explorer — read-only navi.db search (paginated) + EVIDENCE lists (build 467).

search   — free-text over hostname / IP / OS / network.
evidence — {key}: the asset set behind an On the Scent "At a glance" number (core/evidence —
           computed by the hound that owns the number), stored as a result-store run so it
           pages, searches and exports on the server however many assets it holds.
drill    — page / search a stored evidence run.
export   — every row of an evidence run (or its search) as CSV — an explicit download.
"""
import csv
import io
import time

from core import evidence as EV, payload, search

SECTIONS = {"assets": {"sorts": {}, "flags": set()}}
CSV_COLS = ["hostname", "ip_address", "operating_system", "acr", "aes", "last_found", "uuid"]


def run(p):
    try:
        res = search.assets((p.get("q") or "").strip(), int(p.get("offset") or 0), p.get("limit"))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "result": res}, 200


def _acr(r):
    try:
        return float(r.get("acr") or 0)
    except (TypeError, ValueError):
        return 0.0


def evidence(p):
    key = (p or {}).get("key")
    if not isinstance(key, str) or key not in EV.EVIDENCE:
        return {"ok": False, "error": "unknown evidence %r" % (key,), "keys": sorted(EV.EVIDENCE)}, 400
    meta = dict(EV.EVIDENCE[key], key=key)
    t0 = time.time()
    uu = EV.uuids(key)
    rows = sorted(EV.asset_rows(uu), key=lambda r: (-_acr(r), str(r.get("hostname") or "~").lower(), r.get("uuid") or ""))
    W = payload.STORE.begin("ex_assets")
    W.section("assets")
    try:
        for r in rows:
            W.add("assets", r, uid=r.get("uuid"), rk=r.get("uuid"),
                  text=" ".join(str(r.get(k) or "") for k in ("hostname", "ip_address", "operating_system", "uuid")))
    except BaseException:
        W.close(ok=False)
        raise
    W.close()
    first, _c = payload.drill("ex_assets", {"run": W.run, "section": "assets", "limit": 50}, SECTIONS)
    meta.update(count=len(uu), seconds=round(time.time() - t0, 1), computed_at=time.strftime("%Y-%m-%d %H:%M"))
    return payload.response(summary=meta, top=first.get("top") or [], total_=first.get("total"),
                            page=first.get("page"), drill={"action": "drill", "run": W.run, "section": "assets"},
                            evidence=meta), 200


def drill(p):
    return payload.drill("ex_assets", p, SECTIONS)


def export(p):
    run = (p or {}).get("run")
    if not payload.STORE.run_info(run, "ex_assets"):
        return {"ok": False, "expired": True, "error": "this list is no longer on the server — open it again"}, 200
    q = (p or {}).get("q") if isinstance((p or {}).get("q"), str) else ""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLS)
    n = 0
    for r in payload.STORE.iter_rows(run, "assets", (), q.strip()[:200]):
        vals = [r.get(c) if r.get(c) is not None else "" for c in CSV_COLS]
        w.writerow([("'" + v) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v for v in vals])
        n += 1
    return {"ok": True, "rows": n, "csv": buf.getvalue()}, 200


ACTIONS = {"search": run, "evidence": evidence, "drill": drill, "export": export}
