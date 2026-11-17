"""Asset Explorer — read-only navi.db search (paginated) + EVIDENCE lists (build 467).

search   — free-text over hostname / IP / OS / network.
evidence — {key}: the asset set behind an On the Scent "At a glance" number (core/evidence —
           computed by the hound that owns the number), stored as a result-store run so it
           pages, searches and exports on the server however many assets it holds.
drill    — page / search a stored evidence run.
export   — every row of an evidence run (or its search) as CSV — an explicit download.
software — {product, version?}: the assets with one Mimir product (or one of its versions) —
           the same asset set Mimir counts and tags (core.software.assets_for), stored as a run.
           software_page sends it 500 rows at a time (the browser pages them by 20);
           software_export writes every asset in that list (or its search) as CSV (build 481).
"""
import csv
import io
import time

from core import evidence as EV, payload, search, software as SW

SECTIONS = {"assets": {"sorts": {}, "flags": set()}}
CSV_COLS = ["hostname", "ip_address", "operating_system", "acr", "aes", "last_found", "uuid"]
SOFTWARE_CHUNK = 500      # rows sent to the browser per request; it pages them 20 at a time


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


def _sw_key(p):
    """(product, version|None, error) from a software list request."""
    prod = (p or {}).get("product")
    ver = (p or {}).get("version")
    if not isinstance(prod, str) or not prod.strip() or len(prod) > 300:
        return None, None, "product is required"
    if ver is not None and (not isinstance(ver, str) or len(ver) > 200):
        return None, None, "bad version"
    return prod.strip(), ver, None


def _sw_sort(rows):
    return sorted(rows, key=lambda r: (-_acr(r), str(r.get("hostname") or "~").lower(), r.get("uuid") or ""))


def _sw_text(r):
    return " ".join(str(r.get(k) or "") for k in ("hostname", "ip_address", "operating_system", "uuid"))


def software(p):
    """The assets running one product (or one version of it). Every one of them is stored as a
    server-side run (highest ACR first); the page pulls SOFTWARE_CHUNK rows per request
    (software_page) and pages them 20 at a time in the browser."""
    prod, ver, err = _sw_key(p)
    if err:
        return {"ok": False, "error": err}, 400
    t0 = time.time()
    uu = SW.assets_for(product=prod, version=ver)
    rows = _sw_sort(EV.asset_rows(uu))
    W = payload.STORE.begin("ex_assets")
    W.section("assets")
    try:
        for r in rows:
            W.add("assets", r, uid=r.get("uuid"), rk=r.get("uuid"), text=_sw_text(r))
    except BaseException:
        W.close(ok=False)
        raise
    W.close()
    first, _c = _chunk({"run": W.run})
    label = prod + (" " + ver if ver else "")
    meta = {"key": "software", "label": "Assets running " + label, "hound": "Mimir", "agent": "software",
            "why": ("Every asset whose software inventory has " + label + " (software and cpes tables, "
                    "parsed the way Mimir parses them)."),
            "product": prod, "version": ver, "count": len(uu), "chunk": SOFTWARE_CHUNK,
            "seconds": round(time.time() - t0, 1), "computed_at": time.strftime("%Y-%m-%d %H:%M")}
    if not first.get("ok", True):
        return first, _c
    body = dict(first, summary=meta, evidence=meta, drill={"action": "software_page", "run": W.run, "section": "assets"})
    return payload.cap(body, max_rows=SOFTWARE_CHUNK), 200


def _chunk(p):
    """Up to SOFTWARE_CHUNK rows of a software list run (or its search), from `next` on — the
    store's keyset pages (≤ TOP_MAX each) joined into one response, ending on a next-token for
    the following chunk. 500 asset rows stay far under payload.MAX_BYTES."""
    q = {"run": p.get("run"), "section": "assets", "q": p.get("q") or "", "next": p.get("next")}
    rows, first = [], None
    while len(rows) < SOFTWARE_CHUNK:
        q["limit"] = min(payload.TOP_MAX, SOFTWARE_CHUNK - len(rows))
        body, code = payload.drill("ex_assets", q, SECTIONS)
        if not body.get("ok", True):
            return body, code
        first = first or body
        rows += body.get("top") or []
        q["next"] = (body.get("page") or {}).get("next")
        if not q["next"]:
            break
    start = int(((first or {}).get("page") or {}).get("start") or 0)
    body = dict(first or {}, top=rows, page={"next": q["next"], "start": start, "limit": SOFTWARE_CHUNK})
    return payload.cap(body, max_rows=SOFTWARE_CHUNK), 200


def software_page(p):
    """The next SOFTWARE_CHUNK rows (or a search) of a software list run."""
    p = p or {}
    if p.get("next") is not None and not isinstance(p.get("next"), str):
        return {"ok": False, "error": "bad page token"}, 400
    return _chunk(p)


def software_export(p):
    """Every asset in THIS list as CSV — the product (or version) the page was opened for,
    narrowed by the page's search box when one is typed — not just the rows on screen."""
    prod, ver, err = _sw_key(p)
    if err:
        return {"ok": False, "error": err}, 400
    q = (p or {}).get("q") if isinstance((p or {}).get("q"), str) else ""
    q = q.strip()[:200]
    run = (p or {}).get("run")
    if run and payload.STORE.run_info(run, "ex_assets"):
        src = payload.STORE.iter_rows(run, "assets", (), q)          # the stored list, same order
    else:                                                           # list expired: rebuild it from navi.db
        ql = q.lower()
        src = (r for r in _sw_sort(EV.asset_rows(SW.assets_for(product=prod, version=ver)))
               if not ql or ql in _sw_text(r).lower())
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["product", "version"] + CSV_COLS)
    n = 0
    for r in src:
        vals = [prod, ver or ""] + [r.get(c) if r.get(c) is not None else "" for c in CSV_COLS]
        w.writerow([("'" + v) if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v for v in vals])
        n += 1
    return {"ok": True, "rows": n, "q": q, "csv": buf.getvalue()}, 200


ACTIONS = {"search": run, "evidence": evidence, "drill": drill, "export": export,
           "software": software, "software_page": software_page, "software_export": software_export}
