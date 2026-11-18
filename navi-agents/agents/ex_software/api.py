"""Software Explorer — Harrier. A search hound for zero-day hunting over navi.db's software
inventory (`software`, and `cpes` when navi has it). Read-only: it writes no tags.

  status        — is there a software table, how big, is a model configured (for ✨ lookup).
  search        — where a product is installed: by search term (part of the product name) or one
                  exact product, optionally narrowed to a version ("17" = 17.x, "=3.0.2" exactly, "3.0*") and/or an
                  affected version RANGE. Headline KPIs + where-installed breakdowns (version,
                  OS, network, ACR) are computed over the WHOLE selection; asset rows are paged.
                  Each row carries its Nemesis (Exposure Score) score from the saved score map
                  (core.fused_score.score_map — written by a whole-estate, default-weighted
                  Exposure Score build; never computed here). {sort:"nemesis"} ranks the
                  selection most-exposed first.
  export        — that selection as CSV, one row per install (capped at EXPORT_MAX), with the
                  Nemesis score as the last column.
  lookup_plan   — ✨ zero-day lookup, step 1: from the user's words, the sources Harrier
                  proposes to read (NVD / CVE.org / OSV per CVE, an NVD search, pasted URLs).
                  Fetches nothing.
  lookup_fetch  — step 2: reads ONLY the URLs the user ticked (confirm:true), parses them into
                  affected products + version ranges, and counts each product in the inventory
                  in one pass. Not covered by Settings → Auto-approve downloads: the user approves
                  the sites every time.

Version logic, statuses and the range syntax live in core/swsearch; the fetcher and parsers in
core/advisory.
"""
import csv
import io
import os
import threading
import urllib.parse

from core import advisory, db, fused_score, gates, llm, swsearch

_PAGE = 20
_PAGE_MAX = 200
EXPORT_MAX = 50000
_CACHE, _CACHE_LOCK, _CACHE_N = {}, threading.Lock(), 8


def _dbsig():
    p = db.db_path()
    try:
        st = os.stat(p)
        return (p, st.st_mtime_ns, st.st_size)
    except OSError:
        return (p, 0, 0)


def _missing():
    return {"ok": True, "result": {"missing": True}}, 200


def _has_software():
    return swsearch._has("software") or swsearch._has("cpes")


def _ranges(p):
    try:
        return swsearch.parse_ranges(p.get("range") or ""), ""
    except ValueError as e:
        return None, str(e)


def _selection(p):
    """The full search for these filters — cached per navi.db (paging re-reads no SQL)."""
    rg, err = _ranges(p)
    if err:
        raise ValueError("Range: " + err)
    key = (_dbsig(), str(p.get("q") or "").strip().lower(), str(p.get("product") or "").strip().lower(),
           bool(p.get("exact")), str(p.get("version") or "").strip(), swsearch.ranges_text(rg))
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
    if hit is not None:
        return hit
    res = swsearch.search(q=p.get("q"), product=p.get("product"), version=p.get("version"), ranges=rg,
                          exact=bool(p.get("exact")))
    with _CACHE_LOCK:
        _CACHE[key] = res
        while len(_CACHE) > _CACHE_N:
            _CACHE.pop(next(iter(_CACHE)))
    return res


def status(p):
    n = 0
    try:
        if swsearch._has("software"):
            n = int(db.scalar("SELECT COUNT(*) FROM software", budget="open") or 0)
    except Exception:
        n = None
    return {"ok": True, "result": {"software": swsearch._has("software"), "cpes": swsearch._has("cpes"),
                                   "records": n, "llm": llm.available(),
                                   "llm_why": "" if llm.available() else llm.why_unavailable()}}, 200


def _nemesis():
    """(scores dict or None, info for the page) — the saved map only; never scores here."""
    try:
        m = fused_score.score_map()
    except Exception:
        m = None
    if not m:
        return None, {"state": "none"}
    if m.get("stale"):
        return None, {"state": "stale", "built_at": m.get("built_at")}
    return m["scores"], {"state": "ok", "built_at": m.get("built_at"), "assets": m.get("assets")}


def search(p):
    if not _has_software():
        return _missing()
    try:
        res = _selection(p)
    except ValueError as e:
        return {"ok": False, "error": str(e)}, 200
    try:
        limit = max(1, min(_PAGE_MAX, int(p.get("limit") or _PAGE)))
        offset = max(0, int(p.get("offset") or 0))
    except (TypeError, ValueError):
        limit, offset = _PAGE, 0
    st = str(p.get("status") or "").strip().lower()
    rows = [r for r in res["rows"] if r["status"] == st] if st in swsearch.STATUS_ORDER else res["rows"]
    scores, ninfo = _nemesis()
    sort = "nemesis" if (p.get("sort") == "nemesis" and scores is not None) else ""
    if sort:      # most exposed first; unscored last; the search's own order breaks ties (stable)
        rows = sorted(rows, key=lambda r: -(scores.get(r["asset_uuid"], -1)))
    page = rows[offset:offset + limit]
    if scores is not None:
        scored = sum(1 for r in rows if r["asset_uuid"] in scores)
        ninfo = dict(ninfo, scored=scored, unscored=len(rows) - scored)
    return {"ok": True, "result": {
        "kpi": res["kpi"], "breakdowns": res["breakdowns"], "ranges": res["ranges"],
        "products": res["products"][:100], "nproducts": len(res["products"]),
        "rows": [dict(r, installs=r["installs"][:20],
                      nemesis=(scores.get(r["asset_uuid"]) if scores is not None else None)) for r in page],
        "nemesis": ninfo, "sort": sort,
        "total": len(rows), "offset": offset,
        "page": offset // limit + 1, "has_next": offset + limit < len(rows)}}, 200


_CSV = ("hostname", "ip_address", "asset_uuid", "operating_system", "network", "acr", "last_found",
        "asset_status", "product", "version", "install_status", "nemesis_score")


def _cell(v):
    """CSV cell, with spreadsheet-formula text neutralised (= + - @ at the start)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def export(p):
    if not _has_software():
        return _missing()
    try:
        res = _selection(p)
    except ValueError as e:
        return {"ok": False, "error": str(e)}, 200
    st = str(p.get("status") or "").strip().lower()
    scores, _ninfo = _nemesis()
    scores = scores or {}
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_CSV)
    n, capped = 0, False
    for r in res["rows"]:
        if st in swsearch.STATUS_ORDER and r["status"] != st:
            continue
        for i in r["installs"]:
            if n >= EXPORT_MAX:
                capped = True
                break
            w.writerow([_cell(x) for x in (r["hostname"], r["ip_address"], r["asset_uuid"], r["operating_system"],
                                           r["network"], r["acr"], r["last_found"], r["status"], i["product"],
                                           i["version"], i["status"], scores.get(r["asset_uuid"], ""))])
            n += 1
        if capped:
            break
    return {"ok": True, "csv": buf.getvalue(), "rows": n, "capped": capped, "max": EXPORT_MAX}, 200


# ── ✨ zero-day lookup ────────────────────────────────────────────────────────
def lookup_plan(p):
    prompt = str(p.get("prompt") or "").strip()
    if not prompt:
        return {"ok": False, "error": "Describe the vulnerability — a CVE id, a product, or paste an advisory URL."}, 200
    pl = advisory.plan(prompt, interpret=llm.zeroday_interpret if llm.available() else None)
    if not pl["sources"]:
        return {"ok": False, "error": "Nothing to look up — add a CVE id, a product name, or an advisory URL."}, 200
    pl["llm"] = llm.available()
    pl["max_urls"] = advisory.MAX_URLS
    return {"ok": True, "result": pl}, 200


def lookup_fetch(p):
    if not gates.confirmed(p):
        return {"ok": False, "error": "Approve the sites first — nothing is fetched without confirm:true."}, 400
    urls = [str(u).strip() for u in (p.get("urls") or []) if isinstance(u, str) and str(u).strip()]
    seen = []
    for u in urls:
        if u not in seen:
            seen.append(u)
    urls = seen
    if not urls:
        return {"ok": False, "error": "No sites approved — tick at least one."}, 200
    if len(urls) > advisory.MAX_URLS:
        return {"ok": False, "error": "At most %d sites per lookup." % advisory.MAX_URLS}, 200
    reader = llm.zeroday_read if llm.available() else None
    visits, advs = [], []
    for u in urls:
        v = {"url": u, "domain": urllib.parse.urlsplit(u).hostname or "", "ok": False}
        try:
            body, ctype, trunc = advisory.get(u)
            got, how = advisory.parse(u, body, ctype, read_page=reader)
            v.update(ok=True, how=how, bytes=len(body), truncated=trunc, found=len(got))
            if how == "none":
                v["note"] = "not NVD / CVE.org / OSV data, and no model is set up to read a web page"
            elif how == "empty":
                v["note"] = "the page had no readable text (it may need JavaScript)"
            advs += got
        except advisory.Blocked as e:
            v["error"] = "blocked: %s" % e
        except Exception as e:
            code = getattr(e, "code", None)
            v["error"] = ("HTTP %s" % code) if code else ("%s: %s" % (type(e).__name__, str(e)[:160]))
        visits.append(v)
    cards = advisory.combine(advs)
    advisory.kev_flags(cards)
    # aliases from the model for rule-parsed products (NVD's apache:http_server → httpd, apache2 …)
    if llm.available():
        names = sorted({"%s:%s" % (pr["vendor"], pr["product"]) for c in cards for pr in c["products"]})
        al = llm.zeroday_aliases(names) if names else {}
        for c in cards:
            for pr in c["products"]:
                for t in al.get("%s:%s" % (pr["vendor"], pr["product"]), []):
                    if len(t) >= 2 and t.lower() not in (x.lower() for x in pr["terms"]):
                        pr["terms"].append(t)
                pr["terms"] = pr["terms"][:8]
    specs, k = [], 0
    for c in cards:
        for pr in c["products"]:
            pr["key"] = "p%d" % k
            k += 1
            specs.append({"key": pr["key"], "terms": pr["terms"], "ranges": pr["ranges"]})
    counts = swsearch.multi_count(specs) if specs and _has_software() else {}
    for c in cards:
        for pr in c["products"]:
            pr["inventory"] = counts.get(pr["key"])
        c["products"].sort(key=lambda pr: (-((pr.get("inventory") or {}).get("assets") or 0), pr["product"].lower()))
    cards.sort(key=lambda c: str(c.get("published") or ""), reverse=True)          # newest first …
    cards.sort(key=lambda c: -sum((pr.get("inventory") or {}).get("assets") or 0    # … in your estate first
                                  for pr in c["products"]))
    return {"ok": True, "result": {"visits": visits, "advisories": cards, "llm": llm.available(),
                                   "inventory": _has_software()}}, 200


ACTIONS = {"status": status, "search": search, "export": export,
           "lookup_plan": lookup_plan, "lookup_fetch": lookup_fetch}
