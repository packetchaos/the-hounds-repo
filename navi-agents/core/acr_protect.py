"""ACR protection — the NO : UPDATE tag, and a read-only mirror of `navi enrich acr`.

navi (navi-pro 8.8.2, navi/plugins/enrich.py `acr`) resolves an ACR change LOCALLY from
navi.db and never touches an asset tagged exactly ``NO : UPDATE``:

    select acr, asset_uuid from tags left join assets on assets.uuid = tags.asset_uuid
     where tag_key=<C> and tag_value=<V>
    → drop every asset with a tag_key='NO' AND tag_value='UPDATE' row   (tag_checker — exact,
      case-sensitive: 'no'/'update' or 'Hounds-NO' protect nothing)
    → group by the current acr; skip a falsy acr (NULL / '')
    → new = score (set) | min(10, acr+score) (inc) | max(1, acr-score) (dec)
    → bulk ACR update to Tenable (1999 per chunk)

preview() reproduces that selection so a page can say "n change, n protected, n without ACR"
before a write, and core.navi_cli.acr() logs exactly what navi did per asset (core/acrlog.py).
A protection tag written now counts for navi only after the next `navi update assets` sync
(Tenable tag propagation ~30 min).

protect() is the only writer here: a gated `navi enrich tag --c NO --v UPDATE --query …`
through core.navi_cli.tag (the category is exempt from Settings → Test run, core/tagname.py).
Removing protection is a tag REMOVAL — only Tag Removal (Garmr) may do that.
"""
from . import db

PROTECT_CATEGORY = "NO"
PROTECT_VALUE = "UPDATE"
NAVI_DEFAULT_NOTE = "navi Generated"          # navi's --note default (it adds "Other" otherwise)
# navi's own Change Reason labels, in navi's order
REASON_LABELS = (("business", "Business Critical"), ("compliance", "In Scope For Compliance"),
                 ("mitigation", "Existing Mitigation Control"), ("development", "Dev Only"))
CHUNK = 1999      # UUIDs per --query = core.navi_cli.BATCH_UUIDS (byte-guarded by navi_cli.uuid_batches)


def _cols(table):
    try:
        return {r["name"] for r in db.query('PRAGMA table_info("%s")' % table)}
    except Exception:
        return set()


def navi_reasons(reasons, note=None) -> list:
    """The reason list navi sends to Tenable for these flags + note."""
    flags = {str(r) for r in (reasons or [])}
    out = [lbl for k, lbl in REASON_LABELS if k in flags]
    if not out:
        out.append("Key Drivers does not match")
    if note and note != NAVI_DEFAULT_NOTE:                  # navi_cli passes --note only when set
        out.append("Other")
    return out


def business_case(reasons, note=None) -> str:
    """Human-readable business case: navi's reason labels + the note, e.g.
    'Business Critical, In Scope For Compliance — PCI scope'. What users sort/filter by."""
    flags = {str(r) for r in (reasons or [])}
    lbl = ", ".join(l for k, l in REASON_LABELS if k in flags)
    n = " ".join(str(note or "").split())
    if lbl and n:
        return lbl + " — " + n
    return lbl or n


def score_arg(score) -> str:
    """The --score argument as the Hounds pass it to navi: a whole number is rendered without
    '.0' (navi does int(score), which rejects '9.0'); anything else is passed through."""
    try:
        f = float(score)
        if f == int(f):
            return str(int(f))
    except (TypeError, ValueError, OverflowError):
        pass
    return str(score)


def _navi_int(s):
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def protected_uuids(path=None) -> set:
    """Assets navi will not touch: a tag_key='NO' AND tag_value='UPDATE' row in navi.db (exact)."""
    try:
        rows = db.query("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?",
                        (PROTECT_CATEGORY, PROTECT_VALUE), path=path)
    except Exception:
        return set()
    return {r["asset_uuid"] for r in rows if r.get("asset_uuid")}


def refuse_reason(category, value, score, mod) -> str:
    """Why navi would change NOTHING for this change, before reading navi.db ('' = fine)."""
    if "'" in str(category or "") or "'" in str(value or ""):
        return ("navi builds its SQL with the tag text inline, so a ' in the category or value makes "
                "navi's own query fail (DB ERROR) and nothing is changed — rename the tag without '")
    sc = _navi_int(score_arg(score))
    if sc is None or not 1 <= sc <= 10:
        return "the ACR score must be a whole number 1–10 (navi does int(score))"
    if mod not in ("set", "inc", "dec"):
        return "mod must be set, inc or dec"
    return ""


def preview(category, value, score, mod="set", path=None, refuse=True) -> dict:
    """Mirror navi's ACR run for tag <category>:<value>, group by group. Reads only.

    navi: rows = (acr, uuid) from tags LEFT JOIN assets (one row per tags×assets match — a
    duplicate assets row gives the asset two ACR groups); drop NO : UPDATE uuids; acr_dict =
    {acr: [uuid…]} in row order; for each group in that order: skip a falsy acr, else compute
    the new ACR and SEND. int(acr) on an unreadable ACR (inc/dec) raises ValueError and navi
    crashes — groups already sent stay sent.

    assets: [{uuid, hostname, ip, acr_before, acr_after, status, sends:[[group, new]…]}]
      change / unchanged  navi sends it (acr_after = the LAST value navi sends)
      protected           tagged NO : UPDATE — skipped
      no_acr              no ACR in navi.db — skipped
      bad_acr             inc/dec on an ACR navi cannot int() — navi crashes there
      refused             would be sent, but the whole change is refused up front (see `refuse`)
    refuse: '' or why navi would change nothing / the Hounds won't send it (a ' in the tag,
      an invalid score, or inc/dec with bad_acr > 0 — navi would crash part-way). With
      refuse=False the reason is still reported but statuses show what navi would do.
    crash_group: index of the group navi crashes on (None if it doesn't)."""
    sa = score_arg(score)
    sc = _navi_int(sa)
    valid = sc is not None and 1 <= sc <= 10 and mod in ("set", "inc", "dec")
    out = {"ok": False, "category": category, "value": value, "mod": mod, "score": sa,
           "valid_score": valid, "assets": [], "refuse": "", "crash_group": None,
           "counts": {"change": 0, "unchanged": 0, "protected": 0, "no_acr": 0, "bad_acr": 0,
                      "refused": 0, "total": 0}}
    tc, ac = _cols("tags"), _cols("assets")
    if not tc:
        out["error"] = "navi.db has no tags table"
        return out
    if not ac or "acr" not in ac:
        out["error"] = "navi.db has no assets.acr column"
        return out
    host = "assets.hostname" if "hostname" in ac else "NULL"
    ip = "assets.ip_address" if "ip_address" in ac else ("tags.asset_ip" if "asset_ip" in tc else "NULL")
    try:
        rows = db.query("SELECT assets.acr AS acr, tags.asset_uuid AS uuid, %s AS hostname, %s AS ip "
                        "FROM tags LEFT JOIN assets ON assets.uuid = tags.asset_uuid "
                        "WHERE tags.tag_key=? AND tags.tag_value=?" % (host, ip),
                        (str(category or ""), str(value or "")), path=path)
    except Exception as e:
        out["error"] = str(e)
        return out
    prot = protected_uuids(path)
    # per asset, in first-seen order; every joined row kept
    assets, order = {}, []
    groups = {}                                   # navi's acr_dict: acr -> [uuid…], insertion order
    for r in rows:
        u = r.get("uuid")
        if not u:
            continue
        if u not in assets:
            assets[u] = {"uuid": u, "hostname": r.get("hostname") or "", "ip": r.get("ip") or "",
                         "rates": [], "sends": []}
            order.append(u)
        assets[u]["rates"].append(r.get("acr"))
        if u not in prot:
            groups.setdefault(r.get("acr"), []).append(u)
    crash = None
    if valid:
        for gi, (rate, uus) in enumerate(groups.items()):
            if not rate:                                          # navi: `if current_acr:`
                continue
            if mod == "set":
                new = sc
            else:
                ci = _navi_int(rate)
                if ci is None:                                    # ValueError → navi crashes here
                    if crash is None:
                        crash = gi
                    continue                              # (later groups are what it never reaches)
                new = min(10, ci + sc) if mod == "inc" else max(1, ci - sc)
            for u in uus:
                if [gi, new, rate] not in assets[u]["sends"]:
                    assets[u]["sends"].append([gi, new, rate])
    bad_rate = lambda x: bool(x) and mod in ("inc", "dec") and _navi_int(x) is None
    for u in order:
        a = assets[u]
        rates = a.pop("rates")
        sends = a["sends"]
        a["acr_before"] = rates[0]
        if len(set(map(str, rates))) > 1:
            a["acr_rows"] = [None if x is None else str(x) for x in rates]   # duplicate assets rows
        a["acr_after"] = sends[-1][1] if sends else None
        if u in prot:
            a["status"] = "protected"
        elif any(bad_rate(x) for x in rates):
            a["status"] = "bad_acr"
        elif not sends:
            a["status"] = "no_acr" if (valid or not any(rates)) else "refused"
        else:
            a["status"] = "unchanged" if all(_navi_int(rt) == new for _, new, rt in sends) else "change"
        a["sends"] = [[g, n] for g, n, _ in sends]
    reason = refuse_reason(category, value, score, mod)
    nbad = sum(1 for u in order if assets[u]["status"] == "bad_acr")
    if not reason and nbad:
        reason = ("%d asset(s) carry an ACR navi cannot read as a whole number (e.g. '7.0') — navi's %s "
                  "would crash part-way; use set, or fix those ACRs first" % (nbad, mod))
    out["refuse"] = reason
    out["crash_group"] = crash
    for u in order:
        a = assets[u]
        if refuse and reason and a["status"] in ("change", "unchanged"):
            a["status"] = "refused"
        out["assets"].append(a)
        out["counts"][a["status"]] += 1
    out["counts"]["total"] = len(out["assets"])
    out["ok"] = True
    return out


def summary(pv, sample=0) -> dict:
    """A preview without the full asset list (for API responses / confirm text)."""
    pv = pv or {}
    s = {k: v for k, v in pv.items() if k != "assets"}
    if sample:
        s["sample"] = (pv.get("assets") or [])[:sample]
    return s


def _query_for(uuids):
    from . import navi_cli
    return navi_cli.uuids_query(uuids)


def batches(uuids):
    """The protection set (Python-derived: what an ACR batch APPLIED to, from the ACR log) in
    navi-legal batches — ≤ CHUNK UUIDs and < navi_cli.MAX_ARG_BYTES per --query."""
    from . import navi_cli
    return navi_cli.uuid_batches(uuids, size=CHUNK)


def protect(groups, agent="acr", sync=False, batch="") -> dict:
    """Queue the NO : UPDATE tag. `groups` = {business_case: [uuid, …]} (or a plain list of
    uuids). One gated navi tag job per business case per ≤1,999-UUID batch (batches()), so each Tagging-log
    entry carries the business case of the ACR change that prompted it. Already-protected
    assets (in navi.db) and ones whose protection is still pending are left out. Returns {queued_jobs, assets, jobs:[…]}."""
    from . import acrlog, navi_cli
    if isinstance(groups, (list, tuple, set)):
        groups = {"": list(groups)}
    prot = protected_uuids()
    pend = pending_uuids(prot)                 # already queued / awaiting the sync — no duplicate jobs
    jobs, n, seen = [], 0, set()
    for bc, uuids in (groups or {}).items():
        uu = sorted({str(u) for u in (uuids or []) if u and str(u) not in prot and str(u) not in pend
                     and str(u) not in seen})
        seen.update(uu)
        parts = batches(uu)
        stubs = navi_cli.tag_pages(PROTECT_CATEGORY, PROTECT_VALUE, parts, agent=agent, sync=sync,
                                   business_case=bc or "")          # one job, or a paged series
        for part, r in zip(parts, stubs):
            jid = r.get("job_id")
            acrlog.record_protect(part, agent, bc or "", jid, batch)
            jobs.append({"job_id": jid, "assets": len(part), "business_case": bc or "",
                         "ok": bool(r.get("ok")), "message": r.get("message") or ""})
            n += len(part)
    navi_cli.drop_acr_cache()
    return {"ok": True, "queued_jobs": len(jobs), "assets": n, "jobs": jobs,
            "already_protected": len({str(u) for v in (groups or {}).values() for u in (v or [])} & prot),
            "already_pending": len({str(u) for v in (groups or {}).values() for u in (v or [])} & pend),
            "tag": "%s : %s" % (PROTECT_CATEGORY, PROTECT_VALUE)}


def protect_batch(batch, agent, business_case="", sync=False) -> dict:
    """Protect exactly the assets an ACR batch APPLIED to (core.acrlog result='applied')."""
    from . import acrlog
    uu = acrlog.batch_uuids(batch, "applied")
    if not uu:
        return {"ok": True, "queued_jobs": 0, "assets": 0, "jobs": [], "note": "no applied assets in that change"}
    return protect({business_case or "": uu}, agent=agent, sync=sync, batch=batch)


def _asset_rows(uuids, path=None) -> dict:
    """{uuid: {hostname, ip, acr}} from navi.db for these uuids (chunked IN lists)."""
    ac = _cols("assets")
    if not ac:
        return {}
    host = "hostname" if "hostname" in ac else "NULL"
    ip = "ip_address" if "ip_address" in ac else "NULL"
    acr = "acr" if "acr" in ac else "NULL"
    out, uu = {}, list(uuids)
    for i in range(0, len(uu), 900):
        part = uu[i:i + 900]
        try:
            for r in db.query("SELECT uuid, %s AS hostname, %s AS ip, %s AS acr FROM assets WHERE uuid IN (%s)"
                              % (host, ip, acr, ",".join("?" * len(part))), tuple(part), path=path):
                out[r["uuid"]] = r
        except Exception:
            break
    return out


SYNC_WINDOW_S = 24 * 3600     # a done NO : UPDATE job counts as "pending sync" for at most this long


def _jobs(ids) -> dict:
    """{tag job id: (status, ok, finished)} from the Tagging log for these ids."""
    from . import tagq
    ids = sorted({int(i) for i in ids if isinstance(i, int) or str(i).isdigit()})
    out = {}
    for i in range(0, len(ids), 900):
        part = ids[i:i + 900]
        for r in tagq._dbexec("SELECT id, status, ok, finished FROM jobs WHERE id IN (%s)" % ",".join("?" * len(part)),
                              tuple(part), want="all") or []:
            out[r[0]] = (r[1], r[2], r[3])
    return out


def _last_removal() -> float:
    """When a NO : UPDATE removal (Tag Removal / Garmr) last finished — it strips the tag from
    every asset, so a protection requested before it is no longer pending."""
    from . import tagq
    rows = tagq._dbexec("SELECT MAX(finished) FROM jobs WHERE op='remove' AND category=? AND value=? "
                        "AND status='done'", (PROTECT_CATEGORY, PROTECT_VALUE), want="all") or []
    return float(rows[0][0]) if rows and rows[0][0] else 0.0


def pending_uuids(prot=None, now=None) -> set:
    """Assets a Hound asked to protect whose NO : UPDATE is not in navi.db yet. Pending only while
    the latest request's tag job is queued / running, or done (ok) within SYNC_WINDOW_S and not
    followed by a NO : UPDATE removal. A missing job row (Tagging log cleared), a blocked / failed
    job, an expired window or a later removal → not pending (the asset can be protected again)."""
    import time as _t
    from . import acrlog
    prot = protected_uuids() if prot is None else prot
    now = _t.time() if now is None else now
    req = {u: r for u, r in acrlog.protect_requests().items() if u not in prot}
    jobs = _jobs(r.get("job_id") for r in req.values() if r.get("job_id") is not None)
    removed = _last_removal()
    out = set()
    for u, r in req.items():
        j = jobs.get(r.get("job_id"))
        if not j:
            continue
        status, ok, finished = j
        if status in ("queued", "running"):
            out.add(u)
        elif status == "done" and ok and finished and now - float(finished) < SYNC_WINDOW_S \
                and not (removed and removed > float(finished)):
            out.add(u)
    return out


def no_acr_count(path=None):
    """Assets navi would skip for having no ACR (assets.acr NULL or '')."""
    if "acr" not in _cols("assets"):
        return None
    try:
        return db.scalar("SELECT COUNT(*) FROM assets WHERE acr IS NULL OR acr = ''", path=path)
    except Exception:
        return None


def metrics(show="all", limit=2000, path=None) -> dict:
    """At-a-glance numbers + the Protection list for the ACR page. Reads only:
    navi.db (who carries NO : UPDATE now, current ACR) and the ACR log (what the Hounds changed)."""
    from . import acrlog
    prot = protected_uuids(path)
    changed = acrlog.applied_assets()
    req = acrlog.protect_requests()
    ch = set(changed)
    pending = pending_uuids(prot)
    rows_all = []
    info = _asset_rows(ch, path)
    for u, c in changed.items():
        a = info.get(u) or {}
        st = "protected" if u in prot else ("pending" if u in pending else "unprotected")
        rows_all.append({"uuid": u, "hostname": a.get("hostname") or c.get("host") or "",
                         "ip": a.get("ip") or c.get("ip") or "", "acr": a.get("acr"),
                         "in_navi_db": bool(a), "last_change": c["last_ts"], "business_case": c["business_case"],
                         "agent": c["agent"], "acr_set": c["acr_after"], "selector": c["selector"],
                         "changes": c["changes"], "protection": st, "unchanged": c.get("unchanged", False),
                         "requested": (req.get(u) or {}).get("ts"),
                         "request_failed": bool(u in req and u not in prot and u not in pending)})
    rows_all.sort(key=lambda r: -(r["last_change"] or 0))
    by_bc = {}
    for r in rows_all:
        b = by_bc.setdefault(r["business_case"] or "", {"business_case": r["business_case"] or "", "assets": 0,
                                                       "protected": 0})
        b["assets"] += 1
        b["protected"] += 1 if r["protection"] == "protected" else 0
    sel = [r for r in rows_all if show in ("", "all", None) or r["protection"] == show]
    lim = max(1, min(20000, int(limit or 2000)))
    rc = acrlog.result_counts()
    return {"ok": True,
            "protected": len(prot),
            "changed": len(ch),
            "changed_unchanged": sum(1 for c in changed.values() if c.get("unchanged")),
            "changed_protected": len(ch & prot),
            "changed_unprotected": len(ch - prot),
            "changed_unprotected_waiting": len((ch - prot) - pending),
            "pending": len(pending),
            "protected_never_changed": len(prot - ch),
            "last_change": max((c["last_ts"] for c in changed.values()), default=None),
            "no_acr": no_acr_count(path),
            "respected": rc.get("skipped_protected", 0),
            "results": rc,
            "by_business_case": sorted(by_bc.values(), key=lambda b: (-b["assets"], b["business_case"])),
            "rows": sel[:lim], "rows_total": len(sel), "show": show or "all",
            "tag": "%s : %s" % (PROTECT_CATEGORY, PROTECT_VALUE)}
