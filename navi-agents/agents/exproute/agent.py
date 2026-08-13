"""Exposure Routes — owner-mapping agent (Atlas).

Pulls users & groups from navi (`navi explore info users|user_groups|agent_groups`,
live Tenable API) and the application **routes** (`vuln_route`) and filesystem
**paths** (`vuln_paths`) from navi.db. A plain-English instruction then maps each
route/path to an owner; applying a mapping tags every asset on that route/path
with `Owner:<group-or-user>` via the gated navi tag path.
"""
import re

from core import db, navi_cli
from core.agents.base import Agent

_SPLIT = re.compile(r"\s{2,}")
_DIV = re.compile(r"^-{5,}$")

# ---- Dispositions: mark a route/path as handled WITHOUT an owner ------------------
# 'ignore' = not worth assigning (noise); 'accept' = risk acknowledged, tracked not
# assigned. Both are written as Owner tags with a reserved value ('<name>: Ignored' /
# '<name>: Accepted') so the surface stops showing them as gaps — you see only what
# still NEEDS an owner. They're NOT counted as real owners on the graph or workload.
IGNORED, ACCEPTED, MITIGATED = "Ignored", "Accepted", "Mitigated"
DISPOSITIONS = (IGNORED, ACCEPTED, MITIGATED)
_DISP_VERBS = {"ignore": IGNORED, "ignored": IGNORED, "dismiss": IGNORED, "dismissed": IGNORED,
               "skip": IGNORED, "exclude": IGNORED, "hide": IGNORED, "noise": IGNORED,
               "accept": ACCEPTED, "accepted": ACCEPTED, "waive": ACCEPTED, "waived": ACCEPTED,
               "acknowledge": ACCEPTED, "acknowledged": ACCEPTED, "ack": ACCEPTED,
               "mitigate": MITIGATED, "mitigated": MITIGATED, "mitigating": MITIGATED,
               "remediate": MITIGATED, "remediated": MITIGATED, "remediating": MITIGATED,
               "patched": MITIGATED, "fixed": MITIGATED, "resolved": MITIGATED}
_DISP_STOP = {"the", "a", "an", "route", "routes", "path", "paths", "please", "as", "owner",
              "risk", "and", "then", "this", "that", "for", "of", "on", "to", "all", "it",
              "no", "just", "mark", "are", "is", "be", "been", "being", "should", "we", "i",
              "my", "our", "have", "has", "them", "these", "those", "set"}


def disposition_label(owner):
    """Return the canonical disposition ('Ignored'/'Accepted'/'Mitigated') ONLY when the
    owner string IS exactly one of them (case-insensitive).

    We deliberately do NOT match the broad NL verb list (_DISP_VERBS) here. Those verbs are
    for PARSING a plain-English prompt; using them to judge an EXISTING Owner tag would
    misread a real owner/team whose name happens to be 'Accept', 'Fixed', 'Ack', 'Skip',
    etc. as a disposition and silently drop it from the graph (everything looks unassigned).
    tag_owner only ever writes the three canonical labels, so exact-match is correct."""
    o = (owner or "").strip().lower()
    for d in DISPOSITIONS:
        if o == d.lower():
            return d
    return None


def _tokset(s):
    return {t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t}


def _compact(s):
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _targets(toks, rts, pas, kind):
    """Routes/paths that match the instruction terms, best tier first. Matches on the
    COMPACTED name (spaces/punctuation stripped) so 'note pad' hits 'Notepad++' and
    'Microsoft Windows Notepad'; a term counts if it's a substring of the compact name."""
    terms = [t for t in toks if len(t) >= 3]     # ignore tiny/filler tokens
    if not terms:
        terms = toks
    if not terms:
        return []

    def score(name):
        comp = _compact(name)
        return sum(1 for t in terms if t in comp)

    cand = []
    if kind != "path":
        for r in rts:
            nm = r.get("app_name") or ""
            s = score(nm)
            if s:
                cand.append((s, len(_compact(nm)), {"kind": "route", "name": nm,
                             "scope": f"{r.get('total_vulns') or 0} vulns"}))
    if kind != "route":
        for x in pas:
            nm = x.get("path") or ""
            s = score(nm)
            if s:
                cand.append((s, len(_compact(nm)), {"kind": "path", "name": nm, "path": nm,
                             "scope": f"{x.get('assets') or 0} assets"}))
    if not cand:
        return []
    mx = max(c[0] for c in cand)                 # keep only the strongest-match tier
    cand = [c for c in cand if c[0] == mx]
    cand.sort(key=lambda c: c[1])                # most specific (shortest name) first
    return [c[2] for c in cand]


def parse_dispositions(prompt, rts, pas):
    """Pull 'ignore the ICMP route' / 'accept the OpenSSL route' style instructions out of a
    prompt and resolve each to a route/path — no LLM needed. Returns mapping dicts with
    owner set to the disposition sentinel."""
    clauses = re.split(r"\s*(?:,|;|\band\b|\bthen\b|\.|\n)\s*", (prompt or "").lower())
    out, seen = [], set()
    for cl in clauses:
        cl = cl.strip()
        if not cl:
            continue
        disp = None
        for w, lab in _DISP_VERBS.items():
            if re.search(r"\b" + re.escape(w) + r"\b", cl):
                disp = lab
                break
        if not disp:
            continue
        kind = "path" if "path" in cl else ("route" if "route" in cl else None)
        toks = [t for t in re.split(r"[^a-z0-9]+", cl) if t and t not in _DISP_STOP and t not in _DISP_VERBS]
        if not toks:
            continue
        cands = _targets(toks, rts, pas, kind)
        if not cands:
            continue
        # 'all …' or a plural (routes/paths) means EVERY match; otherwise just the best one.
        multi = bool(re.search(r"\ball\b", cl)) or "routes" in cl or "paths" in cl
        chosen = cands[:50] if multi else cands[:1]
        for best in chosen:
            key = (best["kind"], best["name"].lower())
            if key in seen:
                continue
            seen.add(key)
            m = {"kind": best["kind"], "match": best["name"], "owner": disp,
                 "disposition": disp, "scope": best.get("scope", "")}
            if best.get("path"):
                m["path"] = best["path"]
            out.append(m)
    return out


def _info_rows(stdout: str) -> list[list]:
    """Parse a `navi explore info` text table into its DATA rows only.

    navi prints a BANNER ('Level up your … Navi!') that has its OWN dashed divider,
    THEN the column header, THEN the real table divider, THEN the data. Starting at the
    first divider (the banner's) makes the column header ('User Name / Login Email / …')
    parse as a data row — a bogus owner, and the ONLY 'owner' when the table is empty
    (that's the '1 owner' bug). So we parse everything after the LAST divider, which is
    the table divider — skipping both the banner and the header."""
    lines = (stdout or "").splitlines()
    last_div = -1
    for i, ln in enumerate(lines):
        if _DIV.match(ln.strip()):
            last_div = i
    out = []
    for ln in lines[last_div + 1:]:
        t = ln.strip()
        if t:
            out.append([c.strip() for c in _SPLIT.split(t)])
    return out


def owners() -> list[dict]:
    """Users + groups available to assign. navi primary; the Tenable MCP acts as a
    backup/validator in the UI layer."""
    out, seen = [], set()

    def add(name, typ, detail="", search=""):
        name = (name or "").strip()
        if not name:
            return
        k = (typ, name.lower())
        if k in seen:
            return
        seen.add(k)
        # `search` holds every field navi reported (login, friendly name, email, …)
        # lowercased, so a mapping can be made by ANY of them — not just the username.
        out.append({"name": name, "type": typ, "detail": detail,
                    "search": (search or (name + " " + detail)).strip().lower()})

    for sub, typ in (("users", "user"), ("user_groups", "user group"),
                     ("agent_groups", "agent group")):
        r = navi_cli.explore_info(sub)
        for f in _info_rows(r.get("stdout", "")):
            if not f:
                continue
            if typ == "user":
                # f[0] = login/username; the remaining columns are the friendly name /
                # email etc. Keep the username as the canonical name, show the friendly
                # name as detail, and index ALL columns for matching.
                add(f[0], "user", f[1] if len(f) > 1 else "", search=" ".join(f))
            elif typ == "user group":
                cnt = f[-1] if (f and f[-1].isdigit()) else ""
                add(f[0], "user group", (cnt + " users") if cnt else "")
            else:
                add(f[0], "agent group", " · ".join(f[1:]) if len(f) > 1 else "")
    return out


def _own_tokens(s):
    return {t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t}


def _lev(a, b):
    """Levenshtein distance — tiny, for typo-tolerant 'did you mean' hints."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[len(b)]


def _sim(a, b):
    m = max(len(a), len(b)) or 1
    return 1 - _lev(a, b) / m


def _fmt_owner(o):
    """'creid (Casey Reid)' — username with the friendly name when they differ."""
    d = (o.get("detail") or "").strip()
    return o["name"] + (f" ({d})" if d and d.lower() != o["name"].lower() else "")


def _owner_suggest(query, ow, n=3):
    """Closest owner entries to a typed name — prefix, substring, or small typo."""
    ql = (query or "").strip().lower()
    if not ql:
        return []
    scored = []
    for o in ow:
        hay = o.get("search") or (o.get("name", "") + " " + o.get("detail", "")).lower()
        best = 0.0
        for t in _own_tokens(hay):
            if t.startswith(ql) or ql.startswith(t):
                best = max(best, 0.85)
            best = max(best, _sim(ql, t))
        if ql in hay:
            best = max(best, 0.75)
        if best >= 0.6:
            scored.append((best, o))
    scored.sort(key=lambda x: -x[0])
    out, seen = [], set()
    for _, o in scored:
        if o["name"] in seen:
            continue
        seen.add(o["name"])
        out.append(_fmt_owner(o))
        if len(out) >= n:
            break
    return out


def resolve_owner(query, owners_list=None):
    """Resolve a typed / LLM-produced owner string to ONE canonical owner entry.

    Users can be mapped by username (``creid``), full/friendly name (``Casey Reid``),
    first name (``Casey``), or email local-part — not just the login. Groups match by
    name. Returns ``(entry, None)`` on success, or ``(None, reason)`` when it can't be
    resolved unambiguously so the caller can alert instead of tagging a bogus owner.
    """
    ow = owners() if owners_list is None else owners_list
    q = (query or "").strip()
    if not q:
        return None, "no owner given"
    ql = q.lower()

    def _search(o):
        return o.get("search") or (o.get("name", "") + " " + o.get("detail", "")).lower()

    # 1) exact username / group name — the canonical identifier
    for o in ow:
        if o.get("name", "").strip().lower() == ql:
            return o, None
    # 2) exact friendly name (detail)
    ex = [o for o in ow if o.get("detail", "").strip().lower() == ql]
    if len(ex) == 1:
        return ex[0], None
    # 3) all query tokens present in the entry (first name, email local-part, etc.)
    qt = _own_tokens(q)
    if qt:
        tok = {o["name"]: o for o in ow if qt <= _own_tokens(_search(o))}
        if len(tok) == 1:
            return next(iter(tok.values())), None
    # 4) unique case-insensitive substring across all indexed fields
    sub = {o["name"]: o for o in ow if ql in _search(o)}
    if len(sub) == 1:
        return next(iter(sub.values())), None
    if len(sub) > 1:
        cands = " or ".join(_fmt_owner(o) for o in list(sub.values())[:4])
        return None, f"'{q}' matches several — did you mean {cands}? Be more specific."
    sg = _owner_suggest(q, ow)
    if sg:
        return None, f"'{q}' didn't match a user or group — did you mean {' or '.join(sg)}?"
    return None, f"'{q}' didn't match any user or group — pick one from the list."


def routes(db_path=None) -> list[dict]:
    return db.query("SELECT route_id, app_name, vuln_type, total_vulns, plugin_list "
                    "FROM vuln_route ORDER BY total_vulns DESC LIMIT 1000;", path=db_path)


def _plugin_ids(pl) -> list[str]:
    """vuln_route.plugin_list is stored like ['51192', '187315'] — parse to ids."""
    import json
    try:
        return [str(x) for x in json.loads(str(pl or "[]").replace("'", '"'))]
    except Exception:
        return [s for s in re.sub(r"[\[\]'\s]", "", str(pl or "")).split(",") if s]


def paths(db_path=None) -> list[dict]:
    return db.query("SELECT path, MAX(plugin_id) plugin_id, "
                    "COUNT(DISTINCT asset_uuid) assets FROM vuln_paths "
                    "GROUP BY path ORDER BY assets DESC LIMIT 1000;", path=db_path)


def tag_owner(owner: str, route_id=None, path=None, app=None, db_path=None) -> dict:
    """Apply a persistent Owner tag (NO remove) to the assets on a route or path.

    Value scheme: ``<App/technology>: <owner>`` so the tag records WHAT is owned, not
    just by whom. A route is tagged with navi's NATIVE ``--route_id`` selector — it's
    exact and avoids emitting a multi-thousand-plugin ``plugin_id IN (...)`` query (a
    route like "Windows Updates" carries ~750 plugins → a ~7 KB query that clutters the
    Tagging log and is easy to mis-read as truncated). Tagging runs on the background
    worker, so the old "route_id is slow / times out the MCP bridge" concern no longer
    applies (the call returns a job stub immediately). If a route_id can't be resolved,
    fall back to the plugin-membership query.
    """
    # A route can be identified by route_id (from the NL mapping) OR by its app NAME
    # (the Ownership Map hands off names, not ids) — resolve either to its route_id.
    if (route_id not in (None, "")) or (app and not path):
        if route_id not in (None, ""):
            rows = db.query("SELECT route_id, app_name, plugin_list FROM vuln_route WHERE route_id=?",
                            (route_id,), path=db_path)
        else:
            rows = db.query("SELECT route_id, app_name, plugin_list FROM vuln_route "
                            "WHERE app_name=? COLLATE NOCASE LIMIT 1", (app,), path=db_path)
        if not rows:
            return {"ok": False, "message": f"route {app or route_id!r} not found"}
        rid = rows[0].get("route_id")
        name = app or rows[0].get("app_name") or str(rid)
        if rid not in (None, ""):
            # native route selector: exact, one short command, no giant IN() query
            return navi_cli.tag("Owner", f"{name}: {owner}", route_id=rid, remove=False, agent="exproute")
        # fallback — tag by the route's plugin set (local navi.db membership)
        ids = _plugin_ids(rows[0].get("plugin_list"))
        if not ids:
            return {"ok": False, "message": "route has no plugins to tag"}
        inlist = ",".join("'" + i.replace("'", "''") + "'" for i in ids)
        q = "SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN (" + inlist + ")"
        return navi_cli.tag("Owner", f"{name}: {owner}", query=q, remove=False, agent="exproute")
    if path:
        name = app or path
        q = "SELECT asset_uuid FROM vuln_paths WHERE path='" + str(path).replace("'", "''") + "'"
        return navi_cli.tag("Owner", f"{name}: {owner}", query=q, remove=False, agent="exproute")
    return {"ok": False, "message": "no route_id or path supplied"}


# Route↔asset membership: an asset is "on" a route when it carries a vuln whose plugin id
# is in that route's plugin_list (stored like ['51192','187315']). We match the id wrapped
# in quotes ('%'<id>'%') so 519 doesn't match 51192.
_RA = ("WITH ra AS (SELECT DISTINCT r.app_name app, v.asset_uuid au "
       "FROM vuln_route r JOIN vulns v ON r.plugin_list LIKE '%''' || v.plugin_id || '''%') ")


def coverage(db_path=None) -> dict:
    """How much of the attack surface has an owner assigned. An asset is CLOSED only when
    EVERY route it sits on is owned (an Owner:'<app>: <user>' tag for each route). Read-only."""
    def sc(sql):
        try:
            return db.scalar(sql, path=db_path) or 0
        except Exception:
            return 0
    if not db.query("SELECT name FROM sqlite_master WHERE type='table' AND name='vuln_route'", path=db_path):
        return {"ok": True, "owned": 0, "assets_with_routes": 0, "avg_routes": 0.0,
                "closed": 0, "total_routes": 0, "total_paths": 0, "owned_paths": 0,
                "note": "No vuln_route table — run `navi config update route` + `navi config update paths`."}
    owned = sc("SELECT COUNT(DISTINCT asset_uuid) FROM tags WHERE tag_key='Owner'")
    # distinct people/groups actually assigned in Owner tags (the '<app>: <user>' scheme) —
    # what the operator means by "my owners", independent of the navi user directory.
    owner_count = sc("SELECT COUNT(DISTINCT TRIM(substr(tag_value, instr(tag_value, ': ')+2))) "
                     "FROM tags WHERE tag_key='Owner' AND tag_value LIKE '%: %'")
    assets_with_routes = sc(_RA + "SELECT COUNT(DISTINCT au) FROM ra")
    avg_routes = sc(_RA + "SELECT AVG(c) FROM (SELECT au, COUNT(DISTINCT app) c FROM ra GROUP BY au)")
    total_routes = sc("SELECT COUNT(*) FROM vuln_route")
    total_paths = sc("SELECT COUNT(DISTINCT path) FROM vuln_paths")
    # workload reduction: raw path findings (every asset×path row) collapse to distinct
    # paths you actually assign; sum of route vulns collapse to a handful of routes.
    path_findings = sc("SELECT COUNT(*) FROM vuln_paths")
    route_findings = sc("SELECT COALESCE(SUM(total_vulns),0) FROM vuln_route")
    # Owner-tag matching is CASE-INSENSITIVE here to match ownership_map() exactly — the
    # dashboard was case-insensitive but this widget wasn't, so they disagreed (e.g. an
    # 'APACHE: user' tag counted for route 'Apache' on the map but not here). Scheme is
    # '<app/path>: <user>', so we match LOWER(tag_value) LIKE LOWER(<name>) || ': %'.
    closed, owned_paths, routes_owned = 0, 0, 0
    if owned > 0:
        # a ROUTE is owned when EVERY asset on it carries that route's Owner tag — the same
        # definition the Ownership Map uses (its "N owned" count). Reconciles the two widgets.
        routes_owned = sc(_RA + "SELECT COUNT(*) FROM (SELECT app FROM ra GROUP BY app HAVING "
                          "SUM(CASE WHEN EXISTS(SELECT 1 FROM tags t WHERE t.asset_uuid=ra.au "
                          "AND t.tag_key='Owner' AND LOWER(t.tag_value) LIKE LOWER(ra.app) || ': %') "
                          "THEN 0 ELSE 1 END)=0)")
        # an ASSET is closed when every route it sits on is owned.
        closed = sc(_RA + "SELECT COUNT(*) FROM (SELECT au FROM ra GROUP BY au HAVING "
                    "SUM(CASE WHEN EXISTS(SELECT 1 FROM tags t WHERE t.asset_uuid=ra.au "
                    "AND t.tag_key='Owner' AND LOWER(t.tag_value) LIKE LOWER(ra.app) || ': %') THEN 0 ELSE 1 END)=0)")
        # a path is OWNED when it carries its own Owner tag OR when the route that covers
        # it is fully owned — a route covers its paths, so closing a route closes them too.
        owned_paths = sc(_RA +
            "SELECT COUNT(DISTINCT p) FROM ("
            "SELECT DISTINCT vp.path p FROM vuln_paths vp JOIN tags t "
            "ON t.asset_uuid=vp.asset_uuid AND t.tag_key='Owner' "
            "AND LOWER(t.tag_value) LIKE LOWER(vp.path) || ': %' "
            "UNION "
            "SELECT DISTINCT vp.path p FROM vuln_paths vp JOIN vuln_route r "
            "ON r.plugin_list LIKE '%''' || vp.plugin_id || '''%' WHERE r.app_name IN ("
            "SELECT app FROM ra GROUP BY app HAVING SUM(CASE WHEN EXISTS("
            "SELECT 1 FROM tags t2 WHERE t2.asset_uuid=ra.au AND t2.tag_key='Owner' "
            "AND LOWER(t2.tag_value) LIKE LOWER(ra.app) || ': %') THEN 0 ELSE 1 END)=0))")
    # --- outcome of decisions on each route/path + who has no assigned work ------
    # Reuse the Ownership Map so these numbers reconcile exactly with the graph.
    #   owners_total    = people the platform knows as owners (any Owner tag, minus
    #                     disposition sentinels)
    #   owners_assigned = owners actually landed on a route/path (have work)
    #   owners_no_work  = owners with NOTHING assigned to a live route/path
    #   mitigated/accepted/ignored = share of the whole route+path surface handled
    owners_total = owners_assigned = owners_no_work = 0
    surface_total = mit = acc = ign = 0
    try:
        om = ownership_map(db_path)
        k = om.get("kpi", {}) or {}
        surface_total = int(k.get("routes", 0)) + int(k.get("paths", 0))
        mit = int(k.get("mitigated", 0)); acc = int(k.get("accepted", 0)); ign = int(k.get("ignored", 0))
        _disp_words = set(_DISP_VERBS) | {d.lower() for d in DISPOSITIONS}
        assigned_set = {str(o).strip() for o in om.get("owners", []) if str(o).strip()}
        all_set = set(assigned_set)
        for u in om.get("unmatched_owners", []):
            for o in (u.get("owners") or []):
                s = str(o).strip()
                if s and s.lower() not in _disp_words:
                    all_set.add(s)
        owners_assigned = len(assigned_set)
        owners_total = len(all_set)
        owners_no_work = max(0, owners_total - owners_assigned)
    except Exception:
        pass

    # total platform users (the denominator for owner engagement): 4 owners of 87 users.
    users_total = 0
    try:
        ur = navi_cli.explore_info("users")
        users_total = sum(1 for f in _info_rows(ur.get("stdout", "")) if f)
    except Exception:
        users_total = 0

    def _p(n, d):
        return round(100.0 * n / d, 1) if d else 0.0

    return {"ok": True, "owned": int(owned), "owner_count": int(owner_count),
            "users_total": int(users_total),
            "assets_with_routes": int(assets_with_routes),
            "avg_routes": round(float(avg_routes or 0), 1), "closed": int(closed),
            "routes_owned": int(routes_owned),
            "total_routes": int(total_routes), "total_paths": int(total_paths),
            "owned_paths": int(owned_paths), "path_findings": int(path_findings),
            "route_findings": int(route_findings),
            # NEW — owner engagement + decision outcomes (routes+paths surface)
            "owners_total": int(owners_total), "owners_assigned": int(owners_assigned),
            "owners_no_work": int(owners_no_work), "owners_pct": _p(owners_assigned, owners_total),
            "surface_total": int(surface_total),
            "mitigated": int(mit), "mitigated_pct": _p(mit, surface_total),
            "accepted": int(acc), "accepted_pct": _p(acc, surface_total),
            "ignored": int(ign), "ignored_pct": _p(ign, surface_total)}


def ownership_map(db_path=None) -> dict:
    """The Ownership Map — every route/path with the owners assigned to it (the Owner
    tag scheme '<name>: <user>'), the assets behind it, and a coverage status:
      owned   — every asset on it carries that route/path's Owner tag
      partial — some but not all of its assets are owned (too few owners)
      unowned — no owner at all
    Plus per-owner workload (routes/paths/assets each owner carries) and the count of
    assets on the attack surface with no owner. Read-only; feeds the network-thread graph."""
    def q(sql, args=()):
        try:
            return list(db.query(sql, args, path=db_path)) if args else list(db.query(sql, path=db_path))
        except Exception:
            return []
    if not q("SELECT name FROM sqlite_master WHERE type='table' AND name='vuln_route'"):
        return {"ok": True, "routes": [], "paths": [], "owners": [], "owner_load": [],
                "kpi": {"routes": 0, "paths": 0, "owners": 0, "unowned_assets": 0},
                "note": "No vuln_route/vuln_paths tables — run `navi config update route` + `navi config update paths`."}

    # Owner tags -> map a route/path NAME to its owners + the assets carrying that tag.
    # Keyed CASE-INSENSITIVELY (whitespace-collapsed) because owner tags are frequently
    # applied in a different case than navi's route app_name — e.g. an 'SIEMENS: …' tag
    # vs the 'Siemens' route, 'APACHE TOMCAT' vs 'Apache Tomcat'. An exact, case-sensitive
    # key silently drops those from the Sankey even though navi.db has the tag. The
    # value scheme is '<name>: <user>' (split on the LAST ': ' so Windows paths like
    # 'C:\...' survive).
    def _nk(s):
        return " ".join((s or "").strip().lower().split())
    name_owners, name_assets, name_display = {}, {}, {}
    for r in q("SELECT asset_uuid, tag_value FROM tags WHERE tag_key='Owner' AND tag_value IS NOT NULL"):
        val = (r.get("tag_value") or "").strip()
        au = r.get("asset_uuid")
        if ": " in val:
            name, user = val.rsplit(": ", 1)
        else:
            name, user = val, ""
        name, user = name.strip(), user.strip()
        k = _nk(name)
        name_display.setdefault(k, name)
        if user:
            name_owners.setdefault(k, set()).add(user)
        if au:
            name_assets.setdefault(k, set()).add(au)

    # route -> assets (via plugin_list membership) and path -> assets
    route_assets = {}
    for r in q(_RA + "SELECT app, au FROM ra"):
        if r.get("app"):
            route_assets.setdefault(r["app"], set()).add(r.get("au"))
    path_assets = {}
    for r in q("SELECT path, asset_uuid FROM vuln_paths WHERE path IS NOT NULL"):
        path_assets.setdefault(r["path"], set()).add(r.get("asset_uuid"))

    def _item(name, kind, assets):
        k = _nk(name)
        raw = name_owners.get(k, set())
        # split disposition sentinels (Ignored/Accepted/Mitigated) out of the real owners
        disp, real = None, set()
        for u in raw:
            lab = disposition_label(u)
            if lab:
                disp = lab
            else:
                real.add(u)
        owners = sorted(real)
        owned = len((name_assets.get(k, set()) & assets))   # always computed (never drop owners)
        total = len(assets)
        if disp and not owners:                             # disposition ONLY when no real owner
            status = disp.lower()                           # 'ignored' | 'accepted' | 'mitigated'
            # a route may have no plugin-membership assets but the disposition still tagged
            # some — size it by the tagged set so it shows on the Sankey (not filtered out).
            if total == 0:
                total = len(name_assets.get(k, set()))
        else:
            status = ("unowned" if (not owners or owned == 0)
                      else "partial" if owned < total else "owned")
        return {"name": name, "type": kind, "owners": owners, "owner_count": len(owners),
                "assets": total, "owned_assets": owned, "status": status, "disposition": disp}

    routes = [_item(r["app_name"], "route", route_assets.get(r["app_name"], set()))
              for r in q("SELECT DISTINCT app_name FROM vuln_route WHERE app_name IS NOT NULL")]
    paths = [_item(p, "path", a) for p, a in path_assets.items()]

    # ── Per-route/path threat scores: the HIGHEST VPR and HIGHEST CVSS3 on the route wins ──
    # VPR is stored per-finding in vulns.score (navi writes plugin['vpr']['score'] there); the
    # CVSS3 base score is stored per-plugin in plugins.cvss3_base_score. We roll BOTH up to the
    # route/path by taking the MAX across the plugins that define it, so the Ownership graphs can
    # filter to the biggest threats. Defensive: degrades to null (never errors) if a column or
    # table is missing / unscored — q() already returns [] on any query error.
    def _fnum(x):
        try:
            v = float(x)
            return v if v == v else None            # drop NaN
        except (TypeError, ValueError):
            return None
    vpr_by_pid = {}
    for r in q("SELECT plugin_id, MAX(score) m FROM vulns WHERE score IS NOT NULL GROUP BY plugin_id"):
        v = _fnum(r.get("m"))
        if v is not None:
            vpr_by_pid[str(r.get("plugin_id"))] = v
    cvss_by_pid = {}
    if q("SELECT 1 FROM pragma_table_info('plugins') WHERE name='cvss3_base_score'"):
        for r in q("SELECT plugin_id, cvss3_base_score c FROM plugins "
                   "WHERE cvss3_base_score IS NOT NULL AND cvss3_base_score NOT IN ('','None')"):
            v = _fnum(r.get("c"))
            if v is not None:
                cvss_by_pid[str(r.get("plugin_id"))] = v
    app_plugins = {}
    for r in q("SELECT app_name, plugin_list FROM vuln_route WHERE app_name IS NOT NULL"):
        app_plugins.setdefault(r.get("app_name"), set()).update(_plugin_ids(r.get("plugin_list")))
    path_plugin = {}
    for r in q("SELECT path, plugin_id FROM vuln_paths WHERE path IS NOT NULL"):
        path_plugin.setdefault(r.get("path"), set()).add(str(r.get("plugin_id")))

    def _maxscore(pids, table):
        vals = [table[p] for p in pids if p in table]
        return round(max(vals), 1) if vals else None
    for it in routes:
        pids = app_plugins.get(it["name"], set())
        it["vpr"] = _maxscore(pids, vpr_by_pid)
        it["cvss3"] = _maxscore(pids, cvss_by_pid)
    for it in paths:
        pids = path_plugin.get(it["name"], set())
        it["vpr"] = _maxscore(pids, vpr_by_pid)
        it["cvss3"] = _maxscore(pids, cvss_by_pid)

    # PLUGIN-MEDIATED route<->path link — the accurate relationship: a route's plugins
    # (plugin_list) found at a filesystem path (vuln_paths.plugin_id). One app/route can
    # cover MANY paths (e.g. a Jenkins route's plugins fire in many sub-dirs). This is the
    # true CVE→plugin→app→path chain, NOT the loose shared-asset proxy. Surfaces apps with
    # no filesystem-path detail and ORPHAN paths whose plugin belongs to no app.
    route_paths, path_routes = {}, {}
    for r in q("SELECT DISTINCT r.app_name app, vp.path path FROM vuln_route r "
               "JOIN vuln_paths vp ON r.plugin_list LIKE '%''' || vp.plugin_id || '''%'"):
        app, pth = r.get("app"), r.get("path")
        if app and pth:
            route_paths.setdefault(app, set()).add(pth)
            path_routes.setdefault(pth, set()).add(app)
    for it in routes:
        it["paths_on_route"] = len(route_paths.get(it["name"], set()))
    for it in paths:
        cov = path_routes.get(it["name"], set())
        it["routes"] = sorted(cov)                # which app(s) cover this path
        it["on_route"] = bool(cov)
    route_paths_list = {a: sorted(s) for a, s in route_paths.items()}
    orphan_paths = sorted(p["name"] for p in paths if not p["on_route"])

    routes.sort(key=lambda x: (-x["assets"], x["name"]))
    paths.sort(key=lambda x: (-x["assets"], x["name"]))

    # per-owner workload: routes, paths and distinct assets each owner carries
    load = {}
    for it in routes + paths:
        for o in it["owners"]:
            e = load.setdefault(o, {"owner": o, "routes": 0, "paths": 0, "assets": set()})
            e["routes" if it["type"] == "route" else "paths"] += 1
            e["assets"] |= (name_assets.get(_nk(it["name"]), set()))
    owner_load = sorted(([{"owner": e["owner"], "routes": e["routes"], "paths": e["paths"],
                           "assets": len(e["assets"])} for e in load.values()]),
                        key=lambda x: -(x["routes"] + x["paths"]))

    all_assets = set()
    for s in route_assets.values():
        all_assets |= s
    for s in path_assets.values():
        all_assets |= s
    tagged = {r["asset_uuid"] for r in q("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key='Owner'") if r.get("asset_uuid")}
    unowned_assets = len(all_assets - tagged)

    def kc(items, s):
        return sum(1 for i in items if i["status"] == s)

    # disposition tallies across routes+paths, with a % of the whole surface (items)
    surface = routes + paths
    n_items = len(surface) or 1
    n_ignored = sum(1 for i in surface if i["status"] == "ignored")
    n_accepted = sum(1 for i in surface if i["status"] == "accepted")
    n_mitigated = sum(1 for i in surface if i["status"] == "mitigated")
    # paths owned THROUGH a route — a path inherits ownership when the route covering it
    # (linked by shared plugin IDs) is fully owned. Distinct paths under any owned route.
    _owned_route_names = {r["name"] for r in routes if r.get("status") == "owned"}
    paths_via_route = len({p for a in _owned_route_names for p in route_paths.get(a, set())})

    def _pct(n):
        return round(100.0 * n / n_items, 1)

    # ===== Reduction funnel + champion plugin — the workload-reduction story:
    # CVE line-items -> findings -> plugins -> apps/routes. People chase CVEs (the most
    # duplicated work); owning apps collapses that. Champion = one fix clearing the most CVEs.
    funnel, champion = {}, None
    if q("SELECT name FROM sqlite_master WHERE type='table' AND name='plugins'"):
        fr = q("WITH present AS (SELECT DISTINCT plugin_id FROM vulns) "
               "SELECT (SELECT COUNT(*) FROM vulns) findings,(SELECT COUNT(*) FROM present) plugins,"
               "(SELECT COUNT(DISTINCT path) FROM vuln_paths) paths,(SELECT COUNT(DISTINCT app_name) FROM vuln_route) routes,"
               "(SELECT SUM((length(p.cves)-length(replace(p.cves,'CVE-','')))/4) FROM plugins p "
               "JOIN present ON present.plugin_id=p.plugin_id WHERE p.cves IS NOT NULL AND p.cves NOT IN ('','[]','None')) cves")
        if fr:
            row = fr[0]
            funnel = {"cves": int(row.get("cves") or 0), "findings": int(row.get("findings") or 0),
                      "plugins": int(row.get("plugins") or 0), "paths": int(row.get("paths") or 0),
                      "routes": int(row.get("routes") or 0)}
        cr = q("WITH present AS (SELECT DISTINCT plugin_id FROM vulns) "
               "SELECT p.plugin_id,p.name,(length(p.cves)-length(replace(p.cves,'CVE-','')))/4 cve_count,"
               "(SELECT COUNT(DISTINCT asset_uuid) FROM vulns v WHERE v.plugin_id=p.plugin_id) assets "
               "FROM plugins p JOIN present ON present.plugin_id=p.plugin_id "
               "WHERE p.cves IS NOT NULL AND p.cves NOT IN ('','[]','None') ORDER BY cve_count DESC LIMIT 1")
        if cr:
            c = cr[0]
            champion = {"plugin_id": c.get("plugin_id"), "name": c.get("name"),
                        "cve_count": int(c.get("cve_count") or 0), "assets": int(c.get("assets") or 0)}

    # Owner tags that DON'T map to any route or path — surfaced (not silently dropped) so
    # you can see exactly what's not landing on the Sankey and why. These are usually tags
    # whose app-name was truncated/abbreviated differently from navi's route app_name
    # (e.g. 'WEB SERVER' vs 'Web Server Allows', 'ROCKWELL AUTOMATION' vs 'Rockwell
    # Automation RSLinx'). We suggest the closest route/path but never auto-attach — a wrong
    # owner is worse than a visible gap. Re-tag with the exact route name to land them.
    graph_keys = {_nk(r["name"]) for r in routes} | {_nk(p["name"]) for p in paths}
    pool = [r["name"] for r in routes] + [p["name"] for p in paths]

    def _closest(nm):
        n = _nk(nm)
        pre = [x for x in pool if _nk(x).startswith(n) or n.startswith(_nk(x))]
        cand = pre or [x for x in pool if n and (n in _nk(x) or _nk(x) in n)]
        return sorted(set(cand), key=len)[:2]

    unmatched = [{"name": name_display.get(k, k), "owners": sorted(ow),
                  "assets": len(name_assets.get(k, set())), "suggestions": _closest(name_display.get(k, k))}
                 for k, ow in name_owners.items() if k not in graph_keys]
    unmatched.sort(key=lambda x: -x["assets"])

    _vpr_vals = [it["vpr"] for it in routes + paths if it.get("vpr") is not None]
    _cvss_vals = [it["cvss3"] for it in routes + paths if it.get("cvss3") is not None]
    return {"ok": True, "routes": routes, "paths": paths,
            "owners": sorted({o for it in routes + paths for o in it["owners"]}),
            "owner_load": owner_load, "unmatched_owners": unmatched,
            "route_paths": route_paths_list, "orphan_paths": orphan_paths,
            "funnel": funnel, "champion": champion,
            "scores": {"vpr": bool(_vpr_vals), "cvss3": bool(_cvss_vals),
                       "vpr_max": round(max(_vpr_vals), 1) if _vpr_vals else None,
                       "cvss3_max": round(max(_cvss_vals), 1) if _cvss_vals else None},
            "kpi": {"routes": len(routes), "routes_unowned": kc(routes, "unowned"),
                    "routes_partial": kc(routes, "partial"), "routes_owned": kc(routes, "owned"),
                    "paths": len(paths), "paths_unowned": kc(paths, "unowned"),
                    "paths_partial": kc(paths, "partial"), "paths_owned": kc(paths, "owned"),
                    "paths_via_route": int(paths_via_route),
                    "owners": len(owner_load), "unowned_assets": unowned_assets,
                    "ignored": n_ignored, "ignored_pct": _pct(n_ignored),
                    "accepted": n_accepted, "accepted_pct": _pct(n_accepted),
                    "mitigated": n_mitigated, "mitigated_pct": _pct(n_mitigated),
                    "routes_ignored": kc(routes, "ignored"), "paths_ignored": kc(paths, "ignored"),
                    "routes_accepted": kc(routes, "accepted"), "paths_accepted": kc(paths, "accepted"),
                    "routes_mitigated": kc(routes, "mitigated"), "paths_mitigated": kc(paths, "mitigated"),
                    "owners_unmatched": len(unmatched), "asset_scope": len(all_assets),
                    "routes_no_paths": sum(1 for r in routes if r.get("paths_on_route", 0) == 0),
                    "routes_with_paths": sum(1 for r in routes if r.get("paths_on_route", 0) > 0),
                    "paths_orphan": len(orphan_paths),
                    "paths_covered": sum(1 for p in paths if p.get("on_route"))}}


def path_detail(path):
    """Drill-down for a single filesystem path (a newly-found gap): which assets carry it,
    their findings/plugins, and the owner(s) of the app(s) that cover it — so Gabriel can
    email the gap to the right person."""
    from core import db
    if not path:
        return {"ok": False, "error": "path required"}
    dbp = db.db_path()

    def q(sql, args=()):
        try:
            return list(db.query(sql, args, path=dbp))
        except Exception:
            return []

    rows = q("SELECT vp.asset_uuid au, vp.plugin_id pid, vp.finding_id fid, a.hostname host, "
             "a.ip_address ip, a.acr acr, a.url url FROM vuln_paths vp "
             "LEFT JOIN assets a ON a.uuid=vp.asset_uuid WHERE vp.path=?", (path,))
    by, findings, plugins = {}, set(), set()
    for r in rows:
        u = r.get("au")
        e = by.setdefault(u, {"uuid": u, "hostname": r.get("host"), "ip": r.get("ip"),
                              "acr": r.get("acr"), "url": r.get("url"), "plugins": set(), "findings": set()})
        if r.get("pid"):
            e["plugins"].add(str(r["pid"])); plugins.add(str(r["pid"]))
        if r.get("fid"):
            e["findings"].add(str(r["fid"])); findings.add(str(r["fid"]))
    assets = [{"uuid": e["uuid"], "hostname": e["hostname"], "ip": e["ip"], "acr": e["acr"],
               "url": e["url"], "plugins": len(e["plugins"]), "findings": sorted(e["findings"])}
              for e in by.values()]
    assets.sort(key=lambda x: -(float(x["acr"]) if x["acr"] else 0))
    apps = [r["app"] for r in q("SELECT DISTINCT r.app_name app FROM vuln_route r JOIN vuln_paths vp "
            "ON r.plugin_list LIKE '%''' || vp.plugin_id || '''%' WHERE vp.path=?", (path,)) if r.get("app")]
    owners = set()
    apps_ci = {a.strip().lower() for a in apps}
    for r in q("SELECT DISTINCT tag_value FROM tags WHERE tag_key='Owner' AND tag_value IS NOT NULL"):
        val = (r.get("tag_value") or "").strip()
        if ": " in val:
            nm, us = val.rsplit(": ", 1)
            if nm.strip().lower() in apps_ci and us.strip():
                owners.add(us.strip())
    return {"ok": True, "path": path, "apps": sorted(apps), "owners": sorted(owners),
            "assets": assets, "plugins": sorted(plugins), "findings": sorted(findings),
            "asset_count": len(assets)}


class ExpRouteAgent(Agent):
    id = "exproute"
    name = "Exposure Routes"
    icon = "🧭"
    description = ("Pulls users & groups (navi, Tenable MCP backup) and maps exposure "
                  "routes & paths to owners from plain English; tags Owner:<group/user>.")

    def summary(self):
        if not self.result:
            return {}
        c = self.result.get("counts", {})
        return {"owners": c.get("owners"), "routes": c.get("routes"), "paths": c.get("paths")}

    def _run(self, db_path=None, **kwargs):
        ow, rt, pa = owners(), routes(db_path), paths(db_path)
        return {"owners": ow, "routes": rt, "paths": pa,
                "counts": {"owners": len(ow), "routes": len(rt), "paths": len(pa)}}
