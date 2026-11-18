"""Command & Control (Amarok) — self-contained HTTP actions over ``navi action push``.

Read-only: status, hosts, precheck, plan, verify, log.
Executes (gated + confirm): command, push_file, campaign.
The push itself is triple-gated in core/navi_cli.py; this layer adds the operator
workflow — Linux-only host discovery, the destructive-command force step, armed
canary-first batches with an abort switch, and vuln→host patch derivation.
"""
import base64
import hashlib
import json
import os
import re
import threading
import time
import uuid

from core import db, navi_cli, c2_catalog, c2_targets, c2log, c2_remediate, hx_summary, c2_verdict, c2_hostkeys
from .agent import C2Agent
from core.gates import confirmed, flag

AGENT = C2Agent()

# Uploaded files land here (repo_root/data/c2_uploads) so `navi action push --file`
# has a real local path to scp. A push may only ship a file from THIS directory.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_UPLOAD_DIR = os.path.join(_REPO_ROOT, "data", "c2_uploads")
_MAX_UPLOAD = int(os.environ.get("NAVI_C2_MAX_UPLOAD", str(25 * 1024 * 1024)))
# Total bytes kept in the upload dir; the oldest uploads are pruned to make room.
_MAX_UPLOAD_TOTAL = int(os.environ.get("NAVI_C2_MAX_UPLOAD_TOTAL", str(200 * 1024 * 1024)))

# Campaign abort registry — a running _bulk_push checks this between hosts so an
# in-flight batch can be halted (tagq has no native cancel).
_ABORT = set()
_ABORT_LOCK = threading.Lock()
# fix round (linux F8 / sec 5): any multi-host run stops new SSH attempts after this many failed logins — one
# failure per host across 200 hosts can lock a directory-backed (AD / LDAP / FreeIPA) service account
MAX_AUTH_FAILURES = 3


# --------------------------------------------------------------------------- #
#  Host discovery + OS classification (push is Linux/SSH only)
# --------------------------------------------------------------------------- #
def _cols(table, db_path=None):
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}")', path=db_path)}
    except Exception:
        return set()


def _classify_os(os_str):
    s = (os_str or "").lower()
    if not s:
        return "unknown"
    if any(k in s for k in ("linux", "ubuntu", "debian", "centos", "red hat", "redhat", "rhel",
                            "fedora", "suse", "amazon linux", "oracle linux", "rocky", "almalinux",
                            "alma linux", "gentoo", "arch")):
        return "linux"
    if "windows" in s or "microsoft" in s:
        return "windows"
    if any(k in s for k in ("cisco", "ios", "juniper", "junos", "palo alto", "pan-os", "fortinet",
                            "fortios", "arista", "big-ip", "f5", "switch", "router", "firewall")):
        return "network"
    if any(k in s for k in ("vmware", "esxi", "hypervisor")):
        return "hypervisor"
    if any(k in s for k in ("mac os", "macos", "darwin", "os x")):
        return "macos"
    return "other"


def _hosts_raw(db_path=None):
    cols = _cols("assets", db_path)
    ipc = "ip_address" if "ip_address" in cols else ("ip" if "ip" in cols else None)
    sel = ["uuid"]
    sel.append(f'"{ipc}" AS ip' if ipc else "'' AS ip")
    sel.append('hostname AS hostname' if "hostname" in cols else "'' AS hostname")
    sel.append('operating_system AS os' if "operating_system" in cols else "'' AS os")
    sel.append('acr AS acr' if "acr" in cols else "NULL AS acr")
    try:
        rows = db.query(f'SELECT {", ".join(sel)} FROM assets', path=db_path)
    except Exception:
        return []
    out = []
    for r in rows:
        acr = r.get("acr")
        try:
            acrn = float(acr) if acr not in (None, "") else None
        except (TypeError, ValueError):
            acrn = None
        out.append({"uuid": r.get("uuid"), "ip": (r.get("ip") or "").strip(),
                    "hostname": r.get("hostname") or "", "os": r.get("os") or "",
                    "os_class": _classify_os(r.get("os")), "acr": acrn,
                    "crown": (acrn is not None and acrn >= 9)})
    return out


def _linux_hosts(db_path=None):
    return [h for h in _hosts_raw(db_path) if h["os_class"] == "linux" and h["ip"]]


def _breakdown(hs):
    b = {}
    for h in hs:
        b[h["os_class"]] = b.get(h["os_class"], 0) + 1
    return b


# --------------------------------------------------------------------------- #
#  Scale path (build 455): nothing on open reads every asset into Python or ships
#  every host. OS classes come from a GROUP BY over the distinct OS strings (cached
#  per navi.db signature); the host picker is a server-side search (keyset pages of
#  ≤ 200); patch-from-vuln resolves the selector on the PLUGIN dimension first and
#  reads only the matched plugins' findings through hx_v_plugin.
# --------------------------------------------------------------------------- #
_WS = "' '||char(9)||char(10)||char(11)||char(12)||char(13)"   # Python str.strip()'s ASCII set
_SIG_CACHE = {}
_SIG_LOCK = threading.Lock()
_HOST_CAP = 500           # plan(): hosts shipped per list (counts stay exact)


def _sig_cached(kind, db_path, build):
    """build() once per navi.db file signature (navi replacing / rewriting the file refreshes it)."""
    p = db_path or db.db_path()
    try:
        sig = db._sig(p)
    except Exception:
        return build()
    with _SIG_LOCK:
        hit = _SIG_CACHE.get((kind, p))
        if hit and hit[0] == sig:
            return hit[1]
    v = build()
    with _SIG_LOCK:
        _SIG_CACHE[(kind, p)] = (sig, v)
    return v


def _asset_sql(db_path=None):
    """(select-list, ip expression, os expression) for the assets table — _hosts_raw's columns."""
    cols = _cols("assets", db_path)
    ipc = "ip_address" if "ip_address" in cols else ("ip" if "ip" in cols else None)
    ip = f'"{ipc}"' if ipc else "''"
    os_ = "operating_system" if "operating_system" in cols else "''"
    sel = ", ".join(["uuid", f"{ip} AS ip", ("hostname" if "hostname" in cols else "''") + " AS hostname",
                     f"{os_} AS os", ("acr" if "acr" in cols else "NULL") + " AS acr"])
    return sel, ip, os_, bool(cols)


def _host(r):
    """One assets row → the host dict _hosts_raw builds (same rules)."""
    acr = r.get("acr")
    try:
        acrn = float(acr) if acr not in (None, "") else None
    except (TypeError, ValueError):
        acrn = None
    return {"uuid": r.get("uuid"), "ip": (r.get("ip") or "").strip(),
            "hostname": r.get("hostname") or "", "os": r.get("os") or "",
            "os_class": _classify_os(r.get("os")), "acr": acrn,
            "crown": (acrn is not None and acrn >= 9)}


def _os_stats(db_path=None):
    """{linux, excluded, breakdown, linux_os:[the distinct OS strings classified linux]} —
    _classify_os applied to each DISTINCT operating_system (hundreds), counts summed in SQL."""
    def build():
        sel, ip, os_, ok = _asset_sql(db_path)
        if not ok:
            return {"linux": 0, "excluded": 0, "breakdown": {}, "linux_os": []}
        rows = db.query(f"SELECT {os_} AS os, COUNT(*) AS n, SUM(TRIM(COALESCE({ip},''),{_WS})<>'') AS n_ip "
                        f"FROM assets GROUP BY 1", path=db_path, budget="run")
        lin, lin_os, bd, total = 0, [], {}, 0
        for r in rows:
            cls, n, nip = _classify_os(r.get("os")), int(r.get("n") or 0), int(r.get("n_ip") or 0)
            total += n
            rest = n
            if cls == "linux":
                lin_os.append(r.get("os"))
                lin += nip
                rest = n - nip
            if rest:
                bd[cls] = bd.get(cls, 0) + rest
        return {"linux": lin, "excluded": total - lin, "breakdown": bd, "linux_os": lin_os}
    return _sig_cached("os_stats", db_path, build)


def _linux_where(st, ip):
    """SQL + params selecting the Linux hosts that have an IP (the push-able set)."""
    return (f"operating_system IN (SELECT value FROM json_each(?)) AND TRIM(COALESCE({ip},''),{_WS})<>''",
            [json.dumps(st["linux_os"])])


def _host_page(q="", limit=50, after=0, db_path=None):
    """One keyset page (rowid > after, assets-table order — the order the old list had) of
    Linux hosts with an IP, optionally filtered: q is matched like the page's old client-side
    filter (substring of 'ip hostname os', case-insensitive) or an exact uuid. → (hosts, next)."""
    st = _os_stats(db_path)
    sel, ip, os_, ok = _asset_sql(db_path)
    if not ok or not st["linux_os"] or os_ == "''":
        return [], None
    w, params = _linux_where(st, ip)
    w = "rowid > ? AND " + w
    params = [int(after or 0)] + params
    if q:
        w += (f" AND (instr(lower(TRIM(COALESCE({ip},''),{_WS})||' '||COALESCE(hostname,'')||' '||"
              f"COALESCE(operating_system,'')), ?) > 0 OR uuid = ?)")
        params += [q.lower(), q]
    rows = db.query(f"SELECT rowid AS _rid, {sel} FROM assets WHERE {w} ORDER BY rowid LIMIT ?",
                    tuple(params) + (limit + 1,), path=db_path, budget="open")
    nxt = rows[limit - 1]["_rid"] if len(rows) > limit else None
    return [_host(r) for r in rows[:limit]], nxt


def _hosts_where(where, params=(), db_path=None, budget="open"):
    """Hosts for a WHERE over assets, in assets-table order."""
    sel, _ip, _os, ok = _asset_sql(db_path)
    if not ok:
        return []
    return [_host(r) for r in db.query(f"SELECT {sel} FROM assets WHERE {where} ORDER BY rowid",
                                       tuple(params), path=db_path, budget=budget)]


_LIKE_CACHE = {}


class _Like:
    """SQLite `LIKE '%pat%'` (ASCII case-insensitive; % and _ wildcards) without backtracking:
    the pattern is split on % into fixed-length segments ('_' = any one char) that must occur in
    order — linear in the text, so a selector like '_%_%_%_%…' can't pin a thread (a translated
    '.*' regex backtracks exponentially). Earliest match per segment is correct because every
    segment has a fixed length."""

    __slots__ = ("segs",)

    def __init__(self, pat):
        self.segs = [re.compile("".join("." if ch == "_" else re.escape(ch) for ch in seg), re.S)
                     for seg in _alower(pat)[:200].split("%") if seg]

    def search(self, text):
        pos = 0
        for rx in self.segs:
            m = rx.search(text, pos)
            if m is None:
                return None
            pos = m.end()
        return True


def _like(pat):
    rx = _LIKE_CACHE.get(pat)
    if rx is None:
        rx = _Like(pat)
        if len(_LIKE_CACHE) > 200:
            _LIKE_CACHE.clear()
        _LIKE_CACHE[pat] = rx
    return rx


def _alower(s):
    return str(s).translate(_ASCII_LOWER)


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _plugin_dim(db_path=None):
    """({plugin_id: [(name, family, cves), …]}, {plugin_id: vulns plugin_name}) — the plugin dimension the selector is matched on:
    navi's `plugins` table (when synced) plus, with hx_v_plugin, one row per plugin present in
    vulns (DISTINCT over the narrow index + one seek each; cached per navi.db signature). None
    when navi.db has no hx_v_plugin index (plan() then falls back to the row-level scan)."""
    if not db.has_index("hx_v_plugin", db_path):
        return None
    vc = _cols("vulns", db_path)

    def build():
        dim, vnames = {}, {}
        pc = _cols("plugins", db_path)
        if "plugin_id" in pc:
            nm = "name" if "name" in pc else ("plugin_name" if "plugin_name" in pc else "NULL")
            fm = "family" if "family" in pc else ("plugin_family" if "plugin_family" in pc else "NULL")
            cv = "cves" if "cves" in pc else "NULL"
            for r in db.iter(f"SELECT plugin_id, {nm} AS n, {fm} AS f, {cv} AS c FROM plugins",
                             path=db_path, budget="run", tuples=True):
                if r[0] not in (None, ""):
                    dim.setdefault(str(r[0]), []).append((r[1], r[2], r[3]))
        nm = "plugin_name" if "plugin_name" in vc else "NULL"
        fm = "plugin_family" if "plugin_family" in vc else "NULL"
        cv = "cves" if "cves" in vc else "NULL"
        ib = db.indexed_by("hx_v_plugin", db_path)
        if hx_summary.usable(db_path):
            # ⚡ Optimize's hx_plugin IS this list (one representative finding per plugin) —
            # a ~100 B/plugin read instead of a DISTINCT over the index + one seek per plugin
            sql = ("SELECT plugin_id, name, family, cves FROM hx_plugin" if "NULL" not in (nm, fm, cv)
                   else "SELECT plugin_id, NULL, NULL, NULL FROM hx_plugin")
        else:
            sql = (f"SELECT d.plugin_id, v.{nm}, v.{fm}, v.{cv} FROM "
                   f"(SELECT DISTINCT plugin_id FROM vulns{ib}) d JOIN vulns v ON v.rowid = "
                   f"(SELECT rowid FROM vulns{ib} WHERE plugin_id = d.plugin_id LIMIT 1)"
                   if "NULL" not in (nm, fm, cv) else
                   f"SELECT DISTINCT plugin_id, NULL, NULL, NULL FROM vulns{ib}")
        try:
            for r in db.iter(sql, path=db_path, budget="run", tuples=True):
                if r[0] not in (None, ""):
                    dim.setdefault(str(r[0]), []).append((r[1], r[2], r[3]))
                    vnames[str(r[0])] = r[1]
        except db.QueryTimeout:
            # a navi.db too big to list its plugins inside the run budget: match on navi's
            # plugins table alone (+ the exact plugin-id seek in plan()); names come from it too
            if not dim:
                raise
            vnames = {pid: a[0][0] for pid, a in dim.items() if a and a[0][0]}
        return dim, vnames
    return _sig_cached("plugin_dim", db_path, build)


def _match_plugins(sel, dim, vcols):
    """Plugin ids whose id equals the selector, or whose name / CVEs / family contain it — the
    same predicates plan() applied row by row, evaluated once per plugin."""
    rx = _like(sel)
    out = []
    for pid, attrs in dim.items():
        if "plugin_id" in vcols and pid == sel:
            out.append(pid)
            continue
        for n, f, c in attrs:
            if ("plugin_name" in vcols and n is not None and rx.search(_alower(n))) or \
               ("cves" in vcols and c is not None and rx.search(_alower(c))) or \
               ("plugin_family" in vcols and f is not None and rx.search(_alower(f))):
                out.append(pid)
                break
    return out


# --------------------------------------------------------------------------- #
#  Read-only actions
# --------------------------------------------------------------------------- #
def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def load(p):
    return run(p)


def status(p):
    return {"ok": True, **navi_cli.push_status(), "ssh": dict(db.ssh_status(), user=_ssh_user()),
            "known_hosts": c2_hostkeys.locate()}, 200


def hosts(p):
    """Host picker: counts over the whole estate + ONE page (≤ 200, default 50) of Linux hosts
    with an IP — `q` searches IP / hostname / OS (substring) or an exact uuid server-side,
    `after` is the keyset token from the previous page's `next`."""
    q = str(p.get("q") or "").strip()[:200]
    limit = _int(p.get("limit"), 50, 1, 200)
    after = _int(p.get("after"), 0, 0, 2 ** 62)
    try:
        st = _os_stats()
        page, nxt = _host_page(q, limit, after)
    except db.QueryTimeout as e:
        return {**db.budget_payload(e), **navi_cli.push_status()}, 200
    except Exception:
        st, page, nxt = {"linux": 0, "excluded": 0, "breakdown": {}}, [], None
    return {"ok": True, "linux": page, "linux_count": st["linux"], "q": q, "next": nxt,
            "excluded_count": st["excluded"], "excluded_breakdown": st["breakdown"],
            **navi_cli.push_status()}, 200


def precheck(p):
    """Read-only safety review of a proposed command + target: destructive-command
    denylist, OS class (Linux-only), crown-jewel flag, and a secret-in-command warning."""
    cmd = (p.get("command") or "").strip()
    target = (p.get("target") or "").strip()
    dangers = navi_cli.scan_command(cmd) if cmd else []
    host = None
    if target:
        # build 485: the same lookup the push choke point uses (IP OR hostname, case-insensitive) — a
        # hostname that IS in navi.db is no longer reported as "not found" (sec MUST 6, API change 6)
        try:
            _sel, ip, _os, _ok = _asset_sql()
            hs = _hosts_where(f"TRIM(COALESCE({ip},''),{_WS}) = ? OR uuid = ?", (target, target))
            host = hs[0] if hs else c2_targets.lookup(target)
        except Exception:
            host = None
    warnings = []
    if host:
        if host["os_class"] != "linux":
            warnings.append(f"target is classified '{host['os_class']}', not Linux — navi push is "
                            "Linux/SSH only; this will likely fail or misbehave")
        if host["crown"]:
            warnings.append(f"target is a CROWN JEWEL (ACR {host['acr']}) — production-critical; "
                            "treat as a change-window operation")
    elif target:
        warnings.append("target not found in navi.db — confirm it's a real, Linux, in-scope host "
                        "before pushing")
    secret = bool(re.search(r"(?i)(password|passwd|token|secret|api[_-]?key|--pass\b|BEGIN [A-Z ]*PRIVATE KEY)", cmd))
    kind = c2_targets.classify(target)["kind"] if target else ""
    return {"ok": True, "dangers": dangers, "danger": bool(dangers), "host": host, "kind": kind,
            "warnings": warnings, "secret_risk": secret}, 200


def plan(p):
    """Patch-from-vuln: find the hosts a plugin/CVE/software keyword affects and offer
    OS-appropriate, EDITABLE remediation templates. Read-only — nothing executes here."""
    sel = (p.get("selector") or "").strip()
    if not sel:
        return {"ok": False, "error": "enter a plugin id, CVE, or software keyword"}, 400
    vcols = _cols("vulns")
    ors, params = [], []
    if "plugin_id" in vcols:
        ors.append("CAST(plugin_id AS TEXT)=?")
        params.append(sel)
    if "plugin_name" in vcols:
        ors.append("plugin_name LIKE ?")
        params.append(f"%{sel}%")
    if "cves" in vcols:
        ors.append("cves LIKE ?")
        params.append(f"%{sel}%")
    if "plugin_family" in vcols:
        ors.append("plugin_family LIKE ?")
        params.append(f"%{sel}%")
    if not ors:
        return {"ok": False, "error": "vulns table not available in navi.db"}, 200
    opened = " AND UPPER(COALESCE(state,'OPEN')) IN ('OPEN','REOPENED')" if "state" in vcols else ""
    try:
        dim = _plugin_dim()
    except db.QueryTimeout:
        dim = None
    except Exception:
        dim = None
    try:
        if dim is not None:
            # plugin-first: the selector is matched on the plugin dimension, then only the matched
            # plugins' open findings are read — index-only via hx_v_plugin(plugin_id, asset_uuid, state)
            dim, vnames = dim
            mp = _match_plugins(sel, dim, vcols)
            if "plugin_id" in vcols and sel not in mp and db.scalar(
                    f"SELECT 1 FROM vulns{db.indexed_by('hx_v_plugin')} WHERE plugin_id=? LIMIT 1", (sel,), budget="open"):
                mp.append(sel)              # a plugin id navi's plugins table doesn't list
            ib = db.indexed_by("hx_v_plugin")
            vin = f"FROM vulns{ib} WHERE plugin_id IN (SELECT value FROM json_each(?)){opened}"
            jp = (json.dumps(mp),)
            pr = db.query(f"SELECT DISTINCT plugin_id {vin}", jp, budget="run") if mp else []
            pids = {str(r["plugin_id"]) for r in pr if r.get("plugin_id") not in (None, "")}
            names = sorted({vnames.get(pid) for pid in pids if vnames.get(pid)})[:8]
            n_uuids = int(db.scalar(f"SELECT COUNT(DISTINCT asset_uuid) {vin} AND asset_uuid IS NOT NULL "
                                    f"AND asset_uuid<>''", jp, budget="run") or 0) if mp else 0
            hit_where = f"uuid IN (SELECT asset_uuid {vin})"
        else:
            wsql = "(" + " OR ".join(ors) + ")" + opened
            rows = db.query(f"SELECT DISTINCT asset_uuid, plugin_id, plugin_name FROM vulns WHERE {wsql}",
                            tuple(params), budget="run")
            uuids = sorted({r["asset_uuid"] for r in rows if r.get("asset_uuid")})
            pids = {str(r.get("plugin_id")) for r in rows if r.get("plugin_id") not in (None, "")}
            names = sorted({r.get("plugin_name") for r in rows if r.get("plugin_name")})[:8]
            n_uuids, jp = len(uuids), (json.dumps(uuids),)
            hit_where = "uuid IN (SELECT value FROM json_each(?))"
        linux, excluded, n_lin, n_exc = [], [], 0, 0
        if n_uuids:
            sel_, _ip, _os, ok = _asset_sql()
            for r in (db.iter(f"SELECT {sel_} FROM assets WHERE {hit_where} ORDER BY rowid", jp,
                              budget="run") if ok else ()):
                h = _host(r)
                if h["os_class"] == "linux" and h["ip"]:
                    n_lin += 1
                    if len(linux) < _HOST_CAP:
                        linux.append(h)
                else:
                    n_exc += 1
                    if len(excluded) < _HOST_CAP:
                        excluded.append(h)
    except db.QueryTimeout as e:
        return db.budget_payload(e), 200
    except Exception as e:
        return {"ok": False, "error": f"query failed: {e}"}, 200
    sols = _solutions(pids)                 # Tenable's OWN remediation text, from the plugins table
    pkg = _guess_pkg(sel, names, sols)
    # build 485: the package the pre-flight checks (the fixed version comes from the generated plan — plan()
    # itself never reads vulns.output, the scale rule)
    fixed = {"package": pkg, "fixed_version": "", "compare": ""}
    return {"ok": True, "selector": sel, "matched_assets": n_uuids, "plugin_names": names, "fixed": fixed,
            "linux_hosts": linux, "linux_count": n_lin, "excluded": excluded, "excluded_count": n_exc,
            "truncated": n_lin > len(linux) or n_exc > len(excluded),
            "package_guess": pkg, "templates": _remediation_templates(pkg),
            "solutions": sols["items"], "solutions_available": sols["available"],
            "solutions_note": sols["note"],
            "note": "Templates apply Tenable's stated Solution shown below — verify the package + "
                    "target version per host. A CVE does not map 1:1 to a safe command."}, 200


def _solutions(plugin_ids):
    """Pull Tenable's own remediation text from the plugins table (plugins.solution),
    keyed by plugin_id — the authoritative fix per matched plugin. The plugins table is a
    SEPARATE, optional sync (`navi config update plugins --size 10000`); degrade gracefully
    when it's absent, has no `solution` column (minimal fixture), or is unpopulated."""
    pids = [str(x) for x in (plugin_ids or []) if str(x)]
    cols = _cols("plugins")
    if not pids or "plugin_id" not in cols or "solution" not in cols:
        return {"available": False, "items": [],
                "note": "Tenable's Solution text isn't available — the plugins table isn't populated. "
                        "Run `navi config update plugins --size 10000` to ground remediation in "
                        "Tenable's stated fix; falling back to OS templates + a package guess."}
    # build 486 (linux §5 data issue): navi's real plugins table calls the title `name`
    fields = "plugin_id, solution" + (", plugin_name" if "plugin_name" in cols else (", name AS plugin_name" if "name" in cols else "")) \
             + (", description" if "description" in cols else "")
    inl = ",".join("?" * len(pids))
    try:
        rows = db.query(f"SELECT {fields} FROM plugins WHERE CAST(plugin_id AS TEXT) IN ({inl})", tuple(pids))
    except Exception as e:
        return {"available": False, "items": [], "note": f"plugins table lookup failed: {e}"}
    items = []
    for r in rows:
        sol = (r.get("solution") or "").strip()
        if not sol:
            continue
        items.append({"plugin_id": str(r.get("plugin_id")), "plugin_name": r.get("plugin_name") or "",
                      "solution": sol[:1500], "fix_hint": _fix_hint(sol)})
    items.sort(key=lambda x: x["plugin_id"])
    return {"available": bool(items), "items": items[:12],
            "note": ("" if items else "Matched plugins have no Solution text stored — re-run "
                     "`navi config update plugins --size 10000`.")}


def _fix_hint(solution):
    """Best-effort target-version pulled from the Solution prose (advisory, not authoritative)."""
    s = solution or ""
    m = re.search(r"(?:upgrade|update|install)\s+to\s+(?:version\s+)?([A-Za-z][\w.+-]*\s+)?"
                  r"([0-9]+(?:\.[0-9]+){1,3})", s, re.I)
    if m:
        pkgpart = (m.group(1) or "").strip()
        return ("target ≥ " + ((pkgpart + " ") if pkgpart else "") + m.group(2)).strip()
    m2 = re.search(r"\b([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})\b", s)
    return ("version referenced: " + m2.group(1)) if m2 else ""


def _guess_pkg(sel, names, sols=None):
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9._+-]{1,40}", sel or "") and not sel.upper().startswith("CVE"):
        return sel.lower()
    blob = " ".join(names or []).lower()
    if sols and sols.get("items"):
        blob += " " + " ".join((it.get("solution") or "") for it in sols["items"]).lower()
    for k in ("openssl", "openssh", "nginx", "apache", "httpd", "log4j", "bash", "glibc", "curl",
              "sudo", "kernel", "python", "java", "tomcat", "mysql", "postgresql", "samba"):
        if k in blob:
            return k
    return ""


def _remediation_templates(pkg):
    """Static suggestions — build 486 (linux review rec. 10): the SAME validated per-family forms the template plan
    uses (one command each, no `&&` / `||` chains, non-interactive dpkg options and bounded lock waits)."""
    p = pkg or "<package>"
    return [
        {"os": "Debian / Ubuntu",
         "cmd": "sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install --only-upgrade -y "
                f"{c2_remediate.APT_OPTS} {p}"},
        {"os": "RHEL / CentOS / Rocky / Alma 8+ · Amazon Linux 2023", "cmd": f"sudo dnf -y upgrade {p}"},
        {"os": "RHEL / CentOS 7 · Amazon Linux 1 / 2", "cmd": f"sudo yum {c2_remediate.YUM_LOCK_OPT} -y update {p}"},
        {"os": "SUSE", "cmd": f"sudo ZYPP_LOCK_TIMEOUT={c2_remediate.LOCK_WAIT} zypper --non-interactive update {p}"},
    ]


def verify(p):
    """Route→Tag→Push→VERIFY: re-check the local vulns table for a selector across the
    given hosts. Read-only. Reads navi.db as-is — advise a re-scan + vuln sync first."""
    sel = (p.get("selector") or "").strip()
    targets = [str(x).strip() for x in (p.get("hosts") or []) if str(x).strip()]
    if not sel:
        return {"ok": False, "error": "selector required"}, 400
    vcols = _cols("vulns")
    ors, params = [], []
    if "plugin_id" in vcols:
        ors.append("CAST(plugin_id AS TEXT)=?")
        params.append(sel)
    if "plugin_name" in vcols:
        ors.append("plugin_name LIKE ?")
        params.append(f"%{sel}%")
    if "cves" in vcols:
        ors.append("cves LIKE ?")
        params.append(f"%{sel}%")
    if not ors:
        return {"ok": False, "error": "vulns table not available"}, 200
    wsql = "(" + " OR ".join(ors) + ")"
    if "state" in vcols:
        wsql += " AND UPPER(COALESCE(state,'OPEN')) IN ('OPEN','REOPENED')"
    try:
        _sel, ip, _os, _ok = _asset_sql()
        uuids = [h["uuid"] for h in _hosts_where(
            f"TRIM(COALESCE({ip},''),{_WS}) IN (SELECT value FROM json_each(?)) OR uuid IN "
            f"(SELECT value FROM json_each(?))", (json.dumps(targets), json.dumps(targets)))] if _ok else []
    except Exception:
        uuids = []
    still = []
    if uuids:
        inl = ",".join("?" * len(uuids))
        try:
            rows = db.query(f"SELECT DISTINCT asset_uuid FROM vulns WHERE {wsql} AND asset_uuid IN ({inl})",
                            tuple(params) + tuple(uuids))
            still = [r["asset_uuid"] for r in rows]
        except Exception as e:
            return {"ok": False, "error": f"query failed: {e}"}, 200
    return {"ok": True, "selector": sel, "checked_hosts": len(uuids), "still_open": len(still),
            "clear": len(still) == 0,
            "note": "This reads the LOCAL vulns table. Run a verification scan + "
                    "`navi config update vulns` first, or the finding may look open until the next "
                    "sync. When clear, retire the campaign tag (Garmr)."}, 200


def log(p):
    from core import tagq
    entries = [j for j in tagq.list_jobs() if j.get("op") == "push"]
    return {"ok": True, "entries": entries[: int(p.get("limit") or 50)]}, 200


def refresh(p):
    """Background `navi config update assets vulns` so post-patch state lands locally."""
    r = navi_cli.update_async(("assets", "vulns"))
    return {"ok": bool(r.get("ok")), **r}, 200


# --------------------------------------------------------------------------- #
#  Executing actions (gated + confirm)
# --------------------------------------------------------------------------- #
def _prune_uploads(need):
    """Delete the oldest uploads until `need` more bytes fit under _MAX_UPLOAD_TOTAL."""
    try:
        files = [os.path.join(_UPLOAD_DIR, f) for f in os.listdir(_UPLOAD_DIR)]
        files = [f for f in files if os.path.isfile(f)]
    except OSError:
        return 0
    files.sort(key=lambda f: os.path.getmtime(f))
    total = sum(os.path.getsize(f) for f in files)
    removed = 0
    while files and total + need > _MAX_UPLOAD_TOTAL:
        f = files.pop(0)
        try:
            sz = os.path.getsize(f)
            os.remove(f)
            total -= sz
            removed += 1
        except OSError:
            break
    return removed


def upload(p):
    """Save a base64 file server-side so a push can scp it. Returns the local path.
    Gated like a push (writes + remote-exec opt-in + confirm === true): staging a payload
    on the console is the first half of remote execution, and the upload dir is capped."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — staging a file for remote push"}, 400
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.rce_gate_reason(),
                "error": "remote execution is disabled on the server — uploads are refused",
                **navi_cli.push_status()}, 200
    name = os.path.basename((p.get("filename") or "upload.bin").strip()) or "upload.bin"
    b64 = p.get("content_b64") or ""
    if not b64:
        return {"ok": False, "error": "no file content"}, 400
    try:
        raw = base64.b64decode(b64)
    except Exception:
        return {"ok": False, "error": "invalid base64 content"}, 400
    if len(raw) > _MAX_UPLOAD:
        return {"ok": False, "error": f"file too large (max {_MAX_UPLOAD // (1024 * 1024)} MB)"}, 400
    os.makedirs(_UPLOAD_DIR, mode=0o700, exist_ok=True)
    pruned = _prune_uploads(len(raw))
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".") or "upload.bin"
    dest = os.path.join(_UPLOAD_DIR, f"{uuid.uuid4().hex[:8]}_{safe}")
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    return {"ok": True, "path": dest, "name": name, "bytes": len(raw), "pruned": pruned,
            "sha256": hashlib.sha256(raw).hexdigest(), "remote_name": os.path.basename(dest)}, 200


def _file_sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _single_run(kind, label, target, fn):
    """Register a one-host synchronous action (command / file push) in the runs registry, so Activity,
    receipts and the C2-log link are uniform with the background runs (API change 4)."""
    rid = c2log.new_run("cmd" if kind == "command" else "file")
    _run_new(rid, kind, label, [target])
    _run_set(rid, status="running", started=time.time())
    res = {}
    try:
        res = fn(rid) or {}
    finally:
        st = res.get("status") or ("ok" if res.get("ok") else "failed")
        _run_host(rid, 0, {"target": target, "status": st, "exit_code": res.get("exit_code"),
                           "message": (res.get("message") or "")[:300], "output": _cap(res.get("output")),
                           "c2_log": res.get("c2_log"), "in_inventory": res.get("in_inventory"),
                           "asset": res.get("asset")})
        _run_set(rid, status="done", done=1, errors=(0 if st in OK_STATES else 1), finished=time.time(),
                 hostkey_changed=(1 if st == "hostkey_mismatch" else 0), c2_log=res.get("c2_log"),
                 message=f"{kind} on {target}: {st}" + (f" (exit {res.get('exit_code')})" if res.get("exit_code") is not None else ""))
    return rid, res


def _uploaded(path):
    """True only for a real file that lives inside the upload dir (no path escape)."""
    ap = os.path.abspath(path or "")
    return bool(ap) and os.path.exists(ap) and os.path.dirname(ap) == os.path.abspath(_UPLOAD_DIR)


def _src(p, default="c2"):
    """Who asked: 'c2', 'handoff:<hound>' for an action a hand-off proposed (its hosts, its intent,
    its payload — the page decides, sec C5), or 'c2 (after handoff:<hound>)' when the operator acts
    after a hand-off on hosts / intent it did not propose (source_kind:"after_handoff"). The source is
    as reported by the page (a single-operator loopback console)."""
    h = re.sub(r"[^A-Za-z0-9 ._:/()-]", "", str(p.get("source") or ""))[:60].strip()
    if not h:
        return default
    if str(p.get("source_kind") or "") == "after_handoff":
        return f"c2 (after handoff:{h})"
    return "handoff:" + h


def targets_sha256(targets):
    """sha256 of the ORDERED target list ('\\n'-joined) — what the page's frozen action carries as
    expect_targets_sha256 (sec C4)."""
    return hashlib.sha256("\n".join(str(t) for t in targets).encode("utf-8")).hexdigest()


def _expect(p, targets):
    """Sec C4(b): the page's frozen {api, body} carries expect_count + expect_targets_sha256. When either is
    present and the list the server resolved differs (count, members or order), refuse with 409 — nothing
    runs. Absent → ignored (backward compatible)."""
    has_n = p.get("expect_count") not in (None, "")
    has_h = p.get("expect_targets_sha256") not in (None, "")
    if not (has_n or has_h):
        return None
    lst = [str(t) for t in targets]
    got = targets_sha256(lst)
    bad = (has_n and _int(p.get("expect_count"), -1, -1, 10 ** 9) != len(lst)) or \
          (has_h and str(p.get("expect_targets_sha256")).strip().lower() != got)
    if not bad:
        return None
    return ({"ok": False, "mismatch": True, "resolved_count": len(lst), "resolved_sha256": got,
             "error": f"the host list changed: you confirmed {p.get('expect_count', '?')} host(s), the server resolved "
                      f"{len(lst)} — nothing ran. Review 'What will happen' again."}, 409)


def _strict(p, default=True):
    """Host-key policy for CHANGES: strict (refuse an unknown host key) unless the operator
    explicitly sends accept_new_hostkey:true. Read-only checks / credential tests use navi's
    default (accept a NEW key on first contact, always refuse a CHANGED one)."""
    return default and not flag(p, "accept_new_hostkey")


def command(p):
    """Run ONE ad-hoc command on ONE host. Gated + confirm; a destructive command needs
    an extra force=true. Host keys: strict by default (accept_new_hostkey:true relaxes it)."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — remote code execution"}, 400
    target = (p.get("target") or "").strip()
    cmd = (p.get("command") or "").strip()
    if not target or not cmd:
        return {"ok": False, "error": "target host and command required"}, 400
    if not c2_targets.valid_target(target):
        return {"ok": False, "error": "target must be a plain IP address or hostname"}, 400
    mm = _expect(p, [target])
    if mm:
        return mm
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "status": "blocked", "reason": navi_cli.rce_gate_reason(),
                "message": navi_cli.rce_gate_reason(), **navi_cli.push_status()}, 200
    dangers = navi_cli.scan_command(cmd)
    if dangers and not flag(p, "force"):
        return {"ok": False, "needs_force": True, "dangers": dangers,
                "error": "destructive command — resend with force=true to run: " + "; ".join(dangers)}, 200
    src, strict, tmo = _src(p), _strict(p), _int(p.get("timeout"), None, 5, 3600)
    rid, res = _single_run("command", c2log.mask(cmd)[:120], target, lambda r_: navi_cli.push(
        target=target, command=cmd, agent="c2", detail=cmd, source=src, run_id=r_, strict_host_keys=strict, timeout=tmo))
    return {"ok": bool(res.get("ok")), **res, "run_id": rid, **navi_cli.push_status()}, 200


def push_file(p):
    """scp a previously-uploaded file to a host. Gated + confirm. Running it afterwards is
    a SEPARATE, separately-confirmed `command` step (the install_agent.sh pattern)."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — remote file push"}, 400
    target = (p.get("target") or "").strip()
    path = (p.get("path") or "").strip()
    if not target or not path:
        return {"ok": False, "error": "target host and uploaded file required"}, 400
    if not c2_targets.valid_target(target):
        return {"ok": False, "error": "target must be a plain IP address or hostname"}, 400
    if not _uploaded(path):
        return {"ok": False, "error": "file must be one previously uploaded via this agent"}, 400
    mm = _expect(p, [target])
    if mm:
        return mm
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "status": "blocked", "reason": navi_cli.rce_gate_reason(),
                "message": navi_cli.rce_gate_reason(), **navi_cli.push_status()}, 200
    sha = _file_sha256(path)
    src, strict, tmo = _src(p), _strict(p), _int(p.get("timeout"), 600, 5, 3600)
    rid, res = _single_run("file", "scp " + os.path.basename(path), target, lambda r_: navi_cli.push(
        target=target, file=path, agent="c2", detail="scp " + os.path.basename(path) + " sha256=" + sha,
        source=src, run_id=r_, strict_host_keys=strict, timeout=tmo))
    return {"ok": bool(res.get("ok")), **res, "run_id": rid, "sha256": sha,
            "remote_path": "~/" + os.path.basename(path), **navi_cli.push_status()}, 200


def campaign(p):
    """Armed batch across many hosts. Requires armed=true AND confirm=true. Loops per-IP as
    ONE background job: canary-first, stop-on-failure (or an error threshold), blast-radius
    cap, abortable, progress in run_status."""
    if not flag(p, "armed"):
        return {"ok": False, "error": "campaign is not armed — the typed host count was not confirmed (armed:true)"}, 400
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — batch remote code execution"}, 400
    targets = [str(x).strip() for x in (p.get("hosts") or []) if str(x).strip()]
    cmd = (p.get("command") or "").strip()
    path = (p.get("path") or "").strip()
    if not targets:
        return {"ok": False, "error": "no target hosts"}, 400
    bad = [t for t in targets if not c2_targets.valid_target(t)]
    if bad:
        return {"ok": False, "error": "not an IP address or hostname: " + ", ".join(bad[:5])}, 400
    if bool(cmd) == bool(path):
        return {"ok": False, "error": "provide exactly one of a command or an uploaded file"}, 400
    if cmd:
        dangers = navi_cli.scan_command(cmd)
        if dangers and not flag(p, "force"):
            return {"ok": False, "needs_force": True, "dangers": dangers,
                    "error": "destructive command across a batch — resend with force=true: "
                             + "; ".join(dangers)}, 200
    if path and not _uploaded(path):
        return {"ok": False, "error": "file must be one uploaded via this agent"}, 400
    # Fail fast if the gate is closed, rather than queueing a job that only blocks per-host.
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.rce_gate_reason(),
                **navi_cli.push_status()}, 200
    canary = p.get("canary", True) is not False
    stop = p.get("stop_on_failure", True) is not False
    cap = _int(p.get("max_hosts"), 200, 1, 5000)
    # build 485 (sec MUST 4 / R4, ui P1-3): over the cap is REFUSED — never silently truncated. A caller
    # that really wants the first `cap` hosts says so (allow_truncate:true — the page never sends it) and
    # gets {truncated, dropped} back, also kept on the run record.
    if len(targets) > cap and not flag(p, "allow_truncate"):
        return {"ok": False, "over_cap": True, "hosts": len(targets), "max_hosts": cap,
                "error": f"{len(targets)} hosts but max hosts is {cap} — narrow the Target set or raise max hosts "
                         "(nothing ran)"}, 400
    targets = _crown_last_names(targets)                                  # sec F2: crown jewels last
    batch, dropped = targets[:cap], targets[cap:]
    mm = _expect(p, targets)
    if mm:
        return mm
    busy = _busy()
    if busy:
        return busy
    cid = c2log.new_run("camp")
    _run_new(cid, "campaign", c2log.mask(cmd or ("scp " + os.path.basename(path)))[:120], batch,
             {"canary": canary, "stop": stop, "max_errors": (0 if stop else None)})
    if dropped:
        _run_set(cid, truncated=True, dropped=dropped[:500], dropped_count=len(dropped))
    from core import tagq
    # the command itself never goes into the Tagging log's job spec (it may hold a secret) —
    # the job carries only the run id; the work waits in _PENDING
    kw = {"hosts": batch, "command": cmd, "file": path, "canary": canary, "stop": stop, "campaign_id": cid,
          "source": _src(p), "strict": _strict(p), "timeout": _int(p.get("timeout"), 900, 5, 3600),
          "max_errors": (_int(p.get("max_errors"), None, 0, 5000) if not stop else 0),
          "max_errors_pct": (None if stop or p.get("max_errors_pct") in (None, "") else _int(p.get("max_errors_pct"), None, 0, 100)),
          "max_auth_failures": _int(p.get("max_auth_failures"), MAX_AUTH_FAILURES, 0, 5000)}
    _PENDING[cid] = (None, None, {"campaign": kw, "client": _client()})
    job = tagq.submit(
        _job, {"run_id": cid},
        {"agent": "c2", "category": "C2 · campaign", "value": f"{len(batch)} host(s)",
         "selector": ("file" if path else "command"),
         "detail": c2log.mask(cmd or ("scp " + os.path.basename(path)))[:200], "op": "push"})
    _run_set(cid, job_id=job["id"])
    return {"ok": True, "queued": True, "job_id": job["id"], "campaign_id": cid, "run_id": cid, "hosts": len(batch),
            "canary": canary, "stop_on_failure": stop, "truncated": bool(dropped), "dropped": dropped[:500],
            "message": f"campaign #{job['id']} armed & running in the background "
                       f"({len(batch)} host(s){' · canary first' if canary else ''}). "
                       "Track it under Runs (and the C2 log); use Abort to halt.",
            **navi_cli.push_status()}, 200


def _bulk_push(hosts=None, command="", file="", canary=True, stop=True, campaign_id="", agent="c2",
               source="c2", strict=True, max_errors=None, timeout=900, max_errors_pct=None,
               max_auth_failures=MAX_AUTH_FAILURES):
    """Executed on a tagq worker. Loops per host, honoring canary-first, stop-on-failure /
    error threshold, and the abort switch. Each host is pushed via navi_cli.push (its own
    C2-log row + Tagging-log line)."""
    def one(ip):
        label = command or ("scp " + os.path.basename(file))
        r = navi_cli.push(target=ip, command=command, file=file, agent=agent, detail=label, source=source,
                          run_id=campaign_id, strict_host_keys=strict, timeout=timeout)
        return {"target": ip, "status": r.get("status") or ("ok" if r.get("ok") else "failed"),
                "exit_code": r.get("exit_code"), "message": (r.get("message") or "")[:300],
                "output": _cap(r.get("output"))}
    return _loop(campaign_id, hosts or [], one, canary=canary,
                 max_errors=(0 if stop else max_errors), max_errors_pct=(None if stop else max_errors_pct),
                 max_auth_failures=max_auth_failures)


def abort(p):
    cid = (p.get("campaign_id") or p.get("run_id") or "").strip()
    if not cid:
        return {"ok": False, "error": "campaign_id required"}, 400
    with _RUNS_LOCK:
        r = _RUNS.get(cid)
        live = bool(r) and r["status"] in ("queued", "running")
    if not r:
        return {"ok": False, "unknown": True, "error": "unknown run — it is not running in this server process "
                                                       "(server restarted?); see the C2 log"}, 200
    if not live:
        return {"ok": False, "error": f"run already {r['status']} — nothing to abort"}, 200
    with _ABORT_LOCK:
        _ABORT.add(cid)
    _run_set(cid, abort_requested=True)
    return {"ok": True, "campaign_id": cid,
            "message": "abort requested — the run stops before the next host "
                       "(a push already in flight finishes first)."}, 200


# --------------------------------------------------------------------------- #
#  Runs registry (in memory: progress + per-host output for the page; output is
#  NEVER written to the C2 log or any file) and the shared per-host loop.
# --------------------------------------------------------------------------- #
_RUNS = {}
_RUNS_LOCK = threading.Lock()
_RUNS_KEEP = 40
_OUT_CAP = 12000
OK_STATES = ("ok", "changed", "not_applicable", "skipped")


def _int(v, default, lo, hi):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def _cap(text):
    t = str(text or "")
    return t if len(t) <= _OUT_CAP else (t[:_OUT_CAP] + "\n… (truncated for display)")


def _run_new(run_id, kind, label, hosts, opts=None):
    with _RUNS_LOCK:
        _RUNS[run_id] = {"run_id": run_id, "kind": kind, "label": label, "created": time.time(), "status": "queued",
                         "total": len(hosts), "done": 0, "errors": 0, "options": opts or {},
                         "hosts": [{"target": h, "status": "pending"} for h in hosts], "message": ""}
        if len(_RUNS) > _RUNS_KEEP:
            done = [k for k in sorted(_RUNS, key=lambda k: _RUNS[k]["created"])
                    if _RUNS[k]["status"] not in ("queued", "running")]
            for k in done[:len(_RUNS) - _RUNS_KEEP]:
                _RUNS.pop(k, None)


MAX_ACTIVE = int(os.environ.get("NAVI_C2_MAX_ACTIVE_RUNS", "5"))


def _busy():
    """A clear refusal when too many runs are already queued / running (None = go ahead)."""
    with _RUNS_LOCK:
        n = sum(1 for r in _RUNS.values() if r["status"] in ("queued", "running"))
    if n >= MAX_ACTIVE:
        return {"ok": False, "busy": True, "error": f"{n} runs are already queued or running (max {MAX_ACTIVE}) — "
                                                    "wait for one to finish or ⛔ Abort it"}, 429
    return None


def _client():
    """The requesting client's context (loopback or not) — captured at submit, re-bound on the
    worker thread so the C2 log's operator field is right for queued runs too."""
    from core import gates
    return gates._CLIENT.get()


def _run_set(run_id, **kw):
    with _RUNS_LOCK:
        r = _RUNS.get(run_id)
        if r:
            r.update(kw)


def _run_host(run_id, idx, res):
    with _RUNS_LOCK:
        r = _RUNS.get(run_id)
        if r and 0 <= idx < len(r["hosts"]):
            r["hosts"][idx] = res


def _aborted(run_id):
    with _ABORT_LOCK:
        return run_id in _ABORT


def _loop(run_id, hosts, fn, canary=True, max_errors=None, max_errors_pct=None, max_auth_failures=MAX_AUTH_FAILURES,
          canary_policy=""):
    """Sequential per-host loop (navi push drives one pexpect session at a time) with
    canary-first, an error threshold (count and/or % of hosts), and abort between hosts.
    Hosts never reached are marked skipped (threshold) or cancelled (abort) — and, since
    nothing ran on them, they get no C2-log row."""
    _run_set(run_id, status="running", started=time.time())
    errors, done, halted, why, hk, in_flight, af = 0, 0, False, "", 0, [], 0
    n = len(hosts)
    # build 486 (design spec §3.2 / sec R5): canary_policy "first_changing" — in a one-run deploy the canary is the
    # first host that actually CHANGES; hosts before it that had nothing to do (already fixed / not installed) don't
    # count, and a failure before any host changed halts the run like a canary failure
    first_changing = canary and canary_policy == "first_changing"
    changed_seen = False
    with _RUNS_LOCK:
        kind = (_RUNS.get(run_id) or {}).get("kind")
    for i, ip in enumerate(hosts):
        if _aborted(run_id):
            for k in range(i, n):
                _run_host(run_id, k, {"target": hosts[k], "status": "cancelled", "message": "aborted before this host — not touched"})
            with _ABORT_LOCK:
                _ABORT.discard(run_id)
            msg = (f"aborted: completed {done} · in flight when aborted {len(in_flight)}"
                   + (f" ({', '.join(in_flight)})" if in_flight else "") + f" · not touched {n - done}")
            _run_set(run_id, status="aborted", done=done, errors=errors, finished=time.time(), message=msg,
                     abort_summary={"completed": done, "in_flight": in_flight, "not_touched": n - done})
            return {"ok": False, "aborted": True, "message": msg, "run_id": run_id}
        _run_host(run_id, i, {"target": ip, "status": "running"})
        try:
            res = fn(ip)
        except Exception as e:  # pragma: no cover
            res = {"target": ip, "status": "failed", "message": str(e)[:300]}
        if first_changing:
            if not changed_seen and res.get("status") not in ("not_applicable", "skipped"):
                res["canary"] = True
            changed_seen = changed_seen or res.get("status") == "changed"
        elif canary and i == 0:
            res["canary"] = True
        if _aborted(run_id):
            # the abort arrived while this host's command was running: it finished (maybe half-applied)
            res["in_flight_at_abort"] = True
            in_flight.append(ip)
        _run_host(run_id, i, res)
        done += 1
        if res.get("status") == "hostkey_mismatch":
            hk += 1
            _run_set(run_id, hostkey_changed=hk)
        if res.get("status") == "auth_failed":
            af += 1
            _run_set(run_id, auth_failed=af)
        if res.get("status") not in OK_STATES:
            errors += 1
            if res.get("status") == "auth_failed" and max_auth_failures and af >= max_auth_failures and i < n - 1:
                # one failed login on each of 200 hosts can lock a directory-backed (AD / LDAP / FreeIPA) service
                # account across the whole domain — stop new SSH attempts, whatever the stop rule says
                halted, why = True, (f"stopped after {af} failed logins (account-lockout protection) — check the "
                                     "navi SSH credentials before retrying")
            elif res.get("status") == "hostkey_mismatch" and kind in ("remediate", "rollback", "campaign") and i < n - 1:
                # sec MUST 8 / API change 3: one intercepted host can mean an intercepted segment — a
                # state-changing run halts on a CHANGED host key, whatever its stop rule says
                halted, why = True, f"HOST KEY CHANGED on {ip} — a state-changing run halts on a changed host key"
            elif first_changing and res.get("canary") and i < n - 1:
                halted, why = True, f"CANARY host {ip} came back '{res.get('status')}' — {n - 1 - i} host(s) untouched"
            elif canary and not first_changing and i == 0 and n > 1:
                halted, why = True, f"CANARY host {ip} came back '{res.get('status')}' — {n - 1} host(s) untouched"
            elif max_errors is not None and errors > max_errors:
                halted, why = True, f"error threshold reached ({errors} error(s) > {max_errors} allowed)"
            elif max_errors_pct is not None and n and (100.0 * errors / n) > max_errors_pct:
                halted, why = True, f"error threshold reached ({errors}/{n} hosts > {max_errors_pct}%)"
        _run_set(run_id, done=done, errors=errors)
        if halted:
            for k in range(i + 1, n):
                _run_host(run_id, k, {"target": hosts[k], "status": "skipped", "message": "not run — " + why})
            msg = why + f" — halted after {done} of {n}"
            if in_flight:
                _run_set(run_id, abort_summary={"completed": done, "in_flight": in_flight, "not_touched": n - done})
            _run_set(run_id, status="halted", finished=time.time(), message=msg)
            return {"ok": False, "halted": True, "message": msg, "run_id": run_id}
    with _ABORT_LOCK:
        _ABORT.discard(run_id)
    msg = f"ran on {done} host(s); {errors} with errors" + (f"; {hk} host key(s) CHANGED" if hk else "")
    if in_flight:
        msg += f" — the abort arrived while the last host was running; it finished ({', '.join(in_flight)})"
        _run_set(run_id, abort_summary={"completed": done, "in_flight": in_flight, "not_touched": 0})
    _run_set(run_id, status="done", finished=time.time(), message=msg)
    return {"ok": errors == 0, "message": msg, "run_id": run_id}


def run_status(p):
    """Live progress + per-host results of a run (or the recent runs list without run_id)."""
    rid = str(p.get("run_id") or "").strip()
    with _RUNS_LOCK:
        if rid:
            r = _RUNS.get(rid)
            return ({"ok": True, "run": json.loads(json.dumps({k: v for k, v in r.items() if k != "plan"}, default=str))}, 200) if r else \
                ({"ok": False, "unknown": True, "run_id": rid,
                  "error": "unknown run — the server restarted (runs live in memory). Everything that ran is in the "
                           "C2 log."}, 200)
        runs = sorted(_RUNS.values(), key=lambda r: -r["created"])
        return {"ok": True, "runs": [{k: v for k, v in r.items() if k != "hosts"} for r in runs]}, 200


# --------------------------------------------------------------------------- #
#  Targets, catalog, at-a-glance (reads)
# --------------------------------------------------------------------------- #
def catalog(p):
    return {"ok": True, **c2_catalog.public()}, 200


def targets(p):
    """Validate / expand / classify what the operator typed (+ picked hosts). Read-only."""
    raw = p.get("targets")
    if raw in (None, "", []):
        return {"ok": False, "error": "enter at least one IP, hostname or CIDR"}, 400
    ex = c2_targets.expand(raw, cap=_int(p.get("cap"), c2_targets.CIDR_CAP, 1, c2_targets.CIDR_CAP))
    # build 485 (sec C6/C7): each host's safety state comes from the C2 log, not page memory — key CHANGED,
    # unknown state after a timed-out change step, first-use key trust — so it survives a reload
    states = c2log.host_states([t["target"] for t in ex["targets"]], _aliases(ex["targets"]))
    for t in ex["targets"]:
        t["log_state"] = states.get(t["target"]) or {}
    return {"ok": True, **ex}, 200


def _aliases(tlist):
    """{target: {names:[navi.db ip, hostname], uuid}} — the other names of each in-inventory host (sec F1)."""
    out = {}
    for t in tlist:
        a = t.get("asset") or {}
        if a:
            out[t["target"]] = {"names": [x for x in (a.get("ip"), a.get("hostname")) if x], "uuid": a.get("uuid") or ""}
    return out


def _ssh_user():
    """The navi SSH user name, read locally from navi.db's `ssh` table (the same read as db.ssh_status — no
    remote call). Only the user name: the password / key path are never read here."""
    try:
        if "username" not in _cols("ssh"):
            return ""
        rows = db.query("SELECT username FROM ssh", budget=0)
    except Exception:
        return ""
    users = [str(r.get("username") or "").strip() for r in rows if str(r.get("username") or "").strip()]
    u = re.sub(r"[^A-Za-z0-9._@-]", "", users[0])[:64] if users else ""
    return u + (f" (1 of {len(users)} accounts)" if len(users) > 1 else "")


def glance(p):
    st = c2log.stats()
    ch = c2log.verify_chain()
    with _RUNS_LOCK:
        active = sum(1 for r in _RUNS.values() if r["status"] in ("queued", "running"))
    try:
        nlin = _os_stats()["linux"]
    except Exception:
        nlin = 0
    try:
        mtime = os.path.getmtime(db.db_path())
    except Exception:
        mtime = None
    # sec C6: hosts whose latest host-key outcome in the C2 log is a CHANGED key (survives a reload; cleared
    # only by a later strict login) — the page's security banner reads this on open (a read; nothing runs)
    return {"ok": True, **st, "chain": ch, "active_runs": active, "linux_hosts": nlin,
            "hostkey_changed_hosts": c2log.key_changed_hosts(), "navi_db_mtime": mtime,
            "ssh": dict(db.ssh_status(), user=_ssh_user()), "known_hosts": c2_hostkeys.locate(),
            **navi_cli.push_status()}, 200


def ack(p):
    """'I have seen this' on a CHANGED-host-key banner (sec C6): appends an `ack` row (mode ack, no command
    sent anywhere) to the hash-chained C2 log, so the acknowledgement is part of the audit trail. It only
    collapses the banner — the host stays excluded from every change until a strict login succeeds."""
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — recording an acknowledgement in the C2 log"}, 400
    target = str(p.get("target") or "").strip()
    if not c2_targets.valid_target(target):
        return {"ok": False, "error": "target must be a plain IP address or hostname"}, 400
    r = c2log.ack(target, "host key CHANGED banner seen by the operator")
    if r.get("error"):
        return {"ok": False, "error": r["error"]}, 200
    return {"ok": True, "target": target, "c2_log": r}, 200


# --------------------------------------------------------------------------- #
#  Diagnostics, credential test, path check (gated: they run commands remotely)
# --------------------------------------------------------------------------- #
def _resolve_targets(p):
    """(targets[], error_payload|None). Refuses the whole request if anything is invalid."""
    raw = p.get("targets") if p.get("targets") not in (None, "", []) else p.get("target")
    if raw in (None, "", []):
        return None, ({"ok": False, "error": "pick at least one target host"}, 400)
    ex = c2_targets.expand(raw)
    if ex["refused"]:
        return None, ({"ok": False, "refused": ex["refused"],
                       "error": "refused target(s): " + "; ".join(f"{r['input']} ({r['reason']})" for r in ex["refused"][:5])},
                      400)
    if not ex["targets"]:
        return None, ({"ok": False, "error": "no valid targets"}, 400)
    return ex, None


def _checks_from(p):
    ids = p.get("checks") or []
    if isinstance(ids, str):
        ids = [x for x in re.split(r"[,\s]+", ids) if x]
    b = str(p.get("bundle") or "")
    if b:
        bd = next((x for x in c2_catalog.BUNDLES if x["id"] == b), None)
        if not bd:
            return None, f"unknown bundle '{b}'"
        ids = list(bd["checks"]) + [i for i in ids if i not in bd["checks"]]
    if not ids:
        return None, "pick at least one check"
    return [str(i) for i in ids][:30], ""


def _installed_ver(inst, name, compare):
    """The bare version from a pkgver fact: dpkg 'ver' as is; rpm 'name-ver-rel.arch' → 'ver-rel'."""
    v = str(inst or "").strip()
    if compare == "rpm":
        v = re.sub(r"\.(x86_64|i[3-6]86|noarch|aarch64|ppc64le|s390x)$", "", v)
        if name and v.startswith(name + "-"):
            v = v[len(name) + 1:]
    return v


# build 486: the LIVE facts the last strict pre-flight read per host (os-release family + group, package state,
# locks, holds, candidates, downgrade availability). In memory, like the plan store and the runs registry; deploy
# refuses a host whose live family / plan group differs from the plan's (linux M3, second half), and plan_ai groups
# the Target set by it (linux P1-1). Never output — parsed facts only.
_PF = {}
_PF_LOCK = threading.Lock()
_PF_KEEP = 5000


def _pf_put(target, cred=None, checks=None):
    with _PF_LOCK:
        cur = _PF.get(target) or {}
        rec = {"ts": time.time(), "cred": cred if cred is not None else cur.get("cred"),
               "checks": checks if checks is not None else cur.get("checks")}
        _PF[target] = rec
        if len(_PF) > _PF_KEEP:
            for k in sorted(_PF, key=lambda k: _PF[k]["ts"])[:len(_PF) - _PF_KEEP]:
                _PF.pop(k, None)
    return rec


def _pf_get(target, aliases=None):
    """The latest pre-flight record for a host, under its own name or any alias (navi.db ip / hostname)."""
    names = [target] + list(((aliases or {}).get(target) or {}).get("names") or [])
    with _PF_LOCK:
        recs = [_PF[n] for n in names if n in _PF]
    return max(recs, key=lambda r: r["ts"]) if recs else None


def _diag_host(run_id, built, source, retries, kind, strict=False, fixed=None, pkg=""):
    """One host: push each bundle chunk (one SSH session each), parse per-check results. strict=True is the
    pre-flight's strict host-key policy (no trust on first use). fixed={fixed_version, compare} adds a
    server-side version compare to the pkgver fact (vs_fixed: older | at_least)."""
    def one(ip):
        checks, status, msg, attempts = {}, "ok", "", 1
        # build 486 (sec L-1 / C7): navi's known_hosts is read LOCALLY before and after an accept-new contact — a host
        # with no entry before and one after had its key recorded NOW (trust on first use), with its fingerprint
        kh = c2_hostkeys.locate()
        fp_before = c2_hostkeys.lookup(ip) if kh["located"] else None
        for ch in built["chunks"]:
            r = navi_cli.push(target=ip, command=ch["command"], agent="c2",
                              detail=f"C2 {kind}: " + ",".join(ch["ids"]), source=source, run_id=run_id,
                              catalog_id=",".join(ch["ids"]), timeout=ch["timeout"] + 10, retries=retries,
                              strict_host_keys=bool(strict))
            attempts = max(attempts, r.get("attempts") or 1)
            st = r.get("status") or "failed"
            parsed = c2_catalog.parse(r.get("output") or "")
            for cid in ch["ids"]:
                if cid in parsed:
                    checks[cid] = parsed[cid]
                else:
                    checks[cid] = {"status": ("skipped" if st != "ok" else "failed"), "rc": None, "output": "",
                                   "facts": {}, "note": ("not run — " + st) if st != "ok" else "no result markers"}
            if st != "ok":
                status, msg = st, (r.get("message") or "")[:300]
                if st not in ("timeout", "failed"):
                    break              # transport problem — the next chunk would fail the same way
        hk = None
        if kh["located"] and status not in ("hostkey_mismatch",):
            fp_after = c2_hostkeys.lookup(ip)
            hk = {"fingerprints": fp_after, "recorded_now": bool(fp_after) and not fp_before and not strict,
                  "file": kh["file"]}
        pv = (checks.get("pkgver") or {}).get("facts")
        fam = ((checks.get("osrel") or {}).get("facts") or {}).get("family") or \
            ((checks.get("os") or {}).get("facts") or {}).get("family") or ""
        cmp_ = "rpm" if (fixed or {}).get("compare") == "rpm" else "dpkg"
        if fixed and isinstance(pv, dict) and pv.get("installed") and fam and fam != "unknown" and \
                (cmp_ == "dpkg") != (fam == "apt"):
            # fix round (linux F5): a fixed build of another family is not comparable (rpm vs a dpkg version)
            pv["vs_fixed"] = "n/a"
        elif fixed and isinstance(pv, dict) and pv.get("installed") and fixed.get("fixed_version"):
            v = _installed_ver(pv["installed"], pkg, cmp_)
            try:
                pv["vs_fixed"] = "at_least" if c2_remediate.version_ok(
                    v, {"fixed_version": fixed["fixed_version"], "compare": cmp_, "want": "at_least"}) else "older"
                pv["fixed_version"] = fixed["fixed_version"]
            except Exception:
                pv["vs_fixed"] = "unknown"
        res = {"target": ip, "status": status, "message": msg, "checks": checks, "attempts": attempts}
        if hk:
            res["hostkey"] = hk
        if strict and kind == "pre-flight" and status == "ok":
            _pf_put(ip, checks={"status": status, "checks": checks})
        return res
    return one


_PENDING = {}


def _job(run_id=""):
    """tagq entry point (its kwargs must be JSON — the per-host closure waits in _PENDING)."""
    hosts, fn, kw = _PENDING.pop(run_id, (None, None, None))
    if kw is None:
        return {"ok": False, "message": "run vanished before it started (server restarted?)"}
    from core import gates
    tok = gates._CLIENT.set(kw.pop("client", None))
    try:
        if "campaign" in kw:
            out = _bulk_push(**kw["campaign"])
        else:
            out = _loop(run_id, hosts, fn, **kw)
            _after(run_id, out)
    finally:
        gates.reset_client(tok)
    return {k: v for k, v in out.items() if k in ("ok", "message", "run_id", "halted", "aborted")}


def _after(run_id, out):
    with _RUNS_LOCK:
        r = _RUNS.get(run_id) or {}
        plan_id, kind, status, stage, n = r.get("plan_id"), r.get("kind"), r.get("status"), r.get("stage"), r.get("total")
    if plan_id and kind == "remediate":
        # API change 8: per-run plan status — a canary run and a roll-out run of the same plan_id each record
        # their own outcome ("deployed (canary)", "failed (3 hosts)"), so the last run doesn't hide the first
        ok = bool(out.get("ok") and status == "done")
        word = "deployed" if ok else "failed"
        lab = {"canary": "canary", "rollout": f"{n} host(s)", "all": f"canary + {max(0, (n or 1) - 1)} host(s)"}.get(stage)
        st = f"{word} ({lab})" if lab else word
        with _PLANS_LOCK:
            rec = _PLANS.get(plan_id)
            if rec is not None:
                rec["runs"][run_id] = {"run_id": run_id, "stage": stage or "", "status": st, "hosts": n,
                                       "finished": time.time()}
        c2log.plan_upsert(plan_id, st)
    if plan_id and kind == "rollback" and status == "done":
        c2log.plan_upsert(plan_id, "rolled_back")


def _start(kind, label, ex, make_fn, p, sync_max=2, units=1, default_max_errors=None, extra=None):
    """Run make_fn(run_id)(ip) per host — inline when small, else on the tag queue — and answer the page."""
    busy = _busy()
    if busy:
        return busy
    hosts = [t["target"] for t in ex["targets"]]
    # a pre-flight run is recognisable in the C2 log by its run_id prefix ("pre-"): a clean one clears a
    # host's "unknown state" (sec C6)
    run_id = c2log.new_run("pre" if flag(p, "preflight") else kind)
    fn = make_fn(run_id)
    canary = p.get("canary", True) is not False
    max_errors = _int(p.get("max_errors"), default_max_errors, 0, 5000) if p.get("max_errors") not in (None, "") \
        else default_max_errors
    pct = None
    if p.get("max_errors_pct") not in (None, ""):
        try:
            pct = max(0.0, min(100.0, float(p.get("max_errors_pct"))))
        except (TypeError, ValueError):
            pct = None
    maf = _int(p.get("max_auth_failures"), MAX_AUTH_FAILURES, 0, 5000) if p.get("max_auth_failures") not in (None, "") \
        else MAX_AUTH_FAILURES
    _run_new(run_id, kind, label, hosts, {"canary": canary, "max_errors": max_errors, "max_errors_pct": pct,
                                          "max_auth_failures": maf})
    if extra:
        _run_set(run_id, **extra)
    inv = {t["target"]: t for t in ex["targets"]}
    with _RUNS_LOCK:
        for h in _RUNS[run_id]["hosts"]:
            t = inv.get(h["target"]) or {}
            h["in_inventory"] = t.get("in_inventory")
            h["asset"] = t.get("asset")
    cpol = "first_changing" if str(p.get("canary_policy") or "") == "first_changing" else ""
    if len(hosts) * units <= sync_max and not flag(p, "queue"):
        out = _loop(run_id, hosts, fn, canary=canary, max_errors=max_errors, max_errors_pct=pct, max_auth_failures=maf,
                    canary_policy=cpol)
        _after(run_id, out)
        with _RUNS_LOCK:
            run = json.loads(json.dumps(_RUNS.get(run_id), default=str))
        return {"ok": bool(out.get("ok")), "run_id": run_id, "run": run, "message": out.get("message"),
                **navi_cli.push_status()}, 200
    from core import tagq
    _PENDING[run_id] = (hosts, fn, {"canary": canary, "max_errors": max_errors, "max_errors_pct": pct,
                                    "max_auth_failures": maf, "canary_policy": cpol, "client": _client()})
    job = tagq.submit(_job, {"run_id": run_id},
                      {"agent": "c2", "category": "C2 · " + kind, "value": f"{len(hosts)} host(s)",
                       "selector": kind, "detail": label[:200], "op": "c2_run"})
    _run_set(run_id, job_id=job["id"])
    return {"ok": True, "queued": True, "run_id": run_id, "job_id": job["id"], "hosts": len(hosts),
            "message": f"running on {len(hosts)} host(s) in the background"
                       + (" · canary first" if canary else "") + " — progress below; ⛔ Abort stops before the next host.",
            **navi_cli.push_status()}, 200


def _dry(kind, ex, built, extra=None, strict=False):
    """Exactly what WOULD run where — nothing is sent, nothing is logged."""
    return {"ok": True, "dry_run": True, "kind": kind,
            "targets": ex["targets"], "warnings": ex["warnings"],
            "pushes": [{"target": t["target"], "commands": [{"ids": ch["ids"], "command": ch["command"],
                                                             "navi_timeout": ch["timeout"] + 10}
                                                            for ch in built["chunks"]]}
                       for t in ex["targets"]],
            "hostkey_policy": ("strict (--strict-host-keys: a host whose key is not yet known is refused)" if strict else
                               "accept-new (navi default: record a NEW key, refuse a CHANGED one)"),
            "message": f"dry run — {len(ex['targets'])} host(s) × {len(built['chunks'])} push(es); nothing was sent",
            **(extra or {}), **navi_cli.push_status()}, 200


def run_checks(p):
    """Built-in READ-ONLY diagnostics (core/c2_catalog.py) on 1..N hosts. Still remote
    execution: writes + NAVI_REMOTE_CODE_EXECUTION + confirm (one confirm per click).
    dry_run:true shows exactly what would run where and sends nothing."""
    ex, err = _resolve_targets(p)
    if err:
        return err
    ids, e = _checks_from(p)
    if e:
        return {"ok": False, "error": e}, 400
    built = c2_catalog.build(ids, p.get("params") or {}, p.get("timeout"))
    if built["errors"]:
        return {"ok": False, "error": "; ".join(built["errors"])}, 400
    strict = flag(p, "strict")
    if flag(p, "dry_run"):
        return _dry("diagnostics", ex, built, strict=strict)
    mm = _expect(p, [t["target"] for t in ex["targets"]])
    if mm:
        return mm
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — the checks run on remote hosts over SSH"}, 400
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.rce_gate_reason(), **navi_cli.push_status()}, 200
    retries = _int(p.get("retries"), 1, 0, 3)
    src = _src(p)
    fx = p.get("fixed") if isinstance(p.get("fixed"), dict) else None
    fixed = ({"fixed_version": str(fx.get("fixed_version") or "")[:80], "compare": str(fx.get("compare") or "")}
             if fx and fx.get("fixed_version") else None)
    pkg = str(((p.get("params") or {}).get("name")) or "") if isinstance(p.get("params"), dict) else ""
    return _start("preflight-checks" if flag(p, "preflight") else "diag", "checks: " + ",".join(built["checks"]), ex,
                  lambda rid: _diag_host(rid, built, src, retries, "pre-flight" if flag(p, "preflight") else "diagnostics",
                                         strict=strict, fixed=fixed, pkg=pkg), p, units=len(built["chunks"]))


def cred_test(p):
    """`id; sudo -n true` on each host — login works? sudo without a password? Short timeout,
    ONE attempt (auth failures are never retried: lockout), navi's default host-key policy
    (a new host's key is recorded; a CHANGED key is a security event and nothing runs)."""
    ex, err = _resolve_targets(p)
    if err:
        return err
    built = c2_catalog.build(["cred"], {}, 15)
    strict = flag(p, "strict")
    if flag(p, "dry_run"):
        return _dry("cred_test", ex, built, strict=strict)
    mm = _expect(p, [t["target"] for t in ex["targets"]])
    if mm:
        return mm
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — the credential test logs in to remote hosts"}, 400
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.rce_gate_reason(), **navi_cli.push_status()}, 200
    src = _src(p)

    def make(rid):
        base = _diag_host(rid, built, src, 0, "pre-flight login" if flag(p, "preflight") else "credential test",
                          strict=strict)

        def one(ip):
            r = base(ip)
            c = (r.get("checks") or {}).get("cred") or {}
            f = c.get("facts") or {}
            r["sudo"] = ("sudo_ok" if f.get("sudo") == "ok" else "sudo_needs_password"
                         if f.get("sudo") == "needs_password" else "")
            r["user"] = f.get("user") or ""
            r["security_event"] = r["status"] == "hostkey_mismatch"
            if strict and flag(p, "preflight"):
                _pf_put(ip, cred={"status": r["status"], "sudo": r["sudo"], "user": r["user"]}, checks={})
            return r
        return one
    return _start("preflight-cred" if flag(p, "preflight") else "cred",
                  ("pre-flight login (strict host keys)" if flag(p, "preflight") else
                   "credential test" + (" (strict host keys)" if strict else "")), ex, make, p, sync_max=2)


# build 486 (design spec §5, linux P1-6 / C4 / C9 / C10): the Phase 2 pre-flight bundle. Mandatory: identity + sudo
# rights, live os-release family, disk, package-manager lock / auto-updaters / half-configured, holds, reboot state;
# with the plan's packages: status-aware installed versions, repo candidates, downgrade availability (probed BEFORE
# the change). Optional: changelog CVE evidence (auto-on for an upstream-only fixed version), entitlement (off by
# default), Tenable agent, services using old libraries.
PREFLIGHT_BASE = ["ident", "osrel", "disk", "pkglock", "holds", "rebootreq"]
PREFLIGHT_PKGS = ["pkgstate", "pkgcand", "rbavail"]
PREFLIGHT_OPTIONAL = ("chlog", "entitle", "agent", "needrestart", "pkgver", "updates", "time", "mac", "inode", "pkgsim")


def _first_cve(src, sel):
    if re.fullmatch(r"(?i)CVE-\d{4}-\d{4,7}", sel or ""):
        return sel.upper()
    for pl in (src or {}).get("plugins") or []:
        m = re.search(r"CVE-\d{4}-\d{4,7}", pl.get("cves") or "")
        if m:
            return m.group(0)
    return ""


def _plan_ctx(rec, crown=False, include_sudo=False):
    """The eligibility context of a server-side plan record (never page data): family, plan group, packages, the
    fixed build of each and its source, compare type, kernel."""
    if not rec:
        return {"crown": crown, "include_sudo": include_sudo}
    m = rec.get("meta") or {}
    g = rec.get("group") or {}
    return {"family": rec.get("family") or "", "group_key": g.get("key") if g.get("live") else None,
            "group_label": g.get("label") or "", "packages": m.get("packages") or [], "fixed": m.get("fixed") or {},
            "compare": m.get("compare") or "", "kernel": bool(m.get("kernel")), "crown": crown, "cve": rec.get("cve") or "",
            "include_sudo": include_sudo}


def preflight(p):
    """ONE confirmed read-only run per host: a strict login (`id; sudo -n true`, strict host keys — no trust on first
    use), then — on the hosts that logged in — the pre-flight bundle, and a per-host eligibility computed here from
    the parsed facts (core/c2_verdict.eligibility) against the plan's server-side record when plan_id is given.
    Nothing changes on the hosts; every command is in the C2 log under a `pre-…` run id."""
    ex, err = _resolve_targets(p)
    if err:
        return err
    pid, rec = _plan_get(p) if p.get("plan_id") else ("", None)
    # several OS groups → several plans: read the UNION of their packages, judge each host against its own group's plan
    recs = []
    for x in (p.get("plan_ids") or [])[:MAX_GROUPS] if isinstance(p.get("plan_ids"), list) else []:
        _i, r_ = _plan_get({"plan_id": x})
        if r_:
            recs.append(r_)
    if rec and rec not in recs:
        recs.insert(0, rec)
    rec = rec or (recs[0] if recs else None)
    prm = p.get("params") if isinstance(p.get("params"), dict) else {}
    union = list(dict.fromkeys(n for r_ in recs for n in ((r_.get("meta") or {}).get("packages") or [])))
    names = prm.get("names") or union or ([prm["name"]] if prm.get("name") else [])
    if recs and prm.get("names"):
        names = list(dict.fromkeys(list(prm["names"]) + union))[:c2_catalog.MAX_PKGS]
    cve = str(prm.get("cve") or (rec or {}).get("cve") or "").strip().upper()
    opt = [x for x in (p.get("optional") or []) if x in PREFLIGHT_OPTIONAL]
    ctx_up = any((v or {}).get("source") == "upstream" for v in (((rec or {}).get("meta") or {}).get("fixed") or {}).values())
    ids = list(PREFLIGHT_BASE) + (list(PREFLIGHT_PKGS) if names else [])
    if names and cve and ("chlog" in opt or ctx_up):
        ids.append("chlog")                       # auto-on when the fixed version is upstream-only (spec §5)
    ids += [x for x in opt if x not in ids and x != "chlog" and (x != "pkgver" or prm.get("name"))
            and (x != "pkgsim" or names)]
    params = {"names": names} if names else {}
    if cve and "chlog" in ids:
        params["cve"] = cve
    if prm.get("name") and "pkgver" in ids:
        params["name"] = prm["name"]
    built = c2_catalog.build(ids, params, None)
    if built["errors"]:
        return {"ok": False, "error": "; ".join(built["errors"])}, 400
    built_cred = c2_catalog.build(["cred"], {}, 15)
    if flag(p, "dry_run"):
        r_, code = _dry("preflight", ex, built, strict=True)
        r_["login"] = [{"ids": ch["ids"], "command": ch["command"], "navi_timeout": ch["timeout"] + 10} for ch in built_cred["chunks"]]
        r_["checks"] = built["checks"]
        r_["message"] = (f"dry run — {len(ex['targets'])} host(s): 1 strict login + {len(built['chunks'])} read-only push(es) "
                         "on the hosts that log in; nothing was sent")
        return r_, code
    mm = _expect(p, [t["target"] for t in ex["targets"]])
    if mm:
        return mm
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — pre-flight logs in to remote hosts and runs read-only checks"}, 400
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.rce_gate_reason(), **navi_cli.push_status()}, 200
    src = _src(p)
    fx = p.get("fixed") if isinstance(p.get("fixed"), dict) else None
    fixed = ({"fixed_version": str(fx.get("fixed_version") or "")[:80], "compare": str(fx.get("compare") or "")}
             if fx and fx.get("fixed_version") else None)
    crown = {t["target"]: bool((t.get("asset") or {}).get("crown")) for t in ex["targets"]}
    inc = set(str(x) for x in (p.get("include_sudo") or []))

    def make(rid):
        cred_fn = _diag_host(rid, built_cred, src, 0, "pre-flight login", strict=True)
        bundle_fn = _diag_host(rid, built, src, 0, "pre-flight", strict=True, fixed=fixed, pkg=str(prm.get("name") or ""))

        def one(ip):
            r = cred_fn(ip)
            f = (((r.get("checks") or {}).get("cred") or {}).get("facts") or {})
            cred = {"status": r["status"], "sudo": ("sudo_ok" if f.get("sudo") == "ok" else "sudo_needs_password"
                                                    if f.get("sudo") == "needs_password" else ""), "user": f.get("user") or ""}
            _pf_put(ip, cred=cred, checks={})
            out = {"target": ip, "status": r["status"], "message": r.get("message") or "", "cred": cred,
                   "sudo": cred["sudo"], "user": cred["user"], "attempts": r.get("attempts") or 1,
                   "security_event": r["status"] == "hostkey_mismatch"}
            if r.get("hostkey"):
                out["hostkey"] = r["hostkey"]
            if r["status"] == "ok":
                b = bundle_fn(ip)
                out["checks"] = {"status": b["status"], "checks": b["checks"], "message": b.get("message") or ""}
                if b.get("hostkey"):
                    out["hostkey"] = b["hostkey"]
                if b["status"] != "ok":
                    out["status"], out["message"] = b["status"], b.get("message") or ""
            out["group"] = (c2_verdict.live_os({"checks": out.get("checks")}) or {}).get("group")
            gk = (out["group"] or {}).get("key")
            mine = next((r_ for r_ in recs if ((r_.get("group") or {}).get("key") == gk and (r_.get("group") or {}).get("live"))),
                        None) or next((r_ for r_ in recs if r_.get("family") == (out["group"] or {}).get("family")), None) or rec
            if len(recs) > 1 and gk and not any((r_.get("group") or {}).get("key") == gk for r_ in recs):
                mine = None                        # its OS group has no plan (more than MAX_GROUPS groups) — say so
            out["plan_id"] = (mine or {}).get("plan_id", "")
            out["elig"] = c2_verdict.eligibility({"cred": cred, "checks": out.get("checks")},
                                                 _plan_ctx(mine, crown.get(ip), ip in inc) if mine else
                                                 {"packages": names, "crown": crown.get(ip), "include_sudo": ip in inc,
                                                  "cve": cve})
            if len(recs) > 1 and not mine and out["elig"].get("ok"):
                out["elig"].update(ok=False, reason=f"no plan for this host's OS group ({(out['group'] or {}).get('label')}) "
                                                     f"— ④ plans at most {MAX_GROUPS} groups; narrow the Target set")
            return out
        return one
    pp = dict(p, preflight=True, canary=False, retries=0)
    res, code = _start("preflight", "pre-flight (strict host keys): " + ",".join(built["checks"]), ex, make, pp,
                       sync_max=2, units=1 + len(built["chunks"]), extra={"plan_id": pid} if pid else None)
    if isinstance(res, dict):
        res["checks"] = built["checks"]
    return res, code


def path_check(p):
    """'Does this path exist?' on 1..N hosts → exists, type, size, owner, perms, mtime and the
    sha256 (regular files ≤ 50 MB). The path is validated and shell-quoted (one argument)."""
    ex, err = _resolve_targets(p)
    if err:
        return err
    ok, val = c2_catalog.check_path(p.get("path"))
    if not ok:
        return {"ok": False, "error": val}, 400
    built = c2_catalog.build(["pathx"], {"path": val}, p.get("timeout") or 30)
    if flag(p, "dry_run"):
        return _dry("path_check", ex, built, {"path": val})
    mm = _expect(p, [t["target"] for t in ex["targets"]])
    if mm:
        return mm
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — the path check runs on remote hosts over SSH"}, 400
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.rce_gate_reason(), **navi_cli.push_status()}, 200
    src, retries = _src(p), _int(p.get("retries"), 1, 0, 3)

    def make(rid):
        base = _diag_host(rid, built, src, retries, "path check")

        def one(ip):
            r = base(ip)
            c = (r.get("checks") or {}).get("pathx") or {}
            f = c.get("facts") or {}
            r["path"] = val
            r["exists"] = (True if f.get("path") == "exists" else False if f.get("path") == "missing" else None)
            r["denied"] = f.get("path") == "denied"
            for k in ("type", "size", "owner", "group", "mode", "mtime", "sha"):
                if f.get(k):
                    r[k] = f[k]
            return r
        return one
    return _start("path", "path check: " + val[:80], ex, make, p)


# --------------------------------------------------------------------------- #
#  AI remediation: plan (read) → validate (read) → deploy / rollback (gated)
# --------------------------------------------------------------------------- #
def _rem_targets(p):
    raw = p.get("targets") or p.get("hosts") or []
    return c2_targets.expand(raw) if raw else {"targets": [], "refused": [], "warnings": []}


# Server-side plan store: the page never gets to choose what deploys. plan_ai registers the
# generated plan; plan_validate re-validates an operator edit and stores it as the plan's current
# version (with a diff); deploy runs ONLY the stored current version, and only when the page's copy
# hashes the same (so the operator deploys exactly what they last saw validated); rollback runs only
# steps that actually ran on that host in that deployment. In memory — regenerate after a restart.
_PLANS = {}
_PLANS_LOCK = threading.Lock()


def _plan_get(p):
    pid = re.sub(r"[^A-Za-z0-9_.-]", "", str(p.get("plan_id") or ""))[:60]
    with _PLANS_LOCK:
        return pid, _PLANS.get(pid)


def _diff(a, b):
    out = []
    sa = {s["n"]: s for s in (a or {}).get("steps") or []}
    sb = {s["n"]: s for s in (b or {}).get("steps") or []}
    for n in sorted(set(sa) | set(sb)):
        x, y = sa.get(n), sb.get(n)
        if not x:
            out.append(f"step {n} added: {y['command']}")
        elif not y:
            out.append(f"step {n} removed: {x['command']}")
        else:
            for k in ("command", "verify", "rollback"):
                if x.get(k) != y.get(k):
                    out.append(f"step {n} {k} changed")
    for k in ("precheck", "post_verify"):
        if (a or {}).get(k) != (b or {}).get(k):
            out.append(f"{k} changed")
    return out


MAX_GROUPS = 8


def _groups(tg, fam_override=None):
    """linux P1-1: the Target set split by its LIVE (family, ID, major VERSION_ID) from the latest strict pre-flight;
    a host never pre-flighted falls back to navi.db's OS string, labelled unconfirmed. Largest group first."""
    al = _aliases(tg)
    gs = {}
    for t in tg:
        if fam_override:
            g = {"key": "chosen|" + fam_override, "label": fam_override + " (chosen by you)", "family": fam_override,
                 "os_id": "", "major": "", "live": False}
        else:
            rec = _pf_get(t["target"], al)
            los = c2_verdict.live_os(rec) if rec else {}
            if los.get("group") and los.get("family") not in (None, "", "unknown"):
                g = dict(los["group"], live=True)
            else:
                f_, _ = c2_remediate.distro_of((t.get("asset") or {}).get("os"))
                g = {"key": "navi|" + f_, "label": f"{f_} (navi.db — unconfirmed until pre-flight)", "family": f_,
                     "os_id": "", "major": "", "live": False}
        gs.setdefault(g["key"], dict(g, hosts=[]))["hosts"].append(t)
    out = sorted(gs.values(), key=lambda g: (-len(g["hosts"]), g["key"]))
    return out[:MAX_GROUPS], out[MAX_GROUPS:]


def plan_ai(p):
    """Tenable's text (navi.db) → ONE plan per OS group (live os-release family + distro + major release, linux
    P1-1) via the configured model (or the deterministic templates) → the deterministic validator. Nothing runs here.
    The answer's top level is the FIRST (largest) group's plan (backward compatible); `groups[]` lists every group
    with its own plan_id, plan, hash, packages, fixed builds and — for hosts a pre-flight already read — the per-host
    eligibility against that plan (no SSH)."""
    sel = str(p.get("selector") or "").strip()
    if not sel:
        return {"ok": False, "error": "enter a plugin id or CVE"}, 400
    ex = _rem_targets(p)
    if ex["refused"]:
        return {"ok": False, "error": "refused target(s): " + ", ".join(r["input"] for r in ex["refused"][:5])}, 400
    fam_override = str(p.get("family") or "").strip() or None
    tg = ex["targets"]
    groups, dropped = _groups(tg, fam_override) if tg else ([{"key": "none", "label": fam_override or "unknown",
                                                               "family": fam_override or "", "os_id": "", "major": "",
                                                               "live": False, "hosts": []}], [])
    al = _aliases(tg)
    inst = p.get("installed") if isinstance(p.get("installed"), dict) else {}
    out_groups = []
    for g in groups:
        live = {t["target"]: {"family": g["family"]} for t in g["hosts"]} if g.get("live") else None
        src = c2_remediate.sources(sel, g["hosts"], live=live)
        if not src["plugin_ids"]:
            return {"ok": False, "error": "no plugin found for that selector in navi.db"}, 200
        fam = fam_override or (g["family"] if g.get("family") not in ("", "unknown") else None)
        gen = c2_remediate.generate(src, family=fam, use_llm=p.get("use_llm", True) is not False)
        v = c2_remediate.validate(gen["plan"], src)
        fam_used = fam or (src.get("families") or ["unknown"])[0]
        meta = c2_remediate.plan_meta(src, fam_used)
        plan_id = c2log.new_run("plan")
        grp = {k: g.get(k) for k in ("key", "label", "family", "os_id", "major", "live")}
        rec = {"selector": sel, "generator": gen["generator"], "generated_plan": v["plan"], "generated_hash": v["hash"],
               "plan": v["plan"], "hash": v["hash"], "deployable": v["deployable"], "deployed_hashes": set(), "runs": {},
               "family": fam_used, "group": grp, "meta": meta, "cve": _first_cve(src, sel), "plan_id": plan_id,
               "hosts": [t["target"] for t in g["hosts"]],
               # sec F1 (verify round): the plan-time source (≤ 5 sampled hosts) — the coarse authority for the plan's
               # names; at run time every host is narrowed to its OWN finding (never a name added)
               "src": {k: src.get(k) for k in ("plugin_ids", "plugins", "families", "hosts")}}
        with _PLANS_LOCK:
            _PLANS[plan_id] = rec
            if len(_PLANS) > 200:
                for k in list(_PLANS)[:len(_PLANS) - 200]:
                    _PLANS.pop(k, None)
        c2log.plan_upsert(plan_id, "generated", source=_src(p), selector=sel, generator=gen["generator"],
                          generated_sha256=v["hash"], hosts=len(g["hosts"]))
        # per-host eligibility against THIS plan, from facts a pre-flight already read (no SSH — linux M3)
        evals = {}
        for t in g["hosts"]:
            pr = _pf_get(t["target"], al)
            if pr and pr.get("cred"):
                evals[t["target"]] = c2_verdict.eligibility(pr, _plan_ctx(rec, bool((t.get("asset") or {}).get("crown"))))
        vs = {}
        pc = v["plan"].get("precheck") or {}
        if pc.get("fixed_version") and inst:
            # fix round (linux M3): compare the versions the pre-flight already read against the plan's fixed build —
            # a server-side compare, no SSH (so a pre-flight run before the plan needs no second run)
            pkgn = c2_remediate.guess_package(src)
            gh = {t["target"] for t in g["hosts"]}
            for t, row in list(inst.items())[:512]:
                if g is not groups[0] and t not in gh:
                    continue
                row = row if isinstance(row, dict) else {}
                fam_, ver_ = str(row.get("family") or ""), str(row.get("version") or "")[:120]
                if not ver_:
                    continue
                if fam_ and fam_ != "unknown" and (pc.get("compare") == "dpkg") != (fam_ == "apt"):
                    vs[str(t)[:255]] = "n/a"
                    continue
                try:
                    vv = _installed_ver(ver_, pkgn, pc.get("compare"))
                    vs[str(t)[:255]] = "at_least" if c2_remediate.version_ok(
                        vv, {"fixed_version": pc["fixed_version"], "compare": pc.get("compare"), "want": "at_least"}) else "older"
                except Exception:
                    pass
        out_groups.append({"plan_id": plan_id, "generator": gen["generator"], "note": gen.get("note"), "vs_fixed": vs,
                           "model": gen.get("model", ""), "source": {k: src[k] for k in ("plugin_ids", "plugins", "families")},
                           "affected_packages": c2_remediate.affected(src)["packages"],
                           "package_guess": c2_remediate.guess_package(src), "family": fam_used, "group": grp,
                           "group_hosts": [t["target"] for t in g["hosts"]], "meta": meta, "cve": rec["cve"],
                           "hosts_eval": evals,
                           "hosts": [{k: h[k] for k in ("ip", "hostname", "os", "family")} | {"outputs": h["outputs"]}
                                     for h in src["hosts"]],
                           "generated_hash": v["hash"], **v})
    top = dict(out_groups[0])
    top["groups"] = out_groups
    top["groups_dropped"] = [{"label": g["label"], "hosts": [t["target"] for t in g["hosts"]]} for g in dropped]
    return {"ok": True, **top}, 200


def _with_plan_src(src, rec):
    """The deploy targets' current source plus the plan-time sampled hosts (sec F1: a canary whose own output lacks
    one of the group's names is validated, then narrowed to its own names at run time — not refused)."""
    ps = (rec or {}).get("src") or {}
    if not ps:
        return src
    have = {h.get("ip") for h in src.get("hosts") or []}
    return dict(src, hosts=list(src.get("hosts") or []) + [h for h in ps.get("hosts") or [] if h.get("ip") not in have])


def plan_validate(p):
    """Re-validate an operator-edited plan against the SAME source text, store it as the plan's
    current version and return what changed vs. the generated plan."""
    pid, rec = _plan_get(p)
    if not rec:
        return {"ok": False, "error": "unknown plan — generate it first (plans live in server memory)"}, 400
    sel = rec["selector"]
    if p.get("selector") not in (None, "", sel):
        return {"ok": False, "error": "this plan was generated for a different selector"}, 400
    ex = _rem_targets(p)
    src = c2_remediate.sources(sel, ex["targets"])
    plan = p.get("plan") or {}
    if isinstance(plan, dict):
        plan = dict(plan, generator="edited")
    v = c2_remediate.validate(plan, src)
    with _PLANS_LOCK:
        if rec["deployed_hashes"] and v["hash"] not in rec["deployed_hashes"]:
            return {"ok": False, "error": "this plan id was already deployed — an edited plan needs a new plan "
                                         "(✨ Generate plan again)"}, 409
        rec.update(plan=v["plan"], hash=v["hash"], deployable=v["deployable"])
    return {"ok": True, "plan_id": pid, "changes": _diff(rec["generated_plan"], v["plan"]),
            "generated_hash": rec["generated_hash"], **v}, 200


def _exit_ok(r, expect):
    ec = r.get("exit_code")
    if ec is not None:
        return ec in (expect or [0])
    return r.get("status") == "ok"


def _check_ok(r, chk):
    """A precheck / verify passed? exit code, then the expected regex or the version compare —
    both judged on the command's OWN output (after the C2_OUT marker), never the echoed line."""
    out = c2_remediate.unwrap(r.get("output"))
    if chk.get("fixed_version"):
        return r.get("exit_code") in (chk.get("expect_exit") or [0]) and c2_remediate.version_ok(out, chk)
    if not _exit_ok(r, chk.get("expect_exit")):
        return False
    rx = chk.get("expect_regex")
    if not rx:
        return True
    try:
        return re.search(rx, out) is not None
    except re.error:
        return False


def _remediate_host(plan, run_id, source, plan_sha, rollback_upto=None, rollback=False, selector="", observed=None,
                    meta=None):
    plan_pkgs = list((meta or {}).get("packages") or [])

    def one(ip):
        log = []
        reads = {}
        pkgs = plan_pkgs
        keep = None
        if not rollback and selector:
            # sec F1 (verify round): the package scope is PER HOST — this host's own finding output (or, without
            # package lines, Tenable's text) decides which of the plan's names may touch THIS host. Never adds a name.
            haff = c2_remediate.affected(c2_remediate.sources(selector, [ip]))
            keep = {k for k in haff["packages"]}
            pkgs = [n for n in plan_pkgs if n in keep]
            if plan_pkgs and not pkgs:
                return {"target": ip, "status": "not_applicable", "steps": log, "ran_upto": 0, "verdict": "not_in_scope",
                        "message": "— Not in this host's finding — its own plugin output lists none of "
                                   + ", ".join(plan_pkgs) + ". Nothing changed (package scope is per host)."}

        def read(ids, when):
            """build 486: a read-only catalog read of the plan's packages (status-aware installed versions; after the
            change also reboot state and services on old libraries) — logged like every command (mode remediation,
            the plan's sha256), never part of the plan, never output in the log."""
            if not pkgs:
                return None
            b = c2_catalog.build(ids, {"names": pkgs}, None)
            if b["errors"]:
                return None
            got = {}
            for ch in b["chunks"]:
                r = navi_cli.push(target=ip, command=ch["command"], agent="c2", run_id=run_id, source=source,
                                  detail=f"C2 remediation read ({when}): " + ",".join(ch["ids"]),
                                  catalog_id="remediation read: " + ",".join(ch["ids"]), plan_sha256=plan_sha,
                                  timeout=ch["timeout"] + 10, strict_host_keys=True)
                if r.get("status") != "ok":
                    return None
                for cid, x in c2_catalog.parse(r.get("output") or "").items():
                    got[cid] = x.get("facts") or {}
            pk = (got.get("pkgstate") or {}).get("pkgs")
            reads[when] = bool(pk)
            return got if pk else None

        def verdict_after(proven=None, before_f=None):
            """The Phase 2 verdict from the before / after package reads, or None (→ the plan's own checks)."""
            if before_f is None:
                return None
            after_f = read(["pkgstate", "rebootreq", "needrestart"], "after")
            if after_f is None:
                return None
            return c2_verdict.host_verdict(dict(meta or {}, packages=pkgs), (before_f.get("pkgstate") or {}).get("pkgs"),
                                           (after_f.get("pkgstate") or {}).get("pkgs"),
                                           reboot=after_f.get("rebootreq"),
                                           services=(after_f.get("needrestart") or {}).get("services"),
                                           krun=(after_f.get("pkgstate") or {}).get("krun"))

        def push(cmd, cid, timeout=900):
            r = navi_cli.push(target=ip, command=c2_remediate.wrap(cmd), agent="c2", detail=f"C2 {cid}", source=source,
                              run_id=run_id, catalog_id=cid, plan_sha256=plan_sha, timeout=timeout, strict_host_keys=True)
            log.append({"what": cid, "command": cmd, "status": r.get("status"), "exit_code": r.get("exit_code"),
                        "output": _cap(c2_remediate.unwrap(r.get("output")) or r.get("output"))[-4000:],
                        "message": (r.get("message") or "")[:300]})
            return r
        if rollback:
            upto = (rollback_upto or {}).get(ip)
            steps = [s for s in plan["steps"] if s.get("rollback") and upto and s["n"] <= upto]
            if not steps:
                return {"target": ip, "status": "skipped", "steps": log,
                        "message": "no step with a rollback ran on this host — nothing to undo"}
            # per-host pins: each rollback is re-pinned to THIS host's installed version from its OWN plugin
            # output, re-validated against that host alone, and cross-checked with what the deploy's precheck
            # actually read on the host. No fact → the host is skipped (never an unpinned install).
            haff = c2_remediate.affected(c2_remediate.sources(selector, [ip]))
            hkeep = set(haff["packages"])
            resolved = []
            for st in sorted(steps, key=lambda s: -s["n"]):
                # verify round 2 (sec "should"): the downgrade covers only THIS host's own names — another host's names
                # never leave this host without an undo; a step with none of this host's names is skipped here
                rcmd, kept_, dropped_ = c2_remediate.narrow_step(st["rollback"], hkeep)
                if dropped_ and not kept_:
                    continue
                cmd, why = c2_remediate.resolve_rollback(rcmd, haff)
                if not why:
                    rs = c2_remediate.check_command(cmd, "step", haff, rollback=True,
                                                   step_pkgs=c2_remediate.step_packages(st["command"]))
                    why = "; ".join(rs)
                obs = (observed or {}).get(ip)
                if not why and obs and len(c2_remediate.step_packages(st["rollback"]) or ()) <= 1:
                    pins = re.findall(r"[=-](\d[^'\s]*)'?$", cmd)
                    if pins and c2_remediate._norm_ver(pins[-1]) != c2_remediate._norm_ver(obs):
                        why = f"the plugin output says {pins[-1]} but the deploy precheck read {obs} on the host"
                if why:
                    return {"target": ip, "status": "not_applicable", "steps": log,
                            "message": f"rollback skipped on this host — {why}"}
                resolved.append((st, cmd))
            if not resolved:
                return {"target": ip, "status": "not_applicable", "steps": log,
                        "message": "nothing to undo here — this host's own finding lists none of the rolled-back packages"}
            for st, cmd in resolved:
                r = push(cmd, f"rollback step {st['n']}")
                if r.get("status") != "ok":
                    return {"target": ip, "status": r.get("status") or "failed", "steps": log,
                            "message": f"rollback of step {st['n']} failed"}
            return {"target": ip, "status": "changed", "steps": log,
                    "message": f"rolled back step(s) {', '.join(str(s['n']) for s in sorted(steps, key=lambda s: -s['n']))}"}
        pc = plan.get("precheck")
        before = ""
        if pc:
            r = push(pc["command"], "remediation precheck", timeout=120)
            if r.get("status") == "timeout":
                # fix round (linux F7): the host WAS reached; the read-only precheck timed out
                return {"target": ip, "status": "timeout", "steps": log, "ran_upto": 0, "verdict": "precheck_timeout",
                        "message": "✗ Precheck timed out — nothing changed (read-only); retry or run pre-flight."}
            if r.get("status") not in ("ok", "failed"):
                return {"target": ip, "status": r.get("status"), "steps": log, "ran_upto": 0,
                        "verdict": "not_reached", "message": "✗ Not reached — " + str(r.get("status") or "").replace("_", " ")
                                                           + ". Nothing ran. " + (r.get("message") or "")[:200]}
            out = c2_remediate.unwrap(r.get("output"))
            before = (out.strip().splitlines() or [""])[0].strip()[:80]
            if r.get("exit_code") in (126, 127):
                # linux C1: "command not found / not executable" is never "not affected" — it is a check that
                # could not run (wrong distro family?), an error
                return {"target": ip, "status": "failed", "steps": log, "ran_upto": 0, "verdict": "check_failed",
                        "message": f"✗ Check could not run (rc {r.get('exit_code')}: the precheck command is missing or "
                                   "not executable — wrong distro family?). Nothing changed."}
            pc_bad = not _check_ok(r, pc)
        else:
            pc_bad, r = False, None
        # build 486: the plan's packages as the host has them NOW (C7: per package, status-aware) — the "before".
        # linux M2 / F1 / F6 (verify round): when this multi-package read works IT decides (not installed / held /
        # already fixed / fixed on disk); the single-package precheck above decides only when the read failed.
        before_f = read(["pkgstate"], "before")
        if before_f is not None:
            bp = before_f["pkgstate"]["pkgs"]
            pre = c2_verdict.before_state(dict(meta or {}, packages=pkgs), bp, before_f["pkgstate"].get("krun") or "")
            if pre:
                return dict(pre, target=ip, steps=log, ran_upto=0, reads=reads)
        elif pc and pc_bad:
            if pc.get("fixed_version") and before and r.get("exit_code") in (pc.get("expect_exit") or [0]):
                verdict, msg = "already_fixed", (f"— Already fixed — installed {before} ≥ fixed {pc['fixed_version']} "
                                                  "(version compare). Nothing changed.")
            elif r.get("exit_code") == 1 and re.match(r"^\s*(dpkg-query|rpm)\b", pc.get("command") or ""):
                verdict, msg = "not_installed", "— Not installed — the package query found no such package (exit 1). Nothing changed."
            else:
                verdict, msg = "not_affected", (f"— Precheck says not affected (exit {r.get('exit_code')}). Nothing changed.")
            return {"target": ip, "status": "not_applicable", "steps": log, "ran_upto": 0, "verdict": verdict,
                    "before": before, "message": msg}
        proven = None                     # the fixed-version compare that passed after the change, if any
        for st in plan["steps"]:
            cmd = st["command"]
            if keep is not None:
                # sec F1: narrow this step's package names to THIS host's scope; re-validate against this host alone
                cmd, kept, dropped = c2_remediate.narrow_step(cmd, keep)
                if dropped and not kept:
                    return {"target": ip, "status": "not_applicable", "steps": log, "ran_upto": st["n"] - 1,
                            "verdict": "not_in_scope", "reads": reads,
                            "message": f"— Step {st['n']} names only packages this host's finding does not list "
                                       f"({', '.join(dropped)}) — nothing changed here."}
                if dropped:
                    bad = c2_remediate.check_command(cmd, "step", haff)
                    if bad:
                        return {"target": ip, "status": "failed", "steps": log, "ran_upto": st["n"] - 1,
                                "verdict": "step_failed", "reads": reads,
                                "message": f"✗ Step {st['n']} narrowed to this host's packages is not valid here "
                                           f"({bad[0]}) — nothing ran."}
            r = push(cmd, f"remediation step {st['n']}")
            if r.get("status") == "timeout":
                # linux P1-7 (Phase 1 page part): a change step that timed out leaves the host in an UNKNOWN state
                return {"target": ip, "status": "timeout", "failed_step": st["n"], "ran_upto": st["n"], "steps": log,
                        "verdict": "unknown_state", "unknown_state": True,
                        "message": f"⚠ Unknown state — step {st['n']} timed out; the command may still be running on the host. "
                                   "Do not re-run or roll back yet. Next: run pre-flight on this host."}
            if not _exit_ok(r, st.get("expect_exit")) or r.get("status") not in ("ok", "failed"):
                nr = r.get("status") not in ("ok", "failed")
                kind_, words = ("", "") if nr else c2_verdict.classify_step_failure(
                    c2_remediate.unwrap(r.get("output")) or r.get("output") or "", r.get("exit_code"), cmd)
                if kind_ == "pm_busy":
                    # fix round 487 (V3-F1): "nothing changed" only after the package versions are re-read and none moved
                    aft = read(["pkgstate"], "after_busy") if before_f is not None else None
                    if aft is None:
                        words = ("✗ Package manager busy — the package versions could not be re-read; check with "
                                 "pre-flight before retrying.")
                    else:
                        cmpk = (meta or {}).get("compare") or "dpkg"
                        bp_, ap_ = before_f["pkgstate"]["pkgs"], aft["pkgstate"]["pkgs"]
                        moved = [f"{n} {c2_verdict.installed_of(bp_, n, cmpk)[1] or '—'} → {c2_verdict.installed_of(ap_, n, cmpk)[1] or '—'}"
                                 for n in pkgs if c2_verdict.installed_of(bp_, n, cmpk)[1] != c2_verdict.installed_of(ap_, n, cmpk)[1]]
                        if moved:
                            kind_ = "lock_wait"
                            words = ("✗ The step failed after waiting for the package lock; the host may be partly changed ("
                                     + ", ".join(moved[:4]) + "). Run pre-flight before retrying.")
                return {"target": ip, "status": (r.get("status") if r.get("status") != "ok" else
                                                 ("not_applicable" if kind_ == "held" else "failed")),
                        "failed_step": st["n"], "ran_upto": (st["n"] - 1 if nr else st["n"]), "steps": log,
                        "verdict": "not_reached" if nr else ({"lock_wait": "step_failed"}.get(kind_, kind_) or "step_failed"),
                        "partly_changed": kind_ == "lock_wait", "reads": reads,
                        "message": (f"✗ Not reached at step {st['n']} — {r.get('status')}." if nr else
                                    (words.replace("✗ ", f"✗ Step {st['n']}: ", 1) if kind_ in ("pm_busy", "lock_wait") else words)
                                    if kind_ else f"✗ Step {st['n']} failed (exit {r.get('exit_code')}) — stopped here.")}
            if st.get("verify") and before_f is None:
                v = push(st["verify"]["command"], f"remediation verify {st['n']}", timeout=120)
                if not _check_ok(v, st["verify"]):
                    # build 486 (linux C6): a failed version compare after the change is a precise verdict — no change,
                    # or upgraded but still below the fixed build — when the package reads can tell which
                    hv = verdict_after(before_f=before_f) if st["verify"].get("fixed_version") else None
                    if hv and hv["verdict"] in ("no_change", "still_vulnerable", "changed_unexpectedly"):
                        return dict(hv, target=ip, failed_step=st["n"], ran_upto=st["n"], steps=log, reads=reads,
                                    status="failed")
                    return {"target": ip, "status": "failed", "failed_step": st["n"], "ran_upto": st["n"], "steps": log,
                            "verdict": "step_failed", "reads": reads,
                            "message": f"✗ Step {st['n']} ran but its verify did not pass — stopped here."}
                if st["verify"].get("fixed_version"):
                    proven = (st["verify"], (c2_remediate.unwrap(v.get("output")).strip().splitlines() or [""])[0].strip())
        pv = plan.get("post_verify") if before_f is None else None   # linux M2: the after-read decides when it works
        if pv:
            v = push(pv["command"], "remediation post_verify", timeout=120)
            if not _check_ok(v, pv):
                hv = verdict_after(before_f=before_f) if pv.get("fixed_version") else None
                if hv and hv["verdict"] in ("no_change", "still_vulnerable", "changed_unexpectedly"):
                    return dict(hv, target=ip, ran_upto=len(plan["steps"]), steps=log, reads=reads, status="failed")
                return {"target": ip, "status": "failed", "steps": log, "ran_upto": len(plan["steps"]),
                        "verdict": "step_failed", "reads": reads,
                        "message": "✗ Post-verify did not pass — the change did not take."}
            if pv.get("fixed_version"):
                proven = (pv, (c2_remediate.unwrap(v.get("output")).strip().splitlines() or [""])[0].strip())
        # build 486 (linux P1-4 / P1-5 / C6 / C7): the verdict from what the host has AFTER the change — every package
        # vs its own fixed build, the worst one decides; reboot required and services still on the old library
        hv = verdict_after(proven, before_f=before_f)
        if hv:
            return dict(hv, target=ip, ran_upto=len(plan["steps"]), steps=log, reads=reads)
        if before_f is not None:
            return {"target": ip, "status": "changed", "steps": log, "ran_upto": len(plan["steps"]), "verdict": "unproven",
                    "reads": reads, "message": "◐ Steps ran — fix not proven (the after-change package read failed; "
                                               "rescan or re-run pre-flight)."}
        if proven:
            chk, after = proven
            return {"target": ip, "status": "changed", "steps": log, "ran_upto": len(plan["steps"]), "verdict": "fixed",
                    "before": before, "after": after[:80], "fixed": chk["fixed_version"],
                    "message": f"✓ Fixed — {before or '?'} → {after or '?'} (≥ fixed {chk['fixed_version']}, version compare). "
                               "Rescan so Tenable sees it."}
        # linux C3 / U6: nothing says "verified" without a fixed-version compare
        return {"target": ip, "status": "changed", "steps": log, "ran_upto": len(plan["steps"]), "verdict": "unproven",
                "before": before,
                "message": "◐ Steps ran — fix not proven (no fixed version in plugin output; rescan)."}
    return one


PF_VALID = 30 * 60

# verify round 2 (sec M7): the ONE override of a server-side eligibility exclusion — a per-host sudo-password include
# named in the confirmed body (owner decision 1). Every other code is a hard exclusion.
OVERRIDABLE = {"sudo_password"}


def _include_sudo(p):
    v = p.get("include_sudo")
    return {str(x) for x in v if isinstance(x, str)} if isinstance(v, list) else set()


def _not_eligible(rec, tg, p, packages=True):
    """[{target, code, reason}] — hosts whose stored pre-flight (≤ PF_VALID, see sec F3) makes them ineligible for this
    plan: c2_verdict.eligibility(), the same function and plan context the page shows. ok or 'nothing to do' (none)
    passes; code sudo_password passes only for a host named in include_sudo; everything else is refused.
    packages=False (rollback): only the host's operational state (login, sudo, family, disk, package-manager lock)."""
    al = _aliases(tg)
    inc = _include_sudo(p)
    out = []
    for t in tg:
        pr = _pf_get(t["target"], al)
        if not pr:
            continue                                  # (deploy refuses it as no_preflight first)
        crown = bool((t.get("asset") or {}).get("crown"))
        ctx = _plan_ctx(rec, crown, t["target"] in inc)
        if not packages:
            ctx = dict(ctx, packages=[], fixed={}, kernel=False, group_key=None)
        e = c2_verdict.eligibility(pr, ctx)
        if e.get("ok") or e.get("none"):
            continue
        out.append({"target": t["target"], "code": e.get("code") or "other", "reason": e.get("reason") or ""})
    return out          # a pre-flight older than this no longer vouches for a host's live OS (sec F3)


def _crown_last(tg):
    """sec F2 (verify round): crown jewels go LAST in every host-changing stage, server-side, whatever order the
    request gave (stable — the relative order of the others is kept)."""
    c = lambda t: bool(((t.get("asset") or {}) if isinstance(t, dict) else {}).get("crown"))    # noqa: E731
    return [t for t in tg if not c(t)] + [t for t in tg if c(t)]


def _crown_last_names(names):
    try:
        ex = c2_targets.expand(list(names))["targets"]
    except Exception:
        return list(names)
    crown = {t["target"] for t in ex if (t.get("asset") or {}).get("crown")}
    return [n for n in names if n not in crown] + [n for n in names if n in crown]


def _family_refusals(rec, tg):
    """Hosts deploy must refuse: {target, why, code} — code no_preflight (FAILS CLOSED, sec F3: no pre-flight record,
    one older than PF_VALID, no parsed live OS, or a live family 'unknown') or family (another family / release
    group / an immutable OS)."""
    fam = (rec or {}).get("family") or ""
    grp = (rec or {}).get("group") or {}
    al = _aliases(tg)
    out = []
    now = time.time()
    for t in tg:
        pr = _pf_get(t["target"], al)
        los = c2_verdict.live_os(pr) if pr else {}
        if not pr or now - (pr.get("ts") or 0) > PF_VALID:
            out.append({"target": t["target"], "code": "no_preflight",
                        "why": "no pre-flight in the last 30 min — run ③ Pre-flight on this host first"})
            continue
        if not los or los.get("family") in (None, "", "unknown"):
            out.append({"target": t["target"], "code": "no_preflight",
                        "why": "pre-flight could not read this host's live OS family (unknown) — fix and re-run pre-flight"})
            continue
        if los.get("immutable"):
            out.append({"target": t["target"], "code": "family",
                        "why": f"immutable OS ({los.get('immutable_kind')}) — not supported by this plan"})
        elif fam and fam != "unknown" and los["family"] != fam:
            out.append({"target": t["target"], "code": "family", "why": f"family {los['family']} ≠ plan {fam}"})
        elif grp.get("live") and (los.get("group") or {}).get("key") and los["group"]["key"] != grp.get("key"):
            out.append({"target": t["target"], "code": "family",
                        "why": f"{los['group']['label']} ≠ plan group {grp.get('label')}"})
    return out


def _rb_avail(rec, plan, tg):
    """linux C9 / spec §4.4: per host, is each step's downgrade pin still available in that host's repos or cache?
    From the rbavail probe the last pre-flight ran BEFORE the change (after an upgrade the old build is gone from
    dpkg status). {target: [{package, version, available: cache | repos | false | null, kernel}]}"""
    m = (rec or {}).get("meta") or {}
    cmp_ = m.get("compare") or "dpkg"
    al = _aliases(tg)
    has_rb = any(s.get("rollback") for s in (plan or {}).get("steps") or [])
    out = {}
    for t in tg:
        pr = _pf_get(t["target"], al)
        rbf = c2_verdict._f(pr, "rbavail") if pr else {}
        pst = c2_verdict._f(pr, "pkgstate").get("pkgs") if pr else {}
        rows = []
        for n in m.get("packages") or []:
            _s, inst, _a, _h = c2_verdict.installed_of(pst or {}, n, cmp_)
            k = c2_remediate.is_kernel_pkg(n)
            if k:
                av = False                                   # kernels: boot the previous kernel instead
            elif not has_rb or not (pr and rbf):
                av = None                                    # no downgrade step, or never probed
            else:
                av = c2_verdict.rollback_available(rbf, n, inst, cmp_)
            rows.append({"package": n, "version": inst, "kernel": k, "available": av})
        out[t["target"]] = rows
    return out


def _simulation(rec, plan):
    """spec §2.3 ⑤: the package manager's own simulation per family — shown in Review, run only as a read-only check
    (never a plan step; owner decision 6). The text only: the page offers it as a check, nothing runs here."""
    m = (rec or {}).get("meta") or {}
    pk = " ".join(c2_catalog.qword(x) for x in m.get("packages") or [])
    if not pk:
        return ""
    return {"apt": f"apt-get -s install --only-upgrade {pk}", "dnf": f"sudo -n dnf --assumeno upgrade {pk}",
            "yum": f"sudo -n yum --assumeno update {pk}",
            "zypper": f"sudo -n zypper --non-interactive update --dry-run {pk}"}.get((rec or {}).get("family") or "", "")


def deploy(p):
    """Deploy the plan stored server-side under plan_id (never a plan the page sends): it must
    have been validated (plan_ai / plan_validate) and the page's copy must hash the same. Canary
    first, stop on the first error, per-step verify, post_verify. Strict host keys always. Every
    pushed command lands in the C2 log with the approved plan's sha256."""
    ex, err = _resolve_targets(p)
    if err:
        return err
    pid, rec = _plan_get(p)
    if not rec:
        return {"ok": False, "error": "unknown plan_id — generate (and validate) the plan first"}, 400
    if p.get("selector") not in (None, "", rec["selector"]):
        return {"ok": False, "error": "plan_id belongs to a different selector"}, 400
    sel = rec["selector"]
    # build 486: the OS-group refusal comes FIRST — with the 486 package scope a wrong-family host's own output names
    # other packages, and the operator must be told "wrong OS group", not "rejected step"
    # (checked first: the most specific pre-contact refusal)
    if not flag(p, "dry_run"):
        _st = c2log.host_states([t["target"] for t in ex["targets"]], _aliases(ex["targets"]))
        unk = [t for t, d in _st.items() if d.get("unknown_state")]
        if unk:
            # fix round (linux M3): never re-deploy onto a host whose last change step timed out
            return {"ok": False, "unknown_state": unk,
                    "error": "unknown state after a timeout on " + ", ".join(unk[:5]) + " — run pre-flight first"}, 409
    mis = _family_refusals(rec, ex["targets"])
    nop = [m for m in mis if m["code"] == "no_preflight"]
    if nop and not flag(p, "dry_run"):
        # sec F3 (verify round): FAIL CLOSED — no contact, no C2-log row, before anything else
        return {"ok": False, "no_preflight": nop,
                "error": "no usable pre-flight for: " + "; ".join(f"{m['target']} — {m['why']}" for m in nop[:5])
                         + " — nothing ran."}, 409
    fmis = [m for m in mis if m["code"] != "no_preflight"]
    if fmis and not flag(p, "dry_run"):
        return {"ok": False, "family_mismatch": fmis,
                "error": "not this plan's OS group: " + "; ".join(f"{m['target']} — {m['why']}" for m in fmis[:5])
                         + " — nothing ran. Deploy each group's own plan."}, 409
    # verify round 2 (sec M7): eligibility is enforced HERE, from each host's stored pre-flight — before re-validation,
    # the crown check, the typed count, confirm, the gates, any contact or any log row
    inel = _not_eligible(rec, ex["targets"], p)
    if inel and not flag(p, "dry_run"):
        return {"ok": False, "not_eligible": inel,
                "error": "not eligible: " + "; ".join(f"{m['target']} — {m['reason']}" for m in inel[:5])
                         + " — nothing ran. Fix the host and re-run pre-flight, or remove it from the Target set."}, 409
    src = _with_plan_src(c2_remediate.sources(sel, ex["targets"]), rec)
    v = c2_remediate.validate(rec["plan"], src)          # re-validate the STORED plan (source may have changed)
    if p.get("plan") is not None and c2_remediate.plan_hash(c2_remediate.normalize(p.get("plan"))) != rec["hash"]:
        return {"ok": False, "error": "the plan on the page differs from the last validated version — ↻ Re-validate "
                                      "your edits first", "rejected": v["rejected"]}, 409
    if not v["deployable"]:
        return {"ok": False, "error": "plan is not deployable — fix or remove the rejected step(s) first",
                "rejected": v["rejected"], "warnings": v["warnings"]}, 400
    with _PLANS_LOCK:
        if rec["deployed_hashes"] and v["hash"] not in rec["deployed_hashes"]:
            return {"ok": False, "error": "this plan id was deployed with a different plan — generate a new plan"}, 409
    plan = v["plan"]
    stage = str(p.get("stage") or "")
    stage = stage if stage in ("canary", "rollout", "all") else ""
    if stage == "canary":
        # owner decision 3, enforced here too (the page already disables it): the canary is ONE host and never a
        # crown jewel — a request built outside the page can't make a production-critical host the first one changed
        tg = ex["targets"]
        crown = [t.get("target") for t in tg if ((t.get("asset") or {}).get("crown"))]
        if len(tg) != 1 or crown:
            return {"ok": False, "error": ("a crown jewel is never the canary: " + ", ".join(crown[:3])) if crown
                    else "the canary stage takes exactly one host"}, 400
    else:
        # sec F2 (verify round): one-run ("all"), roll-out and an unstaged deploy — crown jewels LAST, server-side.
        # Sorted BEFORE the typed-count / sha check, so a request whose confirmed order put a crown first is refused
        # (409, the list changed) and the page's own crown-last order passes unchanged.
        ex = dict(ex, targets=_crown_last(ex["targets"]))
    mm = _expect(p, [t["target"] for t in ex["targets"]])
    if mm and not flag(p, "dry_run"):
        return mm
    # (the OS-group refusal ran above, before re-validation — build 486, linux M3 / P1-1)
    if flag(p, "dry_run"):
        seq = ([("precheck", plan["precheck"]["command"])] if plan.get("precheck") else []) + \
              [x for st in plan["steps"] for x in ([(f"step {st['n']}", st["command"])] +
                                                    ([(f"verify {st['n']}", st["verify"]["command"])] if st.get("verify") else []))] + \
              ([("post_verify", plan["post_verify"]["command"])] if plan.get("post_verify") else [])
        scope_w, scope = [], {}
        mp = list((rec.get("meta") or {}).get("packages") or [])
        for t in ex["targets"][:50]:
            hk = set(c2_remediate.affected(c2_remediate.sources(sel, [t["target"]]))["packages"])
            keep_, drop_ = [n for n in mp if n in hk], [n for n in mp if n not in hk]
            scope[t["target"]] = {"packages": keep_, "not_listed": drop_}
            if drop_:
                scope_w.append(f"{t['target']}: upgrades only {', '.join(keep_) or 'nothing'} — its own finding does not list "
                               f"{', '.join(drop_)} (package scope is per host)")
        return {"ok": True, "dry_run": True, "targets": ex["targets"], "warnings": ex["warnings"] + v["warnings"]
                + [f"{m['target']}: {m['why']} — deploy would refuse it" for m in mis]
                + [f"{m['target']}: not eligible ({m['code']}) — {m['reason']} — deploy would refuse it" for m in inel]
                + scope_w, "scope": scope, "not_eligible": inel,
                "sequence": [{"what": a, "command": b} for a, b in seq], "approved_hash": v["hash"],
                "rollback_available": _rb_avail(rec, plan, ex["targets"]),
                "simulation": _simulation(rec, plan),
                "hostkey_policy": "strict (--strict-host-keys)",
                "message": f"dry run — {len(seq)} command(s) per host on {len(ex['targets'])} host(s); nothing was sent"}, 200
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — deploying a remediation plan changes remote hosts"}, 400
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.rce_gate_reason(), **navi_cli.push_status()}, 200
    with _PLANS_LOCK:
        rec["deployed_hashes"].add(v["hash"])
    c2log.plan_upsert(pid, "approved", source=_src(p), selector=sel, generator=rec["generator"],
                      generated_sha256=rec["generated_hash"], approved_sha256=v["hash"], hosts=len(ex["targets"]))
    src_tag = "remediation:" + pid + ((" via " + _src(p)) if p.get("source") else "")
    stage = str(p.get("stage") or "")
    stage = stage if stage in ("canary", "rollout", "all") else ""
    res, code = _start("remediate", f"plan {pid} · {sel}" + (f" · {stage}" if stage else ""), ex,
                       lambda rid: _remediate_host(plan, rid, src_tag, v["hash"], meta=rec.get("meta"), selector=sel),
                       p, sync_max=1,
                       default_max_errors=0, extra={"plan_id": pid, "plan": plan, "selector": sel, "stage": stage,
                                                    "plan_hash": v["hash"]})
    if res.get("run_id"):
        with _PLANS_LOCK:
            if not isinstance(rec["runs"].get(res["run_id"]), dict):
                rec["runs"][res["run_id"]] = {"run_id": res["run_id"], "stage": stage, "status": "running",
                                              "hosts": len(ex["targets"])}
    res["plan_id"], res["approved_hash"] = pid, v["hash"]
    return res, code


def rollback(p):
    """Undo — per host, ONLY the steps that ran there in the given deployment (up to and including
    the failed step), newest first, using the stored plan's validated rollback commands. Honors
    dry_run; separately confirmed; never automatic."""
    pid, rec = _plan_get(p)
    if not rec:
        return {"ok": False, "error": "unknown plan_id — rollback needs the deployed plan"}, 400
    rid = str(p.get("run_id") or "")
    with _RUNS_LOCK:
        run = _RUNS.get(rid)
        run = json.loads(json.dumps({k: v for k, v in run.items() if k != "plan"}, default=str)) if run else None
    if not run or run.get("plan_id") != pid or run.get("kind") != "remediate":
        return {"ok": False, "error": "unknown deployment run for this plan (server restarted?) — check the C2 log"}, 400
    if run["status"] in ("queued", "running"):
        return {"ok": False, "error": "the deployment is still running"}, 409
    upto = {h["target"]: int(h.get("ran_upto") or 0) for h in run.get("hosts") or [] if h.get("ran_upto")}
    observed = {}
    for h in run.get("hosts") or []:
        pre = next((x for x in h.get("steps") or [] if x.get("what") == "remediation precheck"), None)
        line = ((pre or {}).get("output") or "").strip().splitlines()
        if line and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,80}", line[0].strip()):
            observed[h["target"]] = line[0].strip()
    plan = (_RUNS.get(rid) or {}).get("plan") or rec["plan"]
    want = [t for t in c2_targets.parse(p.get("targets") or list(upto))]
    hosts = _crown_last_names([h for h in want if upto.get(h)])          # sec F2: crown jewels last
    if not hosts:
        return {"ok": False, "error": "no selected host ran any step of this deployment — nothing to undo"}, 400
    if not any(s.get("rollback") for s in plan["steps"]):
        return {"ok": False, "error": "this plan has no (valid) rollback steps"}, 400
    # fix round (linux F1): the C2 log decides (the same source as targets.log_state) — a clean pre-flight after
    # the timeout clears it, so the downgrade the error message points to becomes possible again
    _st = c2log.host_states(hosts, _aliases(c2_targets.expand(hosts)["targets"]))
    unknown = [h for h in hosts if (_st.get(h) or {}).get("unknown_state")]
    if unknown and not flag(p, "dry_run"):
        # linux SEC-6 / L-7 (the page hides it in Phase 1; refuse here too): a timed-out change step means the
        # command may still be running — a downgrade now could race it
        return {"ok": False, "unknown_state": unknown,
                "error": "unknown state after a timeout on " + ", ".join(unknown[:5]) + " — run pre-flight first"}, 409
    # verify round 2 (sec M7, where it applies): a downgrade needs the same OPERATIONAL eligibility from the host's
    # latest pre-flight (login, sudo, family, disk, package-manager lock / half-configured); the package rows don't
    # apply — the fix is installed by now. No pre-flight record → the run-bound checks above decide (as before).
    inel = _not_eligible(rec, c2_targets.expand(hosts)["targets"], p, packages=False)
    if inel and not flag(p, "dry_run"):
        return {"ok": False, "not_eligible": inel,
                "error": "not eligible: " + "; ".join(f"{m['target']} — {m['reason']}" for m in inel[:5]) + " — nothing ran."}, 409
    mm = _expect(p, hosts)
    if mm and not flag(p, "dry_run"):
        return mm
    if flag(p, "dry_run"):
        seq = []
        for h in hosts:
            haff = c2_remediate.affected(c2_remediate.sources(rec["selector"], [h]))
            for s_ in sorted(plan["steps"], key=lambda s: -s["n"]):
                if s_.get("rollback") and s_["n"] <= upto[h]:
                    rcmd, kept_, dropped_ = c2_remediate.narrow_step(s_["rollback"], set(haff["packages"]))
                    if dropped_ and not kept_:
                        seq.append({"what": f"{h}: undo step {s_['n']}",
                                    "command": "(skipped — this host's finding lists none of " + ", ".join(dropped_) + ")"})
                        continue
                    cmd, why = c2_remediate.resolve_rollback(rcmd, haff)
                    seq.append({"what": f"{h}: undo step {s_['n']}", "command": cmd or ("(skipped — " + why + ")")})
        av = _rb_avail(rec, plan, c2_targets.expand(hosts)["targets"])
        return {"ok": True, "dry_run": True, "sequence": seq, "available": av,
                "message": f"dry run — rollback on {len(hosts)} host(s); nothing was sent"}, 200
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — rollback changes remote hosts"}, 400
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.rce_gate_reason(), **navi_cli.push_status()}, 200
    ex = c2_targets.expand(hosts)
    res, code = _start("rollback", f"rollback {pid}", ex,
                       lambda r_: _remediate_host(plan, r_, "rollback:" + pid, rec["hash"], rollback_upto=upto,
                                                  rollback=True, selector=rec["selector"], observed=observed),
                       p, sync_max=1, default_max_errors=0,
                       extra={"plan_id": pid})
    if res.get("run"):
        if res["run"]["status"] == "done":
            c2log.plan_upsert(pid, "rolled_back")
    return res, code


def plans(p):
    out = c2log.plans(_int(p.get("limit"), 50, 1, 500))
    with _PLANS_LOCK:
        for r in out:
            rec = _PLANS.get(r.get("plan_id"))
            if rec:
                r["runs"] = [x for x in rec["runs"].values() if isinstance(x, dict)]
    return {"ok": True, "plans": out}, 200


# --------------------------------------------------------------------------- #
#  The C2 command log (reads)
# --------------------------------------------------------------------------- #
def _log_filters(p):
    return {k: p.get(k) for k in ("status", "source", "agent", "mode", "run_id", "catalog_id", "target", "q",
                                  "since", "until", "in_inventory", "hostkey_policy") if p.get(k) not in (None, "")}


def c2log_rows(p):
    r = c2log.rows(_log_filters(p), limit=p.get("limit") or 5000)
    return {"ok": True, **r, "facets": c2log.facets(), "chain": c2log.verify_chain()}, 200


def c2log_export(p):
    return {"ok": True, **c2log.export_csv(_log_filters(p))}, 200


ACTIONS = {"run": run, "load": load, "status": status, "hosts": hosts, "precheck": precheck,
           "command": command, "upload": upload, "push_file": push_file, "plan": plan,
           "campaign": campaign, "abort": abort, "verify": verify, "log": log, "refresh": refresh,
           # build 443+: diagnostics, credential test, path check, AI remediation, runs, command log
           "catalog": catalog, "targets": targets, "glance": glance, "run_checks": run_checks,
           "cred_test": cred_test, "path_check": path_check, "run_status": run_status,
           "plan_ai": plan_ai, "plan_validate": plan_validate, "deploy": deploy, "rollback": rollback,
           "plans": plans, "c2log": c2log_rows, "c2log_export": c2log_export,
           # build 485: acknowledge a CHANGED-host-key banner (an `ack` row in the C2 log; sec C6)
           "ack": ack,
           # build 486: the Phase 2 pre-flight (strict login + bundle + per-host eligibility, one confirm)
           "preflight": preflight}
