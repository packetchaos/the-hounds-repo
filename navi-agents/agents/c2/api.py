"""Command & Control (Amarok) — self-contained HTTP actions over ``navi action push``.

Read-only: status, hosts, precheck, plan, verify, log.
Executes (gated + confirm): command, push_file, campaign.
The push itself is triple-gated in core/navi_cli.py; this layer adds the operator
workflow — Linux-only host discovery, the destructive-command force step, armed
canary-first batches with an abort switch, and vuln→host patch derivation.
"""
import base64
import json
import os
import re
import threading
import time
import uuid

from core import db, navi_cli, c2_catalog, c2_targets, c2log, c2_remediate, hx_summary
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


def _like(pat):
    """SQLite `LIKE '%pat%'` (ASCII case-insensitive, % and _ wildcards) as a compiled regex."""
    rx = _LIKE_CACHE.get(pat)
    if rx is None:
        rx = re.compile("".join(".*" if ch == "%" else ("." if ch == "_" else re.escape(ch))
                                for ch in _alower(pat)), re.S)
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
    return {"ok": True, **navi_cli.push_status(), "ssh": db.ssh_status()}, 200


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
        try:
            _sel, ip, _os, _ok = _asset_sql()
            hs = _hosts_where(f"TRIM(COALESCE({ip},''),{_WS}) = ? OR uuid = ?", (target, target))
            host = hs[0] if hs else None
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
    return {"ok": True, "dangers": dangers, "danger": bool(dangers), "host": host,
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
    return {"ok": True, "selector": sel, "matched_assets": n_uuids, "plugin_names": names,
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
    fields = "plugin_id, solution" + (", plugin_name" if "plugin_name" in cols else "") \
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
    p = pkg or "<package>"
    return [
        {"os": "Debian / Ubuntu",
         "cmd": f"sudo DEBIAN_FRONTEND=noninteractive apt-get update && "
                f"sudo DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y {p}"},
        {"os": "RHEL / CentOS / Rocky / Alma", "cmd": f"sudo dnf -y update {p} || sudo yum -y update {p}"},
        {"os": "SUSE", "cmd": f"sudo zypper --non-interactive update {p}"},
        {"os": "Amazon Linux", "cmd": f"sudo yum -y update {p}"},
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
    return {"ok": True, "path": dest, "name": name, "bytes": len(raw), "pruned": pruned}, 200


def _uploaded(path):
    """True only for a real file that lives inside the upload dir (no path escape)."""
    ap = os.path.abspath(path or "")
    return bool(ap) and os.path.exists(ap) and os.path.dirname(ap) == os.path.abspath(_UPLOAD_DIR)


def _src(p, default="c2"):
    """Who asked: 'c2', or 'handoff:<hound>' for a request another hound handed over."""
    h = re.sub(r"[^A-Za-z0-9 ._:/()-]", "", str(p.get("source") or ""))[:60].strip()
    return ("handoff:" + h) if h else default


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
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "status": "blocked", "reason": navi_cli.rce_gate_reason(),
                "message": navi_cli.rce_gate_reason(), **navi_cli.push_status()}, 200
    dangers = navi_cli.scan_command(cmd)
    if dangers and not flag(p, "force"):
        return {"ok": False, "needs_force": True, "dangers": dangers,
                "error": "destructive command — resend with force=true to run: " + "; ".join(dangers)}, 200
    res = navi_cli.push(target=target, command=cmd, agent="c2", detail=cmd, source=_src(p),
                        run_id=c2log.new_run("cmd"), strict_host_keys=_strict(p), timeout=_int(p.get("timeout"), None, 5, 3600))
    return {"ok": bool(res.get("ok")), **res, **navi_cli.push_status()}, 200


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
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "status": "blocked", "reason": navi_cli.rce_gate_reason(),
                "message": navi_cli.rce_gate_reason(), **navi_cli.push_status()}, 200
    res = navi_cli.push(target=target, file=path, agent="c2", detail="scp " + os.path.basename(path),
                        source=_src(p), run_id=c2log.new_run("file"), strict_host_keys=_strict(p),
                        timeout=_int(p.get("timeout"), 600, 5, 3600))
    return {"ok": bool(res.get("ok")), **res, **navi_cli.push_status()}, 200


def campaign(p):
    """Armed batch across many hosts. Requires armed=true AND confirm=true. Loops per-IP as
    ONE background job: canary-first, stop-on-failure (or an error threshold), blast-radius
    cap, abortable, progress in run_status."""
    if not flag(p, "armed"):
        return {"ok": False, "error": "campaign is not armed — flip ARM, then confirm, to run"}, 400
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
    batch = targets[:cap]
    busy = _busy()
    if busy:
        return busy
    cid = c2log.new_run("camp")
    _run_new(cid, "campaign", c2log.mask(cmd or ("scp " + os.path.basename(path)))[:120], batch,
             {"canary": canary, "stop": stop, "max_errors": (0 if stop else None)})
    from core import tagq
    # the command itself never goes into the Tagging log's job spec (it may hold a secret) —
    # the job carries only the run id; the work waits in _PENDING
    kw = {"hosts": batch, "command": cmd, "file": path, "canary": canary, "stop": stop, "campaign_id": cid,
          "source": _src(p), "strict": _strict(p), "timeout": _int(p.get("timeout"), 900, 5, 3600),
          "max_errors": (_int(p.get("max_errors"), None, 0, 5000) if not stop else 0)}
    _PENDING[cid] = (None, None, {"campaign": kw, "client": _client()})
    job = tagq.submit(
        _job, {"run_id": cid},
        {"agent": "c2", "category": "C2 · campaign", "value": f"{len(batch)} host(s)",
         "selector": ("file" if path else "command"),
         "detail": c2log.mask(cmd or ("scp " + os.path.basename(path)))[:200], "op": "push"})
    _run_set(cid, job_id=job["id"])
    return {"ok": True, "queued": True, "job_id": job["id"], "campaign_id": cid, "run_id": cid, "hosts": len(batch),
            "canary": canary, "stop_on_failure": stop,
            "message": f"campaign #{job['id']} armed & running in the background "
                       f"({len(batch)} host(s){' · canary first' if canary else ''}). "
                       "Track it under Runs (and the C2 log); use Abort to halt.",
            **navi_cli.push_status()}, 200


def _bulk_push(hosts=None, command="", file="", canary=True, stop=True, campaign_id="", agent="c2",
               source="c2", strict=True, max_errors=None, timeout=900):
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
                 max_errors=(0 if stop else max_errors))


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


def _loop(run_id, hosts, fn, canary=True, max_errors=None, max_errors_pct=None):
    """Sequential per-host loop (navi push drives one pexpect session at a time) with
    canary-first, an error threshold (count and/or % of hosts), and abort between hosts.
    Hosts never reached are marked skipped (threshold) or cancelled (abort) — and, since
    nothing ran on them, they get no C2-log row."""
    _run_set(run_id, status="running", started=time.time())
    errors, done, halted, why = 0, 0, False, ""
    n = len(hosts)
    for i, ip in enumerate(hosts):
        if _aborted(run_id):
            for k in range(i, n):
                _run_host(run_id, k, {"target": hosts[k], "status": "cancelled", "message": "aborted before this host"})
            with _ABORT_LOCK:
                _ABORT.discard(run_id)
            msg = f"aborted after {done} host(s); {n - done} not touched"
            _run_set(run_id, status="aborted", done=done, errors=errors, finished=time.time(), message=msg)
            return {"ok": False, "aborted": True, "message": msg, "run_id": run_id}
        _run_host(run_id, i, {"target": ip, "status": "running"})
        try:
            res = fn(ip)
        except Exception as e:  # pragma: no cover
            res = {"target": ip, "status": "failed", "message": str(e)[:300]}
        if canary and i == 0:
            res["canary"] = True
        _run_host(run_id, i, res)
        done += 1
        if res.get("status") not in OK_STATES:
            errors += 1
            if canary and i == 0 and n > 1:
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
            _run_set(run_id, status="halted", finished=time.time(), message=msg)
            return {"ok": False, "halted": True, "message": msg, "run_id": run_id}
    with _ABORT_LOCK:
        _ABORT.discard(run_id)
    msg = f"ran on {done} host(s); {errors} with errors"
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
    return {"ok": True, **c2_targets.expand(raw, cap=_int(p.get("cap"), c2_targets.CIDR_CAP, 1, c2_targets.CIDR_CAP))}, 200


def glance(p):
    st = c2log.stats()
    ch = c2log.verify_chain()
    with _RUNS_LOCK:
        active = sum(1 for r in _RUNS.values() if r["status"] in ("queued", "running"))
    try:
        nlin = _os_stats()["linux"]
    except Exception:
        nlin = 0
    return {"ok": True, **st, "chain": ch, "active_runs": active, "linux_hosts": nlin,
            "ssh": db.ssh_status(), **navi_cli.push_status()}, 200


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


def _diag_host(run_id, built, source, retries, kind):
    """One host: push each bundle chunk (one SSH session each), parse per-check results."""
    def one(ip):
        checks, status, msg, attempts = {}, "ok", "", 1
        for ch in built["chunks"]:
            r = navi_cli.push(target=ip, command=ch["command"], agent="c2",
                              detail=f"C2 {kind}: " + ",".join(ch["ids"]), source=source, run_id=run_id,
                              catalog_id=",".join(ch["ids"]), timeout=ch["timeout"] + 10, retries=retries,
                              strict_host_keys=False)
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
        return {"target": ip, "status": status, "message": msg, "checks": checks, "attempts": attempts}
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
        plan_id, kind, status = r.get("plan_id"), r.get("kind"), r.get("status")
    if plan_id and kind == "remediate":
        c2log.plan_upsert(plan_id, "deployed" if (out.get("ok") and status == "done") else "failed")
    if plan_id and kind == "rollback" and status == "done":
        c2log.plan_upsert(plan_id, "rolled_back")


def _start(kind, label, ex, make_fn, p, sync_max=2, units=1, default_max_errors=None, extra=None):
    """Run make_fn(run_id)(ip) per host — inline when small, else on the tag queue — and answer the page."""
    busy = _busy()
    if busy:
        return busy
    hosts = [t["target"] for t in ex["targets"]]
    run_id = c2log.new_run(kind)
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
    _run_new(run_id, kind, label, hosts, {"canary": canary, "max_errors": max_errors, "max_errors_pct": pct})
    if extra:
        _run_set(run_id, **extra)
    inv = {t["target"]: t for t in ex["targets"]}
    with _RUNS_LOCK:
        for h in _RUNS[run_id]["hosts"]:
            t = inv.get(h["target"]) or {}
            h["in_inventory"] = t.get("in_inventory")
            h["asset"] = t.get("asset")
    if len(hosts) * units <= sync_max and not flag(p, "queue"):
        out = _loop(run_id, hosts, fn, canary=canary, max_errors=max_errors, max_errors_pct=pct)
        _after(run_id, out)
        with _RUNS_LOCK:
            run = json.loads(json.dumps(_RUNS.get(run_id), default=str))
        return {"ok": bool(out.get("ok")), "run_id": run_id, "run": run, "message": out.get("message"),
                **navi_cli.push_status()}, 200
    from core import tagq
    _PENDING[run_id] = (hosts, fn, {"canary": canary, "max_errors": max_errors, "max_errors_pct": pct,
                                    "client": _client()})
    job = tagq.submit(_job, {"run_id": run_id},
                      {"agent": "c2", "category": "C2 · " + kind, "value": f"{len(hosts)} host(s)",
                       "selector": kind, "detail": label[:200], "op": "c2_run"})
    _run_set(run_id, job_id=job["id"])
    return {"ok": True, "queued": True, "run_id": run_id, "job_id": job["id"], "hosts": len(hosts),
            "message": f"running on {len(hosts)} host(s) in the background"
                       + (" · canary first" if canary else "") + " — progress below; ⛔ Abort stops before the next host.",
            **navi_cli.push_status()}, 200


def _dry(kind, ex, built, extra=None):
    """Exactly what WOULD run where — nothing is sent, nothing is logged."""
    return {"ok": True, "dry_run": True, "kind": kind,
            "targets": ex["targets"], "warnings": ex["warnings"],
            "pushes": [{"target": t["target"], "commands": [{"ids": ch["ids"], "command": ch["command"],
                                                             "navi_timeout": ch["timeout"] + 10}
                                                            for ch in built["chunks"]]}
                       for t in ex["targets"]],
            "hostkey_policy": "accept-new (navi default: record a NEW key, refuse a CHANGED one)",
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
    if flag(p, "dry_run"):
        return _dry("diagnostics", ex, built)
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — the checks run on remote hosts over SSH"}, 400
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.rce_gate_reason(), **navi_cli.push_status()}, 200
    retries = _int(p.get("retries"), 1, 0, 3)
    src = _src(p)
    return _start("diag", "checks: " + ",".join(built["checks"]), ex,
                  lambda rid: _diag_host(rid, built, src, retries, "diagnostics"), p, units=len(built["chunks"]))


def cred_test(p):
    """`id; sudo -n true` on each host — login works? sudo without a password? Short timeout,
    ONE attempt (auth failures are never retried: lockout), navi's default host-key policy
    (a new host's key is recorded; a CHANGED key is a security event and nothing runs)."""
    ex, err = _resolve_targets(p)
    if err:
        return err
    built = c2_catalog.build(["cred"], {}, 15)
    if flag(p, "dry_run"):
        return _dry("cred_test", ex, built)
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required — the credential test logs in to remote hosts"}, 400
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.rce_gate_reason(), **navi_cli.push_status()}, 200
    src = _src(p)

    def make(rid):
        base = _diag_host(rid, built, src, 0, "credential test")

        def one(ip):
            r = base(ip)
            c = (r.get("checks") or {}).get("cred") or {}
            f = c.get("facts") or {}
            r["sudo"] = ("sudo_ok" if f.get("sudo") == "ok" else "sudo_needs_password"
                         if f.get("sudo") == "needs_password" else "")
            r["user"] = f.get("user") or ""
            r["security_event"] = r["status"] == "hostkey_mismatch"
            return r
        return one
    return _start("cred", "credential test", ex, make, p, sync_max=2)


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


def plan_ai(p):
    """Tenable's text (navi.db) → a STRICT JSON plan via the configured model (or the
    deterministic templates) → the deterministic validator. Nothing runs here."""
    sel = str(p.get("selector") or "").strip()
    if not sel:
        return {"ok": False, "error": "enter a plugin id or CVE"}, 400
    ex = _rem_targets(p)
    if ex["refused"]:
        return {"ok": False, "error": "refused target(s): " + ", ".join(r["input"] for r in ex["refused"][:5])}, 400
    src = c2_remediate.sources(sel, ex["targets"])
    if not src["plugin_ids"]:
        return {"ok": False, "error": "no plugin found for that selector in navi.db"}, 200
    fam = str(p.get("family") or "").strip() or None
    gen = c2_remediate.generate(src, family=fam, use_llm=p.get("use_llm", True) is not False)
    v = c2_remediate.validate(gen["plan"], src)
    plan_id = c2log.new_run("plan")
    with _PLANS_LOCK:
        _PLANS[plan_id] = {"selector": sel, "generator": gen["generator"], "generated_plan": v["plan"],
                           "generated_hash": v["hash"], "plan": v["plan"], "hash": v["hash"],
                           "deployable": v["deployable"], "deployed_hashes": set(), "runs": {}}
        if len(_PLANS) > 200:
            for k in list(_PLANS)[:len(_PLANS) - 200]:
                _PLANS.pop(k, None)
    c2log.plan_upsert(plan_id, "generated", source=_src(p), selector=sel, generator=gen["generator"],
                      generated_sha256=v["hash"], hosts=len(ex["targets"]))
    return {"ok": True, "plan_id": plan_id, "generator": gen["generator"], "note": gen.get("note"),
            "model": gen.get("model", ""), "source": {k: src[k] for k in ("plugin_ids", "plugins", "families")},
            "affected_packages": c2_remediate.affected(src)["packages"],
            "hosts": [{k: h[k] for k in ("ip", "hostname", "os", "family")} | {"outputs": h["outputs"]}
                      for h in src["hosts"]],
            "generated_hash": v["hash"], **v}, 200


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


def _remediate_host(plan, run_id, source, plan_sha, rollback_upto=None, rollback=False, selector="", observed=None):
    def one(ip):
        log = []

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
            resolved = []
            for st in sorted(steps, key=lambda s: -s["n"]):
                cmd, why = c2_remediate.resolve_rollback(st["rollback"], haff)
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
            for st, cmd in resolved:
                r = push(cmd, f"rollback step {st['n']}")
                if r.get("status") != "ok":
                    return {"target": ip, "status": r.get("status") or "failed", "steps": log,
                            "message": f"rollback of step {st['n']} failed"}
            return {"target": ip, "status": "changed", "steps": log,
                    "message": f"rolled back step(s) {', '.join(str(s['n']) for s in sorted(steps, key=lambda s: -s['n']))}"}
        pc = plan.get("precheck")
        if pc:
            r = push(pc["command"], "remediation precheck", timeout=120)
            if r.get("status") not in ("ok", "failed"):
                return {"target": ip, "status": r.get("status"), "steps": log, "ran_upto": 0,
                        "message": r.get("message", "")[:300]}
            if not _check_ok(r, pc):
                return {"target": ip, "status": "not_applicable", "steps": log, "ran_upto": 0,
                        "message": "precheck says this host is not affected (or already fixed) — nothing changed"}
        for st in plan["steps"]:
            r = push(st["command"], f"remediation step {st['n']}")
            if not _exit_ok(r, st.get("expect_exit")) or r.get("status") not in ("ok", "failed"):
                return {"target": ip, "status": (r.get("status") if r.get("status") != "ok" else "failed"),
                        "failed_step": st["n"], "ran_upto": st["n"], "steps": log,
                        "message": f"step {st['n']} failed ({r.get('status')}, exit {r.get('exit_code')}) — stopped here; "
                                   "rollback is offered separately"}
            if st.get("verify"):
                v = push(st["verify"]["command"], f"remediation verify {st['n']}", timeout=120)
                if not _check_ok(v, st["verify"]):
                    return {"target": ip, "status": "failed", "failed_step": st["n"], "ran_upto": st["n"], "steps": log,
                            "message": f"step {st['n']} ran but its verify did not pass — stopped here"}
        pv = plan.get("post_verify")
        if pv:
            v = push(pv["command"], "remediation post_verify", timeout=120)
            if not _check_ok(v, pv):
                return {"target": ip, "status": "failed", "steps": log, "ran_upto": len(plan["steps"]),
                        "message": "post_verify did not pass"}
        return {"target": ip, "status": "changed", "steps": log, "ran_upto": len(plan["steps"]),
                "message": "all steps ran and verified — rescan to confirm Tenable sees it fixed"}
    return one


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
    src = c2_remediate.sources(sel, ex["targets"])
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
    if flag(p, "dry_run"):
        seq = ([("precheck", plan["precheck"]["command"])] if plan.get("precheck") else []) + \
              [x for st in plan["steps"] for x in ([(f"step {st['n']}", st["command"])] +
                                                    ([(f"verify {st['n']}", st["verify"]["command"])] if st.get("verify") else []))] + \
              ([("post_verify", plan["post_verify"]["command"])] if plan.get("post_verify") else [])
        return {"ok": True, "dry_run": True, "targets": ex["targets"], "warnings": ex["warnings"] + v["warnings"],
                "sequence": [{"what": a, "command": b} for a, b in seq], "approved_hash": v["hash"],
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
    res, code = _start("remediate", f"plan {pid} · {sel}", ex,
                       lambda rid: _remediate_host(plan, rid, src_tag, v["hash"]), p, sync_max=1,
                       default_max_errors=0, extra={"plan_id": pid, "plan": plan, "selector": sel})
    if res.get("run_id"):
        with _PLANS_LOCK:
            rec["runs"][res["run_id"]] = True
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
    hosts = [h for h in want if upto.get(h)]
    if not hosts:
        return {"ok": False, "error": "no selected host ran any step of this deployment — nothing to undo"}, 400
    if not any(s.get("rollback") for s in plan["steps"]):
        return {"ok": False, "error": "this plan has no (valid) rollback steps"}, 400
    if flag(p, "dry_run"):
        seq = []
        for h in hosts:
            haff = c2_remediate.affected(c2_remediate.sources(rec["selector"], [h]))
            for s_ in sorted(plan["steps"], key=lambda s: -s["n"]):
                if s_.get("rollback") and s_["n"] <= upto[h]:
                    cmd, why = c2_remediate.resolve_rollback(s_["rollback"], haff)
                    seq.append({"what": f"{h}: undo step {s_['n']}", "command": cmd or ("(skipped — " + why + ")")})
        return {"ok": True, "dry_run": True, "sequence": seq,
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
    return {"ok": True, "plans": c2log.plans(_int(p.get("limit"), 50, 1, 500))}, 200


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
           "plans": plans, "c2log": c2log_rows, "c2log_export": c2log_export}
