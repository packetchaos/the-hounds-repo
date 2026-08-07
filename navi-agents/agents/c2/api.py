"""Command & Control (Amarok) — self-contained HTTP actions over ``navi action push``.

Read-only: status, hosts, precheck, plan, verify, log.
Executes (gated + confirm): command, push_file, campaign.
The push itself is triple-gated in core/navi_cli.py; this layer adds the operator
workflow — Linux-only host discovery, the destructive-command force step, armed
canary-first batches with an abort switch, and vuln→host patch derivation.
"""
import base64
import os
import re
import threading
import uuid

from core import db, navi_cli
from .agent import C2Agent

AGENT = C2Agent()

# Uploaded files land here (repo_root/data/c2_uploads) so `navi action push --file`
# has a real local path to scp. A push may only ship a file from THIS directory.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_UPLOAD_DIR = os.path.join(_REPO_ROOT, "data", "c2_uploads")
_MAX_UPLOAD = int(os.environ.get("NAVI_C2_MAX_UPLOAD", str(25 * 1024 * 1024)))

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
#  Read-only actions
# --------------------------------------------------------------------------- #
def run(p):
    return {"ok": True, "agent": AGENT.meta(), "result": AGENT.run()}, 200


def load(p):
    return run(p)


def status(p):
    return {"ok": True, **navi_cli.push_status(), "ssh": db.ssh_status()}, 200


def hosts(p):
    allh = _hosts_raw()
    linux = [h for h in allh if h["os_class"] == "linux" and h["ip"]]
    other = [h for h in allh if not (h["os_class"] == "linux" and h["ip"])]
    return {"ok": True, "linux": linux, "linux_count": len(linux),
            "excluded_count": len(other), "excluded_breakdown": _breakdown(other),
            **navi_cli.push_status()}, 200


def precheck(p):
    """Read-only safety review of a proposed command + target: destructive-command
    denylist, OS class (Linux-only), crown-jewel flag, and a secret-in-command warning."""
    cmd = (p.get("command") or "").strip()
    target = (p.get("target") or "").strip()
    dangers = navi_cli.scan_command(cmd) if cmd else []
    host = None
    if target:
        for h in _hosts_raw():
            if h["ip"] == target or h["uuid"] == target:
                host = h
                break
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
    wsql = "(" + " OR ".join(ors) + ")"
    if "state" in vcols:
        wsql += " AND UPPER(COALESCE(state,'OPEN')) IN ('OPEN','REOPENED')"
    try:
        rows = db.query(f"SELECT DISTINCT asset_uuid, plugin_id, plugin_name FROM vulns WHERE {wsql}", tuple(params))
    except Exception as e:
        return {"ok": False, "error": f"query failed: {e}"}, 200
    uuids = {r["asset_uuid"] for r in rows if r.get("asset_uuid")}
    pids = {str(r.get("plugin_id")) for r in rows if r.get("plugin_id") not in (None, "")}
    names = sorted({r.get("plugin_name") for r in rows if r.get("plugin_name")})[:8]
    hosts_hit = [h for h in _hosts_raw() if h["uuid"] in uuids]
    linux = [h for h in hosts_hit if h["os_class"] == "linux" and h["ip"]]
    excluded = [h for h in hosts_hit if h not in linux]
    sols = _solutions(pids)                 # Tenable's OWN remediation text, from the plugins table
    pkg = _guess_pkg(sel, names, sols)
    return {"ok": True, "selector": sel, "matched_assets": len(uuids), "plugin_names": names,
            "linux_hosts": linux, "excluded": excluded, "excluded_count": len(excluded),
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
    uuids = [h["uuid"] for h in _hosts_raw() if (h["ip"] in targets or h["uuid"] in targets)]
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
def upload(p):
    """Save a base64 file server-side so a push can scp it. Returns the local path."""
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
    os.makedirs(_UPLOAD_DIR, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    dest = os.path.join(_UPLOAD_DIR, f"{uuid.uuid4().hex[:8]}_{safe}")
    with open(dest, "wb") as f:
        f.write(raw)
    return {"ok": True, "path": dest, "name": name, "bytes": len(raw)}, 200


def _uploaded(path):
    """True only for a real file that lives inside the upload dir (no path escape)."""
    ap = os.path.abspath(path or "")
    return bool(ap) and os.path.exists(ap) and os.path.dirname(ap) == os.path.abspath(_UPLOAD_DIR)


def command(p):
    """Run ONE ad-hoc command on ONE host. Gated + confirm; a destructive command needs
    an extra force=true."""
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required — remote code execution"}, 400
    target = (p.get("target") or "").strip()
    cmd = (p.get("command") or "").strip()
    if not target or not cmd:
        return {"ok": False, "error": "target host and command required"}, 400
    dangers = navi_cli.scan_command(cmd)
    if dangers and not p.get("force"):
        return {"ok": False, "needs_force": True, "dangers": dangers,
                "error": "destructive command — resend with force=true to run: " + "; ".join(dangers)}, 200
    res = navi_cli.push(target=target, command=cmd, agent="c2", detail=cmd)
    return {"ok": bool(res.get("ok")), **res, **navi_cli.push_status()}, 200


def push_file(p):
    """scp a previously-uploaded file to a host. Gated + confirm. Running it afterwards is
    a SEPARATE, separately-confirmed `command` step (the install_agent.sh pattern)."""
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required — remote file push"}, 400
    target = (p.get("target") or "").strip()
    path = (p.get("path") or "").strip()
    if not target or not path:
        return {"ok": False, "error": "target host and uploaded file required"}, 400
    if not _uploaded(path):
        return {"ok": False, "error": "file must be one previously uploaded via this agent"}, 400
    res = navi_cli.push(target=target, file=path, agent="c2", detail="scp " + os.path.basename(path))
    return {"ok": bool(res.get("ok")), **res, **navi_cli.push_status()}, 200


def campaign(p):
    """Armed batch across many hosts. Requires armed=true AND confirm=true. Loops per-IP as
    ONE background job: canary-first, stop-on-failure, blast-radius cap, abortable."""
    if not p.get("armed"):
        return {"ok": False, "error": "campaign is not armed — flip ARM, then confirm, to run"}, 400
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required — batch remote code execution"}, 400
    targets = [str(x).strip() for x in (p.get("hosts") or []) if str(x).strip()]
    cmd = (p.get("command") or "").strip()
    path = (p.get("path") or "").strip()
    if not targets:
        return {"ok": False, "error": "no target hosts"}, 400
    if bool(cmd) == bool(path):
        return {"ok": False, "error": "provide exactly one of a command or an uploaded file"}, 400
    if cmd:
        dangers = navi_cli.scan_command(cmd)
        if dangers and not p.get("force"):
            return {"ok": False, "needs_force": True, "dangers": dangers,
                    "error": "destructive command across a batch — resend with force=true: "
                             + "; ".join(dangers)}, 200
    if path and not _uploaded(path):
        return {"ok": False, "error": "file must be one uploaded via this agent"}, 400
    # Fail fast if the gate is closed, rather than queueing a job that only blocks per-host.
    if not navi_cli.rce_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.rce_gate_reason(),
                **navi_cli.push_status()}, 200
    canary = bool(p.get("canary", True))
    stop = bool(p.get("stop_on_failure", True))
    try:
        cap = max(1, int(p.get("max_hosts") or 200))
    except (TypeError, ValueError):
        cap = 200
    batch = targets[:cap]
    cid = uuid.uuid4().hex[:8]
    from core import tagq
    job = tagq.submit(
        _bulk_push,
        {"hosts": batch, "command": cmd, "file": path, "canary": canary, "stop": stop, "campaign_id": cid},
        {"agent": "c2", "category": "C2 · campaign", "value": f"{len(batch)} host(s)",
         "selector": ("file" if path else "command"),
         "detail": (cmd or ("scp " + os.path.basename(path)))[:200], "op": "push"})
    return {"ok": True, "queued": True, "job_id": job["id"], "campaign_id": cid, "hosts": len(batch),
            "canary": canary, "stop_on_failure": stop,
            "message": f"campaign #{job['id']} armed & running in the background "
                       f"({len(batch)} host(s){' · canary first' if canary else ''}). "
                       "Track it in the Tagging log; use Abort to halt.",
            **navi_cli.push_status()}, 200


def _bulk_push(hosts=None, command="", file="", canary=True, stop=True, campaign_id="", agent="c2"):
    """Executed on a tagq worker. Loops per host, honoring canary-first, stop-on-failure,
    and the abort switch. Each host is pushed via navi_cli.push (its own ledger line)."""
    hosts = hosts or []
    results, done, failed = [], 0, 0
    for i, ip in enumerate(hosts):
        with _ABORT_LOCK:
            aborted = campaign_id in _ABORT
        if aborted:
            with _ABORT_LOCK:
                _ABORT.discard(campaign_id)
            return {"ok": False, "aborted": True, "results": results,
                    "message": f"campaign aborted after {done} host(s); {len(hosts) - done} not touched"}
        label = ("[canary] " if (canary and i == 0) else "") + (command or ("scp " + os.path.basename(file)))
        r = navi_cli.push(target=ip, command=command, file=file, agent=agent, detail=label)
        ok = bool(r.get("ok"))
        results.append({"host": ip, "ok": ok, "message": r.get("message")})
        done += 1
        if not ok:
            failed += 1
            if canary and i == 0:
                return {"ok": False, "halted": True, "results": results,
                        "message": f"CANARY host {ip} failed — batch halted, {len(hosts) - 1} host(s) "
                                   "untouched. Fix the command/host and re-run."}
            if stop:
                return {"ok": False, "halted": True, "results": results,
                        "message": f"host {ip} failed — batch halted (stop-on-failure) after {done}; "
                                   f"{len(hosts) - done} untouched"}
    with _ABORT_LOCK:
        _ABORT.discard(campaign_id)
    return {"ok": failed == 0, "results": results,
            "message": f"pushed to {done} host(s); {failed} failed"}


def abort(p):
    cid = (p.get("campaign_id") or "").strip()
    if not cid:
        return {"ok": False, "error": "campaign_id required"}, 400
    with _ABORT_LOCK:
        _ABORT.add(cid)
    return {"ok": True, "campaign_id": cid,
            "message": "abort requested — the campaign stops before the next host "
                       "(a push already in flight finishes first)."}, 200


ACTIONS = {"run": run, "load": load, "status": status, "hosts": hosts, "precheck": precheck,
           "command": command, "upload": upload, "push_file": push_file, "plan": plan,
           "campaign": campaign, "abort": abort, "verify": verify, "log": log, "refresh": refresh}
