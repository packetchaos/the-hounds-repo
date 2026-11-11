"""Command & Control targets — validate, expand and classify what an operator typed.

`navi action push` accepts ANY IP or hostname (not only navi.db assets). It refuses a target
that is not a plain IP / hostname itself (navi plugins/action.py ``valid_target``: anything
else would reach ssh as an option, e.g. ``-oProxyCommand=…``), and so do we — before navi is
ever spawned, and again inside core.navi_cli (the push choke point).

  parse(text)            → split on commas / whitespace / newlines (de-duplicated, ordered)
  valid_target(host)     → navi's rule: an IPv4/IPv6 address or an RFC-1123 hostname
  expand(items, cap=256) → CIDRs expanded (capped), everything validated + classified

Each accepted target is classified: private / public / loopback / link_local / cgnat, whether
it is in navi.db (and the asset's identity when it is). Refused outright: anything starting
with '-', whitespace or quotes or shell characters, unspecified (0.0.0.0 / ::), multicast,
broadcast, reserved ranges, and CIDRs that expand past the cap. Public addresses and targets
navi.db has never seen are WARNED about (shown in the confirm), not refused — reaching a host
outside inventory is a feature the owner asked for.
"""
import ipaddress
import json
import re

CIDR_CAP = 256

# navi's own hostname rule (plugins/action.py _HOSTNAME_RE) — kept identical on purpose.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")
_BAD_CHARS = re.compile(r"[\s'\"`$;&|<>(){}\[\]\\*?!#=,~^%]")
_SPLIT = re.compile(r"[,\s]+")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def valid_target(host) -> bool:
    """True for a plain IPv4/IPv6 address or a syntactically valid hostname (navi's rule).
    Never true for something that starts with '-' or carries whitespace / shell characters."""
    h = str(host or "")
    if not h or h.startswith("-") or h != h.strip():
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    if _BAD_CHARS.search(h):
        return False
    return bool(_HOSTNAME_RE.match(h))


def parse(text) -> list:
    """Ordered, de-duplicated pieces from a comma / space / newline separated string or a list."""
    if isinstance(text, (list, tuple)):
        raw = []
        for x in text:
            if isinstance(x, dict):
                x = x.get("ip") or x.get("target") or x.get("hostname") or ""
            raw.extend(_SPLIT.split(str(x or "")))
    else:
        raw = _SPLIT.split(str(text or ""))
    seen, out = set(), []
    for p in raw:
        p = p.strip()
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _ip_kind(ip):
    """(kind, refuse_reason) for one address."""
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_unspecified:
        return "unspecified", "unspecified address (0.0.0.0 / ::) is not a host"
    if ip.is_multicast:
        return "multicast", "multicast address — not a single host"
    if ip.version == 4 and ip == ipaddress.ip_address("255.255.255.255"):
        return "broadcast", "broadcast address — not a single host"
    if ip.is_loopback:
        return "loopback", ""
    if ip.is_link_local:
        return "link_local", ""
    if ip.version == 4 and ip in _CGNAT:
        return "cgnat", ""
    if ip.is_reserved:
        return "reserved", "reserved address range — not a routable host"
    if ip.is_private:
        return "private", ""
    if ip.is_global:
        return "public", ""
    return "reserved", "special-purpose address range — not a routable host"


def classify(host) -> dict:
    """{target, kind, refused} for one already-split piece (no CIDR)."""
    if not valid_target(host):
        why = ("starts with '-' (ssh would read it as an option)" if str(host).startswith("-")
               else "not an IP address or hostname (whitespace, quotes or shell characters are refused)")
        return {"target": str(host), "kind": "invalid", "refused": why}
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return {"target": host, "kind": "hostname", "refused": ""}
    kind, refuse = _ip_kind(ip)
    return {"target": str(ip), "kind": kind, "refused": refuse}


def _inventory(db_path=None, keys=None):
    """{ip_or_hostname_lower: asset} from navi.db (read-only; empty when unavailable). With
    `keys` (the lower-cased targets being expanded, ≤ the CIDR cap) only those assets are read
    — one narrow pass over assets in SQL instead of every asset into Python."""
    try:
        from agents.c2 import api as c2api
        if keys is None:
            hosts = c2api._hosts_raw(db_path)
        else:
            ks = sorted({str(k or "").strip().lower() for k in keys} - {""})
            if not ks:
                return {}
            _sel, ip, _os, ok = c2api._asset_sql(db_path)
            if not ok:
                return {}
            hn = "hostname" if "hostname" in c2api._cols("assets", db_path) else "''"
            j = json.dumps(ks)
            hosts = c2api._hosts_where(
                f"lower(TRIM(COALESCE({ip},''),{c2api._WS})) IN (SELECT value FROM json_each(?)) OR "
                f"lower(TRIM(COALESCE({hn},''),{c2api._WS})) IN (SELECT value FROM json_each(?))",
                (j, j), db_path=db_path, budget="run")
    except Exception:
        return {}
    idx = {}
    for h in hosts:
        for k in (h.get("ip"), h.get("hostname")):
            k = str(k or "").strip().lower()
            if k and k not in idx:
                idx[k] = h
    return idx


def lookup(target, db_path=None):
    """The navi.db asset for ONE ip/hostname ({uuid, ip, hostname, os, os_class, acr, crown}) or None."""
    t = str(target or "").strip().lower()
    if not t:
        return None
    try:
        from core import db
        from agents.c2 import api as c2api
        cols = c2api._cols("assets", db_path)
        if not cols:
            return None
        ipc = "ip_address" if "ip_address" in cols else ("ip" if "ip" in cols else None)
        ors, params = [], []
        if ipc:
            ors.append(f'LOWER("{ipc}")=?')
            params.append(t)
        if "hostname" in cols:
            ors.append("LOWER(hostname)=?")
            params.append(t)
        if not ors:
            return None
        sel = ["uuid", (f'"{ipc}" AS ip' if ipc else "'' AS ip"),
               ("hostname" if "hostname" in cols else "'' AS hostname"),
               ("operating_system AS os" if "operating_system" in cols else "'' AS os"),
               ("acr" if "acr" in cols else "NULL AS acr")]
        rows = db.query(f"SELECT {', '.join(sel)} FROM assets WHERE " + " OR ".join(ors) + " LIMIT 1",
                        tuple(params), path=db_path)
    except Exception:
        return None
    if not rows:
        return None
    r = rows[0]
    try:
        acr = float(r.get("acr")) if r.get("acr") not in (None, "") else None
    except (TypeError, ValueError):
        acr = None
    return {"uuid": r.get("uuid"), "ip": r.get("ip") or "", "hostname": r.get("hostname") or "",
            "os": r.get("os") or "", "os_class": c2api._classify_os(r.get("os")), "acr": acr,
            "crown": acr is not None and acr >= 9}


def expand(items, cap=CIDR_CAP, db_path=None) -> dict:
    """Validate + expand + classify. Returns
       {targets:[{target,kind,in_inventory,asset:{uuid,hostname,os,os_class,acr,crown}|None,warnings:[…]}],
        refused:[{input,reason}], warnings:[…], count, cap}
    CIDRs expand to their usable hosts (network/broadcast dropped for IPv4 /0–/30); the TOTAL
    across all inputs may not exceed `cap` (default 256) — the whole request is refused past it."""
    try:
        cap = max(1, min(CIDR_CAP, int(cap or CIDR_CAP)))
    except (TypeError, ValueError):
        cap = CIDR_CAP
    pieces = parse(items)
    out, refused, seen = [], [], set()
    over = False
    for piece in pieces:
        if "/" in piece:
            if piece.startswith("-") or _BAD_CHARS.search(piece):
                refused.append({"input": piece, "reason": "not a CIDR (shell characters refused)"})
                continue
            try:
                net = ipaddress.ip_network(piece, strict=False)
            except ValueError:
                refused.append({"input": piece, "reason": "not a valid CIDR"})
                continue
            size = net.num_addresses - (2 if (net.version == 4 and net.prefixlen <= 30) else 0)
            if size > cap or len(out) + size > cap:
                refused.append({"input": piece, "reason": f"expands to {size} hosts — over the cap of {cap} "
                                                          "(narrow the range)"})
                over = True
                continue
            hosts = list(net.hosts()) if net.num_addresses > 1 else [net.network_address]
            for ip in hosts:
                c = classify(str(ip))
                if c["refused"]:
                    refused.append({"input": str(ip), "reason": c["refused"]})
                elif c["target"] not in seen:
                    seen.add(c["target"])
                    out.append(c)
            continue
        c = classify(piece)
        if c["refused"]:
            refused.append({"input": piece, "reason": c["refused"]})
        elif c["target"] not in seen:
            if len(out) >= cap:
                refused.append({"input": piece, "reason": f"over the cap of {cap} targets"})
                over = True
                continue
            seen.add(c["target"])
            out.append(c)
    inv = _inventory(db_path, keys=[t["target"] for t in out]) if out else {}
    warnings = []
    n_public = n_off = 0
    for t in out:
        a = inv.get(t["target"].lower())
        t["in_inventory"] = bool(a)
        t["asset"] = ({"uuid": a.get("uuid"), "hostname": a.get("hostname"), "ip": a.get("ip"),
                       "os": a.get("os"), "os_class": a.get("os_class"), "acr": a.get("acr"),
                       "crown": a.get("crown")} if a else None)
        w = []
        if t["kind"] == "public":
            n_public += 1
            w.append("PUBLIC address — confirm this host is yours and you are authorised to log in to it")
        if not a:
            n_off += 1
            w.append("not in navi.db — Tenable has never seen it (consider `navi enrich add` / a scan)")
        elif a.get("os_class") not in ("linux", "unknown"):
            w.append(f"navi.db classifies it as '{a.get('os_class')}' — push is Linux/SSH only")
        if a and a.get("crown"):
            w.append(f"CROWN JEWEL (ACR {a.get('acr')}) — treat as a change-window operation")
        if t["kind"] == "loopback":
            w.append("loopback — this runs on the console host itself")
        t["warnings"] = w
    if n_public:
        warnings.append(f"{n_public} public address(es) — make sure you are authorised to reach them")
    if n_off:
        warnings.append(f"{n_off} target(s) not in navi.db")
    return {"targets": out, "refused": refused, "warnings": warnings, "count": len(out), "cap": cap,
            "over_cap": over}
