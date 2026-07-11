"""Host profile — CPU / RAM / scan health from Tenable inventory plugins.

Parses per-asset hardware + scan-info from navi.db plugin output:
  - CPU:  Windows WMI 24270 (Computer Manufacturer Information) ·
          Linux DMI 45432 (Processor Information)
  - RAM:  Windows WMI 24270 (Computer Memory) · Linux DMI 45433 (Memory Information)
  - arch: 24270 / 48942 (OS Version and Processor Architecture)
  - last authenticated scan + last scan duration (min): 19506 (Nessus Scan Information,
    Credentialed checks / Scan Start Date / Scan duration).
Read-only.
"""
import re

_PLUGINS = ("24270", "45432", "45433", "48942", "19506")


def _scan_key(s):
    m = re.search(r"(\d{4})/(\d{1,2})/(\d{1,2})(?:\s+(\d{1,2}):(\d{2}))?", s or "")
    if not m:
        return 0
    y, mo, d, h, mi = (int(x) if x else 0 for x in m.groups())
    return y * 10 ** 8 + mo * 10 ** 6 + d * 10 ** 4 + h * 100 + mi


def profile(asset_uuid, db_path=None):
    from core import db
    if not asset_uuid:
        return {}
    ph = ",".join("'%s'" % p for p in _PLUGINS)
    try:
        rows = list(db.query(
            "SELECT plugin_id, output, last_found FROM vulns "
            "WHERE asset_uuid=? AND plugin_id IN (%s)" % ph, (asset_uuid,), path=db_path))
    except Exception:
        return {}
    by, scans = {}, []
    for r in rows:
        pid = str(r.get("plugin_id"))
        out = r.get("output") or ""
        if pid == "19506":
            cred = bool(re.search(r"Credentialed checks\s*:\s*yes", out, re.I))
            dm = re.search(r"Scan duration\s*:\s*(\d+)\s*sec", out, re.I)
            dur = round(int(dm.group(1)) / 60) if dm else None
            sd = re.search(r"Scan Start Date\s*:\s*([0-9]{4}/[0-9]{1,2}/[0-9]{1,2}\s+[0-9:]+)", out, re.I)
            nm = re.search(r"Scan name\s*:\s*(.+)", out, re.I)
            when = sd.group(1).strip() if sd else (r.get("last_found") or "")[:10]
            scans.append({"cred": cred, "dur": dur, "when": when,
                          "name": (nm.group(1).strip() if nm else ""), "key": _scan_key(when)})
        elif pid not in by:
            by[pid] = out

    def g(txt, rx):
        m = re.search(rx, txt or "", re.I)
        return m.group(1).strip() if m else ""

    cpu = ram = arch = ""
    w = by.get("24270")
    if w:
        phys, log = g(w, r"Physical CPU'?s?\s*:\s*(\d+)"), g(w, r"Logical CPU'?s?\s*:\s*(\d+)")
        a, pc = g(w, r"Architecture\s*:\s*(\S+)"), g(w, r"Physical Cores\s*:\s*(\d+)")
        arch = a
        cpu = " · ".join(x for x in [phys and phys + " phys", log and log + " logical",
                                     pc and pc + "-core", a] if x)
        mem = g(w, r"Computer Memory\s*:\s*([\d.,]+\s*\wB)")
        if mem:
            ram = mem
    lp = by.get("45432")
    if lp and not cpu:
        model, spd = g(lp, r"Version\s*:\s*(.+)"), g(lp, r"Current Speed\s*:\s*([\d.]+\s*MHz)")
        n = g(lp, r"detected\s+(\d+)\s+processor")
        cpu = " · ".join(x for x in [model, n and n + " proc", spd] if x)
    lm = by.get("45433")
    if lm and not ram:
        m = g(lm, r"Total memory\s*:\s*([\d.,]+\s*\wB)")
        if m:
            ram = m
    if not arch and by.get("48942"):
        arch = g(by["48942"], r"Architecture\s*=\s*(\S+)")

    scans.sort(key=lambda s: -s["key"])
    latest = scans[0] if scans else None
    last_auth = next((s for s in scans if s["cred"]), None)
    return {"cpu": cpu, "ram": ram, "arch": arch,
            "last_scan": latest["when"] if latest else "",
            "last_scan_name": latest["name"] if latest else "",
            "last_scan_dur_min": latest["dur"] if latest else None,
            "last_auth_scan": last_auth["when"] if last_auth else "",
            "authenticated": bool(last_auth), "scan_count": len(scans),
            "has_data": bool(cpu or ram or latest)}
