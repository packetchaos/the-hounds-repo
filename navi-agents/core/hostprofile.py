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

# ---- device nature: virtual machine / virtualization host / docker host / physical ----
# Plugin evidence (grounded against a real navi.db):
_NATURE_PLUGINS = {
    # VM guest
    "20094":  ("vm", "VMware Virtual Machine Detection"),
    "105793": ("vm", "VMware Tools Detection"),
    "105792": ("vm", "VMware Tools Detection (macOS)"),
    "186361": ("vm", "VMware/Open VM Tools Installed (Linux)"),
    # virtualization host (hypervisor)
    "20301":  ("vhost", "VMware ESX/GSX Server Authentication Daemon Detection"),
    "299596": ("vhost", "QEMU Installed (Linux)"),
    # docker host
    "93561":  ("docker", "Docker Service Detection"),
    "159488": ("docker", "Docker Installed (Linux)"),
    "117359": ("docker", "Docker for Windows Installed"),
    "106050": ("docker", "Docker Container File Change Detection"),
    "111529": ("docker", "Docker Container Number of Changed Files"),
}
_VM_MAKERS = ("vmware", "qemu", "xen", "innotek", "virtualbox", "parallels",
              "amazon ec2", "google compute", "nutanix", "ovirt", "kvm", "bochs")
_PHYS_MAKERS = ("dell", "hewlett", "hp ", "hpe", "lenovo", "supermicro", "asus",
                "gigabyte", "msi", "intel corporation", "apple", "raspberry",
                "fujitsu", "toshiba", "acer", "panasonic")


def device_nature(asset_uuid, db_path=None):
    """What kind of device this is: [{key,label,via}] — keys vm / vhost / docker /
    cloud / physical. A host can be several at once (a VM that is a Docker host).
    Evidence: detection plugins, ESX/ESXi + hypervisor plugin names, the 24270
    Computer Manufacturer, cloud instance IDs on the asset row. Falls back to
    'physical (likely)' only when hardware data exists but no virtualization
    evidence does."""
    from core import db
    if not asset_uuid:
        return []
    out, seen = [], set()

    def add(key, label, via):
        if key not in seen:
            seen.add(key)
            out.append({"key": key, "label": label, "via": via})

    ph = ",".join("'%s'" % p for p in _NATURE_PLUGINS)
    rows = []
    try:
        rows = list(db.query(
            "SELECT DISTINCT plugin_id, plugin_name FROM vulns WHERE asset_uuid=? "
            "AND (plugin_id IN (%s) OR plugin_name LIKE 'VMware ESX%%' "
            "OR plugin_name LIKE '%%Hypervisor%%')" % ph, (asset_uuid,), path=db_path))
    except Exception:
        rows = []
    labels = {"vm": "Virtual machine", "vhost": "Virtualization host", "docker": "Docker host"}
    for r in rows:
        pid = str(r.get("plugin_id") or "")
        if pid in _NATURE_PLUGINS:
            key, via = _NATURE_PLUGINS[pid]
            add(key, labels[key], "plugin %s — %s" % (pid, via))
        else:  # matched by name: ESX/ESXi / hypervisor checks fire on the host itself
            add("vhost", labels["vhost"], "plugin %s — %s" % (pid, r.get("plugin_name") or ""))

    # 24270 Computer Manufacturer — VMware, Inc. / QEMU… = VM; Dell / HP… = physical
    maker = ""
    try:
        w = db.query("SELECT output FROM vulns WHERE asset_uuid=? AND plugin_id='24270' "
                     "AND output IS NOT NULL LIMIT 1", (asset_uuid,), path=db_path)
        if w:
            m = re.search(r"Computer Manufacturer\s*:\s*(.+)", w[0].get("output") or "", re.I)
            maker = (m.group(1).strip() if m else "")
    except Exception:
        pass
    lk = maker.lower()
    if lk:
        if any(v in lk for v in _VM_MAKERS) or ("microsoft" in lk and "corporation" in lk):
            add("vm", labels["vm"], "24270 Computer Manufacturer: " + maker)

    # cloud instance IDs on the asset row = virtual by definition
    try:
        acols = {r["name"] for r in db.query('PRAGMA table_info("assets");', path=db_path)}
        cc = [c for c in ("aws_id", "azure_vm_id", "gcp_instance_id") if c in acols]
        if cc:
            a = db.query("SELECT %s FROM assets WHERE uuid=? LIMIT 1" % ", ".join(cc),
                         (asset_uuid,), path=db_path)
            if a:
                for c in cc:
                    if str(a[0].get(c) or "").strip():
                        add("cloud", "Cloud instance", c.replace("_", " ") + " present")
                        add("vm", labels["vm"], "cloud instance (" + c + ")")
                        break
    except Exception:
        pass

    if not out:
        if lk and any(p in lk for p in _PHYS_MAKERS):
            add("physical", "Physical device", "24270 Computer Manufacturer: " + maker)
        elif maker or rows is not None:
            add("physical", "Physical device (likely)",
                "no VM / hypervisor / Docker evidence in this host's plugin output")
    return out


def _scan_key(s):
    m = re.search(r"(\d{4})/(\d{1,2})/(\d{1,2})(?:\s+(\d{1,2}):(\d{2}))?", s or "")
    if not m:
        return 0
    y, mo, d, h, mi = (int(x) if x else 0 for x in m.groups())
    return y * 10 ** 8 + mo * 10 ** 6 + d * 10 ** 4 + h * 100 + mi


def docker_containers(asset_uuid, db_path=None):
    """Running containers from plugin 93561 (Docker Service Detection) output.
    Real navi shape: 'The following containers were detected running on the remote
    Docker host :' followed by Name:/Image:/Image ID:/Tag:/ID:/Ports: blocks
    (Ports continues on indented lines) — or 'There were no containers detected
    running on Docker.' Returns {available, version, containers:[{name,image,tag,
    id,ports}]}."""
    from core import db
    empty = {"available": False, "version": "", "containers": []}
    if not asset_uuid:
        return empty
    try:
        rows = list(db.query(
            "SELECT output FROM vulns WHERE asset_uuid=? AND plugin_id='93561' "
            "AND output IS NOT NULL AND output<>''", (asset_uuid,), path=db_path))
    except Exception:
        return empty
    if not rows:
        return empty
    out = max((r.get("output") or "" for r in rows), key=len)
    vm = re.search(r"Server:\s*\n\s*Version:\s*([\w.\-]+)", out) \
        or re.search(r"Version:\s*([\w.\-]+)", out)
    version = vm.group(1) if vm else ""
    containers, cur = [], None
    for raw in out.splitlines():
        line = raw.rstrip()
        s = line.strip()
        m = re.match(r"Name\s*:\s*(.+)$", s, re.I)
        if m:
            cur = {"name": m.group(1).strip().lstrip("/"), "image": "", "tag": "",
                   "id": "", "ports": []}
            containers.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"Image\s*:\s*(.+)$", s, re.I)
        if m and not re.match(r"Image\s+ID", s, re.I):
            cur["image"] = m.group(1).strip()
            continue
        m = re.match(r"Tag\s*:\s*(.+)$", s, re.I)
        if m:
            cur["tag"] = m.group(1).strip()
            continue
        m = re.match(r"ID\s*:\s*([0-9a-f]+)$", s, re.I)
        if m:
            cur["id"] = m.group(1)[:12]
            continue
        m = re.match(r"Ports\s*:\s*(.*)$", s, re.I)
        if m:
            if m.group(1).strip():
                cur["ports"].append(m.group(1).strip())
            cur["_in_ports"] = True
            continue
        if cur.get("_in_ports") and raw.startswith(" ") and ("->" in s or "/" in s) and s:
            cur["ports"].append(s)
        elif s and re.match(r"[A-Za-z][\w ]*:", s):
            cur["_in_ports"] = False
    for c in containers:
        c.pop("_in_ports", None)
    # legacy 'Running containers' list (image tokens) — old navi/plugin outputs
    if not containers and re.search(r"running containers", out, re.I):
        started = False
        for raw in out.splitlines():
            s = raw.strip()
            if not s:
                continue
            if s.lower().startswith("running containers"):
                started = True
                continue
            if started:
                m = re.match(r"([^\s(]+)", s)
                if m and (":" in m.group(1) or "/" in m.group(1)):
                    containers.append({"name": "", "image": m.group(1), "tag": "",
                                       "id": "", "ports": []})
    return {"available": True, "version": version, "containers": containers}


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
    try:
        nature = device_nature(asset_uuid, db_path=db_path)
    except Exception:
        nature = []
    try:
        docker = docker_containers(asset_uuid, db_path=db_path)
    except Exception:
        docker = {"available": False, "version": "", "containers": []}
    return {"cpu": cpu, "ram": ram, "arch": arch, "nature": nature, "docker": docker,
            "last_scan": latest["when"] if latest else "",
            "last_scan_name": latest["name"] if latest else "",
            "last_scan_dur_min": latest["dur"] if latest else None,
            "last_auth_scan": last_auth["when"] if last_auth else "",
            "authenticated": bool(last_auth), "scan_count": len(scans),
            # docker counts as profile data too — a container host with no CPU/RAM
            # plugin output still has a story to tell (93561).
            "has_data": bool(cpu or ram or latest or nature or docker.get("available"))}
