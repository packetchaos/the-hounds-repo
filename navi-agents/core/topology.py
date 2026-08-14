"""Environment topology tree for the classification sunburst (Linnaeus).

Builds a strict tree the zoomable sunburst renders, sized by asset count:

  Environment → Class → Sub-class → Software / 🐳 Docker / Web-server → Version → (assets)

Plus:
- a VIRTUALIZATION narrative — hypervisors, VMs, docker hosts + their container NAMES.
  navi.db has docker containers (plugin 93561) but NO hypervisor→guest edge, so we show
  the FACTS ("2 hypervisors · 20 VMs · 5 running Docker: nginx, redis …") rather than
  draw edges that don't exist.
- SUBNET inference — group by /24 and flag hypervisor/VM co-location on a segment.

`members(path)` lazily returns the asset list at any node (leaf → the Argos asset page).
"""
import re

from core import db, classify as _classify, software as _sw

TOP_SW = 14        # software nodes per sub-class
TOP_VER = 8        # versions per software
_DOCKER = "🐳 Docker"


def _subnet24(ip):
    m = re.match(r"^(\d+\.\d+\.\d+)\.\d+", (ip or "").strip())
    return (m.group(1) + ".0/24") if m else "unknown"


def _containers(output):
    """Container image:tag names from plugin 93561 'Running containers:' output."""
    out, started = [], False
    for ln in (output or "").splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.lower().startswith("running containers"):
            started = True
            continue
        if started:
            m = re.match(r"([^\s(]+)", s)
            if m and (":" in m.group(1) or "/" in m.group(1)):
                out.append(m.group(1))
    return out


def _software_by_asset(db_path, keep):
    out = {}
    try:
        for r in db.query("SELECT asset_uuid, software_string FROM software", path=db_path):
            nm, ver = None, None
            for u in _sw.row_assets(r.get("asset_uuid")):   # single uuid OR stringified list
                if u not in keep:
                    continue
                if nm is None:
                    nm, ver = _sw.parse_software(r.get("software_string") or "")
                if nm:
                    out.setdefault(u, []).append((nm, ver or "—"))
    except Exception:
        pass
    return out


def _docker_by_asset(db_path, keep):
    out = {}
    try:
        for r in db.query("SELECT asset_uuid, output FROM vulns WHERE plugin_id='93561'", path=db_path):
            u = r.get("asset_uuid")
            if u in keep:
                cs = _containers(r.get("output"))
                if cs:
                    out.setdefault(u, []).extend(cs)
    except Exception:
        pass
    return out


def _uniq(vers):
    s = set()
    for uu in vers.values():
        s |= uu
    return s


def tree(db_path=None, by="class"):
    """Return {ok, root, virt, total}. `by`='class' (default) or 'subnet'."""
    cl = _classify.classify(db_path)
    if not cl.get("ok"):
        return cl
    assets = cl["assets"]
    keep = {a["uuid"] for a in assets}
    for a in assets:
        a["subnet"] = _subnet24(a.get("ip"))
    sw = _software_by_asset(db_path, keep)
    dock = _docker_by_asset(db_path, keep)

    # nested: group -> sub -> software -> version -> set(uuids)
    T = {}
    group_count, sub_count = {}, {}
    for a in assets:
        u = a["uuid"]
        g = a["subnet"] if by == "subnet" else a["cls"]
        s = (a["cls"] if by == "subnet" else (a.get("sub") or a.get("reason") or "—"))
        group_count[g] = group_count.get(g, 0) + 1
        sub_count.setdefault(g, {}); sub_count[g][s] = sub_count[g].get(s, 0) + 1
        node = T.setdefault(g, {}).setdefault(s, {})
        for img in dock.get(u, []):
            node.setdefault(_DOCKER, {}).setdefault(img, set()).add(u)
        items = sw.get(u, [])
        for nm, ver in items:
            node.setdefault(nm, {}).setdefault(ver, set()).add(u)
        if not items and not dock.get(u):
            node.setdefault("(no software inventory)", {}).setdefault("—", set()).add(u)

    def _sw_children(subnode):
        ranked = sorted(subnode.items(), key=lambda kv: -len(_uniq(kv[1])))
        kids = []
        for name, vers in ranked[:TOP_SW]:
            vk = [{"name": v, "value": len(uu), "kind": "version"}
                  for v, uu in sorted(vers.items(), key=lambda kv: -len(kv[1]))[:TOP_VER]]
            kids.append({"name": name, "value": len(_uniq(vers)),
                         "kind": ("docker" if name == _DOCKER else "software"),
                         "children": vk})
        if len(ranked) > TOP_SW:
            other = set()
            for _, vers in ranked[TOP_SW:]:
                other |= _uniq(vers)
            kids.append({"name": "Other software", "value": len(other), "kind": "software"})
        return kids

    children = []
    for g, subs in T.items():
        subkids = [{"name": s, "value": sub_count[g][s], "kind": "sub",
                    "children": _sw_children(sub)} for s, sub in subs.items()]
        subkids.sort(key=lambda x: -x["value"])
        children.append({"name": g, "value": group_count[g], "kind": ("subnet" if by == "subnet" else "class"),
                         "children": subkids})
    children.sort(key=lambda x: -x["value"])
    CAP_GROUPS = 40                                   # keep the first ring legible
    if len(children) > CAP_GROUPS:
        rest = children[CAP_GROUPS:]
        children = children[:CAP_GROUPS] + [{"name": f"Other ({len(rest)} groups)",
                                             "value": sum(c["value"] for c in rest),
                                             "kind": ("subnet" if by == "subnet" else "class"),
                                             "children": []}]
    root = {"name": "Environment", "value": len(assets), "kind": "root", "children": children}

    return {"ok": True, "by": by, "root": root, "total": len(assets),
            "virt": _virt(assets, dock, db_path)}


def _virt(assets, dock, db_path):
    """Hypervisors, VMs, docker hosts + container names, and subnet co-location."""
    hyper = [a for a in assets if a["cls"] == "Virtual Infrastructure"]
    vms = [a for a in assets if "vmware" in (a.get("os") or "").lower()]
    docker_hosts = [a for a in assets if a["uuid"] in dock]
    containers = sorted({c for cs in dock.values() for c in cs})
    # subnet co-location of hypervisors + VMs
    seg = {}
    for a in hyper + vms:
        seg.setdefault(a["subnet"], {"hyper": 0, "vm": 0})
        seg[a["subnet"]]["hyper" if a["cls"] == "Virtual Infrastructure" else "vm"] += 1
    colo = [{"subnet": k, **v} for k, v in seg.items() if v["hyper"] and v["vm"]]
    colo.sort(key=lambda x: -(x["hyper"] + x["vm"]))
    return {"hypervisors": len(hyper), "vms": len(vms), "docker_hosts": len(docker_hosts),
            "containers": containers[:60], "container_count": len(containers),
            "colocation": colo[:6],
            "docker_detail": [{"host": a.get("hostname") or a.get("ip"), "uuid": a["uuid"],
                               "containers": dock.get(a["uuid"], [])} for a in docker_hosts[:40]]}


def members(cls=None, sub=None, software=None, version=None, subnet=None, db_path=None, cap=500):
    """Lazy asset list at a node — for the members panel + asset→Argos click."""
    cl = _classify.classify(db_path)
    if not cl.get("ok"):
        return {"ok": False, "error": cl.get("error", "classify failed")}
    rows = cl["assets"]
    for a in rows:
        a["subnet"] = _subnet24(a.get("ip"))
    if subnet:
        rows = [a for a in rows if a["subnet"] == subnet]
    if cls:
        rows = [a for a in rows if a["cls"] == cls]
    if sub:
        rows = [a for a in rows if (a.get("sub") or a.get("reason") or "—") == sub]
    keep = {a["uuid"] for a in rows}
    if software == _DOCKER:
        dock = _docker_by_asset(db_path, keep)
        want = {u for u, cs in dock.items() if (not version or version in cs)}
        rows = [a for a in rows if a["uuid"] in want]
    elif software:
        sw = _software_by_asset(db_path, keep)
        want = {u for u, items in sw.items()
                if any(nm == software and (not version or version == "—" or ver == version) for nm, ver in items)}
        rows = [a for a in rows if a["uuid"] in want]
    out = [{"uuid": a["uuid"], "hostname": a.get("hostname") or "", "ip": a.get("ip") or "",
            "cls": a["cls"], "sub": a.get("sub") or "", "owned": a.get("owned"),
            "acr": a.get("acr"), "kev": a.get("kev"), "critical": a.get("critical")} for a in rows]
    return {"ok": True, "count": len(out), "assets": out[:cap]}
