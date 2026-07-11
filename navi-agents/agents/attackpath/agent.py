"""Fenrir — Attack Path Analysis.

Chains exploitability × identity × reachability into likely attack paths:
  foothold (exploitable or weak-auth asset)
    → lateral movement (same /24 subnet + credential pivot)
      → crown-jewel target (high-ACR asset).

Reachability is INFERRED from subnet adjacency + credential signals, not from
observed traffic. Signals, all from navi.db:
  * CISA-KEV        vulns.xrefs LIKE '%CISA-KNOWN-EXPLOITED%'   (actively exploited)
  * Critical vuln   vulns.severity critical / 4
  * Weak auth       plugin 149334 (SSH password auth) / 41028 + "default/blank
                    password|credential|community" plugin names
  * Crown jewel     assets.acr >= 7

All reads are read-only sqlite3; tag writes are gated (core.navi_cli).
"""
from core import db, navi_cli
from core.agents.base import Agent

ENTRY_CAT = "Attack Path"


def _cols(table):
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}");')}
    except Exception:
        return set()


def _subnet(ip):
    parts = str(ip or "").split(".")
    return ".".join(parts[:3]) if len(parts) >= 4 else ""


def _uset(sql, db_path):
    s = set()
    try:
        for r in db.query(sql, path=db_path):
            if r.get("asset_uuid"):
                s.add(r["asset_uuid"])
    except Exception:
        pass
    return s


def analyze(db_path=None) -> dict:
    cols = _cols("assets")
    sel = ["uuid", "hostname", "ip_address", "acr"]
    if "operating_system" in cols:
        sel.append("operating_system")
    if "url" in cols:
        sel.append("url")
    amap = {}
    for a in db.query("SELECT " + ",".join(sel) + " FROM assets", path=db_path):
        u = a.get("uuid")
        if not u:
            continue
        acr_raw = str(a.get("acr") or "").strip()
        try:
            acr = float(acr_raw) if acr_raw else 0.0
        except ValueError:
            acr = 0.0
        amap[u] = {"uuid": u,
                   "host": (a.get("hostname") or a.get("ip_address") or "").strip() or "(none)",
                   "ip": a.get("ip_address") or "", "acr": acr,
                   "os": a.get("operating_system") or "", "url": a.get("url")}

    kev = _uset("SELECT DISTINCT asset_uuid FROM vulns WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%'", db_path)
    crit = _uset("SELECT DISTINCT asset_uuid FROM vulns WHERE lower(severity)='critical' OR severity='4'", db_path)
    sshpw = _uset("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='149334'", db_path)
    defc = _uset("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='41028' "
                 "OR lower(plugin_name) LIKE '%default password%' "
                 "OR lower(plugin_name) LIKE '%default credential%' "
                 "OR lower(plugin_name) LIKE '%blank password%' "
                 "OR lower(plugin_name) LIKE '%default community%'", db_path)

    assets = []
    for u, a in amap.items():
        a["subnet"] = _subnet(a["ip"])
        a["kev"] = u in kev
        a["crit"] = u in crit
        a["weak"] = (u in sshpw) or (u in defc)
        a["weakWhy"] = "SSH password auth" if u in sshpw else ("Default/blank creds" if u in defc else "")
        a["exploit"] = a["kev"] or a["crit"]
        a["entry"] = a["exploit"] or a["weak"]
        # Crown-jewel target: high business criticality (ACR >= 7) OR — when ACR is
        # uncalibrated (common in labs) — a high-EXPOSURE host (actively-exploited AND
        # carrying a critical). Otherwise a lab with default ACR yields zero targets.
        a["acrTarget"] = a["acr"] >= 7
        a["expTarget"] = a["kev"] and a["crit"]
        a["target"] = a["acrTarget"] or a["expTarget"]
        a["targetReason"] = ("High business criticality (ACR %s)" % a["acr"] if a["acrTarget"]
                             else ("High exposure (CISA-KEV + critical)" if a["expTarget"] else ""))
        a["entryStrength"] = (3 if a["kev"] else (2 if a["crit"] else 0)) + (1 if a["weak"] else 0)
        a["entryReason"] = ("CISA-KEV (actively exploited)" if a["kev"]
                            else ("Critical vuln" if a["crit"]
                                  else (a["weakWhy"] if a["weak"] else "")))
        assets.append(a)

    by_sub = {}
    for a in assets:
        if a["entry"] and a["subnet"]:
            by_sub.setdefault(a["subnet"], []).append(a)

    paths = []
    for t in assets:
        if not t["target"] or not t["subnet"]:
            continue
        ents = [e for e in by_sub.get(t["subnet"], []) if e["uuid"] != t["uuid"]]
        if not ents:
            continue
        ents.sort(key=lambda x: x["entryStrength"], reverse=True)
        e = ents[0]
        pivot = e["weak"] or t["weak"]
        score = round(t["acr"] * 2 + e["entryStrength"] * 2 + (3 if pivot else 0)
                      + (3 if t["kev"] else 0) + (2 if t["crit"] else 0))
        paths.append({"entry": e, "target": t, "subnet": t["subnet"],
                      "altEntries": len(ents) - 1, "pivotWeak": pivot, "score": score})
    paths.sort(key=lambda p: p["score"], reverse=True)

    entries = [a for a in assets if a["entry"]]
    targets = [a for a in assets if a["target"]]
    acr_targets = sum(1 for a in targets if a["acrTarget"])
    note = ""
    if acr_targets <= 1 and len(targets) > acr_targets:
        note = ("ACR looks uncalibrated (few/no assets at ACR ≥ 7), so crown-jewel targets "
                "fall back to HIGH-EXPOSURE hosts (CISA-KEV + critical). Calibrate ACR (Anubis) "
                "to rank real business crown jewels first.")
    return {"ok": True, "paths": paths, "entries": entries, "targets": targets, "note": note,
            "kpi": {"entries": len(entries), "targets": len(targets), "paths": len(paths),
                    "acr_targets": acr_targets, "exposure_targets": len(targets) - acr_targets,
                    "kev_paths": sum(1 for p in paths if p["entry"]["kev"])}}


class AttackPathAgent(Agent):
    id = "attackpath"
    name = "Attack Path Analysis"
    icon = "🕸️"
    description = ("Fenrir — chains exploitability × identity × reachability into "
                  "foothold → lateral movement → crown-jewel attack paths. Gated tagging.")

    def summary(self):
        if not self.result:
            return {}
        k = self.result.get("kpi", {})
        return {"paths": k.get("paths"), "entries": k.get("entries"), "targets": k.get("targets")}

    def _run(self, db_path=None, **kwargs):
        return analyze(db_path)
