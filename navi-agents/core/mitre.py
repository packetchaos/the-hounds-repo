"""MITRE ATT&CK tagging — follows the navi-enrich skill recipe.

Recipe (navi skill `tag-by-cve-external-csv`): download the Center for Threat-
Informed Defense ATT&CK->CVE mapping CSV and tag the ASSETS whose findings cite
each mapped CVE with up to three `Mitre` values (Primary Impact, Secondary Impact,
Exploit Technique). The CVE is only the selector: navi's tag-by-CVE function
(`navi enrich tag --cve`) resolves the affected assets and the tag lands on them.
We do NOT bake navi's tagging in — writes go through core.navi_cli.tag(..., cve=...);
this module fetches the CSV and builds the plan (+ metrics and the ATT&CK view).

Default scope is the CVEs actually present in navi.db (bounded, MCP/CLI-friendly).
The full mapping is thousands of CVEs — per the skill that's a CLI bulk job.
"""
import csv
import io
import json
import os
import re
import urllib.request

from core import db, downloads

CSV_URL = ("https://raw.githubusercontent.com/center-for-threat-informed-defense/"
           "attack_to_cve/master/Att%26ckToCveMappings.csv")
SOURCE_ID = "mitre"
downloads.register(SOURCE_ID, "MITRE ATT&CK→CVE mapping", [CSV_URL], agent="mitre",
                   purpose="Center for Threat-Informed Defense attack_to_cve CSV — drives "
                           "MITRE ATT&CK tagging and the Insights ATT&CK tile.",
                   fallback="baked snapshot agents/mitre/attack_to_cve.csv")
# baked-in snapshot used as a fallback when the live download is unavailable
BUNDLED_CSV = os.path.normpath(os.path.join(os.path.dirname(__file__), "..",
                               "agents", "mitre", "attack_to_cve.csv"))
_CVE = re.compile(r"CVE-\d{4}-\d{3,}", re.I)
# technique ids inside a mapping field ("T1190; T1078", "T1036.", "T1190. T1005") — strict,
# so the CSV's typos still parse and garbage ("T11190") is dropped
_TID = re.compile(r"\bT\d{3,4}(?:\.\d{3})?(?!\d)")
# compact extract of MITRE ATT&CK (enterprise + ics + mobile): technique → name/tactics,
# enterprise tactic order, and revoked → replacement ids. Rebuilt from mitre/cti.
ATTACK_JSON = os.path.normpath(os.path.join(os.path.dirname(__file__), "..",
                               "agents", "mitre", "attack_techniques.json"))
_ATTACK = None
ROLES = ("Primary Impact", "Secondary Impact", "Exploit Technique", "Technique")


def attack():
    global _ATTACK
    if _ATTACK is None:
        try:
            with open(ATTACK_JSON, encoding="utf-8") as f:
                _ATTACK = json.load(f)
        except Exception:
            _ATTACK = {"tactics": [], "techniques": {}, "revoked": {}}
    return _ATTACK


def technique_ids(text: str) -> list:
    """ATT&CK ids in text. ICS-style 3-digit ids in the CSV ('T828') normalise to 'T0828'."""
    return [("T0" + t[1:]) if re.match(r"T\d{3}(?!\d)", t) else t for t in _TID.findall(text or "")]


def resolve_id(tid: str) -> str:
    """Follow ATT&CK revocations (T1066 → T1027.005) to the current id."""
    rv = attack().get("revoked", {})
    for _ in range(5):
        if tid not in rv:
            break
        tid = rv[tid]
    return tid


def technique_info(tid: str) -> dict:
    T = attack().get("techniques", {})
    cur = resolve_id(tid)
    t = T.get(cur) or T.get(cur.split(".")[0]) or {}
    parent = T.get(cur.split(".")[0]) or {}
    return {"id": cur, "name": t.get("n", ""), "parent": cur.split(".")[0],
            "parent_name": parent.get("n", ""), "tactics": t.get("t") or parent.get("t") or [],
            "domain": t.get("d", "enterprise"), "revoked_from": tid if cur != tid else None}


def parse_rows(text: str) -> list[dict]:
    """Parse ATT&CK->CVE CSV text into per-CVE rows."""
    rows = []
    rdr = csv.reader(io.StringIO(text))
    next(rdr, None)  # header
    for r in rdr:
        if not r:
            continue
        m = _CVE.search((r[0] or ""))
        if not m:
            continue
        rows.append({"cve": m.group(0).upper(),
                     "primary": (r[1] if len(r) > 1 else "").strip(),
                     "secondary": (r[2] if len(r) > 2 else "").strip(),
                     "technique": (r[3] if len(r) > 3 else "").strip(),
                     "uncategorized": (r[4] if len(r) > 4 else "").strip()})
    return rows


def fetch_mapping(url: str = CSV_URL, timeout: int = 30, csv_text: str = "",
                  allow_live: bool = True) -> tuple[list[dict], str]:
    """Return (rows, source). Priority: user upload → live download → baked snapshot.
    allow_live=False (download not approved — see core.downloads) skips the network."""
    if csv_text and csv_text.strip():
        return parse_rows(csv_text), "upload"
    try:
        if not allow_live:
            raise RuntimeError("live download not approved")
        req = urllib.request.Request(url, headers={"User-Agent": "navi-agents-mitre"})
        raw = urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")
        return parse_rows(raw), "live"
    except Exception:
        try:
            with open(BUNDLED_CSV, encoding="utf-8") as f:
                return parse_rows(f.read()), "bundled"
        except Exception:
            return [], "unavailable"


def _hx(db_path=None) -> bool:
    """hx_plugin / hx_asset (⚡ Optimize) exist and match this navi.db — read CVEs per plugin
    from hx_plugin and (plugin, asset) pairs from the covering hx_v_* indexes instead of
    scanning every 5.5 KB vulns row three times. CVEs are a plugin attribute in Tenable data;
    hx_plugin carries one representative finding's `cves` per plugin."""
    try:
        from core import hx_summary
        return hx_summary.usable(db_path)
    except Exception:
        return False


def _hx_plugin_cves(db_path=None) -> dict:
    """{plugin_id: {CVE, …}} for every plugin present in vulns that references a CVE."""
    out = {}
    for row in db.query("SELECT plugin_id, cves FROM hx_plugin WHERE TRIM(COALESCE(cves,''))<>''",
                        path=db_path):
        cs = {c.upper() for c in _CVE.findall(row.get("cves") or "")}
        if cs:
            out[str(row.get("plugin_id"))] = cs
    return out


def _hx_cve_assets(db_path=None, only=None) -> dict:
    """cve_assets() over hx_plugin + hx_v_plugin: only the plugins carrying a wanted CVE are
    read, one covering index range each (no table rows)."""
    pc = _hx_plugin_cves(db_path)
    if only is not None:
        pc = {p: cs & only for p, cs in pc.items() if cs & only}
    out = {}
    if not pc:
        return out
    for r in db.iter("SELECT DISTINCT plugin_id, asset_uuid FROM vulns" + db.indexed_by("hx_v_plugin", db_path)
                     + " WHERE plugin_id IN (SELECT value FROM json_each(?))",
                     (json.dumps(sorted(pc)),), path=db_path, tuples=True):
        for c in pc.get(str(r[0]), ()):
            out.setdefault(c, set()).add(r[1])
    return out


def _hx_high_acr_rows(db_path=None, cset=()):
    """(asset_uuid, hostname, ip_address, acr, cves) for ACR > 7 assets carrying a plugin whose
    CVEs are in the mapping — only those plugins' (plugin, asset) pairs, from the covering
    hx_v_plugin index, joined to `assets` by uuid; CVEs from hx_plugin."""
    want = {c.upper() for c in cset}
    pids = sorted(p for p, cs in _hx_plugin_cves(db_path).items() if cs & want)
    if not pids:
        return []
    return db.query("SELECT DISTINCT a.uuid AS asset_uuid, a.hostname, a.ip_address, a.acr, p.cves "
                    "FROM hx_plugin p CROSS JOIN vulns v" + db.indexed_by("hx_v_plugin", db_path)
                    + " ON v.plugin_id = p.plugin_id CROSS JOIN assets a ON a.uuid = v.asset_uuid "
                    "WHERE p.plugin_id IN (SELECT value FROM json_each(?)) AND CAST(a.acr AS REAL)>7",
                    (json.dumps(pids),), path=db_path)


def cve_assets(db_path=None, only=None) -> dict:
    """CVE → set(asset_uuid) from navi.db findings (vulns.cves); `only` limits the CVEs kept."""
    out = {}
    if _hx(db_path):
        try:
            return _hx_cve_assets(db_path, None if only is None else set(only))
        except Exception:
            pass                                    # fall back to the row scan below
    try:
        for row in db.query("SELECT asset_uuid, cves FROM vulns WHERE TRIM(COALESCE(cves,''))<>''", path=db_path):
            for c in _CVE.findall(row.get("cves") or ""):
                c = c.upper()
                if only is not None and c not in only:
                    continue
                out.setdefault(c, set()).add(row.get("asset_uuid"))
    except Exception:
        pass
    return out


def navi_cves(db_path=None) -> set:
    """All CVE IDs referenced by findings in navi.db (vulns.cves)."""
    out = set()
    if _hx(db_path):
        try:
            return set().union(*_hx_plugin_cves(db_path).values())
        except Exception:
            pass
    try:
        for row in db.query("SELECT cves FROM vulns WHERE TRIM(COALESCE(cves,''))<>''", path=db_path):
            for c in _CVE.findall(row.get("cves") or ""):
                out.add(c.upper())
    except Exception:
        pass
    return out


def build_plan(db_path=None, scope: str = "navidb", url: str = CSV_URL,
               csv_text: str = "", allow_live: bool = True) -> dict:
    """Build the per-CVE tag plan. Mapping source: user upload (csv_text) →
    live download (only when allow_live) → baked snapshot. scope='navidb' (default)
    keeps only CVEs present in navi.db; scope='all' is the full mapping."""
    mapping, source = fetch_mapping(url, csv_text=csv_text, allow_live=allow_live)
    nv = navi_cves(db_path)
    actions, matched = [], set()
    for r in mapping:
        if scope == "navidb" and r["cve"] not in nv:
            continue
        matched.add(r["cve"])
        labels = [("Primary Impact", r["primary"]),
                  ("Secondary Impact", r["secondary"]),
                  ("Exploit Technique", r["technique"])]
        # Phase-1 rows only populate the Uncategorized column — surface it as Technique
        if not (r["primary"] or r["secondary"] or r["technique"]) and r.get("uncategorized"):
            labels.append(("Technique", r["uncategorized"]))
        for label, val in labels:
            if val and val.lower() != "nan":
                actions.append({"cve": r["cve"], "category": "Mitre", "value": f"{label}: {val}",
                                "role": label, "techniques": technique_ids(val)})
    # assets with ACR > 7 that carry ATT&CK-mapped CVEs (aligns w/ the insights tile)
    cset = {r["cve"] for r in mapping}
    high = {}
    try:
        for r in (_hx_high_acr_rows(db_path, cset) if _hx(db_path) else
                  db.query("SELECT v.asset_uuid, a.hostname, a.ip_address, a.acr, v.cves "
                           "FROM vulns v LEFT JOIN assets a ON a.uuid=v.asset_uuid "
                           "WHERE CAST(a.acr AS REAL)>7 AND TRIM(COALESCE(v.cves,''))<>''", path=db_path)):
            ms = [c.upper() for c in _CVE.findall(r.get("cves") or "") if c.upper() in cset]
            if not ms:
                continue
            a = high.setdefault(r["asset_uuid"], {
                "asset_uuid": r["asset_uuid"],
                "host": (r.get("hostname") or "").strip() or r.get("ip_address", ""),
                "ip": r.get("ip_address"), "acr": r.get("acr"), "cves": set()})
            a["cves"].update(ms)
    except Exception:
        pass
    high_acr = [{**a, "cves": sorted(a["cves"])} for a in high.values()]
    high_acr.sort(key=lambda x: -(float(x["acr"]) if x["acr"] else 0))

    # ---- assets behind each CVE (the tag lands on these) + metrics + ATT&CK view ----
    ca = cve_assets(db_path, only=matched)
    for a in actions:
        a["assets"] = len(ca.get(a["cve"], ()))
    assets_all = set().union(*ca.values()) if ca else set()

    roles = {}
    techs = {}
    for a in actions:
        rk = roles.setdefault(a["role"], {"role": a["role"], "tags": 0, "values": set(),
                                         "techniques": set(), "cves": set(), "assets": set()})
        rk["tags"] += 1; rk["values"].add(a["value"]); rk["cves"].add(a["cve"])
        rk["assets"].update(ca.get(a["cve"], ()))
        for raw in a["techniques"]:
            info = technique_info(raw)
            tid = info["id"]
            rk["techniques"].add(tid)
            t = techs.setdefault(tid, {**info, "roles": {}, "cves": set(), "assets": set(), "raw": set()})
            t["roles"][a["role"]] = t["roles"].get(a["role"], 0) + 1
            t["cves"].add(a["cve"]); t["assets"].update(ca.get(a["cve"], ())); t["raw"].add(raw)
    role_rows = []
    for r in ROLES:
        if r in roles:
            x = roles[r]
            role_rows.append({"role": r, "tags": x["tags"], "unique_values": len(x["values"]),
                              "unique_techniques": len(x["techniques"]), "cves": len(x["cves"]),
                              "assets": len(x["assets"])})
    tech_rows = sorted(({**{k: v for k, v in t.items() if k not in ("cves", "assets", "raw")},
                         "cves": len(t["cves"]), "assets": len(t["assets"]),
                         "raw_ids": sorted(t["raw"])} for t in techs.values()),
                       key=lambda t: (-t["assets"], -t["cves"], t["id"]))
    tactics_hit = {tc for t in tech_rows for tc in t["tactics"]}
    A = attack()
    metrics = {
        "cves_mapped": len(matched),
        "assets_affected": len(assets_all),
        "tag_pairs": len(actions),
        "unique_tag_values": len({a["value"] for a in actions}),
        "unique_techniques": len(tech_rows),
        "tactics_hit": len(tactics_hit), "tactics_total": len(A.get("tactics", [])),
        "roles": role_rows,
    }

    return {"csv_rows": len(mapping), "navi_cves": len(nv),
            "matched_cves": len(matched), "actions": actions, "scope": scope,
            "mapping_source": source, "url": CSV_URL, "high_acr": high_acr,
            "metrics": metrics, "techniques": tech_rows,
            "attack": {"tactics": A.get("tactics", []), "modified": A.get("modified")}}
