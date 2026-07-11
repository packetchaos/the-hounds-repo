"""MITRE ATT&CK tagging — follows the navi-enrich skill recipe.

Recipe (navi skill `tag-by-cve-external-csv`): download the Center for Threat-
Informed Defense ATT&CK->CVE mapping CSV and, for each CVE, write three `Mitre`
tags (Primary Impact, Secondary Impact, Exploit Technique) using navi's
**tag-by-CVE** function. We do NOT bake navi's tagging in — writes go through
navi's own `navi enrich tag --cve` (core.navi_cli.tag(..., cve=...)); this module
only fetches the live CSV and builds the per-CVE plan.

Default scope is the CVEs actually present in navi.db (bounded, MCP/CLI-friendly).
The full mapping is thousands of CVEs — per the skill that's a CLI bulk job.
"""
import csv
import io
import os
import re
import urllib.request

from core import db

CSV_URL = ("https://raw.githubusercontent.com/center-for-threat-informed-defense/"
           "attack_to_cve/master/Att%26ckToCveMappings.csv")
# baked-in snapshot used as a fallback when the live download is unavailable
BUNDLED_CSV = os.path.normpath(os.path.join(os.path.dirname(__file__), "..",
                               "agents", "mitre", "attack_to_cve.csv"))
_CVE = re.compile(r"CVE-\d{4}-\d{3,}", re.I)


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


def fetch_mapping(url: str = CSV_URL, timeout: int = 30, csv_text: str = "") -> tuple[list[dict], str]:
    """Return (rows, source). Priority: user upload → live download → baked snapshot."""
    if csv_text and csv_text.strip():
        return parse_rows(csv_text), "upload"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "navi-agents-mitre"})
        raw = urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")
        return parse_rows(raw), "live"
    except Exception:
        try:
            with open(BUNDLED_CSV, encoding="utf-8") as f:
                return parse_rows(f.read()), "bundled"
        except Exception:
            return [], "unavailable"


def navi_cves(db_path=None) -> set:
    """All CVE IDs referenced by findings in navi.db (vulns.cves)."""
    out = set()
    try:
        for row in db.query("SELECT cves FROM vulns WHERE TRIM(COALESCE(cves,''))<>''", path=db_path):
            for c in _CVE.findall(row.get("cves") or ""):
                out.add(c.upper())
    except Exception:
        pass
    return out


def build_plan(db_path=None, scope: str = "navidb", url: str = CSV_URL,
               csv_text: str = "") -> dict:
    """Build the per-CVE tag plan. Mapping source: user upload (csv_text) →
    live download → baked snapshot. scope='navidb' (default) keeps only CVEs
    present in navi.db; scope='all' is the full mapping."""
    mapping, source = fetch_mapping(url, csv_text=csv_text)
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
                actions.append({"cve": r["cve"], "category": "Mitre", "value": f"{label}: {val}"})
    # assets with ACR > 7 that carry ATT&CK-mapped CVEs (aligns w/ the insights tile)
    cset = {r["cve"] for r in mapping}
    high = {}
    try:
        for r in db.query("SELECT v.asset_uuid, a.hostname, a.ip_address, a.acr, v.cves "
                          "FROM vulns v LEFT JOIN assets a ON a.uuid=v.asset_uuid "
                          "WHERE CAST(a.acr AS REAL)>7 AND TRIM(COALESCE(v.cves,''))<>''", path=db_path):
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

    return {"csv_rows": len(mapping), "navi_cves": len(nv),
            "matched_cves": len(matched), "actions": actions, "scope": scope,
            "mapping_source": source, "url": CSV_URL, "high_acr": high_acr}
