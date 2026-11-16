"""Evidence behind a number (build 467) — the asset set an On the Scent "At a glance" card counts.

Each entry is computed by the hound that OWNS the number, with its own rule — so the list a
card opens has the card's count (as of now; the card is as of the last release):

  kev          CISA KEV — cisakev summary: an asset with a CISA-KNOWN-EXPLOITED finding
  score60      Nemesis — every asset scoring ≥ 60 (the whole estate, not the leaderboard's top rows)
  crown        Nemesis — crown jewels (ACR ≥ 9)
  crown_kev    Nemesis — crown jewels with KEV
  crown_blind  Nemesis — crown jewels scanned without a credentialed login (core.credstate)
  lit4         Nemesis — assets lit by ≥ 4 hounds' signals
  eol          Charon — assets on EOL / unsupported software (core.eol.analyze)
  pq           Heimdall — quantum-vulnerable assets (postquantum.discover)

The Asset Explorer (agents/ex_assets) stores the set as a result-store run (core.payload) so
the list pages, searches and exports on the server — however many assets — and every row opens
Argos, where the asset's findings can be remediated (C2) or tagged. Read-only.
"""
from core import db

EVIDENCE = {
    "kev": {"label": "KEV-exploitable assets", "agent": "cisakev", "hound": "CISA KEV",
            "why": "assets with a finding CISA lists as known-exploited (CISA-KNOWN-EXPLOITED cross-reference)"},
    "score60": {"label": "Assets scored ≥ 60", "agent": "fused_score", "hound": "Exposure Score (Nemesis)",
                "why": "every asset whose fused exposure score is 60 or more — act on these first"},
    "crown": {"label": "Crown jewels (ACR ≥ 9)", "agent": "fused_score", "hound": "Exposure Score (Nemesis)",
              "why": "assets with an Asset Criticality Rating of 9 or 10"},
    "crown_kev": {"label": "Crown jewels (ACR ≥ 9) with KEV", "agent": "fused_score", "hound": "Exposure Score (Nemesis)",
                  "why": "crown jewels carrying a known-exploited (CISA KEV) finding"},
    "crown_blind": {"label": "Crown jewels (ACR ≥ 9), blind", "agent": "fused_score", "hound": "Exposure Score (Nemesis)",
                    "why": "crown jewels scanned without a credentialed login (19506 / 141118 / 110095) — risk you can't see"},
    "lit4": {"label": "Assets lit by ≥ 4 hounds", "agent": "fused_score", "hound": "Exposure Score (Nemesis)",
             "why": "assets where four or more hounds' signals converge (KEV, crown, EOL, crypto, compliance, SLA, blind, unowned, AI, identity, path)"},
    "eol": {"label": "Assets on EOL / unsupported software", "agent": "eol", "hound": "EOL (Charon)",
            "why": "assets running an operating system or application past its end of life"},
    "pq": {"label": "Quantum-vulnerable assets", "agent": "postquantum", "hound": "Post-Quantum (Heimdall)",
           "why": "assets whose certificates or transport crypto a quantum computer could break (RSA / ECC / DH)"},
}


def _fused(pred, db_path):
    from core import fused_score as fs
    return sorted(s["uuid"] for s, score in fs.iter_scored(db_path) if s.get("uuid") and pred(s, score))


def uuids(key, db_path=None):
    """The asset uuids behind evidence `key` (KeyError for an unknown key)."""
    if key not in EVIDENCE:
        raise KeyError(key)
    if key == "kev":
        from core import hx_summary
        if hx_summary.usable(db_path):
            rows = db.query("SELECT asset_uuid FROM hx_asset WHERE kev_any", path=db_path)
        else:
            from agents.cisakev.agent import XREF
            rows = db.query("SELECT DISTINCT asset_uuid FROM vulns WHERE xrefs LIKE '%" + XREF + "%'", path=db_path)
        return sorted({r["asset_uuid"] for r in rows if r.get("asset_uuid")})
    if key == "score60":
        return _fused(lambda s, sc: sc >= 60, db_path)
    if key == "crown":
        return _fused(lambda s, sc: s.get("crown"), db_path)
    if key == "crown_kev":
        return _fused(lambda s, sc: s.get("crown") and s.get("kev"), db_path)
    if key == "crown_blind":
        return _fused(lambda s, sc: s.get("crown") and s.get("blind"), db_path)
    if key == "lit4":
        from core import fused_score as fs
        return _fused(lambda s, sc: len(fs._signals_on(s)) >= 4, db_path)
    if key == "eol":
        from core import eol
        return list(eol.analyze(db_path, keep_uuids=True).get("_assets") or [])
    if key == "pq":
        from agents.postquantum.agent import discover
        return list(discover(db_path, keep_uuids=True).get("_uuids") or [])
    raise KeyError(key)


def asset_rows(uu, db_path=None, chunk=900):
    """Display rows for a uuid list (assets table), in the order given."""
    cols = {r["name"] for r in db.query('PRAGMA table_info("assets")', path=db_path)}
    sel = ["uuid", "hostname", "ip_address"] + [c for c in ("operating_system", "acr", "aes", "last_found", "url")
                                                  if c in cols]
    by = {}
    for i in range(0, len(uu), chunk):
        part = uu[i:i + chunk]
        for r in db.query("SELECT %s FROM assets WHERE uuid IN (%s)" % (", ".join(sel), ",".join("?" * len(part))),
                          tuple(part), path=db_path):
            by[r["uuid"]] = r
    return [by.get(u) or {"uuid": u, "hostname": "", "ip_address": ""} for u in uu]
