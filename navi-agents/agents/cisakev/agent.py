"""Laelaps — CISA KEV (Known Exploited Vulnerabilities) tagging agent.

Tenable carries each KEV finding as an xref ``{'type':'CISA-KNOWN-EXPLOITED',
'id':'YYYY/MM/DD'}`` (the id is the catalog *dateAdded*). navi can tag straight
off that cross-reference:

  * **Any KEV**      → ``navi enrich tag --c "CISA KEV" --v "Vulnerable" --xrefs CISA-KNOWN-EXPLOITED``
  * **By date**      → add ``--xid YYYY/MM/DD`` → value ``CISA KEV : <Mon> - <DD> - <YYYY>``

Both are navi's internal xref tagging — no external catalog download required.
"""
import datetime

from core import db, navi_cli
from core.agents.base import Agent

XREF = "CISA-KNOWN-EXPLOITED"
_MARK = "CISA-KNOWN-EXPLOITED', 'id': '"      # navi.db xrefs render: {'type': 'CISA-KNOWN-EXPLOITED', 'id': 'YYYY/MM/DD'}


def fmt_date(d: str) -> str:
    """'YYYY/MM/DD' -> 'Mon - DD - YYYY' (the tag value)."""
    try:
        return datetime.datetime.strptime(d, "%Y/%m/%d").strftime("%b - %d - %Y")
    except Exception:
        return d


def kev_dates(db_path=None) -> list[dict]:
    sql = ("SELECT d AS kev_date, COUNT(DISTINCT asset_uuid) assets, COUNT(*) findings FROM ("
           "SELECT asset_uuid, substr(xrefs, instr(xrefs, \"" + _MARK + "\")+%d, 10) AS d "
           "FROM vulns WHERE xrefs LIKE '%%" + XREF + "%%') "
           "WHERE d LIKE '____/__/__' GROUP BY d ORDER BY d DESC") % (len(_MARK),)
    rows = db.query(sql, path=db_path)
    for r in rows:
        r["value"] = fmt_date(r.get("kev_date", ""))
    return rows


def summary(db_path=None) -> dict:
    a = db.scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE xrefs LIKE '%" + XREF + "%'", path=db_path)
    f = db.scalar("SELECT COUNT(*) FROM vulns WHERE xrefs LIKE '%" + XREF + "%'", path=db_path)
    return {"kev_assets": a or 0, "kev_findings": f or 0}


def tag_vulnerable() -> dict:
    """Tag every KEV asset: navi enrich tag --c 'CISA KEV' --v 'Vulnerable' --xrefs CISA-KNOWN-EXPLOITED."""
    return navi_cli.tag("CISA KEV", "Vulnerable", xrefs=XREF, remove=False, agent="cisakev")


def tag_date(kev_date: str) -> dict:
    """Tag KEV assets added on one date: ... --xrefs CISA-KNOWN-EXPLOITED --xid YYYY/MM/DD."""
    kev_date = (kev_date or "").strip()
    if not kev_date:
        return {"ok": False, "message": "empty date"}
    return navi_cli.tag("CISA KEV", fmt_date(kev_date), xrefs=XREF, xid=kev_date,
                        remove=False, agent="cisakev")


class CisaKevAgent(Agent):
    id = "cisakev"
    name = "CISA KEV Tagging"
    icon = "🛡️"
    description = ("Laelaps — tags CISA Known-Exploited vulnerabilities off Tenable's "
                  "CISA-KNOWN-EXPLOITED xref: every KEV asset (CISA KEV:Vulnerable) and "
                  "by catalog date (CISA KEV:<Mon>-<DD>-<YYYY>).")

    def summary(self):
        return self.result.get("summary", {}) if self.result else {}

    def _run(self, db_path=None, **kwargs):
        return {"ok": True, "summary": summary(db_path), "dates": kev_dates(db_path),
                "source": "navi.db vulns.xrefs (CISA-KNOWN-EXPLOITED)"}
