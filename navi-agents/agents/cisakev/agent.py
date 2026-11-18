"""Laelaps — CISA KEV (Known Exploited Vulnerabilities) tagging agent.

Tenable carries each KEV finding as an xref ``{'type':'CISA-KNOWN-EXPLOITED',
'id':'YYYY/MM/DD'}`` (the id is the catalog *dateAdded*). navi can tag straight
off that cross-reference:

  * **Any KEV**      → ``navi enrich tag --c "CISA KEV" --v "Vulnerable" --xrefs CISA-KNOWN-EXPLOITED``
  * **By date**      → add ``--xid YYYY/MM/DD`` → value ``CISA KEV : <Mon> - <DD> - <YYYY>``

Both are navi's internal xref tagging — no external catalog download required.
"""
import datetime

from core import db, hx_summary, navi_cli, tagscope
from core.agents.base import Agent

XREF = "CISA-KNOWN-EXPLOITED"
_MARK = "CISA-KNOWN-EXPLOITED', 'id': '"      # navi.db xrefs render: {'type': 'CISA-KNOWN-EXPLOITED', 'id': 'YYYY/MM/DD'}


def fmt_date(d: str) -> str:
    """'YYYY/MM/DD' -> 'Mon - DD - YYYY' (the tag value)."""
    try:
        return datetime.datetime.strptime(d, "%Y/%m/%d").strftime("%b - %d - %Y")
    except Exception:
        return d


def _sc(scope, col="asset_uuid"):
    """(fragment, params) for an optional (tag_key, tag_value) scope — ('', ()) for the whole estate."""
    k, v = scope if scope else (None, None)
    return tagscope.sql(k, v, col)


def _kev_dates_fast(db_path=None, scope=None) -> list[dict]:
    """kev_dates() over the summaries: the KEV xref (and so its catalog date) is a plugin
    attribute, so read ONE KEV finding's xrefs per KEV plugin, then count each date's findings
    and assets with covering hx_v_plugin ranges — no vulns.xrefs scan."""
    pd = db.query("SELECT plugin_id, (SELECT substr(xrefs, instr(xrefs, \"" + _MARK + "\")+%d, 10) FROM vulns x "
                  "WHERE x.plugin_id = p.plugin_id AND x.xrefs LIKE '%%" % (len(_MARK),) + XREF + "%' LIMIT 1) AS d "
                  "FROM hx_plugin p WHERE p.kev", path=db_path)
    by = {}
    for r in pd:
        d = r.get("d") or ""
        if len(d) == 10 and d[4] == "/" and d[7] == "/":           # = d LIKE '____/__/__'
            by.setdefault(d, []).append(str(r["plugin_id"]))
    if not by:
        return []
    lit = lambda v: "'" + v.replace("'", "''") + "'"
    vals = ",".join("(%s,%s)" % (lit(p), lit(d)) for d, ps in by.items() for p in ps)
    frag, args = _sc(scope, "v.asset_uuid")
    return db.query("WITH kp(plugin_id, d) AS (VALUES " + vals + ") "
                    "SELECT kp.d AS kev_date, COUNT(DISTINCT v.asset_uuid) assets, COUNT(*) findings "
                    "FROM kp CROSS JOIN vulns v" + db.indexed_by("hx_v_plugin", db_path) + " ON v.plugin_id = kp.plugin_id "
                    + ("WHERE 1=1" + frag + " " if frag else "") +
                    "GROUP BY kp.d ORDER BY kp.d DESC", args, path=db_path)


def kev_dates(db_path=None, scope=None) -> list[dict]:
    """scope=(tag_key, tag_value): only that tag's assets' findings (build 489). None = whole estate."""
    if hx_summary.usable(db_path):
        rows = _kev_dates_fast(db_path, scope)
        for r in rows:
            r["value"] = fmt_date(r.get("kev_date", ""))
        return rows
    frag, args = _sc(scope)
    sql = ("SELECT d AS kev_date, COUNT(DISTINCT asset_uuid) assets, COUNT(*) findings FROM ("
           "SELECT asset_uuid, substr(xrefs, instr(xrefs, \"" + _MARK + "\")+%d, 10) AS d "
           "FROM vulns WHERE xrefs LIKE '%%" + XREF + "%%'" + frag.replace("%", "%%") + ") "
           "WHERE d LIKE '____/__/__' GROUP BY d ORDER BY d DESC") % (len(_MARK),)
    rows = db.query(sql, args, path=db_path)
    for r in rows:
        r["value"] = fmt_date(r.get("kev_date", ""))
    return rows


def summary(db_path=None, scope=None) -> dict:
    """scope=(tag_key, tag_value): only that tag's assets (build 489). None = whole estate."""
    if scope:
        frag, args = _sc(scope)
        if hx_summary.usable(db_path):
            # same rules as below, over the tag's assets: kev_any per asset; every finding of a KEV plugin
            a = db.scalar("SELECT COUNT(*) FROM hx_asset WHERE kev_any" + frag, args, path=db_path)
            f = db.scalar("SELECT COUNT(*) FROM vulns" + db.indexed_by("hx_v_plugin", db_path) +
                          " WHERE plugin_id IN (SELECT plugin_id FROM hx_plugin WHERE kev)" + frag, args, path=db_path)
            return {"kev_assets": a or 0, "kev_findings": f or 0}
        a = db.scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE xrefs LIKE '%" + XREF + "%'" + frag, args, path=db_path)
        f = db.scalar("SELECT COUNT(*) FROM vulns WHERE xrefs LIKE '%" + XREF + "%'" + frag, args, path=db_path)
        return {"kev_assets": a or 0, "kev_findings": f or 0}
    if hx_summary.usable(db_path):
        # Phase 1: hx_asset.kev_any = an asset with a KEV-xref finding in any state (the rule
        # below); findings = every finding of a KEV plugin (hx_plugin.findings).
        a = db.scalar("SELECT COUNT(*) FROM hx_asset WHERE kev_any", path=db_path)
        f = db.scalar("SELECT SUM(findings) FROM hx_plugin WHERE kev", path=db_path)
        return {"kev_assets": a or 0, "kev_findings": f or 0}
    a = db.scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE xrefs LIKE '%" + XREF + "%'", path=db_path)
    f = db.scalar("SELECT COUNT(*) FROM vulns WHERE xrefs LIKE '%" + XREF + "%'", path=db_path)
    return {"kev_assets": a or 0, "kev_findings": f or 0}


def xref_view(db_path=None, scope=None) -> dict:
    """The xref half of a run: KEV asset / finding counts + the dateAdded list."""
    return {"ok": True, "summary": summary(db_path, scope), "dates": kev_dates(db_path, scope),
            "source": "navi.db vulns.xrefs (CISA-KNOWN-EXPLOITED)"}


def scoped_xref_sql(scope, kev_date=None):
    """(sql, params) — the assets of the tag with a KEV-xref finding (optionally for one catalog
    dateAdded): what navi --xrefs [--xid] selects, restricted to the tag. Read from navi.db on the
    server; the scope is never a uuid list from the browser."""
    frag, args = _sc(scope)
    pat = "%" + (_MARK + kev_date if kev_date else XREF) + "%"
    return "SELECT DISTINCT asset_uuid FROM vulns WHERE xrefs LIKE ?" + frag, (pat,) + tuple(args)


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
        return xref_view(db_path)
