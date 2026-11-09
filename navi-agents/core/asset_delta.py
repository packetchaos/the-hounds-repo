"""Asset delta — what navi.db holds vs what Tenable licenses.

navi's asset sync pulls only assets seen in its window (90 days by default) and UPSERTS
them: an asset that ages out of the window, or falls off licensing, is never deleted from
navi.db's `assets` table. The `tags` table, though, is dropped and rebuilt on every assets
sync, so it only covers the assets that were pulled. The gap that opens up:

  - Hounds that tag with `--query` over navi.db's assets can tag those stale assets;
  - the next sync doesn't bring them back, so navi.db never shows their tags and
    `navi enrich tag -remove` (which strips from navi.db's view) can't reach them.

This module measures it: navi.db's asset count, how many are stale (last seen before the
window), how many navi.db marks as licensed, and Tenable's live licensed count
(`navi explore info licensed` → /workbenches/asset-stats, 90-day licensed). The fix is a
rebuild: Settings ▸ Rebuild navi.db (`navi config update full -rebuild --days N`).
Reads only — navi.db read-only + one navi read command.
"""
import re

from core import db, navi_cli

DEFAULT_DAYS = 90


def _cols(table, db_path=None):
    try:
        return {r.get("name") for r in db.query('PRAGMA table_info("%s")' % table, path=db_path)}
    except Exception:
        return set()


def _int(v):
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def navi_side(db_path=None, days=DEFAULT_DAYS) -> dict:
    """navi.db's view: assets, stale (last_found older than `days`), licensed-marked,
    and how many assets the tags table covers. Columns missing from older navi.db
    builds come back as None (unknown), never as 0."""
    days = max(1, min(_int(days) or DEFAULT_DAYS, 3650))
    cols = _cols("assets", db_path)
    out = {"days": days, "assets": None, "stale": None, "licensed_marked": None,
           "tagged_assets": None, "oldest_last_found": None, "has_last_found": "last_found" in cols}
    if not cols:
        out["error"] = "navi.db has no assets table — run an assets sync"
        return out
    try:
        out["assets"] = _int(db.scalar("SELECT COUNT(*) FROM assets", path=db_path))
    except Exception as e:
        out["error"] = str(e)
        return out
    if "last_found" in cols:
        try:
            out["stale"] = _int(db.scalar(
                "SELECT COUNT(*) FROM assets WHERE last_found IS NOT NULL AND TRIM(last_found)<>'' "
                "AND date(substr(last_found,1,10)) < date('now', ?)", ("-%d day" % days,), path=db_path))
            out["oldest_last_found"] = db.scalar(
                "SELECT MIN(substr(last_found,1,10)) FROM assets WHERE TRIM(COALESCE(last_found,''))<>''",
                path=db_path)
        except Exception:
            pass
    if "last_licensed_scan_date" in cols:
        try:
            out["licensed_marked"] = _int(db.scalar(
                "SELECT COUNT(*) FROM assets WHERE TRIM(COALESCE(last_licensed_scan_date,''))<>''",
                path=db_path))
        except Exception:
            pass
    if _cols("tags", db_path):
        try:
            out["tagged_assets"] = _int(db.scalar("SELECT COUNT(DISTINCT asset_uuid) FROM tags", path=db_path))
        except Exception:
            pass
    return out


_LIC = re.compile(r"Licensed\s+Count:\s*([0-9][0-9,]*)", re.I)


def parse_licensed(stdout) -> "int|None":
    m = _LIC.search(stdout or "")
    return int(m.group(1).replace(",", "")) if m else None


def tenable_licensed() -> dict:
    """Tenable's licensed asset count (live, via navi — a read, never gated)."""
    r = navi_cli.explore_info("licensed")
    n = parse_licensed(r.get("stdout"))
    if n is None:
        return {"ok": False, "licensed": None,
                "message": r.get("message") or (r.get("stderr") or "").strip()[-300:]
                or "navi explore info licensed returned no count"}
    return {"ok": True, "licensed": n}


def delta(db_path=None, days=DEFAULT_DAYS, live=True) -> dict:
    nv = navi_side(db_path, days)
    ten = tenable_licensed() if live else {"ok": False, "licensed": None, "message": "not requested"}
    lic, n = ten.get("licensed"), nv.get("assets")
    d = (n - lic) if (isinstance(n, int) and isinstance(lic, int)) else None
    if d is None:
        verdict = "unknown"
    elif d > 0 or (nv.get("stale") or 0) > 0:
        verdict = "drift"      # navi.db carries assets Tenable no longer licenses / that aged out
    else:
        verdict = "ok"
    return {"ok": True, "navi": nv, "tenable": ten, "delta": d, "verdict": verdict,
            "fix": "Settings ▸ Rebuild navi.db (navi config update full -rebuild --days N)"}
