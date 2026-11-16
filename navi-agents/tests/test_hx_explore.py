"""Regression tests — Phase 1 summary-table fast paths for EXPLORE, ROUTES & APPS (build 456).

Each rewritten reader takes `if hx_summary.usable(): <hx_plugin / covered hx_v_* SQL> else
<the old SQL>`. On a synthetic navi.db whose plugin attributes (name, family, CVEs) are constant
per plugin — as on Tenable data — and with ⚡ Optimize's indexes + summary tables built, every
check asserts: the fast path returns the SAME result as HOUNDS_NO_SUMMARY=1 (the fallback), the
fast path was actually taken (its SQL reads hx_plugin), and a stale summary (one vulns row
inserted after the build) falls back.

Covered: core/search.plugins (Plugin Explorer) · core/mitre build_plan (navi_cves, cve_assets,
high-ACR) · agents/exproute snapshot (present plugins, findings funnel, champion asset count) ·
agents/c2 _plugin_dim + plan · agents/explore cert_month (incl. > 32,766 uuids).
Synthetic navi.db; no Tenable. Run: python3 tests/test_hx_explore.py"""
import atexit
import os
import random
import re
import shutil
import sqlite3
import sys
import tempfile
import faulthandler; faulthandler.dump_traceback_later(300, exit=True)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-hxe-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"), "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
                   "NAVI_DB_PATH": DB})
os.environ.pop("HOUNDS_NO_SUMMARY", None)

from core import db, hx_summary, mitre, search  # noqa: E402
from agents.exproute import agent as exr  # noqa: E402
from agents.c2 import api as c2  # noqa: E402
from agents.explore import api as exapi  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def _bundled_cves(n=40):
    with open(mitre.BUNDLED_CSV, encoding="utf-8-sig") as f:
        return [r["cve"] for r in mitre.parse_rows(f.read())][:n]


def make_db(path, n=12000, assets=600, plugins=150, cert_assets=0):
    if os.path.exists(path):
        os.remove(path)
    c = sqlite3.connect(path)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE assets (uuid text PRIMARY KEY, hostname text, ip_address text, "
              "operating_system text, acr text, aes text, url text)")
    c.execute("""CREATE TABLE vulns (finding_id text PRIMARY KEY, asset_uuid text, plugin_id text,
                 plugin_name text, plugin_family text, severity text, state text, xrefs text, cves text,
                 score text, output text, last_found text, url text)""")
    c.execute("CREATE TABLE plugins (plugin_id text PRIMARY KEY, name text, cves text, "
              "cvss3_base_score text, solution text)")
    c.execute("CREATE TABLE vuln_route (route_id integer, app_name text, plugin_list text, "
              "total_vulns integer, vuln_type text)")
    c.execute("CREATE TABLE vuln_paths (path text, asset_uuid text, plugin_id text, finding_id text)")
    c.execute("CREATE TABLE tags (asset_uuid text, asset_ip text, tag_key text, tag_value text, "
              "tag_uuid text, tag_added_date text)")
    c.execute("CREATE TABLE certs (asset_uuid text, common_name text, organization text, "
              "organization_unit text, not_valid_after text, signature_algorithm text, key_length text)")
    r = random.Random(11)
    oses = ["Linux Kernel 5.4 on Ubuntu 20.04", "Microsoft Windows Server 2019", "CentOS Linux 7"]
    c.executemany("INSERT INTO assets VALUES (?,?,?,?,?,?,?)",
                  [("u%05d" % i, "h%d" % i, "10.2.%d.%d" % (i // 250, i % 250), oses[i % 3],
                    str(i % 11), "500", "") for i in range(assets)])
    cv = _bundled_cves()
    fams = ["Ubuntu Local Security Checks", "Windows", "General", "Web Servers", "Misc."]
    pl = {}
    for p in range(plugins):
        name = ("SSL Certificate Issue %d" % p if p % 13 == 0 else
                "OpenSSL Vulnerability %d" % p if p % 7 == 0 else "Plugin %d" % p)
        cves = ", ".join(cv[(p * 3 + k) % len(cv)] for k in range(p % 3)) if p % 4 else None
        pl[str(20000 + p)] = (name, fams[p % 5], ["critical", "high", "medium", "low", "info"][p % 5],
                              cves, "%.1f" % (p % 10 + 0.3))
    rows = []
    for i in range(n):
        pid = str(20000 + r.randrange(plugins))
        name, fam, sev, cves, sc = pl[pid]
        # per-finding VPR varies a little (exproute keeps MAX(score) over findings)
        sc = "%.1f" % (float(sc) + (i % 3) * 0.1)
        rows.append(("f%06d" % i, "u%05d" % r.randrange(assets), pid, name, fam, sev,
                     r.choice(["OPEN", "open", "REOPENED", "fixed"]), "", cves, sc, "out", "2026-10-01", ""))
    # the edges the exact counts must carry: a NULL plugin_id row and a NULL asset_uuid row
    rows.append(("fnullp", "u00001", None, "orphan", "General", "low", "open", "", None, None, "", "", ""))
    rows.append(("fnulla", None, "20007", pl["20007"][0], pl["20007"][1], "low", "open", "", pl["20007"][3],
                 "1.0", "", "", ""))
    c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    c.executemany("INSERT INTO plugins VALUES (?,?,?,?,?)",
                  [(p, v[0], v[3] or "", "%.1f" % (int(p) % 10), "Upgrade the package.") for p, v in pl.items()])
    routes = [(1, "OpenSSL", "['20007', '20014', '20021']", 50, "Software"),
              (2, "Web Stack", "['20003', '20008', '20013', '20026']", 40, "Web"),
              (3, "Ghost", "['99999']", 1, "Software")]
    c.executemany("INSERT INTO vuln_route VALUES (?,?,?,?,?)", routes)
    c.executemany("INSERT INTO vuln_paths VALUES (?,?,?,?)",
                  [("/opt/app%d/lib" % (i % 7), "u%05d" % (i * 3 % assets), "20007" if i % 2 else "20039", "p%d" % i)
                   for i in range(60)])
    c.executemany("INSERT INTO tags VALUES (?,?,?,?,?,?)",
                  [("u%05d" % i, "", "Owner", "OpenSSL: alice" if i % 2 else "Web Stack: bob", "t", "2026-01-01")
                   for i in range(0, assets, 9)])
    certs = [("u%05d" % (i % assets), "cn%d" % i, "", "", "Jun 01 12:00:00 2027 GMT", "sha256", "2048")
             for i in range(max(cert_assets, 80))]
    c.executemany("INSERT INTO certs VALUES (?,?,?,?,?,?,?)", certs)
    c.execute("CREATE INDEX hx_v_plugin ON vulns(plugin_id, asset_uuid, state, severity)")
    c.execute("CREATE INDEX hx_v_asset ON vulns(asset_uuid, plugin_id, state, severity)")
    c.commit()
    c.close()
    w = sqlite3.connect(path, isolation_level=None, timeout=10)
    res = hx_summary.build(w)
    w.close()
    hx_summary.invalidate()
    db.close_all()
    return res


# ── harness: run f() fast and fallback, record the SQL the fast run sent ────────────────────────
SQL = []
_orig = {n: getattr(db, n) for n in ("query", "scalar", "iter")}


def _spy(name):
    def g(sql, *a, **k):
        SQL.append(str(sql))
        return _orig[name](sql, *a, **k)
    return g


for _n in _orig:
    setattr(db, _n, _spy(_n))


def _reset():
    hx_summary.invalidate()
    c2._SIG_CACHE.clear()


def both(f):
    """(fast result, fallback result, SQL the fast run sent)."""
    _reset()
    SQL.clear()
    fast = f()
    sent = list(SQL)
    os.environ["HOUNDS_NO_SUMMARY"] = "1"
    try:
        _reset()
        slow = f()
    finally:
        os.environ.pop("HOUNDS_NO_SUMMARY", None)
    _reset()
    return fast, slow, sent


def uses_hx(sent):
    return any("hx_plugin" in s for s in sent)


# ── the readers ──────────────────────────────────────────────────────────────────────────────
def r_plugins():
    out = []
    for q in ("", "OpenSSL", "Windows", "2001"):
        rows = search.plugins(q, 0, 500)["rows"]
        # the old GROUP BY lists a NULL-plugin_id group; the plugin dimension has none (accepted)
        out.append(sorted((r["plugin_id"], r["name"], r["family"], r["assets"]) for r in rows
                          if r["plugin_id"] is not None))
    return out


def r_mitre():
    p = mitre.build_plan(allow_live=False)
    p.pop("attack", None)
    # high_acr is ordered by ACR only; ties keep row-scan order, which differs by access path
    p["high_acr"] = sorted(p["high_acr"], key=lambda a: a["asset_uuid"])
    return p


def r_exproute():
    exr._owners_live = lambda: []
    s = exr.build_snapshot()
    s.pop("meta", None)
    return __import__("json").loads(__import__("json").dumps(s, default=sorted, sort_keys=True))


def r_c2():
    dim, vn = c2._plugin_dim()
    plans = [c2.plan({"selector": s})[0] for s in ("OpenSSL", "20003", _bundled_cves()[4], "Windows")]
    return ({k: sorted(map(tuple, v), key=repr) for k, v in dim.items()}, vn, plans)


def r_cert():
    return exapi.cert_month({"month": "2027-06"})[0]


READERS = [("search.plugins", r_plugins), ("mitre.build_plan", r_mitre),
           ("exproute snapshot", r_exproute), ("c2 plugin dim + plan", r_c2),
           ("explore cert_month", r_cert)]


def t_equivalence():
    res = make_db(DB)
    check(res.get("ok") and res.get("plugins"), "fixture: summaries built (%s)" % res)
    check(hx_summary.usable(), "fixture: hx_summary.usable() is True after the build")
    for name, f in READERS:
        fast, slow, sent = both(f)
        check(uses_hx(sent), "%s: fast path reads hx_plugin" % name)
        check(fast == slow, "%s: fast result == HOUNDS_NO_SUMMARY=1 result" % name)
    m = r_mitre()
    check(m["matched_cves"] > 0 and m["metrics"]["assets_affected"] > 0 and m["high_acr"],
          "mitre: the fixture exercises matched CVEs, assets and high-ACR rows (%d/%d/%d)"
          % (m["matched_cves"], m["metrics"]["assets_affected"], len(m["high_acr"])))
    s = r_exproute()
    check((s["map"].get("funnel") or {}).get("findings") == 12002,
          "exproute: funnel findings counts every vulns row incl. the NULL plugin_id one")
    check((s["map"].get("champion") or {}).get("assets"), "exproute: champion has an asset count")


def t_no_vulns_scan():
    """The fast paths never send a statement that scans vulns rows for a plugin attribute."""
    make_db(DB)
    for name, f in READERS:
        _reset()
        SQL.clear()
        f()
        bad = [s for s in SQL if "FROM vulns" in s and
               (any(t in s for t in ("plugin_name LIKE", "TRIM(COALESCE(cves", "GROUP BY plugin_id ORDER BY assets",
                                     "(SELECT COUNT(*) FROM vulns)"))
                or re.search(r"SELECT DISTINCT plugin_id FROM vulns( INDEXED BY \S+)?\)?\s*$", s)
                or "(SELECT DISTINCT plugin_id FROM vulns" in s)]
        check(not bad, "%s: no attribute scan over vulns on the fast path (%s)" % (name, [b[:80] for b in bad]))


def t_stale_falls_back():
    make_db(DB)
    w = sqlite3.connect(DB, isolation_level=None, timeout=10)
    w.execute("INSERT INTO vulns(finding_id, asset_uuid, plugin_id, plugin_name, state) "
              "VALUES ('late', 'u00002', '20001', 'Plugin 1', 'open')")
    w.close()
    hx_summary.invalidate()
    check(not hx_summary.usable(), "stale: one vulns row after the build makes the summaries unusable")
    for name, f in READERS:
        _reset()
        SQL.clear()
        f()
        check(not uses_hx(SQL), "stale: %s falls back (no hx_plugin read)" % name)


def t_cert_month_many():
    """A month with more assets than SQLite's bound-variable limit (the old IN (?,?,…) raised
    'too many SQL variables') — both paths answer, and agree."""
    make_db(DB, n=3000, assets=34000, plugins=40, cert_assets=34000)
    fast, slow, sent = both(r_cert)
    check(fast.get("ok") and fast["counts"]["assets"] > 32766, "cert_month: %d assets in one month answered"
          % fast.get("counts", {}).get("assets", 0))
    check(fast == slow and uses_hx(sent), "cert_month (> 32,766 uuids): fast == fallback, fast reads hx_plugin")
    check(any(r["plugin_name"].startswith("SSL Certificate") for r in fast["plugins"]),
          "cert_month: certificate plugins listed")


if __name__ == "__main__":
    for t in (t_equivalence, t_no_vulns_scan, t_stale_falls_back, t_cert_month_many):
        try:
            t()
        except Exception as e:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            check(False, "%s raised %r" % (t.__name__, e))
    db.close_all()
    print("\n%d failure(s)" % len(fails))
    sys.exit(1 if fails else 0)
