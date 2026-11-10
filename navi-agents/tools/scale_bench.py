#!/usr/bin/env python3
"""scale_bench.py — read-only scale benchmark for a navi.db (The Hounds scale plan).

Measures what the Hounds' scale plan needs to know about YOUR navi.db, without changing it:
  1. inventory   — file size, page size, journal mode, row counts, which indexes exist
  2. sample      — row shape from a few slices of vulns (bytes/row, severity/state mix,
                   how many rows belong to the ~45 plugins the planned vuln_signals table parses)
  3. scan speed  — read rate over vulns slices (cold, then warm) → projected full-scan time
  4. probes      — the statement shapes the hounds run (by asset, by plugin, tag-query shape),
                   each under a time budget; a budget hit is a result ("> 60 s"), not a failure
  5. --full      — optional full-table statements (GROUP BY plugin / per-asset rollup / COUNT)
  6. --index-trial N — optional: copies the first N million vulns rows into a TEMP file
                   (never navi.db), builds the planned indexes there, times them, re-runs the
                   probes, and projects index size + build time to your full table

Safety:
  - navi.db is opened read-only (mode=ro, query_only). Nothing is written to it, ever.
  - Run it when navi is NOT syncing (a long read during a sync stops the WAL from resetting).
  - Output holds counts and timings only — no hostnames, IPs, plugin output or tags — so
    the report is safe to share. Default output: ./scale_bench_<date>.json and .md

Usage:
  python3 scale_bench.py /path/to/navi.db                  # ~5-15 min, no full scans
  python3 scale_bench.py /path/to/navi.db --budget 120     # longer per-probe budget (s)
  python3 scale_bench.py /path/to/navi.db --full           # + full-table statements (can be hours)
  python3 scale_bench.py /path/to/navi.db --index-trial 5  # + index trial on a 5M-row temp copy
  python3 scale_bench.py /path/to/navi.db --tmpdir /big/disk --out ./reports
Python 3.8+, standard library only.
"""
import argparse
import datetime
import json
import os
import platform
import random
import shutil
import sqlite3
import sys
import tempfile
import time

try:
    import resource
except ImportError:          # Windows
    resource = None

VERSION = 1

# plugins the planned navi `vuln_signals` table would parse — every plugin whose output a hound
# reads (harvested from the hounds' statements by the SQL review, sql_plan.md §4)
SIGNAL_PLUGINS = [
    "19506",                                                    # Nessus scan info (cred, duration, policy)
    "11936", "45590", "25203", "35351", "38689", "55472",       # OS identification / CPE
    "95928", "10860", "83303", "10914", "10915", "10785",       # local users / SMB enumeration
    "41028", "17651",                                           # SNMP community, password policy
    "70657", "153588", "56984", "277652", "277654", "10267", "181418", "168149",   # SSH/TLS/cipher
    "35716", "54615", "66717", "24260", "10107", "55786", "76423", "131732", "19689",
    "22964", "11219", "86420", "43111", "70329", "216040",      # IoT / device carriers
    "24270", "45432", "45433", "48942",                         # hardware / DMI
    "93561",                                                    # Docker
    "99001", "99003",                                           # AI detection
]
# the indexes the scale plan proposes (Phase 0)
PLANNED_INDEXES = [
    ("hx_v_plugin", "vulns", "plugin_id, asset_uuid, state"),
    ("hx_v_asset", "vulns", "asset_uuid, plugin_id, state"),
    ("hx_t_asset", "tags", "asset_uuid, tag_key, tag_value"),
    ("hx_t_kv", "tags", "tag_key, tag_value, asset_uuid"),
    ("hx_c_asset", "compliance", "asset_uuid"),
    ("hx_cert_asset", "certs", "asset_uuid"),
    ("hx_sw_asset", "software", "asset_uuid"),
]


def now():
    return time.perf_counter()


def rss_mb():
    if not resource:
        return None
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(r / (1048576.0 if sys.platform == "darwin" else 1024.0), 1)


def human_s(s):
    if s is None:
        return "—"
    if s < 1:
        return "%.0f ms" % (s * 1000)
    if s < 120:
        return "%.1f s" % s
    if s < 7200:
        return "%.1f min" % (s / 60)
    return "%.1f h" % (s / 3600)


def human_b(b):
    if b is None:
        return "—"
    for u in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024 or u == "TB":
            return ("%.1f %s" % (b, u)) if u != "B" else ("%d B" % b)
        b /= 1024.0


class Budget:
    """Abort a statement after `seconds` (sqlite progress handler) — a hit is a result."""
    def __init__(self, con, seconds):
        self.con, self.seconds, self.t0 = con, seconds, None

    def __enter__(self):
        self.t0 = now()
        self.con.set_progress_handler(lambda: 1 if now() - self.t0 > self.seconds else 0, 20000)
        return self

    def __exit__(self, *a):
        self.con.set_progress_handler(None, 0)
        return False


def open_ro(path, mmap_mb=0, cache_mb=256, temp_file=True):
    uri = "file:%s?mode=ro" % os.path.abspath(path).replace("?", "%3f").replace("#", "%23")
    con = sqlite3.connect(uri, uri=True, check_same_thread=False)
    con.execute("PRAGMA query_only=1")
    con.execute("PRAGMA temp_store=%s" % ("FILE" if temp_file else "MEMORY"))
    con.execute("PRAGMA cache_size=-%d" % (cache_mb * 1024))
    con.execute("PRAGMA mmap_size=%d" % (mmap_mb * 1048576))
    return con


def timed(con, sql, params=(), budget=60, fetch="all"):
    """Run sql under a budget. Returns {s, rows, hit_budget, error}."""
    out = {"sql": " ".join(sql.split()), "budget_s": budget}
    t = now()
    try:
        with Budget(con, budget):
            cur = con.execute(sql, params)
            if fetch == "one":
                r = cur.fetchone()
                out["rows"] = 1 if r is not None else 0
                out["value"] = r[0] if r and len(r) == 1 and isinstance(r[0], (int, float)) else None
            else:
                n = 0
                while True:
                    chunk = cur.fetchmany(5000)
                    if not chunk:
                        break
                    n += len(chunk)
                out["rows"] = n
        out["s"] = round(now() - t, 3)
    except sqlite3.OperationalError as e:
        el = now() - t
        if "interrupt" in str(e).lower():
            out["hit_budget"] = True
            out["s"] = round(el, 3)
        else:
            out["error"] = str(e)[:200]
            out["s"] = round(el, 3)
    return out


def plan(con, sql, params=()):
    try:
        return [r[3] for r in con.execute("EXPLAIN QUERY PLAN " + sql, params)]
    except Exception as e:
        return ["(plan failed: %s)" % str(e)[:120]]


def table_cols(con, t, db="main"):
    try:
        return [r[1] for r in con.execute('PRAGMA %s.table_info("%s")' % (db, t))]
    except Exception:
        return []


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


# ---------------------------------------------------------------------------------------------
def inventory(con, path):
    log("1/6 inventory")
    inv = {"file_bytes": os.path.getsize(path), "path_basename": os.path.basename(path)}
    for side in ("-wal", "-shm"):
        p = path + side
        inv["wal_bytes" if side == "-wal" else "shm_bytes"] = os.path.getsize(p) if os.path.exists(p) else 0
    for k in ("page_size", "page_count", "freelist_count", "journal_mode", "auto_vacuum", "encoding"):
        try:
            inv[k] = con.execute("PRAGMA %s" % k).fetchone()[0]
        except Exception:
            pass
    inv["sqlite_version"] = sqlite3.sqlite_version
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    stat1 = {}
    if "sqlite_stat1" in tables:
        for tbl, idx, st in con.execute("SELECT tbl, idx, stat FROM sqlite_stat1"):
            try:
                stat1.setdefault(tbl, int(str(st).split()[0]))
            except Exception:
                pass
    counts = {}
    for t in tables:
        if t.startswith("sqlite_"):
            continue
        cols = table_cols(con, t)
        approx = None
        try:
            approx = con.execute('SELECT MAX(rowid) FROM "%s"' % t).fetchone()[0]   # rowid b-tree: instant
        except Exception:
            pass
        exact = None
        if (approx or 0) <= 2_000_000:              # exact COUNT only where it's cheap
            try:
                exact = con.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]
            except Exception:
                pass
        counts[t] = {"rows_exact": exact, "rows_approx_maxrowid": approx, "stat1": stat1.get(t),
                     "columns": len(cols)}
    inv["tables"] = counts
    idx = []
    for name, tbl, sql in con.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"):
        idx.append({"name": name, "table": tbl, "sql": " ".join((sql or "").split())})
    inv["indexes"] = idx
    inv["has_asset_uuid_index_on_vulns"] = any(i["table"] == "vulns" and "asset_uuid" in i["sql"].split("(", 1)[-1].split(",")[0]
                                               for i in idx)
    inv["has_plugin_index_on_vulns"] = any(i["table"] == "vulns" and i["sql"].split("(", 1)[-1].strip().startswith("plugin_id")
                                           for i in idx)
    inv["has_sqlite_stat1"] = "sqlite_stat1" in tables
    inv["navi_optional_tables"] = {t: (t in tables) for t in ("certs", "software", "compliance", "vuln_paths", "vuln_route",
                                                              "epss", "fixed", "apps", "findings", "agents", "navi_meta",
                                                              "vuln_signals")}
    # assets: stale vs licensed (cheap — assets is small)
    acols = table_cols(con, "assets")
    a = {}
    try:
        a["assets"] = con.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        if "last_found" in acols:
            for d in (30, 90, 180, 365):
                a["last_seen_older_than_%dd" % d] = con.execute(
                    "SELECT COUNT(*) FROM assets WHERE TRIM(COALESCE(last_found,''))<>'' AND date(substr(last_found,1,10)) < date('now', ?)",
                    ("-%d day" % d,)).fetchone()[0]
        if "last_licensed_scan_date" in acols:
            a["licensed_marked"] = con.execute(
                "SELECT COUNT(*) FROM assets WHERE TRIM(COALESCE(last_licensed_scan_date,''))<>''").fetchone()[0]
    except Exception as e:
        a["error"] = str(e)[:200]
    inv["assets"] = a
    return inv


def slices(con, table, n_slices, rows_per):
    mx = con.execute('SELECT MAX(rowid) FROM "%s"' % table).fetchone()[0] or 0
    if mx <= rows_per:
        return [(1, mx)], mx
    rnd = random.Random(42)
    starts = sorted({1} | {rnd.randint(1, max(1, mx - rows_per)) for _ in range(n_slices - 1)})
    return [(s, s + rows_per - 1) for s in starts], mx


def sample(con, rows_per=200_000, n_slices=5):
    log("2/6 sample vulns slices (%d × %d rows)" % (n_slices, rows_per))
    sl, mx = slices(con, "vulns", n_slices, rows_per)
    vcols = set(table_cols(con, "vulns"))
    ph = ",".join("?" * len(SIGNAL_PLUGINS))
    agg = {"rows": 0, "output_bytes": 0, "row_bytes_est": 0, "signal_rows": 0, "assets_seen": 0,
           "severity": {}, "state": {}}
    widths = [c for c in ("output", "plugin_name", "cves", "xrefs", "synopsis", "solution", "description", "asset_hostname")
              if c in vcols]
    for a, b in sl:
        r = con.execute(
            "SELECT COUNT(*), SUM(LENGTH(output)), SUM(%s), SUM(plugin_id IN (%s)), COUNT(DISTINCT asset_uuid) "
            "FROM vulns WHERE rowid BETWEEN ? AND ?" % ("+".join("COALESCE(LENGTH(%s),0)" % c for c in widths) or "0", ph),
            SIGNAL_PLUGINS + [a, b]).fetchone()
        agg["rows"] += r[0] or 0
        agg["output_bytes"] += r[1] or 0
        agg["row_bytes_est"] += r[2] or 0
        agg["signal_rows"] += r[3] or 0
        agg["assets_seen"] += r[4] or 0
        for col in ("severity", "state"):
            if col in vcols:
                for v, n in con.execute('SELECT %s, COUNT(*) FROM vulns WHERE rowid BETWEEN ? AND ? GROUP BY 1' % col, (a, b)):
                    agg[col][str(v)] = agg[col].get(str(v), 0) + n
    n = max(1, agg["rows"])
    return {"vulns_rows_approx": mx, "sampled_rows": agg["rows"], "slices": len(sl),
            "avg_output_bytes": round(agg["output_bytes"] / n, 1),
            "avg_text_bytes_per_row": round(agg["row_bytes_est"] / n, 1),
            "signal_plugin_share": round(agg["signal_rows"] / n, 4),
            "projected_signal_rows": int(mx * agg["signal_rows"] / n) if mx else None,
            "severity_values": agg["severity"], "state_values": agg["state"],
            "case_mixed": {c: len({k.lower() for k in agg[c]}) < len(agg[c]) for c in ("severity", "state")}}


def scan_speed(con, path, rows_per=500_000):
    log("3/6 scan speed (cold then warm read of a %d-row slice)" % rows_per)
    sl, mx = slices(con, "vulns", 3, rows_per)
    a, b = sl[-1]
    sql = "SELECT SUM(LENGTH(output)) + COUNT(plugin_id) FROM vulns WHERE rowid BETWEEN ? AND ?"
    out = {}
    for label in ("cold", "warm"):
        t = now()
        con.execute(sql, (a, b)).fetchone()
        out[label + "_s"] = round(now() - t, 3)
    rows = b - a + 1
    out["rows"] = rows
    total_pages = con.execute("PRAGMA page_count").fetchone()[0]
    page = con.execute("PRAGMA page_size").fetchone()[0]
    v_share = None
    try:                                          # vulns share of the file (dbstat if compiled in)
        v = con.execute("SELECT SUM(pgsize) FROM dbstat WHERE name='vulns'").fetchone()[0]
        v_share = v / float(total_pages * page) if v else None
    except Exception:
        pass
    out["vulns_share_of_file"] = round(v_share, 3) if v_share else None
    for label in ("cold", "warm"):
        rate = rows / max(out[label + "_s"], 1e-6)
        out[label + "_rows_per_s"] = int(rate)
        out["projected_full_scan_" + label + "_s"] = round(mx / rate, 1) if mx else None
    return out


def probes(con, budget):
    log("4/6 probes (budget %ss each)" % budget)
    res = []
    one_asset = con.execute("SELECT uuid FROM assets LIMIT 1 OFFSET (SELECT COUNT(*)/2 FROM assets)").fetchone()
    one_asset = one_asset[0] if one_asset else ""
    common_plugin = "19506"
    p = [
        ("asset_lookup", "Argos / per-asset drill-down: one asset's open findings",
         "SELECT plugin_id, severity FROM vulns WHERE asset_uuid = ?", (one_asset,)),
        ("plugin_assets", "assets carrying one plugin (navi tag --plugin / hounds' plugin lookups)",
         "SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id = ?", (common_plugin,)),
        ("plugin_in_list", "signal plugins — the rows vuln_signals would parse",
         "SELECT COUNT(*) FROM vulns WHERE plugin_id IN (%s)" % ",".join("?" * len(SIGNAL_PLUGINS)), tuple(SIGNAL_PLUGINS)),
        ("tag_shape_exists", "tag-query shape: assets with a critical finding (EXISTS)",
         "SELECT uuid FROM assets a WHERE EXISTS (SELECT 1 FROM vulns v WHERE v.asset_uuid = a.uuid AND lower(v.severity) = 'critical') LIMIT 200", ()),
        ("output_like", "text search over plugin output (what vuln_signals replaces)",
         "SELECT COUNT(*) FROM vulns WHERE output LIKE '%OpenSSL%'", ()),
        ("tags_by_asset", "tags for one asset",
         "SELECT tag_key, tag_value FROM tags WHERE asset_uuid = ?", (one_asset,)),
        ("tags_by_kv", "assets with one tag (Garmr / tag compare)",
         "SELECT asset_uuid FROM tags WHERE tag_key = (SELECT tag_key FROM tags LIMIT 1) AND tag_value = (SELECT tag_value FROM tags LIMIT 1)", ()),
        ("compliance_asset", "one asset's compliance rows",
         "SELECT status FROM compliance WHERE asset_uuid = ?", (one_asset,)),
    ]
    for key, what, sql, params in p:
        r = timed(con, sql, params, budget)
        r.update({"key": key, "what": what, "plan": plan(con, sql, params)})
        res.append(r)
        log("   %-18s %s%s" % (key, human_s(r.get("s")), "  (budget hit)" if r.get("hit_budget") else ("  ERR " + r["error"] if r.get("error") else "")))
    return res


def full(con, budget):
    log("5/6 full-table statements (budget %ss each)" % budget)
    res = []
    for key, what, sql in [
        ("count_vulns", "COUNT(*) FROM vulns", "SELECT COUNT(*) FROM vulns"),
        ("group_plugin", "per-plugin counts (plugin explorer / hx_plugin build)",
         "SELECT plugin_id, COUNT(*) FROM vulns GROUP BY plugin_id"),
        ("asset_rollup", "per-asset severity rollup (hx_asset build / exposure score)",
         "SELECT asset_uuid, SUM(lower(severity)='critical'), SUM(lower(severity)='high'), COUNT(*) FROM vulns GROUP BY asset_uuid"),
    ]:
        r = timed(con, sql, (), budget)
        r.update({"key": key, "what": what, "plan": plan(con, sql)})
        res.append(r)
        log("   %-18s %s%s" % (key, human_s(r.get("s")), "  (budget hit)" if r.get("hit_budget") else ""))
    return res


def index_trial(src_path, million, tmpdir, budget, total_vulns):
    log("6/6 index trial on a %sM-row temp copy" % million)
    n = int(million * 1_000_000)
    est = os.path.getsize(src_path) * min(1.0, n / float(max(total_vulns or n, 1))) * 1.6
    free = shutil.disk_usage(tmpdir).free
    if free < est * 1.3:
        return {"skipped": "not enough free disk in %s (need ~%s, have %s)" % (tmpdir, human_b(est * 1.3), human_b(free))}
    d = tempfile.mkdtemp(prefix="scale_bench_", dir=tmpdir)
    trial = os.path.join(d, "trial.db")
    out = {"rows_requested": n, "tmp": d}
    try:
        con = sqlite3.connect("file:%s" % trial, uri=True)        # uri=True so ATTACH … ?mode=ro works
        con.execute("PRAGMA journal_mode=OFF")
        con.execute("PRAGMA synchronous=OFF")
        con.execute("PRAGMA temp_store=FILE")
        con.execute("PRAGMA cache_size=-262144")
        con.execute("ATTACH ? AS src", ("file:%s?mode=ro" % os.path.abspath(src_path),))
        t = now()
        # vulns: the first n rows; the small tables in full (only for the assets in the slice where big)
        con.execute("CREATE TABLE vulns AS SELECT * FROM src.vulns WHERE rowid <= ?", (n,))
        con.execute("CREATE TABLE assets AS SELECT * FROM src.assets WHERE uuid IN (SELECT DISTINCT asset_uuid FROM vulns)")
        for t2 in ("tags", "compliance", "certs", "software"):
            if table_cols(con, t2, "src"):
                con.execute('CREATE TABLE "%s" AS SELECT * FROM src."%s" WHERE asset_uuid IN (SELECT uuid FROM assets)' % (t2, t2))
        con.commit()
        con.execute("DETACH src")
        out["copy_s"] = round(now() - t, 1)
        rows = con.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
        out["rows"] = rows
        before = probes_small(con, budget)
        builds = []
        for name, tbl, cols in PLANNED_INDEXES:
            if not table_cols(con, tbl):
                continue
            pages0 = con.execute("PRAGMA page_count").fetchone()[0]
            t = now()
            con.execute("CREATE INDEX %s ON %s(%s)" % (name, tbl, cols))
            con.commit()
            b = {"index": name, "table": tbl, "cols": cols, "build_s": round(now() - t, 2)}
            try:                                # dbstat isn't compiled into every SQLite (macOS) —
                b["bytes"] = con.execute("SELECT SUM(pgsize) FROM dbstat WHERE name=?", (name,)).fetchone()[0]
            except Exception:                   # fall back to how much the file grew
                b["bytes"] = (con.execute("PRAGMA page_count").fetchone()[0] - pages0) * \
                    con.execute("PRAGMA page_size").fetchone()[0]
            builds.append(b)
        t = now()
        con.execute("PRAGMA analysis_limit=1000")
        con.execute("ANALYZE")
        out["analyze_s"] = round(now() - t, 2)
        trap = probes_small(con, budget, keys=("distinct_assets",))      # before the 'unordered' fix
        for name in ("hx_v_plugin", "hx_v_asset"):
            con.execute("UPDATE sqlite_stat1 SET stat = stat || ' unordered' WHERE idx = ? AND stat NOT LIKE '%unordered%'", (name,))
        con.commit()
        con.execute("ANALYZE sqlite_schema")
        after = probes_small(con, budget)
        scale = (total_vulns or rows) / float(max(rows, 1))
        for b in builds:
            if b["table"] == "vulns":
                b["projected_bytes_full"] = int(b["bytes"] * scale) if b.get("bytes") else None
                b["projected_build_s_full"] = round(b["build_s"] * scale * 1.15, 1)   # n·log n, ~15% over linear
        out.update({"before": before, "builds": builds, "trap_without_unordered": trap, "after": after,
                    "scale_factor": round(scale, 2)})
        con.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)
        out["tmp_removed"] = not os.path.exists(d)
    return out


def probes_small(con, budget, keys=None):
    a = con.execute("SELECT asset_uuid FROM vulns LIMIT 1 OFFSET 1000").fetchone()
    a = a[0] if a else ""
    shapes = {
        "asset_lookup": ("SELECT plugin_id, severity FROM vulns WHERE asset_uuid = ?", (a,)),
        "plugin_assets": ("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id = '19506'", ()),
        "distinct_assets": ("SELECT COUNT(*) FROM (SELECT DISTINCT asset_uuid FROM vulns WHERE lower(severity) IN ('critical','high'))", ()),
        "asset_rollup": ("SELECT asset_uuid, COUNT(*) FROM vulns GROUP BY asset_uuid", ()),
        "tags_by_asset": ("SELECT tag_key FROM tags WHERE asset_uuid = ?", (a,)),
    }
    out = {}
    for k, (sql, p) in shapes.items():
        if keys and k not in keys:
            continue
        r = timed(con, sql, p, budget)
        out[k] = {"s": r.get("s"), "hit_budget": r.get("hit_budget", False), "error": r.get("error"),
                  "plan": plan(con, sql, p)}
    return out


# ---------------------------------------------------------------------------------------------
def report_md(R):
    inv, L = R["inventory"], []
    v = inv["tables"].get("vulns", {})
    L.append("# navi.db scale benchmark — %s" % R["run"]["date"])
    L.append("")
    L.append("navi.db %s (WAL %s) · page %s · journal %s · SQLite %s · %s" % (
        human_b(inv["file_bytes"]), human_b(inv.get("wal_bytes")), inv.get("page_size"), inv.get("journal_mode"),
        inv.get("sqlite_version"), R["run"]["platform"]))
    L.append("vulns ≈ %s rows · assets %s · indexes on vulns: %d (asset_uuid index: %s, plugin index: %s, stats: %s)" % (
        "{:,}".format(v.get("rows_approx_maxrowid") or 0), "{:,}".format(inv["assets"].get("assets") or 0),
        sum(1 for i in inv["indexes"] if i["table"] == "vulns"),
        "yes" if inv["has_asset_uuid_index_on_vulns"] else "NO", "yes" if inv["has_plugin_index_on_vulns"] else "NO",
        "yes" if inv["has_sqlite_stat1"] else "no"))
    a = inv["assets"]
    if "last_seen_older_than_90d" in a:
        L.append("assets last seen > 90 d: %s · > 365 d: %s · licensed-marked: %s" % (
            a.get("last_seen_older_than_90d"), a.get("last_seen_older_than_365d"), a.get("licensed_marked")))
    s = R.get("sample") or {}
    if s:
        L.append("")
        L.append("## Row shape (sampled %s rows)" % "{:,}".format(s["sampled_rows"]))
        L.append("- avg output %s B · avg text %s B/row · signal-plugin share %.2f%% → vuln_signals ≈ %s rows" % (
            s["avg_output_bytes"], s["avg_text_bytes_per_row"], s["signal_plugin_share"] * 100,
            "{:,}".format(s["projected_signal_rows"] or 0)))
        L.append("- severity values: %s · state values: %s · mixed case: %s" % (
            s["severity_values"], s["state_values"], s["case_mixed"]))
    sp = R.get("scan") or {}
    if sp:
        L.append("")
        L.append("## Scan speed")
        L.append("- %s rows: cold %s (%s rows/s), warm %s (%s rows/s)" % (
            "{:,}".format(sp["rows"]), human_s(sp["cold_s"]), "{:,}".format(sp["cold_rows_per_s"]),
            human_s(sp["warm_s"]), "{:,}".format(sp["warm_rows_per_s"])))
        L.append("- projected FULL scan of vulns: cold %s · warm %s — every unindexed hound statement costs about this" % (
            human_s(sp.get("projected_full_scan_cold_s")), human_s(sp.get("projected_full_scan_warm_s"))))
    L.append("")
    L.append("## Probes (budget %ss)" % R["run"]["budget_s"])
    L.append("| probe | what | time | plan |")
    L.append("|---|---|---|---|")
    for p in R.get("probes", []) + R.get("full", []):
        t = ("> %s (budget)" % human_s(p["s"])) if p.get("hit_budget") else ("ERR " + p["error"] if p.get("error") else human_s(p.get("s")))
        L.append("| %s | %s | %s | %s |" % (p["key"], p["what"], t, " · ".join(p.get("plan", []))[:120]))
    it = R.get("index_trial")
    if it:
        L.append("")
        L.append("## Index trial (%s-row temp copy, ×%s to full)" % ("{:,}".format(it.get("rows") or 0), it.get("scale_factor")))
        if it.get("skipped"):
            L.append("- skipped: " + it["skipped"])
        else:
            L.append("| index | build | size | projected full build | projected full size |")
            L.append("|---|---|---|---|---|")
            for b in it["builds"]:
                L.append("| %s(%s) | %s | %s | %s | %s |" % (b["index"], b["cols"], human_s(b["build_s"]), human_b(b.get("bytes")),
                                                          human_s(b.get("projected_build_s_full")), human_b(b.get("projected_bytes_full"))))
            L.append("")
            L.append("| shape | no index | indexed (+unordered) |")
            L.append("|---|---|---|")
            for k, v0 in it["before"].items():
                v1 = it["after"].get(k, {})
                f = lambda x: ("> %s" % human_s(x["s"])) if x.get("hit_budget") else human_s(x.get("s"))
                L.append("| %s | %s | %s |" % (k, f(v0), f(v1)))
            tr = it.get("trap_without_unordered", {}).get("distinct_assets")
            if tr:
                L.append("")
                L.append("distinct_assets WITHOUT the 'unordered' fix: %s (plan: %s)" % (
                    ("> " if tr.get("hit_budget") else "") + human_s(tr.get("s")), " · ".join(tr.get("plan", []))))
    L.append("")
    L.append("peak RSS of this script: %s MB · total run %s" % (R["run"].get("peak_rss_mb"), human_s(R["run"].get("elapsed_s"))))
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Read-only navi.db scale benchmark for The Hounds.")
    ap.add_argument("db", help="path to navi.db (opened read-only)")
    ap.add_argument("--budget", type=float, default=60, help="seconds per probe before it is stopped (default 60)")
    ap.add_argument("--full", action="store_true", help="also run full-table statements (can take hours)")
    ap.add_argument("--full-budget", type=float, default=3600, help="seconds per full-table statement (default 3600)")
    ap.add_argument("--index-trial", type=float, default=0, metavar="MILLION_ROWS",
                    help="build the planned indexes on a temp copy of this many million vulns rows")
    ap.add_argument("--tmpdir", default=tempfile.gettempdir(), help="where the index-trial copy goes")
    ap.add_argument("--out", default=".", help="directory for the report files")
    ap.add_argument("--sample-rows", type=int, default=200_000)
    args = ap.parse_args()

    if not os.path.isfile(args.db):
        sys.exit("no such file: %s" % args.db)
    t0 = now()
    con = open_ro(args.db)
    try:
        con.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
    except sqlite3.DatabaseError as e:
        sys.exit("cannot read %s: %s" % (args.db, e))
    R = {"version": VERSION, "run": {"date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                                     "platform": "%s %s / py %s" % (platform.system(), platform.machine(), platform.python_version()),
                                     "cpus": os.cpu_count(), "budget_s": args.budget, "full": args.full,
                                     "index_trial_million": args.index_trial}}
    R["inventory"] = inventory(con, args.db)
    if "vulns" not in R["inventory"]["tables"]:
        sys.exit("navi.db has no vulns table")
    R["sample"] = sample(con, rows_per=args.sample_rows)
    R["scan"] = scan_speed(con, args.db)
    R["probes"] = probes(con, args.budget)
    if args.full:
        R["full"] = full(con, args.full_budget)
    con.close()
    if args.index_trial > 0:
        R["index_trial"] = index_trial(args.db, args.index_trial, args.tmpdir, args.budget,
                                       R["inventory"]["tables"]["vulns"].get("rows_approx_maxrowid"))
    R["run"]["elapsed_s"] = round(now() - t0, 1)
    R["run"]["peak_rss_mb"] = rss_mb()
    os.makedirs(args.out, exist_ok=True)
    stem = os.path.join(args.out, "scale_bench_%s" % datetime.datetime.now().strftime("%Y%m%d_%H%M"))
    with open(stem + ".json", "w") as f:
        json.dump(R, f, indent=1, default=str)
    with open(stem + ".md", "w") as f:
        f.write(report_md(R))
    log("done in %s → %s.md / .json" % (human_s(R["run"]["elapsed_s"]), stem))
    print()
    print(report_md(R))


if __name__ == "__main__":
    main()
