"""Regression tests — Phase 1b (build 460): output-signal hits, route membership, the advisor.

core/hx_signals evaluates each output-searching hound's OWN predicate (AI inventory, Identity)
once during ⚡ Optimize — parallel, read-only — and keeps the matching vulns rowids (hx_hits);
vuln_route.plugin_list is exploded into hx_route_plugin. Checks: the hits equal the predicate ·
AI / Identity results are identical with and without them and the fast path really reads hx_hits
· stale (a sync) or a changed predicate falls back · a cancelled scan keeps nothing half-built ·
route membership equals the LIKE join (SLA disposition, Exposure Routes path detail) · the
slow-query advisor only flags filters on large, full-scanned tables.
Synthetic navi.db; no Tenable. Run: python3 tests/test_hx_signals.py"""
import atexit
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import faulthandler; faulthandler.dump_traceback_later(300, exit=True)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-sig-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"), "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
                   "NAVI_DB_PATH": DB, "HOUNDS_SIGNAL_CHUNK": "37", "HOUNDS_SIGNAL_THREADS": "3"})
os.environ.pop("HOUNDS_NO_SUMMARY", None)

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def make_db():
    """navi 8.8.2-shaped findings with AI / identity / endpoint words in names and outputs."""
    c = sqlite3.connect(DB)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE assets (uuid text PRIMARY KEY, hostname text, ip_address text, acr text, last_found text)")
    c.execute("""CREATE TABLE vulns (finding_id text PRIMARY KEY, asset_uuid text, plugin_id text, plugin_name text,
                 plugin_family text, severity text, state text, xrefs text, cves text, score text, output text,
                 port text, first_found text)""")
    c.execute("CREATE TABLE tags (asset_uuid text, tag_key text, tag_value text)")
    c.execute("CREATE TABLE vuln_route (route_id integer PRIMARY KEY, app_name text, plugin_list text, total_vulns int, vuln_type text)")
    c.execute("CREATE TABLE vuln_paths (path_id integer PRIMARY KEY, plugin_id text, path text, asset_uuid text)")
    outs = ["Ollama API listening on 11434", "The remote host runs a TensorFlow Serving instance",
            "LOCAL USER: svc_backup is a SERVICE ACCOUNT", "default credentials admin/admin accepted",
            "krbtgt password last set 2019", "Nothing to see here", "pytorch 2.1 installed",
            "blank password for user guest", "OpenAI SDK found in site-packages", "random text " * 40,
            "pytorch client posting to https://api.openai.com/v1 and huggingface.co"]
    names = ["Service Detection", "Local Users Enumeration", "Ollama Detection", "Installed Software",
             "Kerberos Info", "Misc"]
    rows = []
    for i in range(600):
        u = "%08x-0000-0000-0000-%012x" % (i % 80, i % 80)
        rows.append(("f%04d" % i, u, str(10000 + i % 37), names[i % len(names)], "General", "info",
                     "OPEN" if i % 5 else "fixed", "", "", "", outs[i % len(outs)], str(11434 if i % 9 == 0 else 0),
                     "2026-01-01"))
    c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    c.executemany("INSERT INTO assets VALUES (?,?,?,?,?)",
                  [("%08x-0000-0000-0000-%012x" % (i, i), "h%d" % i, "10.0.0.%d" % i, "5", "2026-11-01") for i in range(80)])
    c.executemany("INSERT INTO vuln_route VALUES (?,?,?,?,?)",
                  [(1, "Shop", "['10001', '10002']", 5, "web"), (2, "Pay", "['10003']", 2, "web"),
                   (3, "Nope", "['100010']", 1, "web")])
    c.executemany("INSERT INTO vuln_paths VALUES (?,?,?,?)",
                  [(1, "10001", "/opt/shop", "%08x-0000-0000-0000-%012x" % (1, 1)),
                   (2, "10003", "/opt/pay", "%08x-0000-0000-0000-%012x" % (3, 3))])
    c.executemany("INSERT INTO tags VALUES (?,?,?)",
                  [("%08x-0000-0000-0000-%012x" % (1, 1), "Owner", "Shop: Accepted")])
    c.commit()
    c.close()


make_db()
from core import db, hx_optimize, hx_signals, hx_summary, ai_assets, identity, qprofile  # noqa: E402

# ── the scan + build ───────────────────────────────────────────────────────────────────────────
r = hx_optimize.optimize(DB)
st = hx_summary.state(DB, force=True)
check(r.get("ok") and st.get("fresh"), "⚡ Optimize builds the summaries with the signal hits")
check(set(st.get("signals") or {}) == {"ai", "ai_egress", "identity"},
      "signal hits recorded for AI, AI egress and Identity (%s)" % st.get("signals"))
c = sqlite3.connect(DB)
vcols = {x[1] for x in c.execute("PRAGMA table_info(vulns)")}
for h, pf in (("ai", ai_assets.signal_predicate), ("ai_egress", ai_assets.egress_predicate),
              ("identity", identity.signal_predicate)):
    pred = pf(vcols)
    want = [x[0] for x in c.execute("SELECT rowid FROM vulns WHERE %s ORDER BY rowid" % pred)]
    got = [x[0] for x in c.execute("SELECT vrow FROM hx_hits WHERE hound=? ORDER BY vrow", (h,))]
    check(want == got and want, "hx_hits for %s = exactly the rows its predicate matches (%d), across 3 threads × small ranges" % (h, len(want)))
rp = sorted(c.execute("SELECT plugin_id, app_name FROM hx_route_plugin").fetchall())
check(rp == sorted([("10001", "Shop"), ("10002", "Shop"), ("10003", "Pay"), ("100010", "Nope")]),
      "hx_route_plugin explodes plugin_list ('10001' doesn't match '100010') %s" % rp)
c.close()


# ── hounds: same answers, fast path really used ───────────────────────────────────────────────
def traced(fn):
    seen = []
    orig_q, orig_i = db.query, db.iter

    def q(sql, *a, **k):
        seen.append(sql)
        return orig_q(sql, *a, **k)

    def it(sql, *a, **k):
        seen.append(sql)
        return orig_i(sql, *a, **k)
    db.query, db.iter = q, it
    try:
        return fn(), seen
    finally:
        db.query, db.iter = orig_q, orig_i


def both(fn):
    on, sql_on = traced(fn)
    orig = hx_signals.usable_for
    hx_signals.usable_for = lambda *a, **k: False
    try:
        off, sql_off = traced(fn)
    finally:
        hx_signals.usable_for = orig
    return on, off, sql_on, sql_off


on, off, s_on, s_off = both(lambda: ai_assets.scan())
check(on.get("asset_count") and json.dumps(on["assets"], sort_keys=True, default=str) == json.dumps(off["assets"], sort_keys=True, default=str),
      "AI inventory: identical result with and without the signal hits (%d assets)" % on.get("asset_count", 0))
check(any("hx_hits" in x for x in s_on) and not any("hx_hits" in x for x in s_off), "AI inventory reads hx_hits when it is fresh")
check(on.get("egressCount") and any("hound='ai_egress'" in x for x in s_on)
      and not any("asset_uuid IN" in x and "openai.com" in x for x in s_on),
      "AI egress (build 463): reads only the flagged findings — no per-asset output read (%d assets)" % on.get("egressCount", 0))
eg_on, eg_off, _s1, _s2 = None, None, None, None
_o = hx_signals.usable_for
hx_signals.usable_for = lambda h, p, path=None: False if h == "ai_egress" else _o(h, p, path)
try:
    off_eg = ai_assets.scan()
finally:
    hx_signals.usable_for = _o
check(json.dumps(on, sort_keys=True, default=str) == json.dumps(off_eg, sort_keys=True, default=str),
      "AI egress: identical inventory (hosts, snippets, sanctioned) with and without the egress hits")
on, off, s_on, s_off = both(lambda: identity._output_pass(DB))
check(on == off and (on[0] or on[1] or on[2]), "Identity output pass: identical with and without the signal hits")
check(any("hx_hits" in x for x in s_on), "Identity reads hx_hits when it is fresh")

# a changed predicate (code change) → fallback until the next Optimize
orig_pred = ai_assets.signal_predicate
ai_assets.signal_predicate = lambda v: orig_pred(v) + " OR output LIKE '%brand new term%'"
check(not hx_signals.usable_for("ai", ai_assets.signal_predicate(vcols), DB), "a changed AI predicate → its hits are not used")
ai_assets.signal_predicate = orig_pred

# ── route membership readers ───────────────────────────────────────────────────────────────────
from core import sla  # noqa: E402
frag_fast = sla._disp_exclude("vulns.", DB)
orig_ru = hx_signals.routes_usable
hx_signals.routes_usable = lambda *a, **k: False
frag_slow = sla._disp_exclude("vulns.", DB)
hx_signals.routes_usable = orig_ru
c = sqlite3.connect(DB)
n_fast = c.execute("SELECT COUNT(*) FROM vulns WHERE 1=1" + frag_fast).fetchone()[0]
n_slow = c.execute("SELECT COUNT(*) FROM vulns WHERE 1=1" + frag_slow).fetchone()[0]
c.close()
check("hx_route_plugin" in frag_fast and "plugin_list LIKE" in frag_slow and n_fast == n_slow and n_fast < 600,
      "SLA route disposition: hx_route_plugin gives the same findings as the LIKE join (%d / %d)" % (n_fast, n_slow))
from agents.exproute import agent as xr  # noqa: E402
a_fast = xr.path_detail("/opt/shop")
hx_signals.routes_usable = lambda *a, **k: False
a_slow = xr.path_detail("/opt/shop")
hx_signals.routes_usable = orig_ru
check(json.dumps(a_fast, sort_keys=True, default=str) == json.dumps(a_slow, sort_keys=True, default=str),
      "Exposure Routes path detail: same apps / owners via hx_route_plugin")

# ── stale + cancel ─────────────────────────────────────────────────────────────────────────────
c = sqlite3.connect(DB)
c.execute("INSERT INTO vulns (finding_id, asset_uuid, plugin_id, plugin_name, output) VALUES ('new','x','1','x','ollama')")
c.commit()
c.close()
hx_summary.invalidate()
check(not hx_signals.usable_for("ai", ai_assets.signal_predicate(vcols), DB), "after a sync the hits are stale → fallback")
ev = threading.Event()
ev.set()
res = hx_signals.scan(DB, cancel=ev)
check(res.get("cancelled"), "a cancelled signal scan reports cancelled (nothing written)")
sig = hx_signals.scan(DB)
c = sqlite3.connect(DB)
c.execute("INSERT INTO vulns (finding_id, asset_uuid, plugin_id, plugin_name, output) VALUES ('new2','x','1','x','ollama')")
c.commit()
c.close()
cw = sqlite3.connect(DB, isolation_level=None)
r2 = hx_summary.build(cw, signals=sig)
cw.close()
hx_summary.invalidate()
st2 = hx_summary.state(DB, force=True)
check(r2.get("ok") and st2.get("fresh") and not st2.get("signals"),
      "hits scanned before a sync landed are not written (the summaries still build)")

# an older navi.db whose vuln_route lacks route_id, and a failing extras step, never cost the summaries
c = sqlite3.connect(DB)
c.execute("CREATE TABLE vr2 AS SELECT app_name, plugin_list, total_vulns FROM vuln_route")
c.execute("DROP TABLE vuln_route")
c.execute("ALTER TABLE vr2 RENAME TO vuln_route")
c.commit()
c.close()
cw = sqlite3.connect(DB, isolation_level=None)
r3 = hx_summary.build(cw, signals=None)
n_rp = cw.execute("SELECT COUNT(*) FROM hx_route_plugin").fetchone()[0]
cw.close()
check(r3.get("ok") and n_rp == 4, "vuln_route without route_id still explodes (rowid) — %d pairs" % n_rp)
orig_w = hx_signals.write
hx_signals.write = lambda *a, **k: (_ for _ in ()).throw(ValueError("boom"))
cw = sqlite3.connect(DB, isolation_level=None)
r4 = hx_summary.build(cw, signals=None)
left = {x[0] for x in cw.execute("SELECT name FROM sqlite_master WHERE name IN ('hx_hits','hx_route_plugin')")}
cw.close()
hx_signals.write = orig_w
check(r4.get("ok") and not left, "a failing signal/route step leaves the summaries built and no half tables")

# ── the slow-query advisor ─────────────────────────────────────────────────────────────────────
sch = qprofile._schema(DB)
real = set(sch)
qprofile._ROWS["path"] = None
orig_small = qprofile._SMALL_ROWS
qprofile._SMALL_ROWS = 10


def hints(sql):
    sc, pl = qprofile._explain_scans(sql, DB)
    return qprofile._nonsargable(sql, sc, pl, real, sch, DB)


h1 = hints("SELECT asset_uuid FROM vulns WHERE output LIKE '%ollama%'")
check(h1 and "vulns.output" in h1[0] and "hx_hits" in h1[0], "advisor: output LIKE on a scanned vulns is flagged with the column and the fix")
check(not hints("SELECT lower(plugin_name), CAST(score AS REAL), COALESCE(port,'') FROM vulns WHERE rowid=1"),
      "advisor: functions in the SELECT list are not flagged")
check(not hints("SELECT plugin_id FROM hx_plugin WHERE lname LIKE '%x%'"), "advisor: hx_* summary tables are not flagged")
h4 = hints("SELECT DISTINCT r.app_name FROM vuln_route r JOIN vulns v ON r.plugin_list LIKE '%''' || v.plugin_id || '''%'")
check(h4 and "hx_route_plugin" in h4[0], "advisor: a JOIN on LIKE over plugin_list is flagged and points at hx_route_plugin")
h5 = hints("SELECT a.uuid FROM assets a WHERE COALESCE(a.hostname,'')='x'")
check(h5 and "COALESCE(assets.hostname" in h5[0], "advisor: a function in a filter on a scanned table is flagged (alias resolved)")
qprofile._SMALL_ROWS = orig_small
qprofile._ROWS["path"] = None
check(not hints("SELECT a.uuid FROM assets a WHERE COALESCE(a.hostname,'')='x'"), "advisor: a small table's scan isn't worth a hint")
page = open(os.path.join(ROOT, "web", "agent-runs.html"), encoding="utf-8").read()
check("(q.nonsargable||[]).map(" in page, "Runs page shows every advisor hint for a query")

print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
