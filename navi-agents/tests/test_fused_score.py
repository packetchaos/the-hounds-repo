"""Regression tests for the Exposure Score agent (Nemesis): only OPEN findings count, the SLA
breach uses first_found against the severity windows, account reuse outranks other identity
signals (password reuse is never inferred), blank hostnames fall back to the IP, the whole-estate act-now counts, the
server-side Priority tag set (client UUIDs are never trusted), and the snapshot cache.
Tiny synthetic navi.db files in a temp dir; no navi, no network.
Run: python3 tests/test_fused_score.py  (or pytest)."""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
TMP = tempfile.mkdtemp(prefix="hounds-fused-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB

from core import navi_cli  # noqa: E402

TAGGED = []
# build 453: the Priority set is handed to navi_cli.tag_set (the standard paged mechanism —
# one job ≤ 1,999 assets, a tag series above); record the set and its first page's query
navi_cli.tag_set = lambda *a, **k: (TAGGED.append((a, {**k, "query": navi_cli.uuids_query(k.get("uuids") or [])}))
                                   or [{"ok": True, "job_id": len(TAGGED)}])
from core import fused_score as F  # noqa: E402
from agents.fused_score import api  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def ago(days):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - days * 86400))


KEV = "CISA-KNOWN-EXPLOITED:2022/01/01"
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT, aes INTEGER);
CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT, score REAL,
                    xrefs TEXT, state TEXT, first_found TEXT, last_found TEXT);
CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT);""")
for u, h, ip, acr in [("a1", "crown", "10.0.0.1", "10"), ("a2", "fixedkev", "10.0.0.2", "5"),
                      ("a3", "fresh", "10.0.0.3", "5"), ("a4", "overdue", "10.0.0.4", "5"),
                      ("a5", "legacyreuse", "10.0.0.5", "5"), ("a6", "acctreuse", "10.0.0.6", "5"), ("a9", "nhi", "10.0.0.9", "5"),
                      ("a7", " ", "10.0.0.7", "5"), ("a8", "oldmed", "10.0.0.8", "5")]:
    c.execute("INSERT INTO assets VALUES (?,?,?,?,?)", (u, h, ip, acr, 0))
V = [("a1", "1", "x", "critical", 9.8, KEV, "open", ago(100)),
     ("a2", "2", "x", "critical", 9.8, KEV, "fixed", ago(100)),      # fixed → not exposure
     ("a3", "3", "x", "high", 7.0, "", "open", ago(10)),             # within the 30-day high SLA
     ("a4", "4", "x", "high", 7.0, "", "reopened", ago(40)),         # past it (reopened is open)
     ("a8", "8", "x", "medium", 5.0, "", "open", ago(1000))]         # no medium window configured
for r in V:
    c.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?)", r + (ago(1),))
c.executemany("INSERT INTO tags VALUES (?,?,?)", [
    ("a1", "Owner", "Web: alice"), ("a5", "Identity Risk", "Password Reuse"),     # legacy tag value
    ("a6", "Identity Risk", "Account Reuse : svc_deploy"), ("a9", "NHI", "Non-human identity")])
c.commit(); c.close()

ov = F.overview(DB, limit=100)
A = {r["uuid"]: r for r in ov["assets"]}
check(A["a1"]["kev"] and not A["a2"]["kev"], "a fixed KEV finding doesn't count — only open / reopened findings")
check(A["a2"]["vol"] == 0 and A["a2"]["vpr"] == 0, "fixed findings add no volume or VPR")
check(A["a4"]["sla"] and not A["a3"]["sla"], "SLA breach is first_found age vs the severity window (40 d high breaches, 10 d doesn't)")
check(not A["a8"]["sla"], "no window configured for medium → never a breach")
check(A["a1"]["sla"], "a 100-day-old critical breaches the 15-day window")
check(ov["kpi"]["sla_breach"] == 2 and ov["sla_days"] == {"critical": 15, "high": 30},
      "estate SLA count and the windows used are reported")
check(A["a6"]["ident"] == 2 and A["a9"]["ident"] == 1, "account reuse = 2, other NHI / identity = 1")
check(A["a5"]["ident"] == A["a6"]["ident"], "an old 'Password Reuse' tag counts only as account reuse — no extra weight")
check(A["a6"]["factors"]["ident"] > A["a9"]["factors"]["ident"] > 0, "account reuse outscores a bare NHI tag")
check(A["a7"]["host"] == "10.0.0.7", "a blank hostname falls back to the IP")
check(not A["a1"]["unowned"] and A["a3"]["unowned"], "an Owner tag makes an asset owned")

# whole-estate act-now counts match the per-asset scores
scores = [r["score"] for r in ov["assets"]]
for t in F.ACT_THRESHOLDS:
    check(ov["kpi"]["act"][str(t)]["n"] == sum(1 for s in scores if s >= t), f"act-now count at {t} = assets scoring ≥ {t}")

# one asset's score (Argos' At a glance) = its row in the estate view
check(all(F.asset_score(r["uuid"], DB)["score"] == r["score"] and F.asset_score(r["uuid"], DB)["factors"] == r["factors"]
          for r in ov["assets"]) and F.asset_score("nope", DB) is None,
      "asset_score matches the estate overview for every asset; unknown asset → None")

# ---------------------------------------------------------------- server-side tag set
thr = sorted(scores, reverse=True)[2]            # something with a few assets over it
want = {r["uuid"] for r in ov["assets"] if r["score"] >= thr}
check(set(F.select_uuids(DB, threshold=thr)) == want, "select_uuids = every asset scoring over the line")
top = F.select_uuids(DB, threshold=101, fallback=3)
check(len(top) == 3 and top[0] == ov["assets"][0]["uuid"], "nothing over the line → the worst N (same order as the board)")
check(F.select_uuids(DB, uuid="a3") == ["a3"] and F.select_uuids(DB, uuid="nope") == [], "single asset must exist in navi.db")

JOBS = []                                          # the job queue, run inline
api.jobq.submit = lambda fn, meta=None: (JOBS.append({"meta": meta, "result": fn()}) or {"id": len(JOBS)})
TAGGED.clear()
r, code = api.tag({"confirm": True, "mode": "act", "threshold": thr, "uuids": ["evil' OR 1=1 --"], "value": "p2"})
check(r.get("background") and r.get("job_id") == len(JOBS) and JOBS[-1]["meta"]["action"] == "tag"
      and JOBS[-1]["result"]["count"] == len(want), "the act-now tag runs on the job queue and reports its count there")
a, k = TAGGED[0]
check(r["ok"] and code == 200 and set(k["uuids"]) == want and "evil" not in k["query"],
      "tag recomputes the set server-side — client UUIDs are ignored")
check(a[:2] == ("Priority", "P2") and not k.get("remove") and k["agent"] == "fused_score",   # tag_set is add-only
      "Priority : P2, never removes, attributed to fused_score")
check(api.tag({"confirm": True, "value": "P9"})[1] == 400, "only P1–P4")
check(api.tag({"confirm": True, "mode": "one", "uuid": "nope"})[1] == 400, "unknown asset refused")
check(api.tag({"mode": "act", "threshold": 40})[1] == 400, "confirm required")
check(api.tag({"confirm": True, "threshold": "x"})[1] == 400, "bad threshold refused")
TAGGED.clear()
api.tag({"confirm": True, "mode": "one", "uuid": "a1"})
check(TAGGED and TAGGED[0][1]["uuids"] == ["a1"], "single-asset tag (answers at once, no job)")


# ---------------------------------------------------------------- review regressions
TAGGED.clear()
check(api.tag({"confirm": True, "mode": "one"})[1] == 400 and api.tag({"confirm": True, "mode": "one", "uuid": " "})[1] == 400
      and not TAGGED, "single-asset mode without a uuid is refused (it used to tag the whole act-now set)")
check(api.tag({"confirm": True, "mode": "act", "threshold": True})[1] == 400 and not TAGGED,
      "threshold:true is refused (it used to read as threshold 1)")
check(api.overview({"limit": "abc"})[1] == 400 and api.overview({"offset": -3})[1] == 400
      and api.overview({"limit": 10 ** 9})[1] == 400, "overview validates limit / offset")
ovw = api.overview({"weights": {"expl": float("inf"), "sev": float("nan"), "crit": True}})
check(ovw[1] == 200 and ovw[0]["result"]["ok"], "infinite / NaN / boolean weights fall back to defaults — no crash")
check(F._r(4.5) == 5 and F._r(4.49) == 4 and F._r(30 * 0.55) == 17, "scores round half up, like the page")


def mkdb(name, assets, vulns=(), tags=(), certs=None, sla=None):
    p = os.path.join(TMP, name)
    c = sqlite3.connect(p)
    c.executescript("""
    CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT, aes INTEGER);
    CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT, score REAL,
                        xrefs TEXT, state TEXT, first_found TEXT, last_found TEXT);
    CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT);""")
    c.executemany("INSERT INTO assets VALUES (?,?,?,?,0)", assets)
    c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?)", vulns)
    c.executemany("INSERT INTO tags VALUES (?,?,?)", tags)
    if certs is not None:
        c.execute("CREATE TABLE certs (asset_uuid TEXT, signature_algorithm TEXT, not_valid_after TEXT, algorithm TEXT, key_length TEXT)")
        c.executemany("INSERT INTO certs VALUES (?,?,?,?,?)", certs)
    if sla is not None:
        c.execute("CREATE TABLE sla (critical INTEGER, high INTEGER, medium INTEGER, low INTEGER)")
        c.execute("INSERT INTO sla VALUES (?,?,?,?)", sla)
    c.commit(); c.close()
    return p


# ties: the page's worst-N and the server's tag set must be the same assets
T = mkdb("ties.db", [(f"t{i:02d}", f"h{i:02d}", "", "5") for i in range(30)] + [("zm", "mit", "", "10")],
         tags=[(f"t{i:02d}", "Owner", "Web: alice") for i in range(30)] + [("zm", "Owner", "Web: Mitigated")])
board = [r["uuid"] for r in F.overview(T, limit=10)["assets"]]
check(F.select_uuids(T, threshold=101, fallback=10) == board, "tied scores: the tag fallback is exactly the board's worst 10")

# certificates as navi stores them
FAR = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(time.time() + 400 * 86400))
C = mkdb("certs.db", [(u, u, "", "5") for u in ("sha1", "expired", "ecdsa", "rsa1024", "healthy")],
         certs=[("sha1", "SHA-1 With RSA Encryption", FAR, None, "2048 bits"),
                ("expired", "SHA-256 With RSA Encryption", "Dec 12 20:57:22 2023 GMT", None, "2048 bits"),
                ("ecdsa", "ecdsa-with-SHA256", FAR, None, "256 bits"),
                ("rsa1024", "SHA-256 With RSA Encryption", FAR, None, "1024 bits"),
                ("healthy", "SHA-256 With RSA Encryption", FAR, None, "2048 bits")])
CR = {r["uuid"]: r["crypto"] for r in F.overview(C, limit=50)["assets"]}
check(CR["sha1"] == "pq" and CR["rsa1024"] == "pq", "SHA-1 signatures and short RSA keys are weak crypto")
check(CR["expired"] == "certfail", "an expired cert ('Dec 12 20:57:22 2023 GMT') is caught")
check(CR["ecdsa"] is None and CR["healthy"] is None, "ECDSA-256 and a healthy cert valid > 30 days are not penalised")

# tags other Hounds actually write; PQ from the plugin, not the shared tag; IoT counts as a signal
X = mkdb("tags.db", [(u, u, "", "5") for u in ("ci", "le", "iot", "pqready", "pqbad", "none")],
         vulns=[("pqbad", "277650", "Remote Services NOT Using Post-Quantum Ciphers", "info", 0, "", "open", ago(1), ago(1)),
                ("pqready", "277653", "Remote Services Using Post-Quantum Ciphers", "info", 0, "", "open", ago(1), ago(1))],
         tags=[("ci", "Cert Issue", "SSL Certificate Expiry"), ("le", "Lifecycle EOL", "2025-01-01"), ("iot", "IoT", "Camera"),
               ("pqready", "Post-Quantum", "Cipher Analysis"), ("pqbad", "Post-Quantum", "Cipher Analysis")])
xo = F.overview(X, limit=50)
XR = {r["uuid"]: r for r in xo["assets"]}
check(XR["ci"]["crypto"] == "certfail" and XR["le"]["eol"], "'Cert Issue' and 'Lifecycle EOL' tags are read")
check(XR["pqbad"]["crypto"] == "pq" and XR["pqready"]["crypto"] is None,
      "only plugin 277650 is post-quantum exposure — a PQC-ready asset isn't penalised for its tag")
check(xo["kpi"]["no_signal"] == 2, "an IoT-only asset isn't counted as 'no Hound signal' (only 'none' and the PQC-ready one are)")

# an SLA window of 0 days means 'no window', not 'everything breaches'
S0 = mkdb("sla0.db", [("m", "m", "", "5")], vulns=[("m", "9", "x", "medium", 5.0, "", "open", ago(3), ago(1))],
          sla=(15, 30, 0, 0))
check(not F.overview(S0)["assets"][0]["sla"], "an SLA window of 0 days is treated as unset")

# a big act-now set is tagged in chunks (one --query argument must stay under ~128 KB)
real_sel = api.engine.select_uuids
api.engine.select_uuids = lambda **k: [f"{i:08d}-aaaa-bbbb-cccc-{i:012d}" for i in range(4000)]
TAGGED.clear()
r, code = api.tag({"confirm": True, "mode": "act", "threshold": 40})
api.engine.select_uuids = real_sel
_pages = navi_cli.uuid_batches(TAGGED[0][1]["uuids"]) if TAGGED else []
check(code == 200 and JOBS[-1]["result"]["count"] == 4000 and len(TAGGED) == 1
      and [len(p) for p in _pages] == [1999, 1999, 2]
      and all(len(navi_cli.uuids_query(p)) < 100000 for p in _pages),
      "4,000 assets → one tag series of 3 pages (≤ 1,999 each), each query < 100 KB")
TAGGED.clear()

# ---------------------------------------------------------------- snapshot cache
api._submit = lambda fn: (fn(), {"id": 1})[1]     # run builds inline
r, _ = api.snapshot({"peek": True})
check(r["ok"] and r["result"] is None, "peek never builds")
r, _ = api.snapshot({})
r, _ = api.snapshot({"peek": True})
check(r["result"] and r["cached"] and r["result"]["result"]["kpi"]["assets"] == 9, "Run builds, then peek serves the cache")
check(not api.SNAP._building and r["building"] is None, "a finished build leaves no 'building' marker (even when the queue runs it at once)")
api.SNAP._mem.clear()
check(api.snapshot({"peek": True})[0]["result"] is not None, "snapshot survives a restart (read back from disk)")
w = {f["id"]: f["max"] for f in F.FACTORS}; w["own"] = 25
check(api.snapshot({"peek": True, "weights": w})[0]["result"] is None, "a different weighting is a different snapshot")
check(api.snapshot({"peek": True, "weights": {f["id"]: f["max"] for f in F.FACTORS}})[0]["result"] is not None,
      "default weights sent explicitly share the default snapshot")
time.sleep(0.01)
c = sqlite3.connect(DB); c.execute("INSERT INTO tags VALUES ('a3','Owner','Web: bob')"); c.commit(); c.close()
os.utime(DB, None)
check(api.snapshot({"peek": True})[0]["result"] is None, "changing navi.db invalidates the snapshot")


def test_fused_score_regressions():
    assert not fails, "\n".join(fails)


# ---- page: "What drives the score" is its own section, not a glance group (build 447) ----
_pg = open(os.path.join(HERE, "..", "agents", "fused_score", "page.html"), encoding="utf-8").read()
check('id="sec-drv" data-nav=' in _pg and "function renderDrivers()" in _pg,
      "fused_score: 'What drives the score' is a jump-nav section (sec-drv) rendered by renderDrivers()")
_gl = _pg[_pg.index("renderGlance('glxFs'"):_pg.index("onFilter:f=>setFilter(f,true)});")]
check("What drives the score" not in _gl and "Signal prevalence" not in _gl,
      "fused_score: the glance no longer carries the 'What drives the score' group")
check("const nDrv=renderDrivers();" in _pg and "'sec-drv','sec-act'" in _pg and "setNavCount('sec-drv', nDrv)" in _pg,
      "fused_score: renderAll renders + shows sec-drv and sets its nav count (page-cache replay goes through renderAll)")
_ids = [m for m in ("sec-act", "sec-play", "sec-lb", "sec-worst", "sec-score", "sec-drv")]
_pos = [_pg.index('<section class="card" id="%s"' % i) for i in _ids]
check(_pos == sorted(_pos), "fused_score: section order — Act now first, What drives the score last (build 448)")
check("renderMetrics(); renderDrivers(); renderLB();" in _pg,
      "fused_score: changing the filter refreshes the driver rows' active state")
check("data-drvf=" in _pg and "onclick=" not in _pg[_pg.index("function renderDrivers()"):_pg.index("function renderAll()")].lower(),
      "fused_score: driver rows filter through data-drvf + a listener (no inline handlers)")

if __name__ == "__main__":
    print(f"\n{len(fails)} failure(s)")
    sys.exit(1 if fails else 0)
