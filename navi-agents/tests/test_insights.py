"""Regression tests for On the Scent (Sphinx) — the digest built from Release the Hounds
(core/insights.scent / scent_digest, agents/insights/api.py `scent`).

A real release runs in-process over a copy of /home/claude/act/navi_test.db (or the repo's
sample_navi.db) with the catalog downloads NOT approved (MITRE / CISA KEV skipped → a
partial picture). Then: empty state, peek never builds, no navi.db query while building,
numbers equal the owning hounds' cached entries, every link resolves, stale / partial /
outdated states, compact size. Run: python3 tests/test_insights.py  (or pytest)."""
import atexit
import json
import os
import re
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-scent-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
SRC = "/home/claude/act/navi_test.db"
if not os.path.exists(SRC):
    SRC = os.path.join(ROOT, "sample_navi.db")
DB = os.path.join(TMP, "navi.db")
shutil.copy(SRC, DB)
os.environ["NAVI_DB_PATH"] = DB
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ.setdefault("NAVI_HISTORY_DIR", os.path.join(TMP, "hist"))
os.environ.setdefault("NAVI_TAGLOG_DB", os.path.join(TMP, "tl.db"))
os.environ.setdefault("HOUNDS_CONFIG", os.path.join(TMP, "cfg.json"))

from core import db, insights, launcher, pagecache, release, snapcache  # noqa: E402

snapcache.CACHE_DIR = os.environ["NAVI_CACHE_DIR"]
os.makedirs(snapcache.CACHE_DIR, exist_ok=True)
release._auto_approve = lambda: False
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def scent(p):
    body, status = launcher._dispatch("insights", "scent", dict(p, _nocache=True))
    return body.get("result") if isinstance(body, dict) else None


def wait():
    for _ in range(1500):
        if release.state().get("status") != "running":
            return release.state()
        time.sleep(0.1)
    return release.state()


def hrefs(o, out):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in ("href", "fix_href") and isinstance(v, str):
                out.append(v)
            else:
                hrefs(v, out)
    elif isinstance(o, list):
        for v in o:
            hrefs(v, out)
    return out


# ---------------------------------------------------------------- empty: no release yet
r = scent({"peek": True})
check(r and r["state"] == "none" and not r.get("glance"), "no release on this navi.db → state none, no board")
check(scent({}).get("state") == "none", "…and {} has nothing to summarise either")
check(not os.path.exists(insights.SCENT._path(insights.SCENT.key())), "…and nothing was stored")

# ---------------------------------------------------------------- a real release (downloads not approved)
release.start(approve_downloads=False)
st = wait()
check(st["status"] == "done", "release finishes (%s)" % st["status"])
by = {i["agent"]: i for i in st["items"]}
check(by["insights"]["status"] == "done", "On the Scent's digest step ran (last)")
check(release.last() and release.last()["id"] == st["id"], "final release state persisted to release_last.json")
check(by["fused_score"].get("snap") and by["fused_score"]["snap"].get("file", "").startswith("fused_"),
      "the release records which snapshot file Nemesis left")

D = scent({"peek": True})
check(D and D.get("glance") and D["state"] in ("ready", "partial"), "after a release the stored digest peeks (%s)" % D.get("state"))
cov = {c["agent"]: c for c in D["coverage"]}
check(cov["mitre"]["status"] == "skipped" and "download" in (cov["mitre"]["note"] or ""),
      "an unapproved download hound is 'skipped' with its reason")
check(D["state"] == "partial" and D["release"]["hounds_present"] < D["release"]["hounds_total"],
      "…so the picture is partial")
check(cov["eol"]["status"] == "fresh" and cov["fused_score"]["status"] == "fresh" and cov["agentgroup"]["status"] == "live",
      "released hounds are fresh; the live page is 'live'")
check("insights" not in cov, "On the Scent isn't listed as its own input")
size = len(json.dumps(D))
check(size < 64 * 1024, "digest is compact (%d bytes)" % size)
check(not D["outdated"], "freshly built → not outdated")

# numbers are the owning hound's own
e = pagecache.get("/agents/eol/page.html")
eolm = e["resp"][release.req_key("eol", "run", {})]["body"]["result"]["view"]["metrics"]
g = {c["l"]: c for grp in D["glance"] for c in grp["cards"]}
check(g["assets on EOL software"]["v"] == eolm["eol_assets"], "glance EOL == Charon's cached eol_assets")
fs = snapcache.Snapshots("fused")
fsnap = json.load(__import__("gzip").open(os.path.join(snapcache.CACHE_DIR, by["fused_score"]["snap"]["file"]), "rt"))
fk = fsnap["result"]["kpi"]
check(g["avg exposure score / 100"]["v"] == fk["avg"] and g["crown jewels (ACR ≥ 9)"]["v"] == fk["crown"],
      "glance avg / crown == the Nemesis snapshot (crown labelled with its ACR ≥ 9 rule)")
check(g["KEV-exploitable assets"]["v"] is None and "not in this release" in g["KEV-exploitable assets"]["u"],
      "a card whose hound isn't in the release shows — / 'not in this release'")
if fk.get("stack"):
    check([s["assets"] for s in D["stack"]] == fk["stack"] and D["cooccur"]["basis"].startswith("all "),
          "signal stack / overlap map come from Nemesis's whole-estate counts")
check(sum(s["assets"] for s in D["stack"]) == fk["assets"], "signal stack covers every asset")

# every link resolves to a real page (and section)
bad = []
for h in hrefs(D, []):
    if h.startswith("#"):
        continue
    path, _, frag = h.partition("#")
    f = os.path.join(ROOT, path.split("?")[0].lstrip("/"))
    if not (h.startswith("/agents/") or h.startswith("/web/")) or not os.path.exists(f):
        bad.append(h)
    elif frag and not re.search(r'id=["\']%s["\']' % re.escape(frag), open(f, encoding="utf-8").read()):
        bad.append(h)
check(not bad, "every click-through resolves to a real page/section %s" % bad[:5])

# ---------------------------------------------------------------- no navi.db access in the digest
_q, _s, _c = db.query, db.scalar, db.connect


def boom(*a, **k):
    raise AssertionError("navi.db queried")


db.query = db.scalar = db.connect = boom
try:
    P = scent({"peek": True})
    F = scent({"force": True})
    ok = True
except AssertionError:
    ok, P, F = False, None, None
db.query, db.scalar, db.connect = _q, _s, _c
check(ok and P and F and F.get("glance"), "peek and ↻ Rebuild never query navi.db (db.query/scalar/connect patched to raise)")
check(F and json.dumps(F["glance"]) == json.dumps(D["glance"]), "…and the rebuild gives the same numbers")

# peek never builds
os.remove(insights.SCENT._path(insights.SCENT.key()))
insights.SCENT._mem.clear()
pk = scent({"peek": True})
check(pk["state"] == "none" and pk["cached_hounds"] > 0 and not os.path.exists(insights.SCENT._path(insights.SCENT.key())),
      "peek with no stored digest doesn't build one (offers the cached hounds instead)")
scent({})
check(os.path.exists(insights.SCENT._path(insights.SCENT.key())), "{} builds it from the caches")

# outdated: a user re-runs one hound after the summary
time.sleep(0.01)
pagecache.put("/agents/classify/page.html", dict(pagecache.get("/agents/classify/page.html"), at=pagecache.now_ms(), released=None))
o = scent({"peek": True})
check(o["outdated"] and any(c["agent"] == "classify" for c in o["changed"])
      and {c["agent"]: c for c in o["coverage"]}["classify"]["status"] == "user",
      "a hound re-run after the summary → outdated, named, status 'your run'")
check(scent({}).get("outdated") is False, "{} rebuilds when inputs changed")

# partial: one entry gone
pagecache.delete("/agents/identity/page.html")
o = scent({"force": True})
check({c["agent"]: c for c in o["coverage"]}["identity"]["status"] == "missing" and o["state"] == "partial"
      and not any(f["agent"] == "identity" for f in o["footprint"]), "a missing entry → 'missing', its rows drop out")

# stale: navi.db changes after the release
time.sleep(0.02)
os.utime(DB, None)
with open(DB, "ab"):
    pass
os.utime(DB, (time.time() + 5, time.time() + 5))
o = scent({"peek": True})
check(o["state"] == "stale" and o["release"]["stale"] > 0, "navi.db touched after the release → stale (%s)" % o["state"])
check(o.get("glance"), "…and the stale picture still renders")

# legacy actions still dispatch
from agents.insights import api  # noqa: E402
check(set(api.ACTIONS) >= {"scent", "board", "run"}, "legacy board / run actions kept")


def test_insights_regressions():
    assert not fails, "\n".join(fails)


if __name__ == "__main__":
    print(f"\n{len(fails)} failure(s)")
    sys.exit(1 if fails else 0)
