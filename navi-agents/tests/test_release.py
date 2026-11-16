"""Regression tests for Release the Hounds (core/release.py + core/release_recipes.json)
and the server-side page cache (core/pagecache.py) that the console's HC block uses.
No navi, no network: the launcher dispatch is stubbed.
Run: python3 tests/test_release.py  (or pytest)."""
import atexit
import importlib
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
TMP = tempfile.mkdtemp(prefix="hounds-release-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")

from core import pagecache, release, snapcache  # noqa: E402

snapcache.CACHE_DIR = os.environ["NAVI_CACHE_DIR"]
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# ---------------------------------------------------------------- recipes match the console
rc = release.recipes()
pages = rc["pages"]
js = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
side = re.findall(r"'/agents/([a-z_]+)/page\.html'\]", js[js.index("const _SIDE_GROUPS"):js.index("function mountTopNav")])
order = [p["agent"] for p in pages]
# sidebar order — except On the Scent (insights): first in the sidebar, run LAST (it summarises the rest)
check(order[-1] == "insights" and order[:-1] == [a for a in side if a in order and a != "insights"],
      "recipes run in the left-sidebar order, with On the Scent last")
ins = pages[-1]
check(ins["kind"] == "snapshot" and ins["action"] == "scent"
      and "scent" in importlib.import_module("agents.insights.api").ACTIONS,
      "On the Scent runs as a snapshot-like step: its `scent` digest action")
for ex in ("acr", "contract", "argos", "email", "alert", "tagremoval", "c2", "custom_audit", "dashboard",
           "was_asset", "compliance_asset"):
    check(ex not in order, f"{ex} is left out of the release")
check(not any(a.startswith("ex_") for a in order), "search hounds are left out of the release")
for p in pages:
    if p["kind"] != "page":
        continue
    html = open(os.path.join(ROOT, "agents", p["agent"], "page.html"), encoding="utf-8").read()
    check(all(re.search(r'id="%s"[^>]*data-run|data-run[^>]*id="%s"' % (s, s), html) for s in p["steps"]),
          f"{p['agent']}: its run button(s) {p['steps']} exist with data-run")
    for q in p["requests"]:
        mod = importlib.import_module("agents.%s.api" % q["agent"])
        check(q["action"] in getattr(mod, "ACTIONS", {}), f"{p['agent']}: request {q['agent']}/{q['action']} is an API action")
        check(q["action"] in ("tag_plan",) or not re.match(r"^(apply|tag|tag_.+|send|delete|remove|set|save)$", q["action"]),
              f"{p['agent']}: {q['action']} is a read, never a write")

# the page-cache key matches console.js stable(): sorted keys, no spaces, unicode kept
check(release.req_key("a", "b", {"z": 1, "a": {"y": [1, "é"], "b": True}, "_nocache": True, "_run": "x"})
      == 'POST /api/a/b {"a":{"b":true,"y":[1,"é"]},"z":1}', "request key mirrors the browser's")

# ---------------------------------------------------------------- page cache
check(pagecache.put("/agents/eol/page.html", {"steps": [], "resp": {}, "at": 1})[0], "page cache stores an entry")
check(pagecache.get("/agents/eol/page.html")["at"] == 1, "…and reads it back")
check(not pagecache.put("/etc/passwd", {})[0] and pagecache.get("../x") is None, "only /agents/ page keys are accepted")
check(pagecache.delete("/agents/eol/page.html") and pagecache.get("/agents/eol/page.html") is None, "delete works")
_old = pagecache.MAX_BYTES
pagecache.MAX_BYTES = 100
pagecache.MAX_BYTES = _old
pagecache.put("/agents/eol/page.html", {"steps": [{"id": "run"}], "resp": {"k": 1}, "at": 5})
pagecache.MAX_BYTES = 100
r = pagecache.put("/agents/eol/page.html", {"resp": {"x": "y" * 500}})
check(not r[0] and "KB" in r[1] and "0.0" not in r[1], "oversized entries are refused (%s)" % r[1])
check(pagecache.get("/agents/eol/page.html") is None, "…and the stale smaller copy is dropped, not replayed")
pagecache.MAX_BYTES = _old
# small field edits patch the metadata, not the whole entry
pagecache.put("/agents/eol/page.html", {"steps": [{"id": "run"}], "resp": {"k": {"body": 1}}, "at": 10, "final": None})
gz = os.path.getmtime(pagecache._path("/agents/eol/page.html"))
time.sleep(0.02)
check(pagecache.patch("/agents/eol/page.html", {"final": {"q": {"v": "openssl"}}, "at": 10})[0]
      and os.path.getmtime(pagecache._path("/agents/eol/page.html")) == gz
      and pagecache.get("/agents/eol/page.html")["final"] == {"q": {"v": "openssl"}}
      and pagecache.get("/agents/eol/page.html")["resp"] == {"k": {"body": 1}}, "a field edit patches only the small fields")
check(not pagecache.patch("/agents/none/page.html", {"final": {}})[0], "patching a missing entry asks for a full save")
# tied to a navi.db
_dbid = pagecache.db_id
pagecache.db_id = lambda p=None: "/other/navi.db"
check(pagecache.get("/agents/eol/page.html") is None and not pagecache.listing(),
      "an entry computed from another navi.db isn't replayed or listed")
pagecache.db_id = _dbid
check(pagecache.get("/agents/eol/page.html") is not None and pagecache.listing(), "…but is for its own")
pagecache.delete("/agents/eol/page.html")

# ---------------------------------------------------------------- a release, end to end (stubbed dispatch)
CALLS = []


def fake_dispatch(agent, action, payload):
    CALLS.append((agent, action, payload))
    if action == "snapshot":
        return {"ok": True, "result": None, "building": {"job_id": 999}}, 200
    if agent == "certificate":
        return {"ok": False, "error": "no such table: certs"}, 200
    time.sleep(0.01)
    return {"ok": True, "result": {"agent": agent, "action": action}}, 200


from core import launcher, jobq  # noqa: E402

launcher._dispatch = fake_dispatch
launcher.DISPATCH = {p["agent"]: {} for p in pages}
jobq.get = lambda jid: {"id": jid, "status": "done"}
release._auto_approve = lambda: False
release._vuln_rows = lambda: 600000
release.MIN_HIST_S = 0


def wait():
    for _ in range(400):
        if release.state().get("status") != "running":
            return release.state()
        time.sleep(0.02)
    return release.state()


pl = release.plan()
mi = {i["agent"]: i for i in pl["items"]}
check(not mi["mitre"]["run"] and not mi["cisakev"]["run"] and "download" in mi["mitre"]["note"],
      "catalog downloads not approved → MITRE / CISA KEV are skipped")
check(not mi["agentgroup"]["run"] and mi["eol"]["run"] and pl["total_s"] > 0, "live lists skip; others get an estimate")
st = release.start()
check(st["ok"] and release.start().get("already_running") in (True, None), "one release at a time")
s = wait()
check(s["status"] == "done", "the release finishes")
by = {i["agent"]: i for i in s["items"]}
check(by["certificate"]["status"] == "error" and "certs" in by["certificate"]["note"]
      and by["identity"]["status"] == "done", "one hound failing never stops the pack")
check(all(p.get("_nocache") for _, _, p in CALLS), "release reads bypass the short result cache")
check(not any(a in ("mitre", "cisakev") for a, _, _ in CALLS), "skipped hounds aren't called")
e = pagecache.get("/agents/identity/page.html")
check(e and e["steps"] == [{"id": "run", "inputs": {}}] and e["released"]["by"] == "release"
      and release.req_key("identity", "run", {}) in e["resp"], "a page hound's run is saved as its page entry")
check(pagecache.get("/agents/sla/page.html") is None and by["sla"]["status"] == "done",
      "a snapshot hound builds its snapshot (no page entry)")
check(json.load(open(release._hist_path()))["identity"]["sec"] >= 0, "measured times feed the next estimate")
check(next(i for i in release.plan()["items"] if i["agent"] == "eol")["basis"] == "last release",
      "…and the next plan uses them")
lst = release.last()
check(lst and lst.get("id") == s["id"] and lst.get("status") == "done"
      and {i["agent"]: i for i in lst["items"]}["certificate"]["status"] == "error",
      "the final release state is persisted (release_last.json) — a restart still knows who errored")
check(release.record() and release.record()["id"] == s["id"], "release.record() = the run for this navi.db")
check(next(i for i in s["items"] if i["agent"] == "insights")["status"] == "done"
      and [a for a, _, _ in CALLS][-1] == "insights", "On the Scent's digest step runs last")

# approved for this release only → MITRE runs and its replay also clicks ✓ Approve
CALLS.clear()
release.start(approve_downloads=True)
s = wait()
e = pagecache.get("/agents/mitre/page.html")
check(any(a == "mitre" for a, _, _ in CALLS) and e and [x["id"] for x in e["steps"]] == ["run", "approveBtn"]
      and e["steps"][1].get("optional"), "downloads approved → MITRE runs; the replay clicks ✓ Approve only if it shows")
check(release.req_key("mitre", "source", {}) in e["resp"], "…and its approval card's source read is saved too (no live call on open)")
ai = pagecache.get("/agents/ai/page.html")
check(ai and 'POST /api/ai/run {}' in ai["resp"], "the AI page's per-browser fp/allow are left out of its key")
check('data-cache-ignore="fp,allow"' in open(os.path.join(ROOT, "agents", "ai", "page.html"), encoding="utf-8").read(),
      "…matching the page's data-cache-ignore")

# a run the user made after the release started is never overwritten
release.MIN_HIST_S = 0


def user_run_first(agent, action, payload):
    if agent == "classify" and action == "run":
        pagecache.put("/agents/classify/page.html", {"at": pagecache.now_ms(), "title": "USER RUN", "steps": [],
                                                     "resp": {}})
    return fake_dispatch(agent, action, payload)


launcher._dispatch = user_run_first
release.start()
s = wait()
launcher._dispatch = fake_dispatch
check(pagecache.get("/agents/classify/page.html")["title"] == "USER RUN"
      and "newer run" in {i["agent"]: i for i in s["items"]}["classify"]["note"], "a newer user run is kept")

# history: cached / near-instant runs don't become the estimate
h0 = json.load(open(release._hist_path()))
release.MIN_HIST_S = 999
release.start()
wait()
check(json.load(open(release._hist_path())) == h0, "sub-threshold runs don't overwrite the measured history")
release.MIN_HIST_S = 0
release._save_history({"eol": {"sec": 2.0, "rows": 0}})
check(next(i for i in release.plan()["items"] if i["agent"] == "eol")["est_s"] >= 2.0 * 0 + 1.2,
      "a history entry with no row count falls back to max(history, first-run rate)")

# cancel stops before the next request
_orig = fake_dispatch


def slow(agent, action, payload):
    time.sleep(0.15)
    return _orig(agent, action, payload)


launcher._dispatch = slow
release.start()
time.sleep(0.2)
check(release.cancel(), "a running release can be cancelled")
s = wait()
check(s["status"] == "cancelled" and any(i["status"] == "cancelled" for i in s["items"])
      and not any(i["status"] in ("pending", "running") for i in s["items"]), "cancelled: nothing left pending")


# ---------------------------------------------------------------- build 466: pick hounds + preflight
CALLS.clear()
st = release.start(agents=["identity", "insights"])
s = wait()
by = {i["agent"]: i for i in s["items"]}
ran = {a for a, _, _ in CALLS}
check(st["ok"] and by["identity"]["status"] == "done" and by["eol"]["status"] == "skipped" and by["eol"]["note"] == "not selected"
      and "eol" not in ran and "identity" in ran, "release runs only the ticked hounds; the rest are 'not selected'")
check(release.start(agents=[]) == {"ok": False, "error": "no hound selected"}, "nothing ticked → refused")
from agents.hub import api as hub  # noqa: E402
o, code = hub.release_start({"confirm": True, "agents": "identity"})
check(code == 400, "release_start: agents must be a list")
_orig = release._has_rows
present = {"vulns", "assets", "certs", "software", "vuln_paths", "compliance", "fixed", "epss"}   # no WAS, no routes, no SLA
release._has_rows = lambda t, db_path=None: t in present
try:
    pf = {c["key"]: c for c in release.preflight(["was", "sla", "exproute", "asset_ownership", "attackpath", "compliance", "software"])}
finally:
    release._has_rows = _orig
check(not pf["was"]["ok"] and pf["was"]["level"] == "block" and pf["was"]["hounds"] == ["was"] and "#secTables" in pf["was"]["settings"],
      "preflight: no WAS apps → Arachne can't run (skip / go to Settings)")
check(not pf["sla"]["ok"] and "#secSla" in pf["sla"]["settings"] and pf["fixed"]["ok"], "preflight: no SLA policy → SLA can't run")
check(pf["routes_paths"]["ok"] and not pf["routes"]["ok"] and pf["routes"]["level"] == "warn" and "paths" not in pf,
      "preflight: paths but no routes → a warning for Exposure Routes / Ownership, not a block")
check(pf["compliance"]["ok"] and pf["software"]["ok"] and "certs" not in pf, "preflight lists only checks for the selected hounds")
release._has_rows = lambda t, db_path=None: t not in ("vuln_route", "vuln_paths")
try:
    pf2 = {c["key"]: c for c in release.preflight(["exproute"])}
finally:
    release._has_rows = _orig
check(not pf2["routes_paths"]["ok"] and pf2["routes_paths"]["level"] == "block" and "routes" not in pf2,
      "preflight: neither routes nor paths → one blocking check")
check("preflight" in release.plan(), "the release plan carries the preflight")
ix = open(os.path.join(ROOT, "web", "index.html"), encoding="utf-8").read()
check("data-pfskip" in ix and "Go to Settings →" in ix and "input[data-rel]" in ix and "agents})" in ix,
      "Release dialog: preflight (Skip / Go to Settings) + a checkbox per hound, sent as agents")
st_html = open(os.path.join(ROOT, "web", "settings.html"), encoding="utf-8").read()
check('id="relQuick"' in ix and "(i.est_s||0)<lim" in ix and "⏳" in ix,
      "Release dialog: 'Quick ones only' ticks hounds under a time limit; slow ones (≥15 min) are flagged ⏳")
check('id="secTables"' in st_html and 'id="secSla"' in st_html and 'id="secHx"' in st_html, "Settings has the preflight's anchors")


def test_release_regressions():
    assert not fails, "\n".join(fails)


if __name__ == "__main__":
    print(f"\n{len(fails)} failure(s)")
    sys.exit(1 if fails else 0)
