"""Regression tests — build 484: a hound page shows background work, and keeps its last run.

  · /api/hub/bg_status tells a hound page whether Release the Hounds (a ▶ release or its daily
    schedule) has it queued / running, or an AI Contract cycle is running its discovery. The
    page shows a bar with the elapsed time, holds ▶ Run during a Release, and reloads into the
    released result when the hound finishes.
  · The server page cache never prunes a hound's own page; only per-target variants are capped.
    The browser no longer drops a run after 24 h — it shows its age and date instead.
Run: python3 tests/test_bg_484.py"""
import atexit
import os
import shutil
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-484-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ.update({"NAVI_DB_PATH": os.path.join(TMP, "navi.db"), "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from agents.hub import api as hub  # noqa: E402
from core import contract, launcher, pagecache, release  # noqa: E402

# ── 1. Release: queued → running → finished ──────────────────────────────────
t0 = time.time()
with release._LOCK:
    release._STATE.clear()
    release._STATE.update({"id": "R1", "status": "running", "started": t0 - 30, "items": [
        {"agent": "eol", "label": "EOL / Unsupported", "status": "running", "started": t0 - 10},
        {"agent": "cisakev", "label": "CISA KEV", "status": "pending"},
        {"agent": "identity", "label": "Identity", "status": "pending"},
        {"agent": "ai", "label": "AI Inventory", "status": "skipped"}]})
o, code = hub.bg_status({"agent": "identity"})
r = o.get("release") or {}
check(code == 200 and r.get("status") == "pending" and r.get("ahead") == 2 and r.get("now") == ["EOL / Unsupported"]
      and r.get("id") == "R1" and abs(r.get("release_started") - (t0 - 30)) < 1,
      "queued: 2 hounds ahead, what's running now, the release's start time")
release._STATE["items"][0]["status"] = "done"
release._STATE["items"][1]["status"] = "done"
release._STATE["items"][2].update(status="running", started=t0)
r = hub.bg_status({"agent": "identity"})[0].get("release") or {}
check(r.get("status") == "running" and r.get("ahead") == 0 and r.get("started") == t0, "running: its own start time")
release._STATE["items"][2].update(status="done", finished=time.time())
o = hub.bg_status({"agent": "identity"})[0]
check(o.get("release") is None and (o.get("item") or {}).get("status") == "done" and o["item"]["id"] == "R1",
      "finished (release still running others): no bar, and the item says done for the page to reload")
check(hub.bg_status({"agent": "ai"})[0].get("release") is None, "a skipped hound shows no bar")
check(hub.bg_status({"agent": "fused_score"})[0].get("release") is None, "a hound not in the release shows no bar")
release._STATE["status"] = "done"
check(hub.bg_status({"agent": "identity"})[0].get("release") is None, "release done: no bar")

# ── 2. AI Contract discovery ─────────────────────────────────────────────────
gate = threading.Event()
real = contract._ADAPTERS.get("identity")
contract._ADAPTERS["identity"] = lambda cfg: (gate.wait(5), [])[1]
th = threading.Thread(target=lambda: contract._candidates_ex("identity"))
th.start()
time.sleep(0.2)
check((hub.bg_status({"agent": "identity"})[0].get("contract") or {}).get("started"),
      "Contract cycle running Janus's discovery → the Janus page is told")
check(hub.bg_status({"agent": "eol"})[0].get("contract") is None, "… and no other hound's page")
gate.set()
th.join()
check(hub.bg_status({"agent": "identity"})[0].get("contract") is None, "cleared when the discovery ends")
contract._ADAPTERS["identity"] = lambda cfg: 1 / 0
contract._candidates_ex("identity")
check(contract.active() == {}, "cleared after a failing discovery too")
contract._ADAPTERS["identity"] = real
check("bg_status" in launcher._LIVE and ("hub", "bg_status") in launcher._OPEN_ACTIONS,
      "bg_status is a live read (never cached, never a counted run)")

# ── 3. the server page cache never prunes a hound's own page ─────────────────
pagecache.MAX_PAGES = 3
for i in range(8):
    pagecache.put("/agents/h%d/page.html" % i, {"at": i, "steps": [], "resp": {}})
for i in range(8):
    pagecache.put("/agents/argos/page.html?target=u%d" % i, {"at": i, "steps": [], "resp": {}})
keys = {x["key"] for x in pagecache.listing()}
check(all("/agents/h%d/page.html" % i in keys for i in range(8)), "8 hound pages kept with MAX_PAGES=3 — never pruned")
check(sum(1 for k in keys if "?target=" in k) == 3, "per-target variants are capped at MAX_PAGES")

# ── 4. the browser side ──────────────────────────────────────────────────────
js = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
check("return Infinity; })();" in js and "let h=24" not in js, "no 24 h cutoff unless a browser opts in")
check("over a day old" in js and "toLocaleTimeString" in js, "the restored run shows its age, date and time")
check("/api/hub/bg_status" in js and "Release the Hounds is running" in js and "is queued in Release the Hounds" in js
      and "location.reload()" in js and "AI Contract is running this hound" in js,
      "the activity bar: queued / running / Contract, then loads the result")

print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
