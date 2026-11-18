"""Regression tests — build 489: a tag filter on Asset Classification (Linnaeus).

  · Every action the page calls takes {tag_scope:{key, value}} and works over ONLY that tag's
    assets. Each asset's class / sub / owned / KEV / critical / EOL-OS is exactly its whole-
    estate value; only the population (and every count / % built from it) changes.
  · With no tag, every result is identical to the unscoped call (and to tag_scope {} / None).
  · A tag run's drillable rows live in their own result-store hound (classify_t_<hash>), so a
    tag run never prunes the estate's run, and a drill / "select all" of one scope can't read
    the other's run. The newest 5 tag scopes are kept.
  · A tag write from a tag view (every cohort kind) re-reads the tag's assets from navi.db and
    never touches an asset outside it — even when the browser sends outside uuids.
Run: python3 tests/test_scope_classify_489.py"""
import atexit
import json
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-489-classify-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
shutil.copy(os.path.join(ROOT, "sample_navi.db"), DB)
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
os.environ.pop("NAVI_ALLOW_WRITES", None)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# a few classification tags, some inside the scope tag and some outside, so classes vary
con = sqlite3.connect(DB)
TK, TV = "Owner", "VM Team"
scope_set = {r[0] for r in con.execute("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", (TK, TV))}
all_uuids = [r[0] for r in con.execute("SELECT uuid FROM assets ORDER BY uuid")]
inside = sorted(scope_set)[:6]
outside = [u for u in all_uuids if u not in scope_set][:6]
for i, u in enumerate(inside + outside):
    val = ("Class: Windows", "Device Type: Printer", "OS: Ubuntu")[i % 3]
    con.execute("INSERT INTO tags (asset_uuid, tag_key, tag_value) VALUES (?,?,?)", (u, "Asset Inventory", val))
# OS-ID (11936) fingerprints with a confidence, on both sides of the scope, for os_plan / glance
for i, u in enumerate(sorted(scope_set)[6:12] + outside[:3] + [u for u in all_uuids if u not in scope_set][6:9]):
    osn = ("Microsoft Windows Server 2019", "Linux Kernel 5.4 on Ubuntu 20.04", "Mac OS X 13")[i % 3]
    con.execute("INSERT INTO vulns (asset_uuid, plugin_id, plugin_name, output, severity) VALUES (?,?,?,?,?)",
                (u, "11936", "OS Identification", f"Remote operating system : {osn}\nConfidence level : {60 + i * 3}\n", "Info"))
con.commit()
con.close()
NT = len(scope_set)
check(NT >= 5 and outside, f"lab: {len(all_uuids)} assets · scope {TK} : {TV} ({NT} assets)")

# mock the navi write layer — never call real navi
from core import navi_cli  # noqa: E402

WROTE = []
navi_cli.tag_set = lambda *a, **k: (WROTE.append((a, list(k.get("uuids") or []))) or [{"ok": True, "job_id": len(WROTE)}])

from core import classify as C, topology as T, payload, launcher, tagscope  # noqa: E402
from agents.classify import api  # noqa: E402

S = {"tag_scope": {"key": TK, "value": TV}}


def sc(**kw):
    return dict(S, **kw)


def strip(o):
    o = json.loads(json.dumps(o, default=str))
    if isinstance(o, dict):
        o.pop("agent", None)
        r = o.get("result")
        if isinstance(r, dict):
            r.pop("drill", None)
    return o


# ── 1. whole estate unchanged ────────────────────────────────────────────────────────────────
base_cl = C.classify(glance=True)
check(C.classify(glance=True, scope=None) == base_cl, "classify(scope=None) is the unscoped classify")
for name, fn, p in (("run", api.run, {}), ("tree", api.tree, {"by": "class"}), ("tree subnet", api.tree, {"by": "subnet"}),
                    ("members", api.members, {"cls": "Unclassified"}), ("signals", api.signals, {}),
                    ("os_breakdown", api.os_breakdown, {}), ("os_plan", api.os_plan, {"prompt": "tag by OS over 50%"}),
                    ("assets", api.assets, {"cls": "Unclassified"})):
    a = strip(fn(dict(p))[0])
    b = strip(fn(dict(p, tag_scope=None))[0])
    pp = dict(p, tag_scope={})
    check(tagscope.check("classify", name.split()[0], pp) is None and "tag_scope" not in pp,
          f"{name}: tag_scope {{}} is dropped by the launcher (= whole estate)")
    c = strip(fn(pp)[0])
    check(a == b == c and (a.get("result") if isinstance(a.get("result"), dict) else a).get("scope") is None,
          f"{name}: no tag → identical result, no scope field")
o, _ = api.run({})
check(o["result"]["total"] == len(all_uuids) and o["result"]["drill"]["run"].startswith("classify-"),
      "estate run covers every asset, drill run filed under 'classify'")
ERUN = o["result"]["drill"]["run"]

# ── 2. scoped counts = hand count over the tag's assets; per-asset values identical ─────────
est_rows = {r["uuid"]: r for r in base_cl["assets"]}
scl = C.classify(glance=True, scope=(TK, TV))
check(scl["total"] == NT and {r["uuid"] for r in scl["assets"]} == scope_set, "scoped classify covers exactly the tag's assets")
check(all(r == est_rows[r["uuid"]] for r in scl["assets"]), "every asset's row (class, sub, owned, KEV, crit, EOL) equals its estate row")
hand = {}
for u in scope_set:
    hand[est_rows[u]["cls"]] = hand.get(est_rows[u]["cls"], 0) + 1
check({c["cls"]: c["count"] for c in scl["classes"]} == hand, "per-class counts = hand count over the tag's assets")
check(scl["unclassified"] == hand.get("Unclassified", 0) and scl["classified"] == NT - hand.get("Unclassified", 0),
      "classified / unclassified counted over the tag")
for k in ("kev", "critical", "owned"):
    check(sum(c[k] for c in scl["classes"]) == sum(1 for u in scope_set if est_rows[u][k]), f"{k} counted over the tag")
g = scl["glance"]
check(g["eol_os"] == sum(1 for u in scope_set if est_rows[u].get("eol_os")), "glance EOL OS counted over the tag")
conf = {r["uuid"]: r for r in C.os_confidence()}
check(g["os_fingerprinted"] == sum(1 for u in scope_set if u in conf), "glance OS fingerprints counted over the tag")
sconf = C.os_confidence(scope=(TK, TV))
check(all(r == conf[r["uuid"]] for r in sconf) and {r["uuid"] for r in sconf} == {u for u in conf if u in scope_set},
      "os_confidence scoped: the tag's assets, same OS + confidence")

o, _ = api.run(sc())
R = o["result"]
check(o["ok"] and R["total"] == NT and R["scope"]["label"] == f"{TK} : {TV}" and R["scope"]["assets"] == NT,
      "run (scoped): totals + scope block")
TRUN = R["drill"]["run"]
check(TRUN.startswith(api._TAG_PREFIX) and payload.STORE.run_info(ERUN, "classify") is not None,
      "a tag run is filed under its own hound and the estate's run survives")
check(payload.STORE.run_info(TRUN)["meta"].get("scope") == {"key": TK, "value": TV}, "the tag run records its scope")
check(api.AGENT.result == base_cl or api.AGENT.result.get("total") == len(all_uuids),
      "a tag run never replaces AGENT.result (the estate's)")
o, _ = api.run({"tag_scope": {"key": "nope", "value": "x"}})
check(not o["ok"] and "no assets carry" in o["error"], "an unknown tag is refused with how to fix it")

o, _ = api.drill(sc(run=TRUN, section="assets", filter=["cls:Unclassified"], limit=500))
rows = o.get("top") or (o.get("result") or {}).get("top") or []
check(rows and all(r["uuid"] in scope_set for r in rows), "drill (scoped): rows only from the tag")
o, _ = api.drill(sc(run=ERUN, section="assets", filter=["cls:Unclassified"]))
check(o.get("expired"), "drill: a tag view can't page the estate's run")
o, _ = api.drill({"run": TRUN, "section": "assets", "filter": ["cls:Unclassified"]})
check(o.get("expired"), "drill: the estate view can't page a tag's run")

o, _ = api.tree(sc(by="class"))
check(o["result"]["total"] == NT and o["result"]["root"]["value"] == NT and o["result"]["scope"]["assets"] == NT, "tree (scoped)")
check({c["name"]: c["value"] for c in o["result"]["root"]["children"]} == hand, "tree classes = hand count")
o, _ = api.members(sc(cls="Unclassified"))
check(o["count"] == hand.get("Unclassified", 0) and all(a["uuid"] in scope_set for a in o["assets"]), "members (scoped)")
em = {a["uuid"]: a for a in api.members({"cls": "Unclassified"})[0]["assets"]}
check(all(a == em[a["uuid"]] for a in o["assets"] if a["uuid"] in em), "members: per-asset rows identical")
o, _ = api.assets(sc(cls="Unclassified"))
check(o["count"] == hand.get("Unclassified", 0) and all(a["uuid"] in scope_set for a in o["assets"]), "assets (scoped)")

esig = C.os_signals()
hand_sig = {}
for c in esig["cohorts"]:
    n = sum(1 for u in c["uuids"] if u in scope_set)
    if n:
        hand_sig[(c["facet"], c["value"])] = n
o, _ = api.signals(sc())
check({(c["facet"], c["value"]): c["count"] for c in o["result"]["cohorts"]} == hand_sig and o["result"]["scope"],
      "signals (scoped): each cohort = the estate cohort ∩ the tag")
eosb = C.os_breakdown()
o, _ = api.os_breakdown(sc())
hand_osb = {f["family"]: sum(1 for u in f["uuids"] if u in scope_set) for f in eosb["families"]}
check({f["family"]: f["count"] for f in o["result"]["families"]} == {k: v for k, v in hand_osb.items() if v},
      "os_breakdown (scoped): each family = estate family ∩ the tag")
o, _ = api.os_plan(sc(prompt="tag all by OS over 0%"))
eplan, _ = api.os_plan({"prompt": "tag all by OS over 0%", "_with_uuids": True})
hand_plan = {c["value"]: sum(1 for u in c["uuids"] if u in scope_set) for c in eplan["cohorts"]}
check({c["value"]: c["count"] for c in o["cohorts"]} == {k: v for k, v in hand_plan.items() if v} and o["scope"],
      "os_plan (scoped): each cohort = estate cohort ∩ the tag")

# ── 3. the manifest covers every action the page calls ───────────────────────────────────────
import re  # noqa: E402

page = open(os.path.join(ROOT, "agents", "classify", "page.html"), encoding="utf-8").read()
called = set(re.findall(r"API\.post\('([a-z_]+)'", page)) | {"drill"}          # hDrill({api:API}) posts drill
man = json.load(open(os.path.join(ROOT, "agents", "classify", "manifest.json"), encoding="utf-8"))
ts = man.get("tag_scope") or {}
declared = set(ts.get("actions") or []) | set(ts.get("ignore") or [])
check(called and called <= declared, f"every page-called action is declared: {sorted(called)}")
check(set(ts.get("actions") or []) <= set(api.ACTIONS), "every scoped action exists")
check(not re.search(r"\bfetch\(\s*['\"]/api/agents/classify", page), "no raw fetch() to its own api (would skip the scope)")
check("mountTagScope({agent:'classify'" in page, "the page mounts the tag filter bar")
check(page.count("tagScopeNote()") >= 5 and len(re.findall(r"confirm\(", page)) == page.count("tagScopeNote()"),
      "every confirm dialog names the scope")
for a in ts["actions"]:
    p = sc()
    check(tagscope.check("classify", a, p) is None and p["tag_scope"] == {"key": TK, "value": TV}, f"launcher accepts scoped {a}")
p = sc()
check(tagscope.check("classify", "nosuch", p) is not None, "launcher refuses a scoped undeclared action")

# ── 4. scoped writes stay inside the tag (recomputed server-side) ────────────────────────────
o, _ = api.tag(sc(cls="Windows", facet="Class", value="Windows"))
check(not o["ok"] and not WROTE, "tag without confirm: refused, nothing written")


def wrote_last():
    return set(WROTE[-1][1]) if WROTE else set()


SIG0 = next((c for c in esig["cohorts"] if set(c["uuids"]) & scope_set and set(c["uuids"]) - scope_set), esig["cohorts"][0])
cases = [
    ("path cls", {"facet": "Class", "value": "Unclassified", "cls": "Unclassified"}),
    ("subnet path", {"facet": "Subnet", "value": "x", "subnet": est_rows[sorted(scope_set)[0]]["ip"].rsplit(".", 1)[0] + ".0/24"
                     if est_rows[sorted(scope_set)[0]]["ip"] else "unknown"}),
    ("os", {"facet": "OS", "value": "w", "os": {"family": (eosb["families"] or [{"family": "Linux"}])[0]["family"]}}),
    ("sig", {"facet": "Device Type", "value": "s", "sig": {"facet": SIG0["facet"], "value": SIG0["value"]}}),
    ("plan", {"facet": "OS", "value": "p", "plan": {"prompt": "tag all by OS over 0%", "value": eplan["cohorts"][0]["value"]}}),
    ("set", {"facet": "Device Type", "value": "x", "set": {"run": TRUN, "cls": "Unclassified", "q": ""}}),
    ("browser uuids", {"facet": "Device Type", "value": "x", "uuids": sorted(scope_set)[:2] + outside[:3]}),
]
for name, body in cases:
    n0 = len(WROTE)
    o, _ = api.tag(sc(confirm=True, **body))
    got = wrote_last() if len(WROTE) > n0 else set()
    if o["ok"]:
        check(got and got <= scope_set and o["asset_count"] == len(got) and o["scope"]["assets"] == NT,
              f"tag ({name}) from a tag view: {len(got)} asset(s), all inside the tag")
    else:
        check(len(WROTE) == n0 and "among the assets tagged" in o.get("error", ""), f"tag ({name}): nothing in the tag → nothing written")
o, _ = api.tag(sc(confirm=True, facet="Device Type", value="x", uuids=outside[:3]))
check(not o["ok"] and "among the assets tagged" in o["error"], "browser uuids all outside the tag → refused, nothing written")
o, _ = api.tag(sc(confirm=True, facet="Device Type", value="x", set={"run": ERUN, "cls": "Unclassified"}))
check(not o["ok"] and o.get("expired"), "select-all of the estate's run from a tag view → refused")
n0 = len(WROTE)
o, _ = api.tag({"confirm": True, "facet": "Class", "value": "Unclassified", "cls": "Unclassified"})
check(o["ok"] and len(wrote_last()) == sum(1 for r in base_cl["assets"] if r["cls"] == "Unclassified") and "scope" not in o,
      "the same write with no tag covers the whole estate's class (unchanged)")
check(all(a[0][0] == "Asset Inventory" for a in WROTE), "every write is the add-only Asset Inventory tag")

# ── 5. caches keep scoped and estate apart ───────────────────────────────────────────────────
for i in range(api.TAG_RUNS + 3):
    payload.STORE.begin(api._hound(("k", str(i)))).close()
    api._prune_tag_runs()
check(payload.STORE.run_info(ERUN, "classify") is not None, "many tag runs never evict the estate's run")
con = payload.STORE._connect()
hs = {r[0] for r in con.execute("SELECT DISTINCT hound FROM runs WHERE substr(hound,1,11)='classify_t_'")}
con.close()
check(len(hs) == api.TAG_RUNS, f"the newest {api.TAG_RUNS} tag scopes keep their runs")
check(api._hound((TK, TV)) != api._hound((TK, TV + " ")) and api._hound((TK, TV)) == api._hound((TK, TV)),
      "each tag has its own, stable run store name")
k1 = launcher._cache_key("classify", "run", {})
k2 = launcher._cache_key("classify", "run", sc())
check(k1 != k2, "the read cache keys scoped and estate runs apart")

print("\n%d failure(s)" % len(fails) if fails else "\nALL PASS")
sys.exit(1 if fails else 0)
