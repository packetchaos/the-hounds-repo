"""Regression tests — build 489: a tag filter on Scan Evaluations (Chronos).

  · No tag_scope → every result is identical to the unscoped evaluation (whole estate unchanged).
  · With tag_scope {key, value} → only the tag's assets: counts equal a hand count over the tag,
    and every asset's own row (credential state from 19506 + the credential-status plugins,
    freshness, patch, scanner…) is identical to its whole-estate row.
  · Every action the page calls is declared in the manifest's tag_scope block.
  · Tag runs live in their own result-store name: a tag run never pushes the estate's stored
    rows out, a tag drill never reads the estate's run (or another tag's), and vice versa.
  · Tag writes from a tag view are recomputed on the server and stay inside the tag (navi's
    write layer is mocked; a browser uuid list is ignored).
Run: python3 tests/test_scope_scan_eval_489.py"""
import atexit
import copy
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-489-se-")
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


from core import payload, scan_eval, tagscope  # noqa: E402
from agents.scan_eval import api  # noqa: E402

con = sqlite3.connect(DB)
TK, TV, NT = con.execute("SELECT tag_key, tag_value, COUNT(DISTINCT asset_uuid) n FROM tags "
                         "GROUP BY 1,2 HAVING n>=3 ORDER BY n DESC LIMIT 1").fetchone()
TK2, TV2 = con.execute("SELECT tag_key, tag_value FROM tags WHERE NOT (tag_key=? AND tag_value=?) "
                       "GROUP BY 1,2 HAVING COUNT(DISTINCT asset_uuid)>=3 ORDER BY COUNT(DISTINCT asset_uuid) DESC LIMIT 1",
                       (TK, TV)).fetchone()
TAGGED = {r[0] for r in con.execute("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", (TK, TV))}
con.close()
SC = {"tag_scope": {"key": TK, "value": TV}}
print(f"scope {TK} : {TV} ({NT} assets)")


def strip(o):
    """A result without the volatile run id / build time (they differ on every run)."""
    o = copy.deepcopy(o)
    s = json.dumps(o, sort_keys=True, default=str)
    s = re.sub(r'scan_eval(_tag)?-[0-9a-f]{16}', 'RUN', s)
    s = re.sub(r'"next": "[^"]*"', '"next": "N"', s)
    s = re.sub(r'"(built_at|as_of|at|generated_at)": "[^"]*"', r'"\1": "T"', s)
    return s


# ── 1. whole estate unchanged ─────────────────────────────────────────────────
base = scan_eval.evaluate(all_rows=True)
again = scan_eval.evaluate(all_rows=True, scope=None)
check(json.dumps(base, sort_keys=True, default=str) == json.dumps(again, sort_keys=True, default=str),
      "evaluate(scope=None) is byte-identical to the unscoped evaluation")
check("scope" not in base, "a whole-estate result carries no scope")
check(scan_eval.evaluate(all_rows=True, scope=(None, None)) == base, "an empty scope is the whole estate")
o1, s1 = api.run({})
o2, s2 = api.run({"tag_scope": None})
check(s1 == s2 == 200 and o1["ok"] and strip(o1) == strip(o2), "run {} and run {tag_scope:null} give the same response")
check(o1["result"]["metrics"] == base["metrics"] and o1["result"]["scanners"] == base["scanners"],
      "run without a tag = the unscoped evaluation's metrics and scanners")
check(o1["drill"]["run"].startswith("scan_eval-"), "a whole-estate run is stored under scan_eval, as before")
ERUN = o2["drill"]["run"]

# ── 2. scoped counts = a hand count over the tag's assets ─────────────────────
sc = scan_eval.evaluate(all_rows=True, keep_uuids=True, scope=(TK, TV))
rows = {x["asset_uuid"]: x for x in sc["assets"]}
brow = {x["asset_uuid"]: x for x in base["assets"]}
check(set(rows) == TAGGED & set(brow), "the scoped population is exactly the tag's assets")
hand = [brow[u] for u in TAGGED if u in brow]
m = sc["metrics"]
check(m["assets"] == len(hand), "metrics.assets = hand count over the tag (%d)" % len(hand))
for s in scan_eval.STATUS_ORDER:
    check(m["status"][s] == sum(1 for x in hand if x["status"] == s), f"status '{s}' counted over the tag only")
check(m["credentialed"] == sum(1 for x in hand if x["cred"]), "credentialed (19506 yes / 141118 / 110095) counted over the tag")
check(m["blind"] == sum(1 for x in hand if x["status"] in ("failed", "insufficient", "intermittent", "uncredentialed")),
      "blind counted over the tag")
check(m["scanned"] == sum(1 for x in hand if x["fresh"] != "never"), "scanned counted over the tag")
check(m["patch_failed"] == sum(1 for x in hand if x["patch"] == "failed"), "patch failed counted over the tag")
check(m["crown_blind"] == len(sc["_sets"]["crown:blind"]) and sc["_sets"]["crown:blind"] <= TAGGED, "crown blind spots in the tag")
check(sc["credential"]["total_assets"] == len(TAGGED & set(brow))
      and all(a["asset_uuid"] in TAGGED for a in sc["credential"]["assets"]), "the 104410 coverage block is the tag's")
check(all(u in TAGGED for d in sc["_dim_uuids"].values() for s in d.values() for u in s),
      "scanner / policy / scan buckets only hold tagged assets")
check(sum(d["assets"] for d in sc["scanners"]) == sum(len(s) for s in sc["_dim_uuids"]["scanner"].values()),
      "scanner asset counts are over the tag")
check(sc.get("scope") == tagscope.describe(TK, TV) and sc["scope"]["assets"] == NT, "a scoped result says its scope")

# ── 3. per-asset values identical ─────────────────────────────────────────────
check(rows and all(rows[u] == brow[u] for u in rows), "every asset's row is identical to its whole-estate row (%d)" % len(rows))
o, _ = api.run(SC)
check(o["ok"] and o["drill"]["run"].startswith(api.TAG_STORE + "-") and o["result"]["assets_total"] == len(rows)
      and o["result"].get("scope", {}).get("label") == f"{TK} : {TV}", "run with a tag: stored under the tag store, with its scope")
TRUN = o["drill"]["run"]
ids = []
d, _ = api.drill(dict(SC, run=TRUN, section="assets", limit=200))
check(d["ok"] and {x["asset_uuid"] for x in d["top"]} == set(rows) and all(x == brow[x["asset_uuid"]] for x in d["top"]),
      "the tag drill pages exactly the tag's rows, each identical to the estate's")
d, _ = api.drill(dict(SC, run=TRUN, section="assets", filter=["f:blind"], limit=200))
check(d["ok"] and int(d["total"]["value"]) == m["blind"], "a filtered tag drill counts over the tag")
e, _ = api.export(dict(SC, run=TRUN))
check(e["ok"] and e["rows"] == len(rows), "the tag CSV has the tag's rows")

# ── 4. scoped and estate runs never cross ─────────────────────────────────────
d, _ = api.drill({"run": TRUN, "section": "assets"})
check(not d.get("ok") and d.get("expired"), "an estate drill can't read a tag run")
d, _ = api.drill(dict(SC, run=ERUN, section="assets"))
check(not d.get("ok") and d.get("expired"), "a tag drill can't read the estate run")
d, _ = api.drill({"tag_scope": {"key": TK2, "value": TV2}, "run": TRUN, "section": "assets"})
check(not d.get("ok"), "another tag can't read this tag's run")
e, _ = api.export({"tag_scope": {"key": TK2, "value": TV2}, "run": TRUN})
check(not e.get("ok"), "…nor export it")
e, _ = api.export(dict(SC, run=ERUN))
check(not e.get("ok"), "a tag export can't stream the estate run")
for i in range(api.TAG_KEEP + 2):
    api.run({"tag_scope": {"key": TK2 if i % 2 else TK, "value": TV2 if i % 2 else TV}})
check(payload.STORE.run_info(ERUN, "scan_eval") is not None, "many tag runs never evict the estate's stored run")
con = payload.STORE._connect()
n_tag = con.execute("SELECT COUNT(*) FROM runs WHERE hound=?", (api.TAG_STORE,)).fetchone()[0]
con.close()
check(n_tag == api.TAG_KEEP, "the tag store keeps %d tag runs" % api.TAG_KEEP)
o3, _ = api.run({})
check(payload.STORE.run_info(o3["drill"]["run"], "scan_eval") and payload.STORE.run_info(ERUN, "scan_eval"),
      "the estate store still keeps its own 2 runs")
o, _ = api.run({"tag_scope": {"key": "no such key", "value": "x"}})
check(not o["ok"] and "no assets carry the tag" in o["error"], "an unknown tag is refused with how to fix it")

# ── 5. every page-called action is declared ───────────────────────────────────
man = json.load(open(os.path.join(ROOT, "agents", "scan_eval", "manifest.json"), encoding="utf-8"))
pol = man.get("tag_scope") or {}
declared = set(pol.get("actions") or []) | set(pol.get("ignore") or [])
page = open(os.path.join(ROOT, "agents", "scan_eval", "page.html"), encoding="utf-8").read()
called = set(re.findall(r"API\.post\('([a-z_]+)'", page)) | ({"drill"} if "hDrill(" in page else set())
check(called and called <= declared, "every action the page calls is declared: %s" % sorted(called))
check(set(pol["actions"]) <= set(api.ACTIONS), "every declared action exists")
check("mountTagScope({agent:'scan_eval'" in page and page.index("mountTagScope(") > page.index("mountAgentHeader("),
      "the page mounts the tag filter after its header")
check(page.count("tagScopeNote()") >= 2, "both tag confirm dialogs name the scope")
check("fetch(" not in page, "no raw fetch() bypasses the scope")

# ── 6. scoped writes: recomputed server-side, inside the tag ──────────────────
sent = []
real = api.navi_cli.tag_set


def fake_tag_set(category, value, uuids=None, sql="", params=(), agent="", **kw):
    got = list(uuids or []) or api.navi_cli.collect_uuids(sql, params)
    sent.append((category, value, set(got)))
    return [{"ok": True, "queued": True, "job_id": len(sent)}]


api.navi_cli.tag_set = fake_tag_set
try:
    r, st = api.tag(dict(SC, key="status:uncredentialed"))
    check(st == 400 and not sent, "a tag write still needs confirm=true")
    for key in list(api.VALUES):
        sent.clear()
        est_v, est_uu, _ = api.tag_target(key)
        r, st = api.tag(dict(SC, key=key, confirm=True, uuids=["evil-uuid"]))
        want = {u for u in est_uu if u in TAGGED}
        if want:
            check(r.get("ok") and sent and sent[0][2] == want and sent[0][0] == "Scan Health" and sent[0][1] == est_v
                  and r.get("scope", {}).get("key") == TK,
                  f"tag {key} from the tag view: exactly the estate set ∩ the tag ({len(want)})")
        else:
            check(not sent and not r.get("ok") and "among the assets tagged" in r.get("error", ""),
                  f"tag {key} from the tag view: nothing in the tag → nothing sent")
    for kind, lst in (("scanner", sc["scanners"]), ("policy", sc["policies"]), ("scan", sc["scans"])):
        if not lst:
            continue
        sent.clear()
        name = lst[0]["key"]
        r, st = api.tag(dict(SC, key=kind, name=name, confirm=True))
        _v, est_uu, _ = api.tag_target(kind, name)
        check(r.get("ok") and sent and sent[0][2] == {u for u in est_uu if u in TAGGED} and sent[0][2] <= TAGGED
              and len(sent[0][2]) == lst[0]["assets"], f"tag {kind} '{name}' from the tag view: only its tagged assets")
    sent.clear()
    r, _ = api.tag({"key": "status:uncredentialed", "confirm": True})
    _v, est_uu, _ = api.tag_target("status:uncredentialed")
    check(r.get("ok") and sent[0][2] == set(est_uu) and "scope" not in r, "a whole-estate tag write is unchanged")
    check(not os.environ.get("NAVI_ALLOW_WRITES"), "writes stay gated (NAVI_ALLOW_WRITES unset)")
finally:
    api.navi_cli.tag_set = real

# ── 7. the launcher accepts every declared action, refuses others ─────────────
r = tagscope.check("scan_eval", "drill", dict(SC))
check(r is None, "launcher: drill with a scope is allowed")
r = tagscope.check("scan_eval", "nope", dict(SC))
check(r and r[1] == 400, "launcher: an undeclared action with a scope is refused")

print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
