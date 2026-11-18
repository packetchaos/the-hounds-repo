"""Regression tests — build 489: Pythia (AI Inventory) by tag.

  · A scoped run (tag_scope {key, value}) finds only the AI assets that carry the tag; every
    per-asset value (role, frameworks, exposure, risk, egress, ATLAS, ACR, under-rated) is the
    whole-estate value, and the "% of estate" denominator is the tag's asset count.
  · With no scope every result is what it was (same scan, same response shape, no "scope" key).
  · Tag-view runs live in the result store under "ai_tag", kept per tag, so they never evict the
    estate's run; drill / counts / writes refuse a run of another view.
  · Scoped writes (tag, tag_underrated, tag_atlas) re-read the tag's members from navi.db and
    never touch an asset outside it, even when a uuid list is supplied; acr_roles (navi sets ACR
    by tag) is refused for a role whose AI ACR Raise tag reaches outside the scope.
  · Every action the page calls is declared in the manifest's tag_scope; `apply` is refused.
navi writes are monkeypatched: nothing is queued or sent.
Run: python3 tests/test_scope_ai_489.py"""
import atexit
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
TMP = tempfile.mkdtemp(prefix="hounds-ai-489-")
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


# ── fixture: more AI on the sample copy, and a tag that holds some of it ─────────────────────
TK, TV = "Scope Test", "Half"
c = sqlite3.connect(DB)
existing_ai = [r[0] for r in c.execute(
    "SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_family LIKE '%Artificial Intelligence%' ORDER BY 1")]
others = [r[0] for r in c.execute("SELECT uuid FROM assets WHERE uuid NOT IN (%s) ORDER BY uuid LIMIT 8"
                                  % ",".join("?" * len(existing_ai)), existing_ai)]
A = others[:5]           # get AI software below
N = others[5:8]          # stay non-AI
for u, sw in zip(A, ["chromadb 0.4.22", "pytorch 2.2.0", "openai 1.12.0 (python package)",
                     "transformers 4.38", "jupyterlab 4.0.1"]):
    c.execute("INSERT INTO software(asset_uuid, software_string) VALUES (?,?)", (u, sw))
for u, acr in zip(A, [3, 9, 2, 4, 1]):
    c.execute("UPDATE assets SET acr=? WHERE uuid=?", (acr, u))
IN_TAG = [A[0], A[1], A[2], existing_ai[0], N[0], N[1]]
for u in IN_TAG:
    c.execute("INSERT INTO tags(asset_uuid, tag_key, tag_value) VALUES (?,?,?)", (u, TK, TV))
c.commit()
c.close()

from core import ai_assets, navi_cli, payload, tagscope  # noqa: E402
from agents.ai import api  # noqa: E402

# ── 1. the scan ──────────────────────────────────────────────────────────────────────────────
est = ai_assets.scan()
est_by = {x["asset_uuid"]: x for x in est["assets"]}
check(set(A) <= set(est_by) and not (set(N) & set(est_by)), "fixture: the estate finds the added AI assets")
check(json.dumps(ai_assets.scan(scope=None), sort_keys=True, default=str) == json.dumps(est, sort_keys=True, default=str)
      and json.dumps(ai_assets.scan(scope=(None, None)), sort_keys=True, default=str)
      == json.dumps(est, sort_keys=True, default=str), "scan with no scope = the estate scan, exactly")
tagged = tagscope.uuids(TK, TV)
expect = {u for u in est_by if u in tagged}             # hand count: estate AI assets carrying the tag
check(expect == {A[0], A[1], A[2], existing_ai[0]}, "hand count: 4 AI assets carry the tag")
sc = ai_assets.scan(scope=(TK, TV))
sc_by = {x["asset_uuid"]: x for x in sc["assets"]}
check(set(sc_by) == expect and sc["asset_count"] == len(expect), "scoped scan = exactly the tag's AI assets")
check(all(json.dumps(sc_by[u], sort_keys=True, default=str) == json.dumps(est_by[u], sort_keys=True, default=str)
          for u in expect), "every per-asset value (role, evidence, risk, egress, ATLAS) equals the estate's")
check(sc["byRole"] == {r: sum(1 for u in expect if est_by[u]["role"] == r) for r in sc["byRole"]}
      and sum(sc["byRole"].values()) == len(expect), "scoped byRole counts the tag's assets only")
check(sc["kevCount"] == sum(1 for u in expect if est_by[u]["risk"]["kev"])
      and sc["shadowCount"] == sum(1 for u in expect if any(not e["sanctioned"] for e in est_by[u]["egress"])),
      "scoped KEV / shadow counts = hand counts over the tag")
check(ai_assets.scan(scope=("no such key", "x"))["asset_count"] == 0, "an unknown tag scopes to nothing")

# ── 2. the API run ───────────────────────────────────────────────────────────────────────────
o_est, code = api.run({})
check(code == 200 and o_est["ok"] and "scope" not in o_est and "scope" not in o_est["result"],
      "estate run: ok, no scope key anywhere (response shape unchanged)")
o_est2, _ = api.run({"tag_scope": None})
strip = lambda o: json.dumps({k: v for k, v in o.items() if k not in ("drill", "meta")} | {
    "result": {k: v for k, v in o["result"].items() if k != "agent"}}, sort_keys=True, default=str)
check(strip(o_est) == strip(o_est2), "a run with tag_scope=None is the estate run")
RUN_E = o_est["drill"]["run"]
check(RUN_E.startswith("ai-"), "the estate run is stored under 'ai'")
n_assets = sqlite3.connect(DB).execute("SELECT COUNT(*) FROM assets").fetchone()[0]
check(o_est["summary"]["estate"] == n_assets, "estate denominator = every asset in navi.db")

o_t, code = api.run({"tag_scope": {"key": TK, "value": TV}})
RUN_T = o_t["drill"]["run"]
check(code == 200 and o_t["ok"] and RUN_T.startswith("ai_tag-"), "scoped run is stored under 'ai_tag'")
check(o_t["scope"] == {"key": TK, "value": TV, "label": f"{TK} : {TV}", "assets": len(IN_TAG)}
      and o_t["result"]["scope"] == o_t["scope"], "scoped run says its scope (with the tag's asset count)")
m = o_t["summary"]
check(m["estate"] == len(IN_TAG) and o_t["result"]["asset_count"] == len(expect)
      and m["ai_pct"] == round(100.0 * len(expect) / len(IN_TAG), 1), "'% of estate' becomes % of the tag's assets")
rows, _ = api.drill({"run": RUN_T, "section": "assets", "limit": 200, "tag_scope": {"key": TK, "value": TV}})
check(rows["ok"] and {r["asset_uuid"] for r in rows["top"]} == expect, "scoped drill lists the tag's AI assets only")
erows, _ = api.drill({"run": RUN_E, "section": "assets", "limit": 200})
eb = {r["asset_uuid"]: r for r in erows["top"]}
check(all(json.dumps(r, sort_keys=True, default=str) == json.dumps(eb[r["asset_uuid"]], sort_keys=True, default=str)
          for r in rows["top"]), "drill rows (incl. ACR, under-rated, ai_tags) are identical to the estate's")
check(m["underrated"] == sum(1 for r in rows["top"] if r["underrated"]), "under-rated counted over the tag")

# a run of another view is refused
x, _ = api.drill({"run": RUN_E, "section": "assets", "tag_scope": {"key": TK, "value": TV}})
check(x.get("expired") and not x["ok"], "a tag view can't page the estate's run")
x, _ = api.drill({"run": RUN_T, "section": "assets"})
check(x.get("expired") and not x["ok"], "the estate can't page a tag view's run")
x, _ = api.drill({"run": RUN_T, "section": "assets", "tag_scope": {"key": TK, "value": "Other"}})
check(x.get("expired"), "another tag can't page this tag's run")
x, _ = api.counts({"run": RUN_T, "filter": [], "tag_scope": {"key": TK, "value": TV}})
check(x["ok"] and x["total"] == len(expect), "scoped counts = the tag's AI assets")
x, _ = api.counts({"run": RUN_T, "filter": []})
check(x.get("expired"), "unscoped counts refuse a tag run")

# ── 3. own store: tag runs never evict the estate's; kept per tag ────────────────────────────
for _ in range(3):
    api.run({"tag_scope": {"key": TK, "value": TV}})
check(payload.STORE.run_info(RUN_E, "ai") is not None, "several tag runs later, the estate's run is still there")
tag_runs = payload.STORE.runs("ai_tag")
check(len(tag_runs) == payload.KEEP_RUNS, "one tag keeps its newest KEEP_RUNS runs, not more")
for i in range(7):
    c = sqlite3.connect(DB)
    c.execute("INSERT INTO tags(asset_uuid, tag_key, tag_value) VALUES (?,?,?)", (A[0], "Many", f"v{i}"))
    c.commit()
    c.close()
    api.run({"tag_scope": {"key": "Many", "value": f"v{i}"}})
sc_kept = {(r["meta"]["scope"]["key"], r["meta"]["scope"]["value"]) for r in payload.STORE.runs("ai_tag")}
check(len(sc_kept) == tagscope.MAX_TAGS and ("Many", "v6") in sc_kept and (TK, TV) not in sc_kept,
      "tag runs are kept for the 5 most recent tags")
check(payload.STORE.run_info(RUN_E, "ai") is not None, "…and the estate's run is untouched")
api.run({})
api.run({})
check(all(r["run"].startswith("ai_tag-") for r in payload.STORE.runs("ai_tag")) and len(payload.STORE.runs("ai")) == payload.KEEP_RUNS,
      "estate runs keep their own KEEP_RUNS, unaffected by tag runs")

# ── 4. scoped writes stay inside the tag ────────────────────────────────────────────────────
o_t, _ = api.run({"tag_scope": {"key": TK, "value": TV}})
RUN_T = o_t["drill"]["run"]
o_est, _ = api.run({})
RUN_E = o_est["drill"]["run"]
calls, acr_calls = [], []
_r1, _r2, _r3 = navi_cli.tag_uuids_batched, navi_cli.tag_capped, navi_cli.acr


def fake_batched(category, value, uuids, agent="", **kw):
    calls.append({"fn": "batched", "category": category, "value": value, "uuids": list(uuids), "remove": False})
    return [{"job_id": len(calls), "ok": True}]


def fake_capped(category, value, uuids=None, query="", remove=False, agent="", **kw):
    calls.append({"fn": "capped", "category": category, "value": value, "uuids": list(uuids or []),
                  "query": query, "remove": remove})
    return [{"job_id": len(calls), "ok": True}]


def fake_acr(category, value, score, mod="set", note=None, reasons=None, agent="acr"):
    acr_calls.append((category, value, score))
    return {"ok": True}


navi_cli.tag_uuids_batched, navi_cli.tag_capped, navi_cli.acr = fake_batched, fake_capped, fake_acr
S = {"tag_scope": {"key": TK, "value": TV}}
try:
    x, _ = api.tag({"category": "AI", "value": "Present", "run": RUN_T, "key": {"all": True}, **S})
    check(not x["ok"] and not calls, "scoped tag still needs confirm=true")
    x, _ = api.tag({"category": "AI", "value": "Present", "run": RUN_T, "key": {"all": True}, "confirm": True, **S})
    check(x["ok"] and set(calls[-1]["uuids"]) == expect and x["scope"]["label"] == f"{TK} : {TV}",
          "Tag all from the tag view tags the tag's AI assets only")
    n = len(calls)
    x, _ = api.tag({"category": "AI", "value": "Present", "run": RUN_E, "key": {"all": True}, "confirm": True, **S})
    check(not x["ok"] and len(calls) == n, "a tag view can't write from the estate's run")
    x, _ = api.tag({"category": "AI", "value": "Present", "uuids": [A[3], A[4], N[2], A[0]], "confirm": True, **S})
    check(x["ok"] and calls[-1]["uuids"] == [A[0]], "a supplied uuid list is cut to the tag's members (re-read from navi.db)")
    n = len(calls)
    x, _ = api.tag({"category": "AI", "value": "Present", "uuids": [A[3], A[4]], "confirm": True, **S})
    check(not x["ok"] and len(calls) == n, "uuids all outside the tag: nothing queued")
    # a row of the run whose tag is removed in navi.db after the run is not written
    c = sqlite3.connect(DB)
    c.execute("DELETE FROM tags WHERE asset_uuid=? AND tag_key=? AND tag_value=?", (A[2], TK, TV))
    c.commit()
    c.close()
    x, _ = api.tag({"category": "AI", "value": "Present", "run": RUN_T, "key": {"all": True}, "confirm": True, **S})
    check(x["ok"] and A[2] not in calls[-1]["uuids"] and set(calls[-1]["uuids"]) == expect - {A[2]},
          "the set is re-read at write time: an asset that left the tag is not written")
    c = sqlite3.connect(DB)
    c.execute("INSERT INTO tags(asset_uuid, tag_key, tag_value) VALUES (?,?,?)", (A[2], TK, TV))
    c.commit()
    c.close()
    # under-rated: A[0] (ACR 3) and A[2] (ACR 2) are in the tag; A[3]/A[4] are under-rated outside it
    under_out = [r for r in rows["top"] if r["underrated"]]
    for role in sorted({r["role"] for r in under_out}):
        x, _ = api.tag_underrated({"role": role, "run": RUN_T, "confirm": True, **S})
        if x.get("ok"):
            check(set(calls[-1]["uuids"]) <= expect, f"tag_underrated ({role}) stays inside the tag")
    x, _ = api.tag_underrated({"role": est_by[A[3]]["role"], "uuids": [A[3], A[4]], "confirm": True, **S})
    check(not x.get("ok"), "tag_underrated: uuids outside the tag are dropped")
    # ATLAS: from the stored run, and from a rescan
    x, _ = api.tag_atlas({"key": "tech:AML.T0047", "run": RUN_T, "confirm": True, **S})
    check(x["ok"] and set(calls[-1]["uuids"]) == expect and calls[-1]["remove"] is False,
          "tag_atlas from the tag view: the tag's AI assets, remove=False")
    x, _ = api.tag_atlas({"key": "tech:AML.T0047", "confirm": True, **S})
    check(x["ok"] and set(calls[-1]["uuids"]) == expect, "tag_atlas rescan is scoped too")
    x, _ = api.tag_atlas({"key": "tech:AML.T0047", "run": RUN_E, "confirm": True})
    check(x["ok"] and set(calls[-1]["uuids"]) == set(est_by), "estate tag_atlas unchanged (all AI assets)")
    check(all(c_.get("remove") is False for c_ in calls), "no write removes tags")
    # ACR by tag: refused when AI ACR Raise : <role> reaches outside the scope
    role = est_by[A[0]]["role"]
    c = sqlite3.connect(DB)
    c.execute("INSERT INTO tags(asset_uuid, tag_key, tag_value) VALUES (?,?,?)", (A[0], "AI ACR Raise", role))
    c.commit()
    c.close()
    x, _ = api.acr_roles({"roles": [role], "confirm": True, **S})
    check(x["applied"] == 1 and acr_calls == [("AI ACR Raise", role, ai_assets.ROLE_ACR[role])],
          "acr_roles from the tag view: sent when every AI ACR Raise asset is in the tag")
    c = sqlite3.connect(DB)
    c.execute("INSERT INTO tags(asset_uuid, tag_key, tag_value) VALUES (?,?,?)", (A[3], "AI ACR Raise", role))
    c.commit()
    c.close()
    x, _ = api.acr_roles({"roles": [role], "confirm": True, **S})
    check(not x["ok"] and len(acr_calls) == 1 and x["results"][0]["outside"] == 1
          and "outside" in x["error"], "acr_roles refused when the ACR tag holds an asset outside the scope")
    x, _ = api.acr_roles({"roles": [role], "confirm": True})
    check(x["ok"] and len(acr_calls) == 2, "estate acr_roles unchanged")
finally:
    navi_cli.tag_uuids_batched, navi_cli.tag_capped, navi_cli.acr = _r1, _r2, _r3

# ── 5. the manifest contract ─────────────────────────────────────────────────────────────────
man = json.load(open(os.path.join(ROOT, "agents", "ai", "manifest.json")))
pol = man["tag_scope"]
declared = set(pol["actions"]) | set(pol["ignore"])
page = open(os.path.join(ROOT, "agents", "ai", "page.html"), encoding="utf-8").read()
called = set(re.findall(r"API\.post\('([a-z_]+)'", page)) | ({"drill"} if "hDrill(" in page else set())
check(called and called <= declared, f"every page-called action is declared: {sorted(called)}")
check(set(pol["actions"]) <= set(api.ACTIONS), "every declared action exists")
check("mountTagScope({agent:'ai'" in page, "the page mounts the tag filter")
for a_ in pol["actions"]:
    p_ = {"tag_scope": {"key": TK, "value": TV}}
    check(tagscope.check("ai", a_, p_) is None and p_["tag_scope"]["key"] == TK, f"launcher lets scoped '{a_}' through")
r_ = tagscope.check("ai", "apply", {"tag_scope": {"key": TK, "value": TV}})
check(r_ is not None and r_[1] == 400, "launcher refuses a scoped 'apply' (legacy whole-family shortcut)")


def test_scope_ai_489():
    assert not fails, "\n".join(fails)


if __name__ == "__main__":
    print(f"\n{len(fails)} failure(s)")
    sys.exit(1 if fails else 0)
