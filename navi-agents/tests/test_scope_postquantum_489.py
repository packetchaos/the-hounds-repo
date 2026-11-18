"""Regression tests — build 489: Heimdall (postquantum) by tag.

  · With no tag the run, cert, transport and roadmap answers are exactly what they were.
  · With tag_scope {key, value} every count covers only the tag's assets, each asset keeps its
    whole-estate facts (priority score, broken certs, transport signals, crypto stack, KEV),
    and the result names its scope.
  · Every action the page calls is declared in the manifest's tag_scope block; roadmap_tag
    (browser UUIDs, not called by the page) is refused with a scope.
  · Writes from a tag view re-read their set from navi.db inside the tag: tag_uuids ignores
    browser UUIDs and needs a selection, tag_signal / tag scope the signal / surface SQL.
  · A scoped run never touches the module-level AGENT (the hub's status card), and the
    launcher's read cache keys scoped and estate requests apart.
Run: python3 tests/test_scope_postquantum_489.py"""
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
TMP = tempfile.mkdtemp(prefix="hounds-489-pq-")
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


from core import launcher, navi_cli, tagscope  # noqa: E402
from agents.postquantum import api, agent as pq  # noqa: E402

# pick the tag with the most quantum-exposed assets (so the scope really bites)
est_road = pq.roadmap()
exposed_all = {r["uuid"] for r in est_road["rows"]}
c = sqlite3.connect(DB)
pairs = c.execute("SELECT tag_key, tag_value FROM tags WHERE TRIM(COALESCE(tag_value,''))<>'' GROUP BY 1,2 "
                  "HAVING COUNT(DISTINCT asset_uuid)>=3").fetchall()
best = max(pairs, key=lambda kv: len(exposed_all & {r[0] for r in c.execute(
    "SELECT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", kv)}))
TK, TV = best
TAG = {r[0] for r in c.execute("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", (TK, TV))}
n_assets = c.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
SC = {"key": TK, "value": TV}
print(f"lab: {n_assets} assets · {len(exposed_all)} exposed · scope {TK} : {TV} ({len(TAG)} assets, "
      f"{len(exposed_all & TAG)} exposed)")
check(0 < len(exposed_all & TAG) < len(exposed_all), "the chosen tag holds some, not all, exposed assets")


def strip_time(o):
    """Drop the per-call clock bits (years-left floats move by microseconds between two calls)."""
    s = json.dumps(o, sort_keys=True, default=str)
    return re.sub(r'"(years|urgency|maxYears|score|last_run)": [^,}]+', '"\\1": 0', s)


# ── 1. whole estate unchanged ─────────────────────────────────────────────────
for col in ("asset_uuid", "uuid"):
    check(pq._w("SELECT 1", None, col) == ("SELECT 1", ()) and pq._w("SELECT 1", (None, None), col) == ("SELECT 1", ()),
          f"no scope → the SQL is untouched ({col})")
base_run, _ = api.run({})
for payload in ({"tag_scope": None}, {"tag_scope": {}}, {"tag_scope": {"key": TK}}):
    p = dict(payload)
    if payload["tag_scope"] is None or payload["tag_scope"] == {}:
        assert tagscope.check("postquantum", "run", p) is None     # the launcher drops it
    else:
        assert tagscope.check("postquantum", "run", dict(p))[1] == 400   # the launcher refuses half a scope
    o, _ = api.run(p)                                                  # …and the hound reads it as the estate
    check(strip_time(o) == strip_time(base_run), f"run with {payload} == the no-scope baseline")
check("scope" not in base_run and "scope" not in base_run["result"], "the estate run carries no scope")
check(base_run["result"]["metrics"]["assets_total"] == n_assets, "estate assets_total = every asset")
# hand-computed estate exposure: certs ∪ transport ∪ 277650
cert_q = {r[0] for r in c.execute(pq._CERT_TAG_QUERY) if r[0]}
trans_q = set()
for s in pq.PQT_SIGNALS:
    trans_q |= {r[0] for r in c.execute(s["sql"]) if r[0]}
p650 = {r[0] for r in c.execute("SELECT asset_uuid FROM vulns WHERE plugin_id='277650'") if r[0]}
check(base_run["result"]["assets"] == len(cert_q | trans_q | p650), "estate exposure = hand-computed union")
for name, fn in (("cert", api.cert), ("transport", api.transport), ("roadmap", api.roadmap_run)):
    a, _ = fn({})
    b, _ = fn({"tag_scope": None})
    check(strip_time(a) == strip_time(b) and "scope" not in a, f"{name}: whole estate unchanged")

# ── 2. scoped counts = hand counts over the tag ───────────────────────────────
o, st = launcher.dispatch("postquantum", "run", {"tag_scope": dict(SC)})
check(st == 200 and o["ok"], "launcher accepts a scoped run")
R = o["result"]
m = R["metrics"]
check(R["scope"]["key"] == TK and R["scope"]["assets"] == len(TAG) and o["scope"] == R["scope"], "the result names its scope")
in_tag_assets = {r[0] for r in c.execute("SELECT uuid FROM assets")} & TAG
check(m["assets_total"] == len(in_tag_assets), "assets_total = the tag's assets")
check(R["assets"] == len((cert_q | trans_q | p650) & TAG), "exposed = hand-computed union ∩ tag")
check(R["cert_assets"] == len(cert_q & TAG) and R["transport_assets"] == len(trans_q & TAG),
      "cert / transport exposure counted over the tag")
n_certs = c.execute("SELECT COUNT(*) FROM certs WHERE asset_uuid IN (SELECT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?)",
                    (TK, TV)).fetchone()[0]
check(m["certs"] == n_certs, f"certificates counted over the tag ({n_certs})")
for s in R["transport"]["signals"]:
    sig = next(x for x in pq.PQT_SIGNALS if x["key"] == s["key"])
    hand = {r[0] for r in c.execute(sig["sql"]) if r[0]} & TAG
    check(set(s["uuids"]) == hand, f"signal '{s['key']}': {len(hand)} tagged asset(s)")
check({r["uuid"] for r in R["roadmap"]["rows"]} == exposed_all & TAG, "roadmap rows = the estate's rows ∩ tag")
check(m["crown"] == sum(1 for r in est_road["rows"] if r["uuid"] in TAG and r["acr"] >= 7), "crown jewels counted over the tag")
check(m["exposed_pct"] == (round(100.0 * R["assets"] / m["assets_total"], 1) if m["assets_total"] else None),
      "exposed % is of the tag's assets")

# ── 3. per-asset values identical ─────────────────────────────────────────────
E = {r["uuid"]: r for r in base_run["result"]["roadmap"]["rows"]}
same = all(strip_time({k: v for k, v in r.items()}) == strip_time(E[r["uuid"]]) and abs(r["score"] - E[r["uuid"]]["score"]) <= 1
           for r in R["roadmap"]["rows"])
check(same, "every roadmap row (ACR, certs, transport, stack, KEV, priority) equals its estate row")
EH = [h for h in base_run["result"]["cert"]["harvest_now"] if h["uuid"] in TAG]
check(strip_time(R["cert"]["harvest_now"]) == strip_time(EH), "harvest-now rows = the estate's ∩ tag")
EA = [h for h in base_run["result"]["transport"]["agility"]["hosts"] if h["uuid"] in TAG]
check(R["transport"]["agility"]["hosts"] == EA, "crypto-stack tiers = the estate's ∩ tag")
inv_e = {r["algo"]: r for r in base_run["result"]["cert"]["inventory"]}
check(all(r["verdict"] == inv_e[r["algo"]]["verdict"] and set(r["uuids"]) == set(inv_e[r["algo"]]["uuids"]) & TAG
          for r in R["cert"]["inventory"]), "algorithm inventory: same verdicts, assets ∩ tag")
o, _ = api.roadmap_run({"tag_scope": dict(SC)})
check({r["uuid"] for r in o["result"]["rows"]} == exposed_all & TAG and o["scope"]["assets"] == len(TAG), "roadmap action scoped")
o, _ = api.cert({"tag_scope": dict(SC)})
check(o["result"]["kpi"]["certs"] == n_certs and o["scope"], "cert action scoped")
o, _ = api.transport({"tag_scope": dict(SC)})
check(o["result"]["agility"]["hosts"] == EA and o["scope"], "transport action scoped")
o, _ = api.run({"tag_scope": {"key": "no such key", "value": "x"}})
check(o["ok"] and o["result"]["assets"] == 0 and o["result"]["metrics"]["assets_total"] == 0, "an unknown tag scopes to nothing")

# ── 4. manifest: every page-called action declared ────────────────────────────
man = json.load(open(os.path.join(ROOT, "agents", "postquantum", "manifest.json"), encoding="utf-8"))
pol = man.get("tag_scope") or {}
declared = set(pol.get("actions") or []) | set(pol.get("ignore") or [])
page = open(os.path.join(ROOT, "agents", "postquantum", "page.html"), encoding="utf-8").read()
called = set(re.findall(r"API\.post\('([a-z_]+)'", page)) | set(re.findall(r"jpost\('/api/postquantum/([a-z_]+)'", page)) \
    | set(re.findall(r"runAgentJob\('postquantum',\s*'([a-z_]+)'", page))
check(called and called <= declared, f"page-called actions {sorted(called)} are all declared")
check(set(pol.get("actions") or []) <= set(api.ACTIONS), "every declared action exists")
check("mountTagScope({agent:'postquantum'" in page, "the page mounts the tag filter")
tagscope._POLICY.pop("postquantum", None)
r = tagscope.check("postquantum", "roadmap_tag", {"tag_scope": dict(SC), "uuids": ["x"], "confirm": True})
check(r and r[1] == 400, "roadmap_tag (browser UUIDs) is refused from a tag view")

# ── 5. scoped writes: recomputed on the server, inside the tag ────────────────
TAGGED = []


def _fake_set(cat, val, uuids=None, sql="", params=(), **kw):
    uu = navi_cli.collect_uuids(sql, params) if sql else list(uuids or [])
    TAGGED.append((cat, val, set(uu)))
    return [{"ok": True, "job_id": len(TAGGED), "queued": True}]


def _fake_tag(cat, val, **kw):
    TAGGED.append((cat, val, ("navi-selector", kw.get("plugin") or kw.get("query"))))
    return {"ok": True, "job_id": len(TAGGED), "queued": True}


_o_set, _o_tag = navi_cli.tag_set, navi_cli.tag
navi_cli.tag_set, navi_cli.tag = _fake_set, _fake_tag
try:
    outsider = sorted(exposed_all - TAG)[0]
    road = R["roadmap"]["rows"]
    # tag_uuids: browser UUIDs ignored, selection recomputed
    o, st = api.tag_uuids({"tag_scope": dict(SC), "confirm": True, "category": "PQC Priority", "value": "Migrate",
                           "uuids": [outsider, "evil"]})
    check(st == 400 and not TAGGED, "scoped tag_uuids with only a UUID list is refused — nothing queued")
    o, st = api.tag_uuids({"tag_scope": dict(SC), "category": "PQC Priority", "value": "Migrate",
                           "select": {"kind": "roadmap"}})
    check(st == 400 and not TAGGED, "no confirm → refused")
    o, st = api.tag_uuids({"tag_scope": dict(SC), "confirm": True, "category": "PQC Priority", "value": "Migrate",
                           "uuids": [outsider, "evil"], "select": {"kind": "roadmap"}})
    check(o["ok"] and TAGGED[-1][2] == exposed_all & TAG and outsider not in TAGGED[-1][2] and o["scope"],
          "tag shown (no filter): the tag's roadmap, browser UUIDs ignored")
    for f, fn in (("crown", lambda p: p["acr"] >= 7), ("cert", lambda p: p["brokenCerts"] > 0),
                  ("legacy", lambda p: p["agility"] == "Legacy"), ("kev", lambda p: p["kev"]),
                  ("kex", lambda p: p["uuid"] in set(m["kex_uuids"]))):
        want = {p["uuid"] for p in road if fn(p)}
        o, _ = api.tag_uuids({"tag_scope": dict(SC), "confirm": True, "category": "PQC Priority", "value": "x",
                              "select": {"kind": "roadmap", "filter": f}})
        got = TAGGED[-1][2] if o.get("ok") else set()
        check(got == want and got <= TAG, f"roadmap filter '{f}': {len(want)} asset(s), all in the tag")
    o, _ = api.tag_uuids({"tag_scope": dict(SC), "confirm": True, "category": "PQC Priority", "value": "Migrate",
                          "select": {"kind": "asset", "uuid": outsider}})
    check(not o["ok"] and TAGGED[-1][2] != {outsider}, "a single asset outside the tag is not tagged")
    inside = sorted(exposed_all & TAG)[0]
    o, _ = api.tag_uuids({"tag_scope": dict(SC), "confirm": True, "category": "PQC Priority", "value": "Migrate",
                          "select": {"kind": "asset", "uuid": inside}})
    check(o["ok"] and TAGGED[-1][2] == {inside}, "a single asset inside the tag is tagged")
    broken = [r for r in R["cert"]["inventory"] if r["verdict"] == "broken"]
    if broken:
        o, _ = api.tag_uuids({"tag_scope": dict(SC), "confirm": True, "category": "PQC Risk", "value": "Vulnerable : " + broken[0]["fam"],
                              "select": {"kind": "algo", "algo": broken[0]["algo"]}})
        check(o["ok"] and TAGGED[-1][2] == set(broken[0]["uuids"]) <= TAG, "algorithm tag = the tag's assets using it")
    hn0 = {h["uuid"] for h in R["cert"]["harvest_now"] if h["years"] > 0}
    if hn0:
        o, _ = api.tag_uuids({"tag_scope": dict(SC), "confirm": True, "category": "PQC Harvest-Now", "value": "Priority",
                              "select": {"kind": "harvest", "hz": 0}})
        check(o["ok"] and TAGGED[-1][2] == hn0 <= TAG, "harvest-now tag = the tag's still-valid broken certs")
    for tier in ("Legacy", "Upgradable", "PQC-ready"):
        want = {h["uuid"] for h in EA if h["tier"] == tier}
        if want:
            o, _ = api.tag_uuids({"tag_scope": dict(SC), "confirm": True, "category": "PQC Agility", "value": tier,
                                  "select": {"kind": "agility", "tier": tier}})
            check(o["ok"] and TAGGED[-1][2] == want <= TAG, f"agility '{tier}' tag = the tag's {tier} stacks")
    # tag_signal
    for s in R["transport"]["signals"]:
        if not s["assets"]:
            continue
        o, _ = api.tag_signal({"tag_scope": dict(SC), "confirm": True, "key": s["key"]})
        check(o["ok"] and o["count"] == s["assets"] and TAGGED[-1][2] == set(s["uuids"]) <= TAG,
              f"tag_signal '{s['key']}' stays in the tag ({s['assets']})")
        break
    # surface tag
    n0 = len(TAGGED)
    o, _ = api.tag({"tag_scope": dict(SC), "confirm": True})
    p_all = {r[0] for r in c.execute("SELECT asset_uuid FROM vulns WHERE plugin_id IN ('277650','277652','277653')") if r[0]}
    want = (cert_q | p_all) & TAG
    check(o["ok"] and len(TAGGED) == n0 + 1 and TAGGED[-1][2] == want and o["count"] == len(want),
          f"surface tag from a tag view = (cert set ∪ PQC plugins) ∩ tag ({len(want)}), one set, no navi selector")
    # estate writes still behave as before
    o, _ = api.tag_uuids({"confirm": True, "category": "PQC Priority", "value": "Migrate", "uuids": [outsider]})
    check(o["ok"] and TAGGED[-1][2] == {outsider}, "estate tag_uuids still tags the posted UUIDs")
    n0 = len(TAGGED)
    o, _ = api.tag({"confirm": True})
    check(o["ok"] and any(t[2][0] == "navi-selector" for t in TAGGED[n0:]), "estate surface tag still uses the navi selectors")
finally:
    navi_cli.tag_set, navi_cli.tag = _o_set, _o_tag

# ── 6. no own cache mixing ────────────────────────────────────────────────────
api.run({})
before = json.dumps(api.AGENT.result, sort_keys=True, default=str)
api.run({"tag_scope": dict(SC)})
check(json.dumps(api.AGENT.result, sort_keys=True, default=str) == before and api.AGENT.result["assets"] == len(cert_q | trans_q | p650),
      "a scoped run leaves the estate's AGENT result (hub status card) alone")
k1 = launcher._cache_key("postquantum", "run", {})
k2 = launcher._cache_key("postquantum", "run", {"tag_scope": dict(SC)})
k3 = launcher._cache_key("postquantum", "run", {"tag_scope": {"key": TK, "value": "other"}})
check(len({json.dumps(k, default=str) for k in (k1, k2, k3)}) == 3, "the read cache keys estate and each tag apart")
c.close()

print(("\n%d FAILURE(S)" % len(fails)) if fails else "\nALL PASS")
sys.exit(1 if fails else 0)
