"""Regression tests — build 489: Identity (Janus) by tag.

A tag view is the whole-estate identity scan cut to one tag's assets (core.identity.project):
  · an identity is listed when it was enumerated on at least one of the tag's assets;
  · its hosts / assets / max ACR / crown-jewel / privileged-host counts cover only those assets;
  · flags that are evidence ON A HOST (privileged, SSH password auth, weak policy, KEV, critical,
    default cred, AD attack path) stay only when one of the tag's hosts carries the evidence;
  · class, authority and account-wide flags (non-expiring pw, status lists, scan credential,
    account reuse ×N — the account's reach across the estate) are the estate's, unchanged;
  · host-level sets (signals, uncredentialed, credentialed) are the estate's sets ∩ the tag.
Tag views store their runs under their own name (idt_<hash>), so they never evict the estate's
run, and drill / tag / interpret are bound to the run's scope. Scoped writes re-read the tag from
navi.db and never leave it; uuid lists from the browser are refused in a tag view.
Run: python3 tests/test_scope_identity_489.py"""
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
TMP = tempfile.mkdtemp(prefix="hounds-489id-")
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


from core import credstate, identity, launcher, navi_cli, payload, tagscope  # noqa: E402
from agents.identity import api  # noqa: E402

TAGGED = []
navi_cli.tag_uuids_batched = lambda cat, val, uu, agent=None: (TAGGED.append((cat, val, sorted(uu))) or
                                                               [{"ok": True, "job_id": len(TAGGED)}])
navi_cli.jobs_summary = lambda jobs: {"result": {"ok": True, "job_id": jobs[0]["job_id"]}, "jobs": jobs,
                                      "job_ids": [j["job_id"] for j in jobs]}

con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row
ALL = {r[0] for r in con.execute("SELECT uuid FROM assets")}
ACR = {r["uuid"]: float(r["acr"] or 0) for r in con.execute("SELECT uuid, acr FROM assets")}
# the tag with the most identities on it (the lab DB has several)
est = identity.scan()
best = None
for r in con.execute("SELECT tag_key k, tag_value v, COUNT(DISTINCT asset_uuid) n FROM tags "
                     "WHERE TRIM(COALESCE(tag_value,''))<>'' GROUP BY 1,2 HAVING n>=3"):
    s = {x[0] for x in con.execute("SELECT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", (r["k"], r["v"]))}
    nid = sum(1 for a in est["accounts"] if s & set(a["asset_uuids"]))
    nh = len({u for a in est["accounts"] for u in a["asset_uuids"] if u in s})   # identity hosts in the tag
    if nh >= 2 and len(s) < len(ALL) and (best is None or (nh, nid) > (best[4], best[3])):
        best = (r["k"], r["v"], s, nid, nh)
TK, TV, TS, NID, _NH = best
con.close()
SC = {"tag_scope": {"key": TK, "value": TV}}
print(f"lab: {len(ALL)} assets · {len(est['accounts'])} identities · scope {TK} : {TV} ({len(TS)} assets, {NID} identities)")


def strip(o):
    """A run response without what differs between two runs (run id, tokens, timestamps)."""
    s = json.dumps(o, sort_keys=True, default=str)
    s = re.sub(r'identity-[0-9a-f]{16}|idt_[0-9a-f]{16}-[0-9a-f]{16}', 'RUN', s)
    s = re.sub(r'"(next|built_at|as_of|at|generated_at)": "[^"]*"', r'"\1": "X"', s)
    s = re.sub(r'"next": "[^"]*"', '"next": "X"', s)
    return s


# ── 1. whole estate unchanged ────────────────────────────────────────────────
k1 = identity.scan(keep=True)
k1.pop("_keep")
for a in k1["accounts"]:
    a.pop("priv_uuids", None)
check(json.dumps(k1, sort_keys=True, default=str) == json.dumps(est, sort_keys=True, default=str),
      "scan(keep=True) minus its keep fields == scan() (the estate result is untouched)")
whole = identity.project(identity.scan(keep=True), ALL)
check(json.dumps(whole["accounts"], sort_keys=True) == json.dumps(est["accounts"], sort_keys=True)
      and whole["counts"] == est["counts"] and whole["blind"] == est["blind"]
      and whole["credentialed"] == est["credentialed"] and whole["host_sets"] == est["host_sets"]
      and whole["identity_hosts"] == est["identity_hosts"] and whole["scan_creds"] == est["scan_creds"],
      "project() over every asset reproduces the estate result exactly")
o0, _ = api.run({})
o1, _ = api.run({})
o2, _ = api.run({"tag_scope": {"key": "", "value": ""}})
check(o0["ok"] and strip(o0) == strip(o1) == strip(o2) and "scope" not in o0 and "scope" not in o0["result"],
      "run with no tag (or an empty scope) == the no-scope baseline, and carries no scope")
ER = o2["drill"]["run"]          # the estate's newest run (the store keeps 2 per hound)
check(ER.startswith("identity-"), "the estate's run is stored under 'identity' as before")
check(o0["result"]["metrics"]["estate"] == len(ALL), "estate metric counts every asset")

# ── 2. scoped counts == hand-computed over the tag's assets ───────────────────
o, st = launcher.dispatch("identity", "run", json.loads(json.dumps(SC)))
r = o.get("result") or {}
check(st == 200 and o["ok"] and o["scope"]["label"] == f"{TK} : {TV}" and o["scope"]["assets"] == len(TS),
      "a scoped run passes the launcher and says what it covers")
hand = [a for a in est["accounts"] if TS & set(a["asset_uuids"])]
check(r["accounts_total"] == len(hand) == NID, f"identities = those enumerated on the tag's assets ({len(hand)})")
check(r["counts"]["total"] == len(hand)
      and all(r["counts"][k] == sum(1 for a in hand if a["klass"] == k) for k in ("nhi", "human", "service", "machine")),
      "class counts over the tag's identities only")
check(r["identity_hosts"] == len({u for a in hand for u in a["asset_uuids"] if u in TS}),
      "identity hosts = the tag's assets that carry an identity")
cs = credstate.sets()
blind, cred = set(cs["blind"]) & TS, set(cs["credentialed"]) & TS
check(r["blind"] == r["metrics"]["blind"] == len(blind) and r["credentialed"] == len(cred - blind),
      "coverage (blind / credentialed) = the estate's sets ∩ the tag")
check(r["metrics"]["estate"] == len(TS), "the 'estate' metric is the tag's asset count in a tag view")
check(r["view"]["host_sets"] == {k: len(set(v) & TS) for k, v in est["host_sets"].items()},
      "every host signal = the estate's hosts ∩ the tag")

# ── 3. per-identity / per-asset values ────────────────────────────────────────
srun = o["drill"]["run"]
rows, _ = api.drill(dict(SC, run=srun, section="ids", limit=200))
by = {x["user"]: x for x in rows["top"]}
estrows, _ = api.drill({"run": ER, "section": "ids", "limit": 200})
eby = {x["user"]: x for x in estrows["top"]}
check(set(by) == {a["user"] for a in hand} and all(by[u]["klass"] == eby[u]["klass"] and by[u]["authority"] == eby[u]["authority"]
                                                  for u in by), "class and authority identical to the estate's")
ok_hosts = ok_acr = ok_flags = True
hsf = {k: set(v) for k, v in est["host_sets"].items()}
for a in hand:
    x, uu = by[a["user"]], [u for u in a["asset_uuids"] if u in TS]
    ok_hosts &= x["assets_n"] == len(uu)
    vals = [ACR.get(u, 0) for u in uu]
    ok_acr &= x["max_acr"] == (max(vals) if vals else None) and x["crown_hosts"] == sum(1 for v in vals if v >= api.CROWN_ACR)
    want = [f for f in a["flags"] if not (f in identity.HOST_FLAGS and not (set(uu) & hsf.get(f, set())))
            and not (f == "privileged" and not x.get("privileged_hosts"))]
    ok_flags &= [f for f in x["flags"] if f != "privileged"] == [f for f in want if f != "privileged"]
    ok_flags &= all(f in x["flags"] for f in a["flags"] if f not in identity.HOST_FLAGS and f != "privileged")
check(ok_hosts, "asset counts cover only the tag's assets")
check(ok_acr, "max ACR / crown-jewel hosts = over the tag's assets, from each asset's own ACR")
check(ok_flags, "account-wide flags unchanged; host flags kept only when a tag host carries the evidence")

# synthetic: privileged evidence and reuse outside the tag
U = ["%08x-0000-0000-0000-000000000000" % i for i in range(20)]
syn = {"accounts": [
    {"user": "svc", "klass": "service", "asset_uuids": U[0:10], "hosts": ["h%d" % i for i in range(10)], "flags":
     ["privileged", "account reuse ×10", "non-expiring pw", "on KEV host"], "privilege": ["UID 0 (superuser)"],
     "privileged_hosts": 2, "priv_uuids": [U[8], U[9]], "reuse_uuids": U[0:10], "plugins": []},
    {"user": "ops", "klass": "human", "asset_uuids": [U[1], U[12]], "hosts": ["h1", "h12"], "flags": ["privileged"],
     "privilege": ["in the wheel group"], "privileged_hosts": 1, "priv_uuids": [U[1]], "plugins": []},
    {"user": "far", "klass": "human", "asset_uuids": [U[15]], "hosts": ["h15"], "flags": [], "plugins": []}],
    "host_sets": {"on KEV host": [U[9]], "uncredentialed": [U[2], U[15]]}, "scan_creds": [],
    "_keep": {"scan_uu": {}, "cred": [U[0], U[1], U[12]]}}
p = identity.project(syn, {U[0], U[1], U[2]})
ps = {a["user"]: a for a in p["accounts"]}
check(set(ps) == {"svc", "ops"}, "synthetic: an identity with no host in the tag drops out")
check(ps["svc"]["flags"] == ["account reuse ×10", "non-expiring pw"] and "privilege" not in ps["svc"]
      and ps["svc"]["reuse_uuids"] == [U[0], U[1], U[2]],
      "synthetic: privileged / KEV evidence outside the tag dropped; reuse ×N kept, its hosts cut to the tag")
check(ps["ops"]["flags"] == ["privileged"] and ps["ops"]["privileged_hosts"] == 1 and ps["ops"]["asset_uuids"] == [U[1]],
      "synthetic: privileged on a tag host stays, counted over the tag")
check(p["blind"] == 1 and p["credentialed"] == 2 and p["counts"]["reused"] == 1 and p["counts"]["reused_hosts"] == 3,
      "synthetic: coverage and reuse totals over the tag")

# ── 4. every page-called action is declared ───────────────────────────────────
pg = open(os.path.join(ROOT, "agents", "identity", "page.html"), encoding="utf-8").read()
called = set(re.findall(r"API\.post\('([a-z_]+)'", pg)) | ({"drill"} if "hDrill(" in pg else set())
man = json.load(open(os.path.join(ROOT, "agents", "identity", "manifest.json"), encoding="utf-8"))["tag_scope"]
check(called and called <= set(man["actions"]) | set(man["ignore"]), f"page actions {sorted(called)} all in the manifest")
check(set(man["actions"]) <= set(api.ACTIONS), "manifest scoped actions exist")
check("mountTagScope({agent:'identity'" in pg and "tagScopeNote()" in pg and "fetch(" not in pg,
      "page mounts the tag bar, names the scope in confirms, no raw fetch")
check(tagscope.check("identity", "nope", dict(SC)) is not None, "an undeclared action is refused with a scope")

# ── 5. own result store: estate and tag views kept apart ─────────────────────
erun = ER
d, _ = api.drill({"run": srun, "section": "ids"})
check(d.get("expired"), "a tag view's run can't be drilled as the whole estate")
d, _ = api.drill(dict(SC, run=erun, section="ids"))
check(d.get("expired"), "the estate's run can't be drilled from a tag view")
o_b, _ = api.run({"tag_scope": {"key": TK, "value": TV}})
o_c, _ = api.run({"tag_scope": {"key": TK, "value": TV}})
d, _ = api.drill({"run": o1["drill"]["run"], "section": "ids"})
d1, _ = api.drill({"run": ER, "section": "ids"})
check(d.get("ok") is not False and d1.get("ok") is not False,
      "three tag runs later the estate's 2 latest runs are still on the server (tag runs don't evict them)")
check(d1.get("total") and d1["total"]["value"] == len(est["accounts"]), "…and still page the estate's identities")
hn = api._hound(TK, TV)
check(re.fullmatch(r"idt_[0-9a-f]{16}", hn) and o_c["drill"]["run"].startswith(hn + "-")
      and api._hound(None, None) == "identity" and api._hound(TK, TV + "x") != hn, "a tag's own store name")
payload.STORE.begin(api._hound("Old", "tag")).close()
api._trim_tag_runs(hn)
c2 = sqlite3.connect(payload.STORE.path())
hs = {h for (h,) in c2.execute("SELECT hound FROM runs WHERE hound LIKE 'idt_%'")}
c2.close()
check(hn in hs and api._hound("Old", "tag") not in hs, "runs of tags no longer among the 5 recent are dropped")

# ── 6. scoped writes stay inside the tag, re-read from navi.db ───────────────
srun = o_c["drill"]["run"]
dry, _ = api.tag(dict(SC, category="Identity Coverage", value="No Credentials",
                      set={"run": srun, "kind": "hs", "key": "uncredentialed"}, dry=True))
check(dry["ok"] and dry["assets"] == len(blind) and dry["scope"]["label"] == f"{TK} : {TV}" and not TAGGED,
      "dry count is the tag's hosts and names the scope; nothing written")
b, st = api.tag(dict(SC, category="Identity", value="x", set={"run": srun, "kind": "union", "filter": []}))
check(st == 400 and not TAGGED, "no confirm → 400")
b, st = api.tag(dict(SC, category="Identity", value="x", asset_uuids=sorted(ALL - TS)[:3], confirm=True))
check(st == 400 and not TAGGED, "a uuid list from the browser is refused in a tag view")
b, st = api.tag(dict(SC, category="Identity", value="x", items=[{"value": "y", "asset_uuids": sorted(ALL)}], confirm=True))
check(st == 400 and not TAGGED, "items with uuids from the browser are refused in a tag view")
api.tag(dict(SC, category="Identity", value="all", set={"run": srun, "kind": "union", "filter": []}, confirm=True))
check(TAGGED and set(TAGGED[-1][2]) <= TS and TAGGED[-1][2], "union tag from a tag view: only the tag's assets")
# move one tagged asset out of the tag AFTER the run: the write re-reads navi.db and skips it
gone = TAGGED[-1][2][0]
c3 = sqlite3.connect(DB)
c3.execute("DELETE FROM tags WHERE asset_uuid=? AND tag_key=? AND tag_value=?", (gone, TK, TV))
c3.commit()
c3.close()
b, _ = api.tag(dict(SC, category="Identity", value="all", set={"run": srun, "kind": "union", "filter": []}, confirm=True))
check(b.get("ok") and b["count"] == len(TS & {u for a in est["accounts"] for u in a["asset_uuids"]}) - 1 and gone not in TAGGED[-1][2] and set(TAGGED[-1][2]) <= tagscope.uuids(TK, TV),
      "the tag is re-read at write time (an asset that left the tag is not written)")
n0 = len(TAGGED)
api.tag(dict(SC, category="Identity", value="", set={"run": srun, "kind": "each", "filter": []}, confirm=True))
inside = tagscope.uuids(TK, TV)
check(len(TAGGED) > n0 and all(set(t[2]) <= inside for t in TAGGED[n0:]), "per-identity tags from a tag view stay inside")
b, st = api.tag(dict(SC, category="Identity", value="x", set={"run": erun, "kind": "union", "filter": []}, confirm=True))
check(st == 400 and b.get("expired"), "a tag view can't write from the estate's run")
api.tag({"category": "Identity", "value": "all", "set": {"run": ER, "kind": "union", "filter": []}, "confirm": True})
check(set(TAGGED[-1][2]) == {u for a in est["accounts"] for u in a["asset_uuids"]}, "the estate's union tag is unchanged")
iv, _ = api.interpret(dict(SC, prompt="x", run=erun))
check(iv.get("ok") is False and "no longer" in iv.get("error", ""), "interpret from a tag view only reads its own run")

o, _ = api.run({"tag_scope": {"key": "no such key", "value": "x"}})
check(o["ok"] is False and "navi update assets" in o["error"], "an unknown tag is refused with how to fix it")
print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
