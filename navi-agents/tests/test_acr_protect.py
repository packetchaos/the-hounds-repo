"""Regression tests for ACR protection (NO : UPDATE) and the ACR log.

- core.acr_protect.preview() mirrors navi's `enrich acr` selection EXACTLY (navi-pro 8.8.2,
  navi/plugins/enrich.py `acr` + tag_helper.tag_checker — transcribed below as the reference):
  set / inc (cap 10) / dec (floor 1), NULL/'' ACR skipped, NO : UPDATE skipped by exact,
  case-sensitive match ('Hounds-NO', 'no : update', 'NO : update' protect nothing).
- core.navi_cli.acr() (the single ACR choke point) logs one ACR-log row per asset with the
  right before / after / result — 'blocked' when writes are off, never 'applied' — attributed
  to the calling Hound, and the Tagging-log entry carries the business case.
- The protect action writes category exactly 'NO' even with Settings → Test run on; protect
  after applying covers exactly the applied assets; metrics match SQL truth.
- AI Contract: per-rule protected counts in the plan, the protect_acr option (validated),
  export-script lines; pages follow the console pattern and confirm first.
Synthetic navi.db + taglog in a temp dir; navi + subprocess are stubbed — no navi, no network.
Run: python3 tests/test_acr_protect.py  (or pytest)."""
import atexit
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from collections import defaultdict

_REAL_RUN = subprocess.run          # the stubs below replace subprocess.run module-wide

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-acrprot-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "CONTRACT_DIR": os.path.join(TMP, "contracts"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db")})
for k in ("NAVI_TAG_TEST_RUN", "NAVI_TAG_PREFIX", "NAVI_ALLOW_WRITES", "NAVI_MCP_ALLOW_WRITES", "ANTHROPIC_API_KEY"):
    os.environ.pop(k, None)
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


# ------------------------------------------------------------------ synthetic navi.db (navi's schema)
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT, aes TEXT);
CREATE TABLE tags (tag_id integer PRIMARY KEY, asset_uuid text, asset_ip text, tag_key text, tag_uuid text,
                   tag_value text, tag_added_date text);
""")
ASSETS = [("a1", "web1", "10.0.0.1", "5"), ("a2", "db1", "10.0.0.2", "9"), ("a3", "nullacr", "10.0.0.3", None),
          ("a4", "emptyacr", "10.0.0.4", ""), ("a5", "low", "10.0.0.5", "1"), ("a6", "top", "10.0.0.6", "10"),
          ("a7", "locked", "10.0.0.7", "7"), ("a8", "hprefix", "10.0.0.8", "3"), ("a9", "lower", "10.0.0.9", "4"),
          ("a10", "mixed", "10.0.0.10", "6"), ("a12", "weird", "10.0.0.12", "x7"), ("a13", "other", "10.0.0.13", "2")]
c.executemany("INSERT INTO assets VALUES (?,?,?,?,'0')", ASSETS)
TAGS = [(u, "Tier", "Prod") for u in ("a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "a11")]
TAGS += [("a7", "NO", "UPDATE"),                      # the one real protection
         ("a8", "Hounds-NO", "UPDATE"),               # test-run name: NOT honoured by navi
         ("a9", "no", "update"),                      # lowercase: NOT honoured
         ("a10", "NO", "update"),                     # value case differs: NOT honoured
         ("a12", "Tier", "Weird"), ("a13", "NO", "UPDATE")]   # a13 protected, never changed
c.executemany("INSERT INTO tags(asset_uuid,asset_ip,tag_key,tag_uuid,tag_value,tag_added_date) VALUES (?,'',?,'',?,'')",
              [(u, k, v) for u, k, v in TAGS])
c.commit()
c.close()


def navi_reference(score, v, cat, mod):
    """navi's own acr() selection, transcribed (string-formatted SQL included). Returns
    {uuid: new_acr} for every asset navi sends to Tenable, or None if navi rejects the score."""
    con = sqlite3.connect(DB)

    def db_query(q):
        return con.execute(q).fetchall()

    def tag_checker(uuid, key, value):
        return 'yes' if len(db_query("SELECT * from tags where asset_uuid='{}' and tag_key='{}' and tag_value='{}';"
                                     .format(uuid, key, value))) != 0 else 'no'
    sent = {}
    if int(score) not in range(1, 11):
        return None
    acr_dict = defaultdict(list)
    data = db_query("select acr, asset_uuid from tags left join assets on assets.uuid = tags.asset_uuid "
                    "where tag_key='{}' and tag_value='{}';".format(cat, v))
    allow_list = [a[1] for a in data if tag_checker(a[1], "NO", "UPDATE") == 'no']
    for rate, uuid in data:
        if uuid in allow_list:
            acr_dict[rate].append(uuid)
    for keys in acr_dict:
        current_acr = keys
        if current_acr:
            if mod == 'set':
                new_acr = score
            elif mod == 'inc':
                new_acr = min(10, int(current_acr) + int(score))
            else:
                new_acr = max(1, int(current_acr) - int(score))
            for u in acr_dict[keys]:
                sent[u] = int(new_acr)
    con.close()
    return sent


from core import acr_protect as AP, tagname  # noqa: E402

# ------------------------------------------------------------------ tagname exemption
os.environ["NAVI_TAG_TEST_RUN"] = "1"
check(tagname.EXEMPT == frozenset({"NO"}) and tagname.is_exempt("NO"), "tagname.EXEMPT = {'NO'}")
check(tagname.effective("NO") == "NO", "test run on: 'NO' is never prefixed")
check(tagname.effective("no") == "Hounds-no" and tagname.effective("Lifecycle") == "Hounds-Lifecycle",
      "…exact match only: 'no' and other categories are still prefixed")
os.environ.pop("NAVI_TAG_TEST_RUN")

# ------------------------------------------------------------------ preview == navi
check(AP.protected_uuids() == {"a7", "a13"}, "protected_uuids: exact NO : UPDATE only (not Hounds-NO / no:update / NO:update)")
for mod, score in (("set", 8), ("set", 5), ("inc", 3), ("inc", 9), ("dec", 2), ("dec", 9), ("set", 1), ("set", 10)):
    pv = AP.preview("Tier", "Prod", score, mod)
    got = {a["uuid"]: a["acr_after"] for a in pv["assets"] if a["status"] in ("change", "unchanged")}
    ref = navi_reference(str(score), "Prod", "Tier", mod)
    check(pv["ok"] and got == ref, "preview %s %s == navi's selection %s" % (mod, score, sorted(ref.items())))
pv = AP.preview("Tier", "Prod", 3, "inc")
st = {a["uuid"]: a["status"] for a in pv["assets"]}
check(st["a7"] == "protected" and st["a8"] != "protected" and st["a9"] != "protected" and st["a10"] != "protected",
      "only NO : UPDATE protects (Hounds-NO, no:update and NO:update do not)")
check(st["a3"] == "no_acr" and st["a4"] == "no_acr" and st["a11"] == "no_acr", "NULL / '' / missing-asset ACR → no_acr (skipped)")
a = {x["uuid"]: x for x in pv["assets"]}
check(a["a6"]["acr_after"] == 10 and a["a6"]["status"] == "unchanged" and a["a2"]["acr_after"] == 10,
      "inc caps at 10 (10 stays 10 = unchanged)")
pd = {x["uuid"]: x for x in AP.preview("Tier", "Prod", 4, "dec")["assets"]}
check(pd["a5"]["acr_after"] == 1 and pd["a5"]["status"] == "unchanged" and pd["a1"]["acr_after"] == 1,
      "dec floors at 1")
check(pv["counts"] == {"change": 6, "unchanged": 1, "protected": 1, "no_acr": 3, "bad_acr": 0, "refused": 0, "total": 11},
      "preview counts: %s" % pv["counts"])
check(AP.preview("Tier", "Prod", 9.0, "set")["valid_score"] and AP.score_arg(9.0) == "9" and AP.score_arg("8") == "8",
      "a whole-number score is passed to navi as '9', never '9.0' (navi does int(score))")
for bad in (0, 11, 8.5):
    check(not AP.preview("Tier", "Prod", bad, "set")["valid_score"], "score %r: navi would ignore it (valid_score False)" % bad)
pw = AP.preview("Tier", "Weird", 1, "inc")
check(pw["assets"][0]["status"] == "bad_acr" and AP.preview("Tier", "Weird", 4, "set")["assets"][0]["status"] == "change",
      "inc/dec on an ACR navi cannot int() → bad_acr; set still works")
check(AP.preview("Nope", "Nope", 5, "set")["counts"]["total"] == 0, "unknown tag → nothing")
check(AP.business_case(["compliance", "business"], " PCI  scope ") == "Business Critical, In Scope For Compliance — PCI scope",
      "business case = navi's reason labels in navi's order + the note")
check(AP.business_case(["development"], "") == "Dev Only" and AP.navi_reasons(["mitigation"], "x") == ["Existing Mitigation Control", "Other"],
      "business case without note; navi adds 'Other' for a note")

# ------------------------------------------------------------------ the choke point + ACR log
from core import navi_cli, tagq, acrlog  # noqa: E402

RAN = []


class _P:
    returncode, stdout, stderr = 0, "Processing your ACR update requests", ""


navi_cli.navi_available = lambda: True
navi_cli._resolve_navi = lambda: "navi"
navi_cli._navi_cwd = lambda: TMP
navi_cli.subprocess.run = lambda cmd, **k: (RAN.append(list(cmd)) or _P())
SUB = []
# queued jobs get a REAL Tagging-log row (status queued) so "pending" can be judged from it
tagq.submit = lambda fn, kw, meta=None: (SUB.append((fn, dict(kw), dict(meta or {}))) or {"id": tagq._db_insert(
    {"status": "queued", "created": 0, "op": (meta or {}).get("op", "tag"), "category": kw.get("category"),
     "value": kw.get("value"), "agent": (meta or {}).get("agent", ""), "spec": {}})})

navi_cli.allow_writes = lambda: False
r = navi_cli.acr("Tier", "Prod", 8, mod="set", reasons=["business"], note="Prod tier", agent="acr")
blk = acrlog.rows({"batch": r["acr_log"]["batch"]})["rows"]
res = {x["asset_uuid"]: x["result"] for x in blk}
check(not RAN and r.get("blocked"), "writes off: navi not called, result blocked")
check(res and "applied" not in res.values() and res["a1"] == "blocked" and res["a7"] == "skipped_protected"
      and res["a3"] == "skipped_no_acr", "writes off: rows logged blocked / skipped — never applied")

navi_cli.allow_writes = lambda: True
r = navi_cli.acr("Tier", "Prod", 9.0, mod="set", reasons=["business", "compliance"], note="PCI scope", agent="contract")
check(RAN and RAN[-1][RAN[-1].index("--score") + 1] == "9", "navi gets --score 9 (not 9.0)")
b = r["acr_log"]["batch"]
rows = {x["asset_uuid"]: x for x in acrlog.rows({"batch": b})["rows"]}
check(len(rows) == 11 and r["acr_log"]["counts"] == {"applied": 7, "blocked": 0, "failed": 0, "skipped_protected": 1,
                                                    "skipped_no_acr": 3, "no_assets": 0}, "one row per asset: %s" % r["acr_log"]["counts"])
check(rows["a1"]["acr_before"] == "5" and rows["a1"]["acr_after"] == "9" and rows["a1"]["result"] == "applied"
      and rows["a1"]["host"] == "web1" and rows["a1"]["agent"] == "contract", "a1: 5 → 9 applied, host + agent attribution")
check(rows["a7"]["result"] == "skipped_protected" and rows["a7"]["acr_after"] == "" and "NO : UPDATE" in rows["a7"]["message"],
      "a7 (NO : UPDATE): skipped_protected, no after value")
check(rows["a1"]["business_case"] == "Business Critical, In Scope For Compliance — PCI scope"
      and rows["a1"]["reasons"] == ["business", "compliance"], "ACR log row carries reasons + business case")
check(r["preview"]["counts"]["change"] == 6 and "assets" not in r["preview"], "result carries preview counts (no asset list)")
jobs = tagq.list_jobs()
j = next(x for x in jobs if x.get("selector") == "acr set" and x.get("business_case"))
check(j["business_case"] == "Business Critical, In Scope For Compliance — PCI scope" and j["agent"] == "acr",
      "Tagging-log ACR entry carries business_case (agent stays 'acr' — build_from_log reads it)")
check(j["spec"].get("_acr") and j["spec"]["score"] == "9", "Tagging-log ACR entry keeps a replayable spec")
navi_cli.acr("Tier", "Prod", 9, mod="rm; id", reasons=["business"], note="x")
check(not tagq.list_jobs()[0]["spec"], "a malformed mod is never kept as a replayable spec")


class _Fail:
    returncode, stdout, stderr = 1, "", "boom"


navi_cli.subprocess.run = lambda cmd, **k: (RAN.append(list(cmd)) or _Fail())
r2 = navi_cli.acr("Tier", "Prod", 2, mod="inc", reasons=["business"], agent="ai")
cn = r2["acr_log"]["counts"]
check(cn["failed"] == 7 and cn["applied"] == 0 and cn["skipped_protected"] == 1, "navi failure → failed rows")
navi_cli.subprocess.run = lambda cmd, **k: (RAN.append(list(cmd)) or _P())
os.environ["NAVI_DB_PATH"] = os.path.join(TMP, "missing.db")
r3 = navi_cli.acr("Tier", "Prod", 5, mod="set", reasons=["business"], agent="acr")
one = acrlog.rows({"batch": r3["acr_log"]["batch"]})["rows"]
check(len(one) == 1 and one[0]["asset_uuid"] == "" and one[0]["result"] == "applied" and "preview unavailable" in one[0]["message"],
      "navi.db unreadable → the change is still registered (one summary row)")
os.environ["NAVI_DB_PATH"] = DB
for x in ("applied", "skipped_protected", "blocked", "failed"):
    check(acrlog.rows({"result": x})["total"] > 0, "log filter result=%s" % x)
check(acrlog.rows({"q": "web1"})["total"] >= 3 and acrlog.rows({"agent": "contract"})["total"] == 11,
      "log search by host + filter by agent")
check(acrlog.rows({"business_case": "Dev Only"})["total"] == 0
      and acrlog.rows({"business_case": "Business Critical, In Scope For Compliance — PCI scope"})["total"] == 11,
      "log filter by business case")
ex = acrlog.export_csv({"result": "applied"})
check(ex["count"] == acrlog.rows({"result": "applied"})["total"] and "business_case" in ex["csv"].splitlines()[0],
      "CSV export: same rows as the filter, business_case column")

# ------------------------------------------------------------------ metrics vs SQL truth
m = AP.metrics()
con = sqlite3.connect(os.environ["NAVI_TAGLOG_DB"])
changed = {u for (u,) in con.execute("SELECT DISTINCT asset_uuid FROM acr_log WHERE result='applied' AND asset_uuid<>''")}
con.close()
prot = AP.protected_uuids()
check(m["changed"] == len(changed) == 7 and m["protected"] == 2, "metrics: changed %d / protected %d" % (m["changed"], m["protected"]))
check(m["changed_protected"] == len(changed & prot) and m["changed_unprotected"] == len(changed - prot)
      and m["protected_never_changed"] == len(prot - changed) == 2, "metrics: changed × protected splits match SQL")
check(m["no_acr"] == 2 and m["respected"] >= 3, "metrics: 2 assets without ACR; NO : UPDATE respected rows counted")
check(any(b["business_case"] == "Business Critical, In Scope For Compliance — PCI scope" for b in m["by_business_case"]),
      "metrics: changes by business case")

# ------------------------------------------------------------------ protect action
from agents.acr import api as ACRAPI  # noqa: E402

os.environ["NAVI_TAG_TEST_RUN"] = "1"
o, code = ACRAPI.protect({"uuids": ["a1"]})
check(code == 400 and not SUB, "protect: confirm=true required")
o, code = ACRAPI.protect({"uuids": ["a13"], "confirm": True})
check(code == 400, "protect: only assets the Hounds changed")
SUB.clear()
o, code = ACRAPI.protect({"all_unprotected": True, "confirm": True})
check(code == 200 and o["assets"] == len(changed - prot) and SUB, "protect all unprotected: %s asset(s)" % o.get("assets"))
check(all(s[1]["category"] == "NO" and s[1]["value"] == "UPDATE" and s[2]["category"] == "NO" for s in SUB),
      "protect writes category exactly 'NO' / value 'UPDATE' with Test run ON")
check(all(not s[1]["remove"] for s in SUB) and SUB[0][2]["business_case"], "protect is an add (never -remove) and carries the business case")
qry = " ".join(s[1]["query"] for s in SUB)
check("'a1'" in qry and "'a7'" not in qry and "FROM assets WHERE uuid IN" in qry, "protect query lists the unprotected changed assets only")
m2 = AP.metrics(show="pending")
check(m2["pending"] == len(changed - prot) and all(x["protection"] == "pending" for x in m2["rows"]),
      "after protect: rows show pending until navi.db syncs")
o, _ = ACRAPI.protect({"all_unprotected": True, "confirm": True})
check(o["assets"] == 0, "protect all: pending assets are not re-queued")
o, _ = ACRAPI.protect({"uuids": ["a1"], "confirm": True})
check(o["assets"] == 0, "protect selected: a pending asset is not re-queued")
bad_job = tagq.record({"agent": "acr", "category": "NO", "value": "UPDATE", "selector": "query"}, {"ok": False, "blocked": True})
acrlog.record_protect(["a1"], "acr", "", bad_job["id"])
m3 = {x["uuid"]: x for x in AP.metrics()["rows"]}
check(m3["a1"]["protection"] == "unprotected" and m3["a1"]["request_failed"],
      "a failed / blocked NO : UPDATE job leaves the asset unprotected (retryable), flagged")
SUB.clear()
o, _ = ACRAPI.protect({"uuids": ["a1"], "confirm": True})
check(o["assets"] == 1 and SUB, "…and it can be protected again")
os.environ.pop("NAVI_TAG_TEST_RUN")

# bug 4 — "pending" must end: done → synced/removed, window expiry, Tagging log cleared
import time as _time  # noqa: E402
now = _time.time()
tagq._dbexec("UPDATE jobs SET status='done', ok=1, finished=? WHERE category='NO' AND status='queued'", (now - 60,))
pend = AP.pending_uuids()
check(pend and "a1" in pend, "bug4: a done NO : UPDATE job is pending while navi.db hasn't synced (within the window)")
check(not AP.pending_uuids(now=now + AP.SYNC_WINDOW_S + 1), "bug4: …but not forever — after the sync window it is unprotected again")
tagq.record({"agent": "tagremoval", "op": "remove", "category": "NO", "value": "UPDATE", "selector": "remove"}, {"ok": True})
check(not AP.pending_uuids(), "bug4: a later Garmr NO : UPDATE removal ends 'pending' (the asset can be re-protected)")
SUB.clear()
o, _ = ACRAPI.protect({"uuids": ["a1"], "confirm": True})
check(o["assets"] == 1, "bug4: …and re-protect works after the removal")
check(AP.pending_uuids() == {"a1"}, "bug4: the new (queued) request is pending")
tagq._dbexec("UPDATE jobs SET status='error', ok=0 WHERE category='NO' AND status='queued'")
tagq.clear()                                                      # Tagging log → 🧹 Clear finished
check(not AP.pending_uuids(), "bug4: a protect job whose Tagging-log row was cleared is not pending")

# protect after applying = exactly the applied rows of that change
SUB.clear()
o, _ = ACRAPI.apply({"confirm": True, "category": "Tier", "value": "Prod", "score": 7, "mod": "set",
                     "reasons": ["business"], "note": "lock prod", "protect_after": True})
applied = set(acrlog.batch_uuids(o["acr_log"]["batch"]))
q = SUB[-1][1]["query"] if SUB else ""
check(o["protection"]["assets"] == len(applied) == 7 and all("'%s'" % u in q for u in applied) and "'a7'" not in q
      and "'a3'" not in q, "protect_after: NO : UPDATE on exactly the applied assets")
check(SUB and SUB[-1][2]["business_case"] == "Business Critical — lock prod", "protect_after job carries that change's business case")
SUB.clear()
o, _ = ACRAPI.apply({"confirm": True, "category": "Tier", "value": "Prod", "score": 7, "mod": "set",
                     "reasons": ["business"], "note": "lock prod", "protect_after": True})
check(not SUB and o["protection"]["assets"] == 0 and o["protection"]["already_pending"] == 7,
      "protect_after skips assets whose NO : UPDATE is already pending (no duplicate jobs)")
navi_cli.allow_writes = lambda: False
SUB.clear()
o, _ = ACRAPI.apply({"confirm": True, "category": "Tier", "value": "Prod", "score": 7, "mod": "set",
                     "reasons": ["business"], "note": "x", "protect_after": True})
check(not SUB and o["protection"]["assets"] == 0, "protect_after with writes off: nothing queued (nothing applied)")
navi_cli.allow_writes = lambda: True
o, code = ACRAPI.apply({"category": "Tier", "value": "Prod", "score": 7, "reasons": ["business"], "note": "x"})
check(code == 400, "apply still needs confirm")
pr, _ = ACRAPI.preview({"changes": [{"category": "Tier", "value": "Prod", "score": 9, "mod": "set"}]})
check(pr["totals"]["protected"] == 1 and pr["totals"]["change"] == 6, "preview action totals")
for act in ("preview", "metrics", "log", "log_export", "protect"):
    check(act in ACRAPI.ACTIONS, "ACR action exposed: " + act)

# AI ACR Raise is attributed to 'ai'
from agents.ai import api as AIAPI  # noqa: E402
AIAPI.acr_roles({"confirm": True, "roles": [next(iter(AIAPI.ai_assets.ROLE_ACR))]})
ai = acrlog.rows({"agent": "ai", "category": "AI ACR Raise"})["rows"]
check(len(ai) == 1 and ai[0]["asset_uuid"] == "" and "no asset in navi.db" in ai[0]["message"],
      "AI ACR Raise → ACR log with agent 'ai' (a change that matched no asset is still registered)")

# ------------------------------------------------------------------ AI Contract
from core import contract as C  # noqa: E402

C._candidates_ex = lambda aid, db_path=None, cfg=None: ([], None, None)
check(C.default_contract()["protect_acr"] is False, "contract: protect_acr off by default")
for v, want in ((True, True), ("true", True), ("on", True), (1, True), ("false", False), ("0", False), (None, False), ([1], False)):
    check(C.set_contract({"protect_acr": v})["protect_acr"] is want, "set_contract protect_acr %r → %s" % (v, want))
DOC = {**C.default_contract(), "acr": [{"category": "Tier", "value": "Prod", "score": 4, "mod": "set",
                                         "reasons": ["mitigation"], "note": "WAF in front"}]}
DOC["agents"] = {a: dict(x, enabled=False) for a, x in DOC["agents"].items()}
p = C.plan(DOC)
ap = p["acr_preview"][0]
check(ap["protected"] == 1 and ap["no_acr"] == 3 and ap["change"] + ap["unchanged"] == 7 and p["protect_acr"] is False,
      "plan: per-rule change / protected / no-ACR counts")
check(ap["business_case"] == "Existing Mitigation Control — WAF in front", "plan: rule business case")
sc = C.export_script(C.set_contract(DOC))
check("# navi enrich acr skips every asset tagged NO : UPDATE" in sc and "--c NO" not in sc, "export: NO : UPDATE comment; no protect line when off")
sc2 = C.export_script(C.set_contract({**DOC, "protect_acr": True}))
line = next((ln for ln in sc2.splitlines() if ln.startswith("navi enrich tag --c NO --v UPDATE --query ")), "")
check(line and "'\"'\"'a1'\"'\"'" in line and "a7" not in line and "a3" not in line,
      "export (protect on): navi enrich tag --c NO --v UPDATE --query <changed assets>, shell-quoted")
check(sc2.index("navi enrich acr") < sc2.index("navi enrich tag --c NO"), "export: protection after the ACR lines")
SUB.clear()
tagq._dbexec("UPDATE jobs SET status='error', ok=0 WHERE category='NO'")   # earlier requests: not pending
ex = C.execute({**C.set_contract({**DOC, "protect_acr": True}), "armed": True}, enforce_pause=False)
check(ex.get("acr_protected") == 7 and SUB and all(s[2]["agent"] == "contract" and s[1]["category"] == "NO" for s in SUB),
      "execute (protect on): NO : UPDATE on the 7 applied assets, agent contract")
check(acrlog.rows({"agent": "contract", "business_case": "Existing Mitigation Control — WAF in front"})["total"] == 11,
      "contract ACR rule → ACR log rows with agent 'contract'")
SUB.clear()
ex = C.execute({**C.set_contract(DOC), "armed": True}, enforce_pause=False)
check("acr_protected" not in ex and not SUB, "execute (protect off): no protection tag")

# ------------------------------------------------------------------ Tagging log CSV + pages
from agents.explore import api as XAPI  # noqa: E402
o, _ = XAPI.tag_export({"format": "csv"})
hdr = o["script"].splitlines()[0]
check(hdr.endswith(",business_case") and "Existing Mitigation Control — WAF in front" in o["script"],
      "Tagging log CSV: business_case column (appended — older imports keep working)")
o, _ = XAPI.tag_export({"format": "sh", "include_acr": True})
check("enrich acr --c Tier --v Prod --score 4 --mod set -mitigation --note 'WAF in front'" in o["script"],
      "Tagging log .sh export replays the ACR change")

# ------------------------------------------------------------------ reviewer bugs (build 442 review)
c = sqlite3.connect(DB)
c.executemany("INSERT INTO tags(asset_uuid,asset_ip,tag_key,tag_uuid,tag_value,tag_added_date) VALUES (?,'',?,'',?,'')",
              [("a1", "Owner", "Bob's"), ("a2", "Owner", "Bob's"),            # bug 1: a ' in the value
               ("a1", "Inc", "W"), ("a12", "Inc", "W"),                        # bug 2: '5' group, then 'x7'
               ("d1", "Dup", "D")])                                            # bug 3: two assets rows
c.executemany("INSERT INTO assets VALUES (?,?,?,?,'0')", [("d1", "dup", "10.0.0.20", "3"), ("d1", "dup", "10.0.0.20", "6")])
c.commit(); c.close()
SUB.clear()

# bug 1 — a ' in category/value: navi's .format() SQL fails (DB ERROR, exit 0, nothing sent)
pq = AP.preview("Owner", "Bob's", 8, "set")
check(pq["refuse"] and "'" in pq["refuse"] and pq["counts"]["change"] == 0 and pq["counts"]["refused"] == 2,
      "bug1: preview of Owner : Bob's → 0 changes, refused with the reason")
n0 = len(RAN)
r = navi_cli.acr("Owner", "Bob's", 8, reasons=["business"], agent="acr")
rq = acrlog.rows({"batch": r["acr_log"]["batch"]})["rows"]
check(len(RAN) == n0 and r.get("refused") and not r["ok"], "bug1: navi is not called")
check(rq and all(x["result"] == "failed" and "not sent" in x["message"] for x in rq), "bug1: ACR log rows are failed, never applied")
o, code = ACRAPI.apply({"confirm": True, "category": "Owner", "value": "Bob's", "score": 8, "reasons": ["business"], "note": "x"})
check(code == 400 and "'" in o["error"], "bug1: the ACR page's apply refuses it up front (400 + reason)")


class _DbErr:
    returncode, stdout, stderr = 0, "\nDB ERROR:\nselect …\nCreated the following error: near \"s\": syntax error", ""


navi_cli.subprocess.run = lambda cmd, **k: (RAN.append(list(cmd)) or _DbErr())
r = navi_cli.acr("Tier", "Prod", 8, reasons=["business"], agent="acr")
check(not r["ok"] and r["acr_log"]["counts"]["applied"] == 0 and r["acr_log"]["counts"]["failed"] == 7,
      "bug1: 'DB ERROR' in navi's stdout (exit 0) → failed, not applied")
navi_cli.subprocess.run = lambda cmd, **k: (RAN.append(list(cmd)) or _P())
CD = {**C.default_contract(), "acr": [{"category": "Owner", "value": "Bob's", "score": 8, "mod": "set", "reasons": ["business"]}]}
CD["agents"] = {k: dict(x, enabled=False) for k, x in CD["agents"].items()}
check(C.plan(CD)["acr_preview"][0]["refuse"], "bug1: the contract plan flags the rule")
check("# SKIPPED —" in C.export_script(C.set_contract(CD)) and "\nnavi enrich acr --c Owner" not in C.export_script(C.set_contract(CD)),
      "bug1: the contract export comments the rule out")

# bug 2 — inc/dec over an ACR navi can't int(): refused up front; a crash anyway logs partially
pi = AP.preview("Inc", "W", 3, "inc")
check(pi["refuse"] and pi["counts"]["refused"] == 1 and pi["counts"]["bad_acr"] == 1, "bug2: inc over 'x7' is refused up front")
n0 = len(RAN)
r = navi_cli.acr("Inc", "W", 3, mod="inc", reasons=["business"], agent="acr")
check(len(RAN) == n0 and r["acr_log"]["counts"]["applied"] == 0, "bug2: …navi is not called")
o, code = ACRAPI.apply({"confirm": True, "category": "Inc", "value": "W", "score": 3, "mod": "inc", "reasons": ["business"], "note": "x"})
check(code == 400 and "cannot read" in o["error"], "bug2: apply refuses with a clear message")
check(not AP.preview("Inc", "W", 3, "set")["refuse"], "bug2: set over the same tag is fine (navi doesn't int() the old ACR)")
praw = AP.preview("Inc", "W", 3, "inc", refuse=False)
check(praw["crash_group"] == 1, "bug2: navi's group order — '5' first, crashes on 'x7' (group 1)")
lg = acrlog.record_change(praw, {"ok": False, "returncode": 1, "stderr": "ValueError: invalid literal for int() with base 10: 'x7'"},
                          "acr", "Inc", "W", "inc", "3", ["business"], "", "Business Critical")
rr = {x["asset_uuid"]: x for x in acrlog.rows({"batch": lg["batch"]})["rows"]}
check(rr["a1"]["result"] == "applied" and rr["a1"]["acr_after"] == "8" and rr["a12"]["result"] == "failed",
      "bug2: crash part-way → groups sent before the bad one are applied, the rest failed")

# bug 3 — duplicate assets rows: one update per ACR group, the last one wins
pd = AP.preview("Dup", "D", 2, "inc")
d = pd["assets"][0]
check(len(pd["assets"]) == 1 and d["sends"] == [[0, 5], [1, 8]] and d["acr_after"] == 8 and d["acr_rows"] == ["3", "6"],
      "bug3: e-dup style asset (ACR 3 and 6), inc 2 → navi sends 5 then 8; acr_after 8")
check(navi_reference("2", "D", "Dup", "inc") == {"d1": 8}, "bug3: …same as navi's own selection (last send 8)")
r = navi_cli.acr("Dup", "D", 2, mod="inc", reasons=["business"], agent="acr")
row = acrlog.rows({"batch": r["acr_log"]["batch"]})["rows"][0]
check(row["acr_after"] == "8" and row["result"] == "applied" and "2 rows" in row["message"], "bug3: the ACR log says 3 → 8 and why")

# bug 5 — build-from-log: no bogus NO : UPDATE rule; reasons + note from the log
bl = C.build_from_log(tagq.list_jobs())["acr"]
check(bl and not any(x["category"] == "NO" for x in bl), "bug5: the protection job does not become an ACR rule")
tp = C.build_from_log([j for j in tagq.list_jobs() if "WAF in front" in (j.get("business_case") or "")])["acr"]
check(tp and tp[0]["reasons"] == ["mitigation"] and tp[0]["note"] == "WAF in front",
      "bug5: a logged rule keeps its own reasons / note (from the retained spec): %s" % tp)
bl = C.build_from_log([{"agent": "acr", "category": "X", "value": "Y", "selector": "acr set", "detail": "score=6 (set)",
                        "business_case": "In Scope For Compliance, Dev Only — PCI"},
                       {"agent": "acr", "category": "NO", "value": "UPDATE", "selector": "query"},
                       {"agent": "acr", "category": "Z", "value": "W", "selector": "query", "detail": "x"}])["acr"]
check(len(bl) == 1 and bl[0]["reasons"] == ["compliance", "development"] and bl[0]["note"] == "PCI" and bl[0]["score"] == 6,
      "bug5: from CSV rows — reasons + note rebuilt from the business case; non-ACR rows skipped")

# bug 6 — Tagging-log replay: ACR only on opt-in, only applied ones, with a warning comment
navi_cli.allow_writes = lambda: False
navi_cli.acr("Tier", "Prod", 3, reasons=["business"], note="blocked one", agent="acr")
navi_cli.allow_writes = lambda: True
o, _ = XAPI.tag_export({"format": "sh"})
check("enrich acr" not in o["script"] and o["acr_left_out"] > 0, "bug6: default export leaves every ACR change out (as build 441)")
o, _ = XAPI.tag_export({"format": "sh", "include_acr": True})
check("enrich acr" in o["script"] and "blocked one" not in o["script"] and "NOT recorded in The Hounds' ACR log" in o["script"]
      and "NO : UPDATE" in o["script"], "bug6: opt-in exports only applied ACR changes, with the warning comment")
o, _ = XAPI.tag_export({"format": "py", "include_acr": True})
check("NOT recorded in The Hounds' ACR log" in o["script"] and "blocked one" not in o["script"], "bug6: .py export too")

# bug 7 — CSV formula injection
navi_cli.acr("Tier", "Prod", 4, reasons=["business"], note="=HYPERLINK(\"http://x\")", agent="acr")
ex = acrlog.export_csv({"result": "applied"})
import csv as _csv  # noqa: E402
cells = [c for row in _csv.reader(ex["csv"].splitlines()) for c in row]
check(any(c.startswith("'=HYPERLINK") for c in cells) and not any(c.startswith("=") for c in cells),
      "bug7: ACR log CSV neutralises = cells")
o, _ = XAPI.tag_export({"format": "csv"})
check("'Business Critical — =HYPERLINK" not in o["script"] and XAPI.csv_safe("-1+1") == "'-1+1" and XAPI.csv_safe("@x") == "'@x"
      and XAPI.csv_safe("\tx") == "'\tx" and XAPI.csv_safe("ok") == "ok", "bug7: Tagging-log CSV cells guarded (= + - @ TAB CR)")
from agents.contract import api as CAPI  # noqa: E402
check(CAPI._uncsv("'=x") == "=x" and CAPI._uncsv("'quoted") == "'quoted", "bug7: the contract's CSV import undoes the guard")

# extras: non-integer scores refused up front; cache dropped after any ACR write; no-asset rows not counted
o, code = ACRAPI.apply({"confirm": True, "category": "Tier", "value": "Prod", "score": 9.5, "reasons": ["business"], "note": "x"})
check(code == 400 and "whole number" in o["error"], "extra: apply rejects score 9.5 (navi int()s it)")
o, _ = ACRAPI.bulk_apply({"confirm": True, "changes": [{"category": "Tier", "value": "Prod", "score": "7.5", "mod": "set", "reasons": ["business"]}]})
check(o["applied"] == 0 and "whole number" in o["results"][0]["message"], "extra: bulk_apply rejects 7.5")
o, code = CAPI.set_({"contract": {**CD, "acr": [{"category": "T", "value": "V", "score": 9.5, "mod": "set", "reasons": ["business"]}]}})
check(code == 400 and "whole number" in o["error"], "extra: contract set rejects an ACR rule score of 9.5")
o, code = CAPI.set_({"contract": {**CD, "acr": [{"category": "T", "value": "V", "score": 9, "mod": "set", "reasons": ["business"]}]}})
check(code == 200, "extra: …and accepts 9")
import types  # noqa: E402
_fake, _inv = types.ModuleType("core.launcher"), []
_fake._invalidate = _inv.append
_had = sys.modules.get("core.launcher")
sys.modules["core.launcher"] = _fake
navi_cli.acr("Tier", "Prod", 5, reasons=["business"], agent="contract")
AP.protect(["a1"], agent="acr")
if _had is None:
    del sys.modules["core.launcher"]
else:
    sys.modules["core.launcher"] = _had
check(_inv.count("acr") >= 2 and "contract" in _inv, "extra: every ACR write / protect drops the acr + contract result cache")
nr = acrlog.rows({"category": "AI ACR Raise"})["rows"]
check(nr and nr[0]["result"] == "no_assets" and "AI ACR Raise" not in [x["selector"].split(" : ")[0] for x in acrlog.applied_assets().values()],
      "extra: a change that matched no asset is result no_assets and is not counted as changed")
check("document.activeElement===sel" in src("web/tags-log.html"), "extra: the Tagging log doesn't rebuild an open business-case dropdown")

# ground truth: the REAL navi-pro 8.8.2 enrich.acr code (reviewer's fake navi records payloads)
FAKENAVI = "/tmp/claude-0/r3/fakenavi/navi"
if os.path.exists(FAKENAVI) and os.path.isdir("/tmp/claude-0/navisrc/x/navi"):
    fl = os.path.join(TMP, "fake.log")
    os.environ["FAKELOG"] = fl
    navi_cli.subprocess.run = _REAL_RUN
    navi_cli._resolve_navi = lambda: FAKENAVI

    def real(cat, val, score, mod):
        open(fl, "w").close()
        res = navi_cli._acr_exec(cat, val, score, mod=mod, reasons=["business"])
        sent = {}
        for ln in open(fl):
            for pl in json.loads(ln)["payload"] or []:
                for a_ in pl["asset"]:
                    sent.setdefault(a_["id"], []).append(pl["acr_score"])
        return res, sent
    for cat, val, score, mod in (("Tier", "Prod", 8, "set"), ("Tier", "Prod", 3, "inc"), ("Tier", "Prod", 4, "dec"),
                                 ("Dup", "D", 2, "inc"), ("Inc", "W", 3, "inc")):
        pv_ = AP.preview(cat, val, score, mod, refuse=False)
        res, sent = real(cat, val, score, mod)
        lg = acrlog.record_change(pv_, res, "acr", cat, val, mod, str(score), ["business"], "", "")
        logged = {x["asset_uuid"]: (x["result"], x["acr_after"]) for x in acrlog.rows({"batch": lg["batch"]})["rows"]}
        want = {u: ("applied", str(v[-1])) for u, v in sent.items()}
        got = {u: v for u, v in logged.items() if v[0] == "applied"}
        check(got == want, "real navi %s %s %s: ACR log applied/after == what navi sent %s" % (cat, val, mod, sent))
    res, sent = real("Owner", "Bob's", 8, "set")
    check(not sent and "DB ERROR" in (res.get("stdout") or ""), "real navi: a ' in the value → DB ERROR, nothing sent (why bug1 refuses)")
else:
    print("SKIP real-navi ground truth (no /tmp/claude-0/r3/fakenavi)")

pg = src("agents/acr/page.html")
check(all(x in pg for x in ('id="secGlance" data-nav=', 'id="secProtect" data-nav=', "mountSectionNav()", "setNavCount(",
                            "renderGlance('glxAcr'", "mountAgentHeader({id:'acr'")), "ACR page: data-nav sections, jump nav, shared glance template, header id")
check('class="mk' not in pg and not re.search(r"^\s*\.(mkpi|mk|mhead)\b", pg, re.M), "ACR page: no page-local .mk/.mkpi cards (the shared template is phone-safe)")
check("confirm('Tag '+N(n)+' asset" in pg and 'category "NO", value "UPDATE"' in pg and "Garmr" in pg,
      "ACR page: protect confirm names the exact tag + asset count; removal → Garmr")
check(pg.count("previewText(") >= 3 and "protected by NO : UPDATE — navi skips them" in pg and "without an ACR in navi.db" in pg,
      "ACR page: every apply confirm shows the preview counts")
check("protect_after:protectAfter" in pg and 'id="acrProtectAfter"' in pg and 'id="bulkProtectAfter"' in pg
      and "checked" not in re.search(r'<input type="checkbox" id="acrProtectAfter"[^>]*>', pg).group(0),
      "ACR page: protect after applying, off by default")
check(not re.search(r"onclick=\"[^\"]*\$\{", pg) and "remove=True" not in pg and "-remove" not in pg,
      "ACR page: no inline JS built from data; never removes a tag")
lg = src("web/acr-log.html")
check(all(x in lg for x in ("API.post('log'", "log_export", 'data-k="business_case"', 'id="fBc"', 'id="fAgent"', 'id="fResult"',
                            'id="fFrom"', 'id="fQ"')), "ACR log page: sortable business case, filters, search, CSV")
check("['🎯 ACR log',       '/web/acr-log.html']" in src("web/assets/console.js") and "/web/acr-log.html" in src("web/tools.html")
      and "/web/acr-log.html" in pg and "/web/acr-log.html" in src("web/tags-log.html"), "ACR log linked from Tools, the ACR page and the Tagging log")
tl = src("web/tags-log.html")
check('data-k="business_case"' in tl and 'id="fBc"' in tl and "j.business_case" in tl, "Tagging log: sortable / filterable Business case column")
cp = src("agents/contract/page.html")
check('id="protectAcrChk"' in cp and "C.protect_acr=" in cp and "acr_preview" in cp, "contract page: protect option + per-rule protected counts")

print("\n%d failure(s)" % len(fails))
if fails:
    sys.exit(1)
