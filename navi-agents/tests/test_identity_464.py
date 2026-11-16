"""Regression tests — build 464: Identity (Janus) on the payload contract.

The ▶ Run ships the decision data + page 1 (no account list, no uuid arrays); the identity list,
its filters and search page on the server; every tag button sends a KEY and the server rebuilds
the exact hosts — the same hosts the old uuid-carrying buttons sent.
Run: python3 tests/test_identity_464.py"""
import atexit
import json
import re
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-464i-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db"), "NAVI_DB_PATH": os.path.join(TMP, "navi.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


U = ["%08x-0000-0000-0000-000000000000" % i for i in range(300)]
ACCTS = [{"user": "svc_deploy", "klass": "service", "asset_uuids": U[0:120], "hosts": ["h%d" % i for i in range(120)],
          "flags": ["account reuse ×120", "privileged", "on KEV host"], "reuse_uuids": U[0:120], "plugins": [95928]},
         {"user": "jenkins", "klass": "nhi", "asset_uuids": [U[200]], "hosts": ["ci"], "flags": ["non-expiring pw"]},
         {"user": "alice", "klass": "human", "asset_uuids": [U[201], U[202]], "hosts": ["a", "b"], "flags": ["privileged", "on critical host"]},
         {"user": "bob", "klass": "human", "asset_uuids": [U[203]], "hosts": ["c"], "flags": []},
         {"user": "HOST$", "klass": "machine", "asset_uuids": [U[204]], "hosts": ["d"], "flags": ["on KEV host"]}]
for a in ACCTS:
    a["risky"] = [f for f in a["flags"] if f != "scan credential"]
    a["reused"] = 120 if a["user"] == "svc_deploy" else 0
    a["crown_hosts"] = 1 if a["user"] == "alice" else 0
    a["max_acr"] = 9 if a["user"] == "alice" else 3
FULL = {"ok": True, "accounts": ACCTS, "counts": {"total": 5, "human": 2, "nhi": 1, "service": 1, "machine": 1,
                                                  "reused": 1, "reused_hosts": 120, "flagged": 4},
        "host_sets": {"ssh password auth": U[0:3], "on KEV host": U[0:5], "uncredentialed": U[250:300]},
        "metrics": {"identity_hosts": 125, "blind": 50}, "scan_creds": []}

from agents.identity import api  # noqa: E402
from core import navi_cli  # noqa: E402

api.scan_full = lambda: json.loads(json.dumps(FULL))
TAGGED = []
navi_cli.tag_uuids_batched = lambda cat, val, uu, agent=None: (TAGGED.append((cat, val, sorted(uu))) or
                                                               [{"ok": True, "job_id": len(TAGGED)}])
navi_cli.jobs_summary = lambda jobs: {"result": {"ok": True, "job_id": jobs[0]["job_id"]}, "jobs": jobs,
                                      "job_ids": [j["job_id"] for j in jobs]}

o, st = api.run({})
body = json.dumps(o)
r = o["result"]
check(st == 200 and o["ok"] and "accounts" not in r and "host_sets" not in r and U[100] not in body,
      "run ships no account list and no uuid arrays (%d bytes)" % len(body))
check(r["accounts_total"] == 5 and r["view"]["host_sets"] == {"ssh password auth": 3, "on KEV host": 5, "uncredentialed": 50}
      and r["view"]["auth_ids"]["on KEV host"] == 1 and r["view"]["classes"]["human"] == 2,
      "decision data counted on the server (signals, identities per signal, classes)")
check(dict(r["view"]["flag_top"]).get("privileged") == 2 and dict(r["view"]["flag_top"]).get("account reuse ≥ 5 hosts") == 1,
      "most common risk flags counted over every identity")
run = o["drill"]["run"]
check(len(o["top"]) == 5 and all("asset_uuids" not in x and "reuse_uuids" not in x for x in o["top"])
      and o["top"][0]["assets_n"] == 120 and len(o["top"][0]["hosts"]) == api.HOSTS_SHOWN and o["top"][0]["hosts_n"] == 120,
      "page rows are slim: host / asset counts, the first hosts, no uuid arrays")


def ids(flt=None, q=""):
    d, _ = api.drill({"run": run, "section": "ids", "filter": flt or [], "q": q, "limit": 200})
    return sorted(x["user"] for x in d["top"])


check(ids(["g:human"]) == ["alice", "bob"] and ids(["g:service"]) == ["jenkins", "svc_deploy"] and ids(["g:machine"]) == ["HOST$"],
      "group filters (human / service+NHI / machine) on the server")
check(ids(["f:privexp"]) == ["alice", "svc_deploy"] and ids(["f:kev"]) == ["svc_deploy"] and ids(["f:crown"]) == ["alice"]
      and ids(["reused"]) == ["svc_deploy"] and ids(["flagged"]) == ["HOST$", "alice", "jenkins", "svc_deploy"],
      "metric-card filters match the page's rules (KEV / crown skip machine identities)")
check(ids(q="jenk") == ["jenkins"] and ids(["g:human"], "ali") == ["alice"], "server-side search (+ filter)")
d, st = api.drill({"run": run, "section": "ids", "filter": ["role:x"]})
check(st == 400, "undeclared filter → 400")
rd, _ = api.drill({"run": run, "section": "reuse"})
check([x["user"] for x in rd["top"]] == ["svc_deploy"], "account-reuse section")


def tag(**kw):
    return api.tag(dict(kw, confirm=True))


rk = {x["user"]: x["rk"] for x in o["top"]}
dry, _ = api.tag({"category": "Identity", "value": "svc_deploy", "set": {"run": run, "kind": "id", "rk": rk["svc_deploy"]}, "dry": True})
check(dry["ok"] and dry["dry"] and dry["assets"] == 120 and not TAGGED, "dry run counts (no confirm, nothing written)")
b, st = api.tag({"category": "Identity", "value": "x", "set": {"run": run, "kind": "id", "rk": rk["alice"]}})
check(st == 400 and not TAGGED, "a key tag without confirm → 400")
b, _ = tag(category="Identity", value="svc_deploy", set={"run": run, "kind": "id", "rk": rk["svc_deploy"]})
check(TAGGED[-1] == ("Identity", "svc_deploy", sorted(U[0:120])), "row Tag → that identity's exact hosts")
tag(category="NHI", value="Non-human identity", set={"run": run, "kind": "union", "filter": ["k:nhi"]})
check(TAGGED[-1] == ("NHI", "Non-human identity", [U[200]]), "class button (NHI) → union of the class's hosts")
n0 = len(TAGGED)
tag(category="Owner", value="", set={"run": run, "kind": "each", "filter": ["k:human"], "category": "Owner"})
check(TAGGED[n0:] == [("Owner", "alice", sorted(U[201:203])), ("Owner", "bob", [U[203]])],
      "Human → Owner : <name>, one tag per identity")
n0 = len(TAGGED)
tag(category="Identity", value="", set={"run": run, "kind": "each", "filter": ["f:privileged"], "q": ""})
check(sorted(TAGGED[n0:]) == sorted([("Identity", "svc_deploy", sorted(U[0:120])), ("Identity", "alice", sorted(U[201:203]))]),
      "Tag shown → one Identity / NHI / Machine ID tag per shown identity")
tag(category="Identity Risk", value="Account Reuse", set={"run": run, "kind": "reuse"})
check(TAGGED[-1] == ("Identity Risk", "Account Reuse", sorted(U[0:120])), "Tag account-reuse hosts")
tag(category="Identity Coverage", value="No Credentials", set={"run": run, "kind": "hs", "key": "uncredentialed"})
check(TAGGED[-1] == ("Identity Coverage", "No Credentials", sorted(U[250:300])), "Tag uncredentialed hosts")
b, st = tag(category="Identity Risk", value="x", set={"run": run, "kind": "hs", "key": "DROP TABLE"})
check(st == 400, "unknown host signal → 400")
n0 = len(TAGGED)
tag(category="", value="", set={"run": run, "kind": "assign", "list": [{"user": "jenkins", "category": "NHI", "value": "automation"},
                                                                        {"user": "nobody", "value": "x"}]})
check(TAGGED[n0:] == [("NHI", "automation", [U[200]])], "model proposals → tags by account name (unknown names skipped)")
b, st = tag(category="Identity", value="x", set={"run": "identity-gone", "kind": "id", "rk": "i0"})
check(st == 400 and b.get("expired"), "a key for a pruned run → 400 expired")

pg = open(os.path.join(ROOT, "agents", "identity", "page.html"), encoding="utf-8").read()
check(not re.search(r"IDENT\.accounts(?!_total)", pg) and "asset_uuids" not in pg
      and "hDrill(" in pg and "search:'idQ'" in pg and "{prompt:q,run:RUN}" in pg,
      "page: server-paged list + search, key tags, the model reads the stored run")
print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
