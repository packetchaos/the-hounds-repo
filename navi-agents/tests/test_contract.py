"""Regression tests for the AI Contract (Covenant) — it must orchestrate EVERY tagging agent and
plan exactly the tags each agent's own page would apply: Asset Classification (Linnaeus), Attack
Paths (Fenrir), WAS (Arachne), Exposure Score (Nemesis), Compliance owner (Minos), Asset
Ownership (Terminus), Atlas owner mappings, the CISA KEV date / due / ransomware tags, and the
fixed adapters (identity: account reuse only, scan health keys, IoT inventory scheme, EOL by
plugin name). Also: an older saved contract (no new agents) still loads, no adapter ever emits
remove=True, and no --query passes the OS per-argument limit (UUID lists are chunked).
Tiny synthetic navi.db in a temp dir; navi_cli.tag / tag_capped are recorded, no navi, no network.
Run: python3 tests/test_contract.py  (or pytest)."""
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
TMP = tempfile.mkdtemp(prefix="hounds-contract-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ["CONTRACT_DIR"] = os.path.join(TMP, "contracts")
os.environ["HOUNDS_CONFIG"] = os.path.join(TMP, "cfg.json")
os.environ["NAVI_HISTORY_DIR"] = os.path.join(TMP, "hist")
os.environ["NAVI_TAGLOG_DB"] = os.path.join(TMP, "taglog.db")
os.environ.pop("ANTHROPIC_API_KEY", None)
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB

from core import navi_cli  # noqa: E402

TAGGED = []
navi_cli.tag = lambda *a, **k: (TAGGED.append(("tag", a, k)) or {"ok": True, "queued": True, "job_id": len(TAGGED)})
navi_cli.tag_capped = lambda *a, **k: (TAGGED.append(("capped", a, k)) or [{"ok": True, "job_id": len(TAGGED)}])
navi_cli.explore_info = lambda sub: {"ok": True, "stdout": ""}          # no live Tenable calls
navi_cli.acr = lambda *a, **k: {"ok": True}

from core import contract as C, llm  # noqa: E402

llm.available = lambda: False                                          # key-free paths only
ARG_LIMIT = 128 * 1024

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# ----------------------------------------------------------------------------- fixture
U = ["u%04d-0000-0000-0000-000000000000" % i for i in range(12)]
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, operating_system TEXT, acr TEXT, aes INTEGER);
CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, plugin_family TEXT, severity TEXT,
                    score REAL, cves TEXT, xrefs TEXT, state TEXT, first_found TEXT, last_found TEXT, output TEXT);
CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE compliance (asset_uuid TEXT, check_id TEXT, check_name TEXT, audit_file TEXT, status TEXT,
                         reference TEXT);
CREATE TABLE apps (name TEXT, target TEXT, uuid TEXT, config_id TEXT, asset_uuid TEXT, scan_completed_time TEXT,
                   pages_crawled INTEGER, requests_made INTEGER, critical_count INTEGER, high_count INTEGER,
                   medium_count INTEGER, low_count INTEGER, info_count INTEGER, owasp TEXT, tech_list TEXT,
                   notes TEXT);
CREATE TABLE findings (asset_uuid TEXT);
CREATE TABLE vuln_route (route_id TEXT, app_name TEXT, vuln_type TEXT, total_vulns INTEGER, plugin_list TEXT);
CREATE TABLE vuln_paths (asset_uuid TEXT, path TEXT, plugin_id TEXT);
CREATE TABLE software (asset_uuid TEXT, software_string TEXT);
CREATE TABLE certs (asset_uuid TEXT, common_name TEXT, issuer_name TEXT, not_valid_after TEXT, not_valid_before TEXT,
                    organization TEXT, organization_unit TEXT, key_length TEXT, signature_algorithm TEXT, public_key_algorithm TEXT);""")
OS = {0: "Microsoft Windows Server 2016 Standard", 1: "Ubuntu 22.04", 2: "Ubuntu 22.04", 3: "", 4: "Microsoft Windows 10 Pro"}
for i, u in enumerate(U):
    c.execute("INSERT INTO assets VALUES (?,?,?,?,?,?)",
              (u, "host%d" % i, "10.0.0.%d" % i, OS.get(i, ""), "9" if i == 0 else "5", 0))
KEV = "{'type': 'CISA-KNOWN-EXPLOITED', 'id': '2022/01/10'}"
c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", [
    (U[0], "1001", "Apache Log4j RCE", "General", "critical", 10.0, "CVE-2021-44228", KEV, "open",
     "2021-12-11T00:00:00.000Z", "2026-11-01T00:00:00.000Z", ""),
    # build 453: KEV due/ransomware tags are now the analysis' own SQL rule (core.kev.cve_tag_query),
    # so the stubbed catalog row CVE-2099-0001 → U[1] must exist in navi.db as an open finding
    (U[1], "1002", "OpenSSH flaw", "General", "high", 8.0, "CVE-2099-0001", "", "open",
     "2025-01-01T00:00:00.000Z", "2026-11-01T00:00:00.000Z", ""),
    (U[5], "1003", "Info", "General", "info", 0, "", "", "open",
     "2025-01-01T00:00:00.000Z", "2026-11-01T00:00:00.000Z", ""),
    (U[8], "1004", "Unsupported Windows OS", "Windows", "critical", 10.0, "", "", "open",
     "2025-01-01T00:00:00.000Z", "2026-11-01T00:00:00.000Z", "")])
c.executemany("INSERT INTO tags VALUES (?,?,?)", [
    (U[4], "Asset Inventory", "OS: Windows 10"),             # already classified → not a signal
    (U[0], "Environment", "Production"), (U[1], "Environment", "Production"),
    (U[2], "Environment", "Lab")])
c.executemany("INSERT INTO compliance VALUES (?,?,?,?,?,?)", [
    (U[0], "CIS-1.1", "Password length", "cis.audit", "FAILED", ""),
    (U[1], "CIS-1.1", "Password length", "cis.audit", "FAILED", ""),
    (U[2], "CIS-1.1", "Password length", "cis.audit", "PASSED", ""),
    (U[2], "CIS-2.2", "SMB signing", "cis.audit", "FAILED", ""),
    (U[3], "CIS-3.3", "All good", "cis.audit", "PASSED", "")])
c.executemany("INSERT INTO apps VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [
    ("shop", "https://shop", "app1", "c1", U[6], "", 1, 1, 2, 0, 0, 0, 5, "", "", ""),
    ("blog", "https://blog", "app2", "c2", U[7], "", 1, 1, 0, 1, 0, 0, 5, "", "", ""),
    ("orphan", "https://x", "app3", "c3", "", "", 1, 1, 3, 0, 0, 0, 0, "", "", "")])
c.executemany("INSERT INTO vuln_route VALUES (?,?,?,?,?)", [
    ("11", "Payments API", "app", 40, "['1001']"), ("12", "Payments API", "app", 3, "['1002']"),
    ("13", "ICMP Timestamp", "net", 2, "['1003']")])
c.executemany("INSERT INTO vuln_paths VALUES (?,?,?)", [(U[0], "/opt/payments", "1001")])
c.commit()
c.close()


def specs_of(aid, cfg=None):
    items, err = C._candidates(aid, cfg=cfg or C.agent_default(aid))
    return items, err


def run_sql(q):
    con = sqlite3.connect(DB)
    try:
        return sorted({r[0] for r in con.execute(q)})
    finally:
        con.close()


# ------------------------------------------------- 1. every tagging agent is orchestrated
TAG_ACT = re.compile(r"^(tag|tag_\w+|tags_\w+|apply|bulk_apply|assign|retag|roadmap_tag|remove)$")
taggers_found = set()
for d in sorted(os.listdir(os.path.join(ROOT, "agents"))):
    api = os.path.join(ROOT, "agents", d, "api.py")
    man = os.path.join(ROOT, "agents", d, "manifest.json")
    if not (os.path.exists(api) and os.path.exists(man)):
        continue
    if json.load(open(man, encoding="utf-8")).get("hidden"):
        continue                                   # hidden pages (explore's tag-queue tools, hub …)
    src = open(api, encoding="utf-8").read()
    m = re.search(r"ACTIONS\s*=\s*\{(.*?)\}", src, re.S)
    acts = re.findall(r'"([a-z_]+)"\s*:', m.group(1)) if m else []
    if any(TAG_ACT.match(a) for a in acts) and ("navi_cli" in src or "engine" in src or "tag_" in src):
        taggers_found.add(d)
missing = sorted(a for a in taggers_found if a not in C.TAGGERS and a not in C.AGENT_EXCLUDED)
check(not missing, "every agent with a tag action is in TAGGERS or documented in AGENT_EXCLUDED (missing: %s)" % missing)
for a in ("classify", "attackpath", "was", "fused_score", "compliance", "asset_ownership"):
    check(a in C.TAGGERS, "%s is a contract tagger" % a)
check(set(C.TAGGERS) == set(C._ADAPTERS), "every TAGGERS entry has an adapter (and vice versa)")
check(set(C.TAGGERS) <= set(C.AGENT_INFO), "every tagger has a page label/description")
check(not (set(C.TAGGERS) & set(C.AGENT_EXCLUDED)), "no agent is both orchestrated and excluded")

# ------------------------------------------------- 2. defaults + old saved contract still loads
d = C.default_contract()
check(all(d["agents"][a]["enabled"] for a in ("classify", "attackpath", "was", "fused_score")),
      "new automatic taggers default to enabled")
check(not d["agents"]["compliance"]["enabled"] and d["agents"]["compliance"]["owner"] == "",
      "compliance (needs an owner name) defaults to disabled with an empty owner")
check(not d["agents"]["asset_ownership"]["enabled"] and not d["agents"]["exproute"]["enabled"],
      "owner-mapping agents (Terminus, Atlas) default to disabled")
OLD = ["iot_squad", "customapp", "exproute", "eol", "software", "ai", "identity", "mitre", "scan_eval",
       "certificate", "cisakev", "postquantum", "agentgroup"]
old = {"name": "legacy", "armed": False, "schedule_hours": 6, "defaults": {"top_n": 7, "rank": "risk"},
       "agents": {a: {"enabled": a != "mitre", "logic": "keep it" if a == "exproute" else ""} for a in OLD},
       "acr": [], "bogus_key": 1}
os.makedirs(os.environ["CONTRACT_DIR"], exist_ok=True)
with open(os.path.join(os.environ["CONTRACT_DIR"], "legacy.json"), "w") as f:
    json.dump(old, f)
ld = C.load("legacy")
check(set(ld["agents"]) >= set(C.TAGGERS), "an old saved contract loads with every current tagger present")
check(ld["agents"]["exproute"] == {"enabled": True, "logic": "keep it"} and not ld["agents"]["mitre"]["enabled"],
      "saved per-agent choices survive the merge")
check(ld["agents"]["classify"]["enabled"] and not ld["agents"]["compliance"]["enabled"]
      and ld["agents"]["compliance"]["checks"] == [], "missing agents get their defaults (incl. extra keys)")
check(ld["schedule_hours"] == 6 and ld["defaults"]["top_n"] == 7 and "bogus_key" not in ld,
      "other saved settings kept, unknown keys dropped")
part = C.set_contract({"agents": {"compliance": {"enabled": True, "owner": "Ann"}}})
check(part["agents"]["compliance"] == {"enabled": True, "logic": "", "owner": "Ann", "checks": []},
      "a partial agent entry is filled with the agent's default keys")
C.set_contract(C.default_contract())

# ------------------------------------------------- 3. new adapters on the fixture
# Asset Classification — untagged assets with an OS / device signal
items, err = specs_of("classify")
vals = {i["spec"]["value"] for i in items}
check(err is None and items and all(i["spec"]["category"] == "Asset Inventory" for i in items),
      "classify → category Asset Inventory")
check(any(v.startswith("OS: ") for v in vals), "classify → 'OS: <os>' values from OS signals (%s)" % sorted(vals))
classified = {u for i in items for u in run_sql(i["spec"]["query"])}
check(U[4] not in classified, "classify skips an asset that already carries an inventory tag")
check(U[0] in classified and U[1] in classified, "classify tags the untagged Windows / Ubuntu hosts")

# Attack Path — entries that reach a crown jewel + targets (stubbed engine result)
_real_run = C._agent_run


def fake_run(aid):
    if aid == "attackpath":
        return {"entries": [{"uuid": U[1], "reaches_any": True}, {"uuid": U[2], "reaches_any": False}],
                "reachable": [U[0]], "paths": []}
    if aid == "identity":
        return {"accounts": [{"user": "svc_deploy", "klass": "service", "asset_uuids": [U[1], U[2]],
                              "flags": ["account reuse ×5"], "reuse_uuids": [U[1], U[2]]},
                             {"user": "jenkins", "klass": "nhi", "asset_uuids": [U[3]], "flags": []},
                             {"user": "HOST$", "klass": "machine", "asset_uuids": [U[0]], "flags": []}],
                "host_sets": {"ssh password auth": [U[2]], "uncredentialed": [U[5]]}}
    if aid == "iot_squad":
        return {"tag_actions": [{"value": "Camera", "facet": "Device Type", "asset_count": 3,
                                 "selectors": [{"plugin": 42, "output": "Hikvision"}, {"name": "Axis"}]}]}
    return _real_run(aid)


C._agent_run = fake_run
C._identity_full = lambda: fake_run("identity")      # build 464: the adapter reads the engine
C._attackpath_full = lambda: fake_run("attackpath")
items, err = specs_of("attackpath")
by = {i["spec"]["value"]: run_sql(i["spec"]["query"]) for i in items}
check(err is None and {i["spec"]["category"] for i in items} == {"Attack Path"}, "attackpath → category Attack Path")
check(by.get("Entry Point") == [U[1]], "Entry Point = only entries that reach a crown jewel")
check(by.get("Target") == [U[0]], "Target = the reachable crown jewels")

# WAS — tag_plan cohorts on each app's asset_uuid (apps without one are skipped)
from core import was as W  # noqa: E402
items, err = specs_of("was")
got = {(i["spec"]["category"], i["spec"]["value"]): run_sql(i["spec"]["query"]) for i in items}
check(err is None and got.get(("WAS Severity", "Critical")) == [U[6]], "WAS Severity : Critical → shop's asset only")
check(got.get(("WAS Severity", "High")) == [U[7]], "WAS Severity : High → blog's asset")
check(all("FROM apps" in i["spec"]["query"] for i in items), "WAS tags select over apps.asset_uuid (like api.tag)")
tt = W.tag_targets(dimension="severity", key="critical")
check(tt and sorted(tt["uuids"]) == got.get(("WAS Severity", "Critical")), "WAS targets == was.tag_targets")

# Exposure Score — Priority : P1 on select_uuids(threshold=80)
from core import fused_score as F  # noqa: E402
items, err = specs_of("fused_score")
want = sorted(F.select_uuids(threshold=80))
got = sorted({u for i in items for u in run_sql(i["spec"]["query"])})
check(err is None and items and {(i["spec"]["category"], i["spec"]["value"]) for i in items} == {("Priority", "P1")},
      "fused_score → Priority : P1")
check(got == want and got, "P1 set == fused_score.select_uuids(threshold=80) (server-side)")

# Compliance — needs an owner; with one, Audit Owner on assets failing each control
items, err = specs_of("compliance")
pl = C.plan({**C.default_contract(), "agents": {"compliance": {"enabled": True, "owner": ""}}})
blk = [b for b in pl["agents"] if b["agent"] == "compliance"][0]
check(not items and blk.get("needs_input") and not blk.get("error"),
      "compliance without an owner plans nothing and says it needs input (not an error)")
items, err = specs_of("compliance", {"enabled": True, "owner": "Jane Smith", "checks": []})
got = {i["unit"]: run_sql(i["spec"]["query"]) for i in items}
check(all(i["spec"]["category"] == "Audit Owner" and i["spec"]["value"] == "Jane Smith" for i in items),
      "compliance → Audit Owner : <configured owner>")
check(got == {"check:CIS-1.1": [U[0], U[1]], "check:CIS-2.2": [U[2]]},
      "one candidate per FAILING control, exactly control_targets' assets (%s)" % got)
from core import compliance as CO  # noqa: E402
check(sorted(CO.control_targets(check_id="CIS-1.1")["uuids"]) == got["check:CIS-1.1"],
      "compliance SQL == compliance.control_targets")
items, _ = specs_of("compliance", {"enabled": True, "owner": "Jane", "checks": ["CIS-2.2"]})
check([i["unit"] for i in items] == ["check:CIS-2.2"], "compliance.checks restricts to the listed controls")

# Asset Ownership — the policy line is the owner instruction (rule parser, no model)
items, err = specs_of("asset_ownership")
check(not items and err is None, "asset_ownership with no instruction plans nothing")
items, err = specs_of("asset_ownership", {"enabled": True, "logic": "assign Jane Smith to production"})
check(err is None and items and items[0]["spec"]["category"] == "Business Owner",
      "asset_ownership → Business Owner : <owner> (%s)" % (items[0]["spec"] if items else err))
check(items and run_sql(items[0]["spec"]["query"]) == [U[0], U[1]],
      "Business Owner lands on the assets the instruction matched (Environment: Production)")

# Atlas owner mapping — a disposition parsed locally, route tagged by --route_id
items, err = specs_of("exproute", {"enabled": True, "logic": "ignore the ICMP route"})
check(err is None and items and all(i["spec"]["category"] == "Owner" for i in items),
      "exproute → category Owner (%s)" % ([i["spec"] for i in items] or err))
check(items and items[0]["spec"].get("route_id") == "13" and items[0]["spec"]["value"].startswith("ICMP Timestamp: "),
      "exproute → '<route>: <owner>' via the native --route_id selector")
items, _ = specs_of("exproute", {"enabled": True, "logic": ""})
check(not items, "exproute with no owner mapping plans nothing (never a bare 'Route' tag)")

# CISA KEV — Vulnerable + per-date (xrefs) + ransomware / due date (catalog, stubbed)
import agents.cisakev.api as KA  # noqa: E402
KA._cves_for = lambda pred, p: [r for r in [
    {"cve": "CVE-2021-44228", "due_date": "2021-12-24", "ransomware": True, "uuids": [U[0]]},
    {"cve": "CVE-2099-0001", "due_date": "2022-05-03", "ransomware": False, "uuids": [U[1]]}] if pred(r)]
items, err = specs_of("cisakev")
sp = {(i["spec"]["category"], i["spec"]["value"]): i["spec"] for i in items}
check(sp.get(("CISA KEV", "Vulnerable"), {}).get("xrefs") == "CISA-KNOWN-EXPLOITED", "KEV Vulnerable via --xrefs")
check(sp.get(("CISA KEV", "Jan - 10 - 2022"), {}).get("xid") == "2022/01/10", "KEV date tag via --xrefs --xid")
check(run_sql(sp.get(("CISA KEV", "Ransomware"), {}).get("query", "SELECT 1 WHERE 0")) == [U[0]],
      "CISA KEV : Ransomware on the ransomware-linked CVE's assets")
check(run_sql(sp.get(("CISA KEV Due", "2022-05-03"), {}).get("query", "SELECT 1 WHERE 0")) == [U[1]],
      "CISA KEV Due : <date> per catalog due date")

# ------------------------------------------------- 4. fixed adapters keep the agent's scheme
items, _ = specs_of("identity")
cats = {(i["spec"]["category"], i["spec"]["value"]) for i in items}
check(("Identity Risk", "Account Reuse") in cats, "identity → Identity Risk : Account Reuse")
check(not any("password" in v.lower() and "reuse" in v.lower() for _c, v in cats), "no password-reuse tag anywhere")
check(("Identity", "svc_deploy") in cats and ("NHI", "jenkins") in cats and ("Machine ID", "HOST$") in cats,
      "identity per-account categories match the page (Identity / NHI / Machine ID)")
check(("Identity Risk", "SSH Password Auth") in cats and ("Identity Coverage", "No Credentials") in cats,
      "identity auth signals + coverage gap")
items, _ = specs_of("iot_squad")
check(items and {i["spec"]["category"] for i in items} == {"Asset Inventory"}
      and {i["spec"]["value"] for i in items} == {"Device Type: Camera"},
      "iot_squad → Asset Inventory : 'Device Type: <device>' (tags_apply scheme)")
check(items and items[0]["spec"].get("plugin") == "42" and items[1]["spec"].get("plugin_name") == "Axis",
      "iot_squad keeps one navi built-in selector per command")
items, _ = specs_of("scan_eval")
import agents.scan_eval.api as SA  # noqa: E402
check(items and all(i["spec"]["category"] == "Scan Health" and i["spec"]["value"] in SA.VALUES.values() for i in items),
      "scan_eval → Scan Health : <one of the agent's VALUES>")
items, _ = specs_of("eol")
check(any(i["spec"]["category"] == "Lifecycle" for i in items)
      and all(i["spec"].get("plugin_name") for i in items if i["spec"]["category"] == "Lifecycle"),
      "eol Lifecycle groups use the --name (plugin name) selector like eol.apply")

# ------------------------------------------------- 5. never remove; queries stay small
big = ["b%05d-1111-2222-3333-444444444444" % i for i in range(4000)]
F_sel = F.select_uuids
F.select_uuids = lambda **k: big
items, _ = specs_of("fused_score")
F.select_uuids = F_sel
lens = [len(i["spec"]["query"].encode()) for i in items]
check(len(items) == 3 and max(lens) < ARG_LIMIT and len({i["unit"] for i in items}) == 1,
      "4,000 UUIDs → 3 chunked --query candidates of one tag (max %d bytes)" % max(lens))
check(all(len(re.findall(r"'b\d{5}-", i["spec"]["query"])) <= C.CHUNK_UUIDS for i in items),
      "no chunk inlines more than CHUNK_UUIDS UUIDs")
huge = [{"label": "x", "rank": 1, "unit": "x", "spec": {"category": "A", "value": "B", "remove": False,
         "query": "SELECT uuid AS asset_uuid FROM assets WHERE uuid IN (" + ",".join("'%s'" % u for u in big) + ")"}}]
split = C._enforce_size(huge)
check(len(split) == 3 and all(len(s["spec"]["query"].encode()) < C.MAX_QUERY_BYTES for s in split)
      and sum(len(re.findall(r"'b\d{5}-", s["spec"]["query"])) for s in split) == 4000,
      "the size safety net splits an oversized IN (...) list without losing UUIDs")
sel, _n = C._select("fused_score", items, "", 1)
check(len(sel) == 3, "top-N selects whole tags: all chunks of a kept tag are kept together")

full = C.default_contract()
for a in C.TAGGERS:
    full["agents"][a]["enabled"] = True
full["agents"]["compliance"]["owner"] = "Jane Smith"
full["agents"]["asset_ownership"]["logic"] = "assign Jane Smith to production"
full["agents"]["exproute"]["logic"] = "ignore the ICMP route"
full["defaults"]["top_n"] = 500
pl = C.plan(full)
allspecs = [it["spec"] for b in pl["agents"] for it in b["items"]]
check(len(allspecs) > 10, "a full plan over the fixture plans tags (%d commands)" % len(allspecs))
check(all(s.get("remove") is False for s in allspecs), "no adapter emits remove=True")
check(all(len((s.get("query") or "").encode()) < ARG_LIMIT for s in allspecs), "every --query is under 128 KB")
SEL = ("query", "plugin", "plugin_name", "xrefs", "group", "route_id", "cve")
check(all(sum(1 for k in SEL if s.get(k)) == 1 for s in allspecs), "every spec carries exactly ONE selector")
agents_with_tags = {b["agent"] for b in pl["agents"] if b["items"]}
check({"classify", "attackpath", "was", "fused_score", "compliance", "asset_ownership", "exproute"} <= agents_with_tags,
      "the new agents all plan tags in a full plan (%s)" % sorted(agents_with_tags))
script = C.export_script(full)
check("-remove" not in script and script.count("navi enrich tag") == len(allspecs),
      "exported navi script is add-only: one add per planned tag, nothing removed")
full["removal"] = {"enabled": True, "tags": [{"category": "Old", "value": "Stale"}], "pause_minutes": 1,
                   "navi_update": True}
script = C.export_script(full)
check(script.count("-remove") == 1 and "--c Old --v Stale -remove || true" in script
      and script.count("navi enrich tag") == len(allspecs) + 1,
      "export removes ONLY the contract's removal list")
full["removal"] = C.default_contract()["removal"]

# shell quoting: every value is one inert shell word
evil = {"category": "A$(touch /tmp/pwn)", "value": "x`id`\"; rm -rf ~ #", "plugin": "1; id", "remove": False}
import shlex as _shlex  # noqa: E402
cmd = C._cmd_for_spec(evil)
toks = _shlex.split(cmd)
check(toks[:8] == ["navi", "enrich", "tag", "--c", evil["category"], "--v", evil["value"], "--plugin"]
      and toks[8] == "1; id" and len(toks) == 9, "export quotes $(), backticks, quotes and ; as literal text")
_acr = dict(C.default_contract(), acr=[{"category": "T'x", "value": "$(id)", "score": "9; id", "mod": "rm", "reasons": ["x"]}])
_acr["agents"] = {a: dict(v, enabled=False) for a, v in _acr["agents"].items()}
sc = C.export_script(C.set_contract(_acr))
check("navi enrich acr --c 'T'\"'\"'x' --v '$(id)' --score 8 --mod set -business" in sc,
      "ACR export: score/mod/reasons sanitised, text quoted")

TAGGED.clear()
full["armed"] = True
ex = C.execute(full)
check(ex.get("ok") and ex["queued_tags"] == len(allspecs) == len(TAGGED), "armed execute queues every planned tag")
check(all(not k.get("remove") for _kind, _a, k in TAGGED), "execute never queues a removal")
check(all(k.get("agent") in C.TAGGERS for _kind, _a, k in TAGGED), "each queued tag is attributed to its agent")
full["armed"] = False
TAGGED.clear()
check(not C.execute(full).get("ok") and not TAGGED, "a disarmed contract writes nothing")

# manual runs (enforce_pause=False) never sleep wait_minutes
_slept = []
_ts = C.time.sleep
C.time.sleep = lambda x: _slept.append(x)
full["armed"] = True
full["wait_minutes"] = 5
C.execute(full, enforce_pause=False)
check(not _slept, "a manual run skips the between-agent wait")
C.execute(full)
check(_slept and _slept[0] == 300, "the autonomous loop still waits wait_minutes")
C.time.sleep = _ts
full["wait_minutes"] = 0

# removal without a pause holds those tags until the next cycle (no add/remove race)
TAGGED.clear()
t0 = allspecs[0]
ex = C.execute(full, enforce_pause=False, skip_tags={(t0["category"], t0["value"])})
check(ex.get("held_tags", 0) >= 1 and TAGGED and not any(k.get("category") == t0["category"] and k.get("value") == t0["value"]
                                                for _kind, _a, k in TAGGED),
      "a tag on the removal list isn't re-added in the same un-paused cycle")
full["armed"] = False

# build 450: "⚡ Execute one cycle now" (apply=True) writes even when the loop isn't armed
TAGGED.clear()
ex = C.execute(full, enforce_pause=False, apply=True)
check(ex.get("ok") and ex["queued_tags"] == len(allspecs) == len(TAGGED) and not full.get("armed"),
      "a confirmed manual run applies the plan while disarmed (and doesn't arm the loop)")
TAGGED.clear()
check(not C.execute(full, apply=False).get("ok") and not TAGGED, "…but a disarmed contract with no manual apply still writes nothing")
_upd, _sent = C._navi_update_bg, C._notify_run
C._navi_update_bg = lambda *a, **k: {"started": [], "stub": True}
C._notify_run = lambda c, e: {"skipped": "test"}
TAGGED.clear()
cy = C.run_cycle(dict(full, armed=False), enforce_pause=False, apply=True)
check(cy.get("mode") == "manual" and cy.get("applied") and cy.get("queued_tags") == len(TAGGED) > 0,
      "run_cycle(apply=True) on a disarmed contract: mode 'manual', tags queued")
TAGGED.clear()
cy = C.run_cycle(dict(full, armed=False), enforce_pause=False)
check(cy.get("mode") == "plan" and not cy.get("applied") and cy.get("queued_tags") == 0 and not TAGGED,
      "run_cycle() without apply on a disarmed contract only plans")
C._navi_update_bg, C._notify_run = _upd, _sent
import inspect as _insp  # noqa: E402
from agents.contract import api as _capi  # noqa: E402
check("apply=True" in _insp.getsource(_capi.run_now), "the run_now API passes apply=True (confirmed manual run)")

# build 450: the background navi.db refresh runs the real navi 8.x commands, in order
from core import cli_jobs as _cj  # noqa: E402
_calls = []
_su, _po, _na = _cj.start_update, _cj.poll, navi_cli.navi_available
_cj.start_update = lambda k, refresh_summaries=True: (_calls.append(k) or {"ok": True, "job": {"id": len(_calls)}})
_cj.poll = lambda jid, since=0: {"ok": True, "job": {"id": jid, "status": "done"}}
navi_cli.navi_available = lambda: True
r = C._navi_update_bg()
import time as _t  # noqa: E402
for _ in range(50):
    if len(_calls) >= 2:
        break
    _t.sleep(0.05)
check(_calls == ["assets", "vulns"], "contract refresh runs assets then vulns through cli_jobs (got %r)" % _calls)
check(r.get("commands") == ["navi config update assets", "navi config update vulns"],
      "…as `navi config update <kind>` (navi 8.x), not the old `navi update <kind>`")
check('"update", k]' not in open(os.path.join(ROOT, "core", "contract.py"), encoding="utf-8").read(),
      "core/contract.py no longer spawns `navi update <kind>`")
_cj.start_update, _cj.poll, navi_cli.navi_available = _su, _po, _na

# PROMPT_DRIVEN agents aren't cut to top-N
pi = [{"label": "u%d" % i, "rank": 1, "unit": "u%d" % i, "spec": {"category": "Owner", "value": str(i)}} for i in range(9)]
check(len(C._select("asset_ownership", pi, "assign x to y", 2)[0]) == 9, "owner mappings are never cut to top-N")
check(len(C._select("eol", pi, "", 2)[0]) == 2, "…other agents still are")

# set_contract coerces types
sc = C.set_contract({"defaults": {"top_n": "<img src=x onerror=alert(1)>"}, "schedule_hours": "abc",
                     "removal": "nope", "notify": [1], "acr": [{"score": "<b>", "mod": "x"}], "wait_minutes": -5})
check(sc["defaults"]["top_n"] == 50 and sc["schedule_hours"] == 4 and isinstance(sc["removal"], dict)
      and sc["notify"] == {"enabled": True, "to": ""} and sc["acr"][0]["score"] == 8
      and sc["acr"][0]["mod"] == "set" and sc["wait_minutes"] == 0, "set_contract rejects/clamps junk fields")
C.set_contract(C.default_contract())

C._agent_run = _real_run

# discovery leaves the hound's own last result alone
import importlib as _il  # noqa: E402
_m = _il.import_module("agents.eol.api")
if getattr(_m, "AGENT", None) is not None and hasattr(_m.AGENT, "result"):
    _m.AGENT.result = {"mine": 1}
    try:
        C._agent_run("eol")
    except Exception:
        pass
    check(_m.AGENT.result == {"mine": 1}, "contract discovery restores the agent's stored result")


def test_contract_regressions():
    assert not fails, fails


if __name__ == "__main__":
    print("\n%d failure(s)" % len(fails))
    sys.exit(1 if fails else 0)
