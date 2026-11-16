"""Regression tests for Settings → Test run (core/tagname.py): every tag CATEGORY a Hound
writes becomes '<phrase>-<category>' while it is on; removals and user-typed ACR stay exact;
every reader that recognises a Hound's own output (What the Hounds know, Done so far, SLA
dispositions, Exposure Score identity/ownership, Classification, Argos, Insights, applied
badges) matches both the plain and the prefixed name; and with the setting OFF the plan /
export / navi command are byte-identical to build 440 (/home/claude/base440, when present).
Tiny synthetic navi.db in a temp dir; navi + subprocess are stubbed — no navi, no network.
Run: python3 tests/test_tagprefix.py  (or pytest)."""
import atexit
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-tagprefix-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
CFG = os.path.join(TMP, "cfg.json")
os.environ.update({"NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "CONTRACT_DIR": os.path.join(TMP, "contracts"),
                   "HOUNDS_CONFIG": CFG, "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"),
                   "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db")})
for k in ("NAVI_TAG_TEST_RUN", "NAVI_TAG_PREFIX", "NAVI_ALLOW_WRITES", "ANTHROPIC_API_KEY"):
    os.environ.pop(k, None)
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB
BASE440 = "/home/claude/base440"

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def test_run(on, phrase=None):
    if on:
        os.environ["NAVI_TAG_TEST_RUN"] = "1"
    else:
        os.environ.pop("NAVI_TAG_TEST_RUN", None)
    if phrase is None:
        os.environ.pop("NAVI_TAG_PREFIX", None)
    else:
        os.environ["NAVI_TAG_PREFIX"] = phrase


from core import tagname as T  # noqa: E402

# ------------------------------------------------------------------ the central helper
check(T.normalize_phrase("Hounds-") == (True, "Hounds", ""), "a typed trailing '-' is stripped (we add it)")
check(T.normalize_phrase("  My Test -  ")[:2] == (True, "My Test"), "surrounding spaces + '-' stripped, inner space kept")
check(T.normalize_phrase("")[:2] == (True, "Hounds") and T.normalize_phrase(None)[:2] == (True, "Hounds"),
      "blank phrase = the default 'Hounds'")
check(T.normalize_phrase("trial_2")[:2] == (True, "trial_2"), "letters / digits / _ allowed")
for bad in ("Ho!unds", "a-b", "x" * 25, "it's", "<b>", "semi;colon", "ünï"):
    ok, _, err = T.normalize_phrase(bad)
    check(not ok and "1–24" in err, "invalid phrase rejected with a clear message: %r" % bad)
check(T.normalize_phrase("x" * 24)[0], "24 characters is the limit (allowed)")

test_run(False)
check(not T.enabled() and T.prefix() == "" and T.configured_prefix() == "Hounds-", "off by default; reads know 'Hounds-'")
check(T.effective("Lifecycle") == "Lifecycle", "off: effective() leaves the category alone")
test_run(True)
check(T.effective("Lifecycle") == "Hounds-Lifecycle", "on: Lifecycle → Hounds-Lifecycle")
check(T.effective("Hounds-Lifecycle") == "Hounds-Lifecycle" and T.effective("hounds-Lifecycle") == "hounds-Lifecycle",
      "never double-prefixed (case-insensitive)")
check(T.effective("") == "" and T.effective(None) is None and T.effective("  ") == "  ", "blank category untouched")
test_run(True, "Trial-")
check(T.effective("Owner") == "Trial-Owner" and T.phrase() == "Trial", "custom phrase, trailing '-' normalised")
test_run(True, "bad!phrase")
check(T.effective("Owner") == "Hounds-Owner", "an invalid stored phrase falls back to the default")
test_run(True)
check(T.base("Hounds-Owner") == "Owner" and T.base("Owner") == "Owner" and T.base("Hounds-") == "Hounds-",
      "base() strips the configured prefix only")
check(T.names("Owner") == ["Owner", "Hounds-Owner"] and T.names("Hounds-Owner") == ["Owner", "Hounds-Owner"],
      "names() = base + prefixed, de-duplicated")
check(T.sql_in("tag_key", "Owner") == ("tag_key IN (?,?)", ("Owner", "Hounds-Owner")), "sql_in fragment + params")
check(T.sql_lit("k", "Owner") == "k IN ('Owner','Hounds-Owner')", "sql_lit inline literals")
check(T.example() == "Lifecycle : EOL → Hounds-Lifecycle : EOL", "the Settings example")
_c = sqlite3.connect(":memory:")
check([r[0] for r in _c.execute("SELECT " + T.sql_base("x") + " FROM (SELECT 'Hounds-Attack Path' x UNION ALL "
                                "SELECT 'hounds-mitre' UNION ALL SELECT 'Owner' UNION ALL SELECT 'Hounds-' UNION ALL SELECT NULL)")]
      == ["Attack Path", "mitre", "Owner", "Hounds-", None], "sql_base() strips the prefix in SQL (NULL-safe)")
_c.close()
test_run(False)

# ------------------------------------------------------------------ Settings: persistence + validation
from core import config_store  # noqa: E402
from agents.settings import api as S  # noqa: E402

b, _ = S.status({})
tp = b["tag_prefix"]
check(tp["enabled"] is False and tp["phrase"] == "Hounds" and tp["env"] == "NAVI_TAG_TEST_RUN", "status reports the switch (off)")
keys = [f["key"] for f in b["env"] if f.get("section") == "testrun"]
check(keys == ["NAVI_TAG_TEST_RUN", "NAVI_TAG_PREFIX"], "two Settings fields in their own 'testrun' section")
check(all(k in config_store.MANAGED for k in keys), "both are managed by the config store (persist like Auto-approve)")
b, _ = S.set_env({"env": {"NAVI_TAG_TEST_RUN": "1", "NAVI_TAG_PREFIX": "Trial -"}})
check(set(b["applied"]) == set(keys) and os.environ.get("NAVI_TAG_PREFIX") == "Trial", "set: on + phrase 'Trial -' → 'Trial'")
check(b["tag_prefix"]["enabled"] and b["tag_prefix"]["prefix"] == "Trial-", "status echoes Trial-")
check(b["persisted"] and json.load(open(CFG))["env"].get("NAVI_TAG_PREFIX") == "Trial"
      and json.load(open(CFG))["env"].get("NAVI_TAG_TEST_RUN") == "1", "saved to the config file (file mode)")
b, _ = S.set_env({"env": {"NAVI_TAG_PREFIX": "Bad!"}})
check(b.get("invalid", {}).get("NAVI_TAG_PREFIX") and os.environ.get("NAVI_TAG_PREFIX") == "Trial"
      and "1–24" in (b.get("warning") or ""), "invalid phrase rejected, previous value kept, clear message")
b, _ = S.set_env({"env": {"NAVI_TAG_PREFIX": "Hounds-"}})
check("NAVI_TAG_PREFIX" not in os.environ and b["tag_prefix"]["phrase"] == "Hounds", "'Hounds-' = default → unset")
b, _ = S.set_env({"env": {"NAVI_TAG_TEST_RUN": "0"}})
check(not b["tag_prefix"]["enabled"] and os.environ.get("NAVI_TAG_TEST_RUN", "0") == "0", "clear: off again")
from core import health  # noqa: E402
health.invalidate()
check((health.health().get("tag_prefix") or {}).get("enabled") is False, "/api/health carries tag_prefix (header chip)")

# ------------------------------------------------------------------ writes: navi_cli
from core import navi_cli, tagq  # noqa: E402

RAN = []


class _P:
    returncode, stdout, stderr = 0, "1 asset tagged", ""


navi_cli.allow_writes = lambda: True
navi_cli.navi_available = lambda: True
navi_cli._resolve_navi = lambda: "navi"
navi_cli._navi_cwd = lambda: TMP
navi_cli.subprocess.run = lambda cmd, **k: (RAN.append(list(cmd)) or _P())
SUB = []
_real_submit = tagq.submit
tagq.submit = lambda fn, kw, meta=None: (SUB.append((fn, dict(kw), dict(meta or {}))) or {"id": len(SUB)})


def cat_of(cmd):
    return cmd[cmd.index("--c") + 1]


test_run(True)
navi_cli.tag("Lifecycle", "Unsupported", query="SELECT 1", sync=True)
check(cat_of(RAN[-1]) == "Hounds-Lifecycle" and RAN[-1][RAN[-1].index("--v") + 1] == "Unsupported",
      "navi enrich tag --c Hounds-Lifecycle --v Unsupported (value untouched)")
navi_cli.tag("Hounds-Lifecycle", "X", query="SELECT 1", sync=True)
check(cat_of(RAN[-1]) == "Hounds-Lifecycle", "an already-prefixed category is not double-prefixed")
navi_cli.tag("Lifecycle", "Unsupported", remove=True, op="remove", agent="tagremoval", sync=True)
check(cat_of(RAN[-1]) == "Lifecycle" and "-remove" in RAN[-1], "a removal is EXACT — never prefixed")
navi_cli._tag_exec("Lifecycle", "Unsupported", remove=True)
check(cat_of(RAN[-1]) == "Lifecycle", "_tag_exec removal stays exact too")
navi_cli.tag("Owner", "Web: alice", query="SELECT 1", agent="exproute")
fn, kw, meta = SUB[-1]
check(kw["category"] == "Hounds-Owner" and meta["category"] == "Hounds-Owner",
      "queued job: spec AND Tagging-log metadata carry the written name (Done so far / log)")
navi_cli.tag("Owner", "Web: alice", remove=True, op="remove", agent="tagremoval")
check(SUB[-1][1]["category"] == "Owner" and SUB[-1][2]["category"] == "Owner", "queued removal: exact name in spec + log")
SUB.clear()
navi_cli.tag_capped("Software", "OpenSSL", uuids=["u1", "u2"], agent="software")
navi_cli.tag_capped("Software", "OpenSSL", uuids=["u%d" % i for i in range(5)], threshold=2,
                    fallbacks=[{"plugin": 20811, "output": "OpenSSL"}, {"cpe": "cpe:/a:openssl"}], agent="software")
check(len(SUB) == 3 and all(s[1]["category"] == "Hounds-Software" for s in SUB),
      "tag_capped (query path and built-in fallbacks) writes Hounds-Software")
navi_cli.delete_tag("Software", "OpenSSL", sync=True)
check(cat_of(RAN[-1]) == "Software" and RAN[-1][1:3] == ["action", "delete"], "delete_tag stays exact")
navi_cli.acr("Business Tier", "Production", 9, reasons=["business"])
check(cat_of(RAN[-1]) == "Business Tier", "ACR on a user-typed category is exact (no prefix)")
test_run(False)
navi_cli.tag("Lifecycle", "Unsupported", query="SELECT 1", sync=True)
check(cat_of(RAN[-1]) == "Lifecycle", "off: plain category")

# AI ACR raise targets the tag the Hound itself wrote
from agents.ai import api as AIAPI  # noqa: E402
test_run(True)
before = len(RAN)
AIAPI.acr_roles({"confirm": True, "roles": [next(iter(AIAPI.ai_assets.ROLE_ACR))]})
check(len(RAN) > before and cat_of(RAN[-1]) == "Hounds-AI ACR Raise", "AI ACR Raise ACR targets Hounds-AI ACR Raise")
r, code = AIAPI.tag({"confirm": True, "category": "Hounds-AI ATLAS", "uuids": ["u1"]})
check(code == 400 and "tag_atlas" in r["error"], "a prefixed 'AI ATLAS' still can't bypass tag_atlas")
test_run(False)

# ------------------------------------------------------------------ activity.allowed_category
from core import activity  # noqa: E402

test_run(True)
check(activity.allowed_category("ai", "Hounds-AI Role") and activity.allowed_category("ai", "AI Role")
      and activity.allowed_category("software", "Hounds-Software EOL"), "allowed_category accepts the prefixed name")
check(not activity.allowed_category("ai", "Hounds-Owner") and not activity.allowed_category("software", "Hounds-Business Unit"),
      "…but only for categories that agent owns")
test_run(False)
check(activity.allowed_category("ai", "Hounds-AI Role"), "a test-run name is still the agent's own after the run")

# ------------------------------------------------------------------ AI Contract: plan specs + export
from core import contract as C  # noqa: E402


def _fake_candidates(aid, db_path=None, cfg=None):
    if aid == "eol":
        return (C._items("Lifecycle : Unsupported", 5, [{"category": "Lifecycle", "value": "Unsupported",
                                                          "plugin_name": "Unsupported", "remove": False}])
                + C._items("EOL 2020-01-01", 3, C._uuid_specs("Lifecycle EOL", "2020-01-01", ["a1", "a2"]))), None, None
    if aid == "fused_score":
        return C._items("Priority : P1 (score ≥ 80)", 9, C._uuid_specs("Priority", "P1", ["a1"])), None, None
    return [], None, None


C._candidates_ex = _fake_candidates
REMOVAL = {"enabled": True, "pause_minutes": 0, "tags": [{"category": "Lifecycle", "value": "Old"}]}
DOC = {**C.default_contract(), "removal": REMOVAL,
       "acr": [{"category": "Business Tier", "value": "Prod", "score": 9, "mod": "set", "reasons": ["business"]}]}
test_run(False)
plan_off, script_off = C.plan(DOC), C.export_script(DOC)
test_run(True)
plan_on, script_on = C.plan(DOC), C.export_script(DOC)
specs_on = [it["spec"] for b in plan_on["agents"] for it in b["items"]]
labels_on = [it["label"] for b in plan_on["agents"] for it in b["items"]]
check(specs_on and all(s["category"].startswith("Hounds-") for s in specs_on), "plan specs carry the prefix")
check("Hounds-Lifecycle : Unsupported" in labels_on and "Hounds-Priority : P1 (score ≥ 80)" in labels_on,
      "plan labels name the category that will be written")
check(plan_on.get("tag_prefix") == "Hounds-" and "tag_prefix" not in plan_off, "plan flags the test run (page banner)")
check("--c Hounds-Lifecycle --v Unsupported --name Unsupported" in script_on
      and "--c 'Hounds-Lifecycle EOL'" in script_on and "--c Hounds-Priority" in script_on,
      "export_script add-phase carries the prefix")
check("navi enrich tag --c Lifecycle --v Old -remove || true" in script_on, "export_script removal phase is EXACT")
check("navi enrich acr --c 'Business Tier'" in script_on, "contract ACR rules are exact")
check(script_on.replace("Hounds-", "") == script_off, "on vs off differ ONLY by the category prefix")
C._CURRENT = {**DOC, "armed": True}
SUB.clear()
navi_cli.tag = navi_cli.tag                                     # real tag → stubbed queue
C.execute(C._CURRENT, enforce_pause=False)
check(SUB and all(s[1]["category"].startswith("Hounds-") for s in SUB), "execute() queues the prefixed names")
C._remove_tags(C._CURRENT)
check(SUB[-1][1]["category"] == "Lifecycle" and SUB[-1][1]["remove"], "contract removal phase queues the EXACT name")
test_run(False)

# off-mode byte-identical to build 440 (same stubs, same fake candidates, run in each tree)
PROBE = r'''
import json, os, sys
root = sys.argv[1]; sys.path.insert(0, root)
from core import navi_cli
RAN = []
class P: returncode, stdout, stderr = 0, "ok", ""
navi_cli.allow_writes = lambda: True; navi_cli.navi_available = lambda: True
navi_cli._resolve_navi = lambda: "navi"; navi_cli._navi_cwd = lambda: "/tmp"
navi_cli.subprocess.run = lambda cmd, **k: (RAN.append(list(cmd)) or P())
from core import contract as C
def fc(aid, db_path=None, cfg=None):
    if aid == "eol":
        return (C._items("Lifecycle : Unsupported", 5, [{"category": "Lifecycle", "value": "Unsupported", "plugin_name": "Unsupported", "remove": False}])
                + C._items("EOL 2020-01-01", 3, C._uuid_specs("Lifecycle EOL", "2020-01-01", ["a1", "a2"]))), None, None
    if aid == "fused_score":
        return C._items("Priority : P1 (score ≥ 80)", 9, C._uuid_specs("Priority", "P1", ["a1"])), None, None
    return [], None, None
C._candidates_ex = fc
DOC = {**C.default_contract(), "removal": {"enabled": True, "pause_minutes": 0, "tags": [{"category": "Lifecycle", "value": "Old"}]},
       "acr": [{"category": "Business Tier", "value": "Prod", "score": 9, "mod": "set", "reasons": ["business"]}]}
navi_cli.tag("Lifecycle", "Unsupported", query="SELECT 1", sync=True)
navi_cli.tag("Lifecycle", "Unsupported", remove=True, sync=True)
print(json.dumps({"plan": C.plan(DOC), "script": C.export_script(DOC), "cmds": RAN}, sort_keys=True, default=str))
'''
if os.path.isdir(os.path.join(BASE440, "core")):
    pf = os.path.join(TMP, "probe.py")
    open(pf, "w").write(PROBE)
    env = {k: v for k, v in os.environ.items() if k not in ("NAVI_TAG_TEST_RUN", "NAVI_TAG_PREFIX")}
    outs = []
    for root in (BASE440, ROOT):
        e = dict(env, HOUNDS_CONFIG="off", NAVI_TAGLOG_DB=os.path.join(TMP, "probe-%d.db" % len(outs)))
        p = subprocess.run([sys.executable, pf, root], capture_output=True, text=True, env=e, cwd=TMP)
        outs.append(p.stdout.strip().splitlines()[-1] if p.stdout.strip() else "ERR " + p.stderr[-400:])

    def _no_acr_protect(line):
        # build 442 added ACR protection (core/acr_protect.py): the plan's per-rule ACR preview,
        # the protect_acr flag and one NO : UPDATE comment above the export's ACR lines. Drop
        # exactly those before comparing — everything else must still be byte-identical.
        try:
            o = json.loads(line)
        except Exception:
            return line
        for k in ("acr_preview", "protect_acr"):
            o.get("plan", {}).pop(k, None)
        o["script"] = "\n".join(ln for ln in o.get("script", "").split("\n")
                                if not ln.startswith("# navi enrich acr skips every asset tagged NO : UPDATE"))
        return json.dumps(o, sort_keys=True, default=str)
    outs = [outs[0], _no_acr_protect(outs[1])]
    check(outs[0] == outs[1] and not outs[0].startswith("ERR"),
          "OFF: plan + export_script + navi commands are byte-identical to build 440")
else:
    print("SKIP base440 not present — byte-identical comparison skipped")

# ------------------------------------------------------------------ readers on a synthetic navi.db
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, operating_system TEXT, acr TEXT, aes INTEGER);
CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, plugin_family TEXT, severity TEXT, score REAL,
                    xrefs TEXT, state TEXT, first_found TEXT, last_found TEXT, output TEXT);
CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE vuln_route (app_name TEXT, plugin_list TEXT, total_vulns INTEGER);
CREATE TABLE vuln_paths (asset_uuid TEXT, plugin_id TEXT, path TEXT);""")
for u, h, acr in [("a1", "web", "10"), ("a2", "db", "9"), ("a3", "app", "5"), ("a4", "reuse", "5"),
                  ("a5", "plain", "5"), ("a6", "human", "5")]:
    c.execute("INSERT INTO assets VALUES (?,?,?,?,?,0)", (u, h, "10.0.0." + u[1], "Linux", acr))
c.execute("INSERT INTO vuln_route VALUES ('Apache', \"['100']\", 3)")
for u in ("a1", "a2", "a3", "a4", "a5", "a6"):
    c.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?)",
              (u, "100", "apache", "Web", "medium", 5.0, "", "open", "2020-01-01T00:00:00.000Z", "2020-01-02T00:00:00.000Z", ""))
c.executemany("INSERT INTO tags VALUES (?,?,?)", [
    ("a1", "Hounds-Owner", "Apache: Linux Team"),          # test-run route owner
    ("a1", "Hounds-Lifecycle", "Unsupported"),             # test-run signal
    ("a2", "Hounds-Asset Owner", "netsec · complete"),     # test-run single owner
    ("a2", "Hounds-Asset Inventory", "Class: Server"),
    ("a3", "Hounds-Owner", "Apache: Accepted"),            # test-run disposition
    ("a4", "Hounds-Identity Risk", "Account Reuse : svc"),  # test-run identity reuse
    ("a6", "Owner", "Apache: Human Team"),                 # a human-written Owner still counts
    ("a5", "Hounds-Mitre", "T1190: Exploit Public-Facing Application")])
c.commit()
c.close()

# 1. Asset Ownership — "what the Hounds know" + ownership
from core import asset_ownership as AO  # noqa: E402
ov = AO.overview(DB)
R = {r["uuid"]: r for r in ov["assets"]}
check(R["a1"]["has_owner"] and R["a1"]["tech_owners"] == ["Linux Team"], "ownership: Hounds-Owner counts as an Owner tag")
check(R["a2"]["asset_owner"] == "netsec" and R["a2"]["claimed_pct"] == 100.0, "ownership: Hounds-Asset Owner = single owner")
check(R["a6"]["has_owner"] and R["a6"]["tech_owners"] == ["Human Team"], "a human-written Owner tag still counts")
check(R["a3"]["accepted"] == 1 and not R["a3"]["has_owner"], "a Hounds-Owner disposition is a disposition, not an owner")
check("Hounds-Lifecycle" in R["a1"]["signals"] and "Hounds-Owner" not in R["a1"]["signals"],
      "what the Hounds know: shows Hounds-Lifecycle as is, ownership keys excluded")
check("Hounds-Owner" not in AO.tag_schema(DB) and "Hounds-Lifecycle" in AO.tag_schema(DB), "tag_schema excludes prefixed ownership keys")

# 2. SLA dispositions
from core import sla  # noqa: E402
con = sqlite3.connect(DB)
d = sla.dispositions(con)
con.close()
check(d.get("a3") == {"100"}, "SLA: a Hounds-Owner 'Apache: Accepted' disposition excludes the route's findings")
frag = sla._disp_exclude(DB) if hasattr(sla, "_disp_exclude") else ""
check("Hounds-Owner" in (frag or "Hounds-Owner"), "SLA SQL disposition fragment matches the prefixed key")
rd = sla.readiness(DB)
check(rd["owner_key_present"] and rd["default_tag_key"] == "Owner", "SLA segments by Owner by default (plain key present)")

# 3. Exposure Score — identity reuse + ownership + Mitre / EOL tags
from core import fused_score as F  # noqa: E402
A = {r["uuid"]: r for r in F.overview(DB, limit=50)["assets"]}
check(A["a4"]["ident"] == 2, "Exposure Score: Hounds-Identity Risk 'Account Reuse' = reuse tier 2")
check(not A["a1"]["unowned"] and not A["a6"]["unowned"] and A["a5"]["unowned"], "Exposure Score: Hounds-Owner / Owner make an asset owned")
check(A["a1"]["eol"] == 1, "Exposure Score: Hounds-Lifecycle counts as an EOL tag")

# 4. Activity — Done so far
os.environ["NAVI_TAG_TEST_RUN"] = "1"
tagq.record({"agent": "eol", "category": "Hounds-Lifecycle", "value": "Unsupported", "op": "tag"}, {"ok": True})
s = activity.summary("eol")
check("Hounds-Lifecycle" in s["kpi"]["categories"] and "Lifecycle" in s["kpi"]["categories"],
      "Done so far: plain + prefixed categories are both checked")
t = [x for x in s["tags"] if x["category"] == "Hounds-Lifecycle"]
check(t and t[0]["assets"] == 1 and t[0]["status"] == "on assets" and s["kpi"]["assets_tagged"] == 1,
      "Done so far: the test-run tag the hound wrote is found on its asset (real name shown)")
test_run(False)

# 5. Classification + Argos + Insights + applied badges
from core import classify as CL  # noqa: E402
check(CL._read_tags(DB).get("a2", {}).get("class") == "Server", "Classification reads Hounds-Asset Inventory 'Class: Server'")
from agents.argos import api as AR  # noqa: E402
dz = AR._decipher("Hounds-Lifecycle", "Unsupported")
check(dz["agent"] == "eol" and dz["category"] == "Hounds-Lifecycle", "Argos glance: Hounds-Lifecycle → Charon, name shown as is")
check(AR._decipher("Hounds-Asset Inventory", "Class: Server").get("facet") == "Class", "Argos: prefixed inventory facet")
own = AR._ownership([{"tag_key": "Hounds-Owner", "tag_value": "Apache: Linux Team"}])
check(bool(own) and "Linux Team" in json.dumps(own), "Argos ownership pie reads Hounds-Owner")
from core import insights as INS  # noqa: E402
n_owned = sqlite3.connect(DB).execute("SELECT COUNT(DISTINCT asset_uuid) FROM tags WHERE "
                                      + T.sql_lit("tag_key", "Owner")).fetchone()[0]
check(n_owned == 3, "the Owner reader SQL counts plain + Hounds-Owner assets (3)")
try:
    ins = INS.compute(DB)
    owned_story = (ins.get("stories") or {}).get("owned") if isinstance(ins, dict) else None
except Exception as e:                                           # pragma: no cover
    owned_story = "error: %s" % e
check(owned_story == 3, "Insights 'owned' story counts Owner + Hounds-Owner assets (got %r)" % (owned_story,))
from agents.explore import api as EX  # noqa: E402
ap = {(r["tag_key"], r.get("base")) for r in EX.applied({})[0]["applied"]}
check(("Hounds-Lifecycle", "Lifecycle") in ap and ("Owner", None) in ap, "applied badges: a test-run tag also answers for its base")
test_run(True)
from core import was as W  # noqa: E402
coh = W._cohort("A01", [{"asset_uuid": "a1"}], "WAS OWASP", {("Hounds-WAS OWASP", "A01")})
check(coh["category"] == "Hounds-WAS OWASP" and coh["applied"], "WAS tag_plan shows the written name; applied matches it")
test_run(False)
coh = W._cohort("A01", [{"asset_uuid": "a1"}], "WAS OWASP", {("WAS OWASP", "A01")})
check(coh["category"] == "WAS OWASP" and coh["applied"], "WAS off: unchanged")

# ---- review fixes (build 441)
from core import launcher as _L  # noqa: E402
test_run(False)
k_off = _L._cache_key("contract", "export", {})
test_run(True)
k_on = _L._cache_key("contract", "export", {})
check(k_off != k_on, "the launcher's result cache is keyed on the test-run prefix (an export can't lose it)")
test_run(False)
check(not T.normalize_phrase("Audit")[0] and not T.normalize_phrase("PQC Harvest")[0]
      and T.normalize_phrase("Trial")[0], "a phrase that starts a real category ('Audit-Vuln Link') is refused")
import shutil as _sh  # noqa: E402
if _sh.which("node"):
    _js = os.path.join(os.path.dirname(HERE), "web", "assets", "console.js")
    _code = ("const s=require('fs').readFileSync(%r,'utf8');const i=s.indexOf('function tagKeySql');"
             "const j=s.indexOf('function mountTestRunChip');let _TR={configured_prefix:'Hounds-'};eval(s.slice(i,j));"
             "process.stdout.write(tagKeySql(\"tag_key IN ('IoT','Device Type') OR tag_key='Class' OR tag_key='Hounds-Owner'\"))") % _js
    import tempfile as _tf  # subprocess.run is stubbed above (fake navi) — run node via os.popen
    with _tf.NamedTemporaryFile("w", suffix=".js", delete=False) as _f:
        _f.write(_code)
    _out = os.popen("node " + _f.name).read()
    os.unlink(_f.name)
    check(_out == "tag_key IN ('IoT','Device Type','Hounds-IoT','Hounds-Device Type') OR tag_key IN ('Class','Hounds-Class') "
          "OR tag_key='Hounds-Owner'", "dashboard preset SQL: IN lists and = both gain the test-run name (%s)" % _out)
_ai = open(os.path.join(os.path.dirname(HERE), "agents", "ai", "api.py"), encoding="utf-8").read()
check('"AI ACR Raise")' in _ai and 'tagname.base(t.split(" : ", 1)[0]) == "AI ACR Raise"' in _ai,
      "AI page: the AI ACR Raise tag (plain or test-run) enables Set ACR")

tagq.submit = _real_submit
print("\n%d failure(s)" % len(fails))
if fails:
    sys.exit(1)
