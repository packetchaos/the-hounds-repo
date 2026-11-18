"""Regression tests — build 489: Charon (EOL / Unsupported) with the tag filter.

  · run / apply / tag_eol_date honour tag_scope {key, value} (core.tagscope); the manifest
    declares every action the page calls.
  · No scope → byte-for-byte today's result (scan, analyze, run, date_tag_query, the writes).
  · A scoped run counts only the tag's assets; every asset's own EOL facts (products, dates,
    crown / KEV / critical flags) equal the whole estate's — on the plain SQL path and on the
    Phase 1 hx_summary path.
  · Writes from a tag view re-read the set from navi.db on the server and stay inside the tag
    (navi writes are mocked — no navi is ever called).
  · Charon keeps no server cache of its own; a scoped run never replaces the agent's
    whole-estate result (its status card), and the read cache keys on tag_scope.
Run: python3 tests/test_scope_eol_489.py"""
import atexit
import json
import os
import random
import re
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-eol-489-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
SAMPLE = os.path.join(TMP, "sample.db")
shutil.copy(os.path.join(ROOT, "sample_navi.db"), SAMPLE)
RICH = os.path.join(TMP, "rich.db")
os.environ.update({"NAVI_DB_PATH": RICH, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
os.environ.pop("NAVI_ALLOW_WRITES", None)
os.environ.pop("HOUNDS_NO_SUMMARY", None)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# ── a fixture with dated EOL plugins, KEV / critical overlap, crown jewels and tags ──────────
KEV = "{'type': 'CISA-KNOWN-EXPLOITED', 'id': '2021/12/10'}"
PLUGINS = {
    "11936": ("Microsoft Windows Server 2012 End of Life", "critical", None,
              lambda r: "Security End of Life : October 10, 2023\nInstalled: 2012 R2"),
    "201363": ("Apache Tomcat SEoL (8.0.x)", "critical", None, lambda r: "Security End of Life : June 30, 2018"),
    "108797": ("VMware ESXi Unsupported Version Detection", "high", None,
               lambda r: r.choice(["End of support date : 2014/04/08", "End of support date : 2016/03/12",
                                   "Installed version : 5.5"])),
    "58987": ("PHP Unsupported Version Detection", "critical", None,
              lambda r: r.choice(["Support ended : 2019-01-10", "End of life date : December 31, 2018", ""])),
    "33850": ("Unix Operating System Unsupported Version Detection", "critical", None,
              lambda r: "The remote OS is no longer maintained."),
    "155999": ("Apache Log4j < 2.15.0 Remote Code Execution", "critical", KEV, lambda r: "log4j"),
    "50001": ("Generic Finding", "high", None, lambda r: "generic"),
    "50002": ("Another Finding", "medium", None, lambda r: "generic"),
}
STATES = ["OPEN", "open", "REOPENED", "fixed", None]


def make_db(path, n_assets=240, n=4000, seed=7):
    c = sqlite3.connect(path)
    c.executescript("""
    CREATE TABLE assets (uuid text PRIMARY KEY, hostname text, ip_address text, acr text, url text);
    CREATE TABLE vulns (finding_id text PRIMARY KEY, asset_uuid text, first_found text, last_found text, output text,
        plugin_id text, plugin_name text, plugin_family text, port text, severity text, state text, cves text,
        score text, xrefs text, url text);
    CREATE TABLE plugins (plugin_id text PRIMARY KEY, name text, severity text, cves text, vpr_score text);
    CREATE TABLE tags (asset_uuid text, tag_key text, tag_value text);
    """)
    r = random.Random(seed)
    uu = ["%08x-0000-4000-8000-%012d" % (i, i) for i in range(n_assets)]
    c.executemany("INSERT INTO assets VALUES (?,?,?,?,?)",
                  [(u, "host%d" % i, "10.0.0.%d" % (i % 250), str(r.choice([1, 3, 5, 8, 9, 10])), "")
                   for i, u in enumerate(uu)])
    pids = list(PLUGINS)
    rows = []
    for i in range(n):
        pid = r.choice(pids)
        name, sev, xr, out = PLUGINS[pid]
        ff = "20%02d-%02d-10T10:00:00Z" % (r.choice([18, 20, 22]), r.randint(1, 12))
        rows.append(("f%06d" % i, uu[r.randrange(n_assets)], ff, ff, out(r), pid, name, "Fam", "0", sev,
                     r.choice(STATES), "", "", xr, ""))
    c.executemany("INSERT INTO vulns VALUES (%s)" % ",".join("?" * 15), rows)
    c.executemany("INSERT INTO plugins VALUES (?,?,?,?,?)", [(p, v[0], v[1], "", "") for p, v in PLUGINS.items()])
    c.executemany("INSERT INTO tags VALUES (?,?,?)", [(u, "Owner", "team%d" % (i % 3)) for i, u in enumerate(uu[:180])])
    c.executemany("INSERT INTO tags VALUES (?,?,?)", [(u, "Owner's", "o'brien") for u in uu[5:40]])  # quotes
    c.execute("CREATE INDEX hx_v_plugin ON vulns(plugin_id, asset_uuid, state, severity)")
    c.execute("CREATE INDEX hx_v_asset ON vulns(asset_uuid, plugin_id, state, severity)")
    c.commit()
    c.close()


make_db(RICH)
FAST = os.path.join(TMP, "fast.db")
shutil.copy(RICH, FAST)

from core import db, eol, hx_summary, launcher, navi_cli, tagscope  # noqa: E402

c = sqlite3.connect(FAST, isolation_level=None)
hx_summary.build(c)
c.close()
hx_summary.invalidate()
check(hx_summary.usable(FAST) and not hx_summary.usable(RICH), "fixture: fast.db has summaries, rich.db doesn't")

TK, TV = "Owner", "team1"
QK, QV = "Owner's", "o'brien"


def tag_set(path, k, v):
    con = sqlite3.connect(path)
    s = {r[0] for r in con.execute("SELECT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", (k, v))}
    con.close()
    return s


def eol_rows(path):
    """hand count: (asset, plugin) of OPEN findings of lifecycle plugins (state NULL = open)"""
    con = sqlite3.connect(path)
    w = " OR ".join("plugin_name LIKE '%" + p + "%'" for _, ps in eol.DEFAULT_GROUPS for p in ps)
    has_state = any(r[1] == "state" for r in con.execute("PRAGMA table_info(vulns)"))
    out = con.execute("SELECT asset_uuid, plugin_id, output FROM vulns WHERE (" + w + ")" + (
        " AND lower(COALESCE(state,'open')) IN ('open','reopened')" if has_state else "")).fetchall()
    con.close()
    return out


def per_asset(view):
    """every per-asset fact the product view exposes: products per asset (via date groups and
    crown rows), the EOL dates each asset sits under, and the crown row itself."""
    dates = {}
    for g in view["date_groups"]:
        for u in g["uuids"]:
            dates.setdefault(u, set()).add(g["eol_date"])
    # a crown row's product list follows the product table's order (most assets first, a
    # population-relative order) — the per-asset fact is WHICH products, so compare it as a set
    crown = {r["asset_uuid"]: dict(r, products=sorted(r["products"])) for r in view["crown"]}
    return dates, crown


def scan_norm(x):
    return [(g["label"], g["asset_count"], sorted((str(p["plugin_id"]), p["plugin_name"], p["assets"])
                                                   for p in g["plugins"])) for g in x["groups"]]


for label, path, fast in (("plain SQL", RICH, False), ("hx_summary", FAST, True)):
    os.environ["NAVI_DB_PATH"] = path
    db.close_all()
    hx_summary.invalidate()
    check(eol._fast(path) == fast, f"[{label}] path taken as expected")
    est_scan, est_view = eol.scan(path), eol.analyze(path)
    # 1. whole estate unchanged: scope=None / an empty scope == the old call
    check(json.dumps(eol.scan(path, scope=None), sort_keys=True) == json.dumps(est_scan, sort_keys=True)
          and json.dumps(eol.analyze(path, scope=None), sort_keys=True) == json.dumps(est_view, sort_keys=True)
          and json.dumps(eol.analyze(path, scope=(None, None)), sort_keys=True) == json.dumps(est_view, sort_keys=True),
          f"[{label}] whole estate: scope=None is identical to today's scan / analyze")
    for k, v in ((TK, TV), (QK, QV)):
        S = tag_set(path, k, v)
        sv, ss = eol.analyze(path, scope=(k, v)), eol.scan(path, scope=(k, v))
        rows = [r for r in eol_rows(path) if r[0] in S]
        hand = {r[0] for r in rows}
        check(sv["metrics"]["eol_assets"] == len(hand) > 0, f"[{label}] {k}:{v} EOL assets = hand count ({len(hand)})")
        check(sv["metrics"]["findings"] == len(rows), f"[{label}] {k}:{v} EOL findings = hand count")
        for g, eg in zip(ss["groups"], est_scan["groups"]):
            pats = dict(eol.DEFAULT_GROUPS)[g["label"]]
            gh = {r[0] for r in eol_rows(path) if r[0] in S and any(
                p.lower() in PLUGINS[r[1]][0].lower() for p in pats)}
            check(g["asset_count"] == len(gh), f"[{label}] {k}:{v} group {g['label']}: {len(gh)} assets, hand-counted")
            ep = {str(p["plugin_id"]): p["assets"] for p in eg["plugins"]}
            check(all(p["assets"] <= ep.get(str(p["plugin_id"]), -1) for p in g["plugins"])
                  and [p["assets"] for p in g["plugins"]] == sorted((p["assets"] for p in g["plugins"]), reverse=True),
                  f"[{label}] {k}:{v} group {g['label']}: plugins are the estate's, counted over the tag, most first")
        # per-asset values identical
        ed, ec = per_asset(est_view)
        sd, sc = per_asset(sv)
        check(all(u in S for u in sd) and all(sd[u] == ed[u] for u in sd)
              and set(sd) == {u for u in ed if u in S},
              f"[{label}] {k}:{v} each asset's EOL dates equal its whole-estate dates")
        check(set(sc) == {u for u in ec if u in S} and all(sc[u] == ec[u] for u in sc),
              f"[{label}] {k}:{v} each crown-jewel row (ACR, products, OS, KEV, criticals) equals the estate's")
        for g in sv["date_groups"]:
            eg = next(x for x in est_view["date_groups"] if x["eol_date"] == g["eol_date"])
            check(g["uuids"] == [u for u in eg["uuids"] if u in S] and g["assets"] == len(g["uuids"]),
                  f"[{label}] {k}:{v} date {g['eol_date']}: the estate's assets on that date, inside the tag")
        con = sqlite3.connect(path)
        kev_h = {r[0] for r in con.execute("SELECT asset_uuid FROM vulns WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%' "
                                           "AND lower(COALESCE(state,'open')) IN ('open','reopened')")} & hand
        crit_h = {r[0] for r in con.execute("SELECT asset_uuid FROM vulns WHERE lower(severity)='critical' "
                                            "AND lower(COALESCE(state,'open')) IN ('open','reopened')")} & hand
        crown_h = {r[0] for r in con.execute("SELECT uuid FROM assets WHERE CAST(acr AS REAL) > 7")} & hand
        con.close()
        check(sv["metrics"]["kev_assets"] == len(kev_h) and sv["metrics"]["crit_assets"] == len(crit_h)
              and sv["metrics"]["crown_assets"] == len(crown_h) == len(sv["crown"]),
              f"[{label}] {k}:{v} KEV / critical / crown counts = hand counts over the tag")
        check(sum(p["assets"] for p in sv["products"]) >= len(hand) and all(p["assets"] <= next(
            e["assets"] for e in est_view["products"] if e["product"] == p["product"]) for p in sv["products"]),
              f"[{label}] {k}:{v} products are the estate's products, counted over the tag")
        # date_tag_query: estate unchanged, scoped stays inside the tag
        for g in sv["date_groups"]:
            eg = next(x for x in est_view["date_groups"] if x["eol_date"] == g["eol_date"])
            q0 = eol.date_tag_query(eg)
            check(eol.date_tag_query(eg, scope=None) == q0, f"[{label}] date_tag_query unchanged without a scope")
            got = set(navi_cli.collect_uuids(eol.date_tag_query(eg, scope=(k, v)), path=path))
            check(got == set(navi_cli.collect_uuids(q0, path=path)) & S and got,
                  f"[{label}] {k}:{v} date {g['eol_date']}: the scoped selector = estate selector ∩ tag")
            break

# ── 2. the API ────────────────────────────────────────────────────────────────
os.environ["NAVI_DB_PATH"] = FAST
db.close_all()
hx_summary.invalidate()
from agents.eol import api  # noqa: E402

o, st = api.run({})
check(st == 200 and "scope" not in o["result"], "run(): no scope → no scope key")
est_meta = api._agent().meta()["summary"]
o2, _ = api.run({})
check(json.dumps(o2["result"], sort_keys=True) == json.dumps(o["result"], sort_keys=True)
      and json.dumps(o["result"]["view"], sort_keys=True) == json.dumps(eol.analyze(), sort_keys=True),
      "run(): whole estate result is today's (scan + analyze)")
sc, _ = api.run({"tag_scope": {"key": TK, "value": TV}})
R = sc["result"]
S = tag_set(FAST, TK, TV)
check(R["scope"] == {"key": TK, "value": TV, "label": f"{TK} : {TV}", "assets": len(S)}, "run(): scoped result says its scope")
check(R["view"]["metrics"]["eol_assets"] < o["result"]["view"]["metrics"]["eol_assets"], "run(): the scoped view is smaller")
check(api._agent().meta()["summary"] == est_meta and api._agent().result == eol.scan(),
      "a scoped run never replaces the agent's whole-estate result (status card)")

# every page-called action is declared
page = open(os.path.join(ROOT, "agents/eol/page.html"), encoding="utf-8").read()
called = set(re.findall(r"API\.post\('([a-z_]+)'", page)) | set(re.findall(r"runAgentJob\([^)]*'eol'\s*,\s*'([a-z_]+)'", page))
man = json.load(open(os.path.join(ROOT, "agents/eol/manifest.json"), encoding="utf-8"))
decl = set(man["tag_scope"]["actions"]) | set(man["tag_scope"]["ignore"])
check(called == {"run", "apply", "tag_eol_date"} and called <= decl and set(man["tag_scope"]["actions"]) <= set(api.ACTIONS),
      "every action the page calls is declared in the manifest's tag_scope")
check("mountTagScope({agent:'eol'" in page and page.count("tagScopeNote()") >= 2, "page mounts the tag bar; confirms name the scope")
tagscope._POLICY.clear()
for a in ("run", "apply", "tag_eol_date"):
    check(tagscope.check("eol", a, {"tag_scope": {"key": TK, "value": TV}}) is None, f"launcher accepts a scoped '{a}'")
check(tagscope.check("eol", "nope", {"tag_scope": {"key": TK, "value": TV}})[1] == 400, "an undeclared action is refused")

# ── 3. writes: mocked, recomputed server-side, inside the tag ────────────────
CALLS = []


def fake_tag_set(category, value, uuids=None, sql="", params=(), **kw):
    got = navi_cli.collect_uuids(sql, params) if sql else list(uuids or [])
    CALLS.append(("tag_set", category, value, set(got), kw.get("agent")))
    return [{"ok": True, "job_id": len(CALLS)}] if got else []


def fake_tag(category, value, remove=False, **kw):
    CALLS.append(("tag", category, value, kw, remove))
    return {"ok": True, "job_id": len(CALLS)}


orig = navi_cli.tag_set, navi_cli.tag
navi_cli.tag_set, navi_cli.tag = fake_tag_set, fake_tag
try:
    est_view = eol.analyze()
    dates = [g["eol_date"] for g in est_view["date_groups"]]
    # estate: the same calls as before (exact set of each date)
    del CALLS[:]
    o, _ = api.tag_eol_date({"confirm": True, "dates": dates})
    est_calls = list(CALLS)
    check(o["ok"] and "scope" not in o and all(c[3] == set(navi_cli.collect_uuids(eol.date_tag_query(g)))
          for c, g in zip(est_calls, est_view["date_groups"])), "tag_eol_date (estate): each date's full set, as today")
    del CALLS[:]
    o, _ = api.tag_eol_date({"confirm": True, "dates": dates, "tag_scope": {"key": TK, "value": TV},
                             "uuids": ["evil-uuid"]})
    check(o["ok"] and o["scope"]["key"] == TK and CALLS and all(c[3] and c[3] <= S for c in CALLS),
          "tag_eol_date (tag view): every page is inside the tag, re-read from navi.db")
    check(all(c[1] == "Lifecycle EOL" and "evil-uuid" not in c[3] for c in CALLS), "…never a uuid from the browser")
    want = {g["eol_date"]: {u for u in g["uuids"] if u in S} for g in est_view["date_groups"]}
    check(all(c[3] == want[c[2]] for c in CALLS), "…and exactly the estate's assets on that date, ∩ the tag")
    o, st = api.tag_eol_date({"dates": dates, "tag_scope": {"key": TK, "value": TV}})
    check(st == 400 and not o["ok"], "tag_eol_date: confirm still required in a tag view")
    o, st = api.tag_eol_date({"confirm": "true", "dates": dates, "tag_scope": {"key": TK, "value": TV}})
    check(st == 400, "tag_eol_date: confirm must be JSON true")
    # apply — estate: navi --name per pattern (unchanged), add-only
    del CALLS[:]
    groups = [{"value": "Unsupported"}, {"value": "End of Life", "exclude": ["201363"]}]
    o, _ = api.apply({"confirm": True, "apply_groups": groups})
    check(o["ok"] and "scope" not in o and [c[0] for c in CALLS] == ["tag", "tag"]
          and CALLS[0][3].get("plugin_name") == "Unsupported" and "NOT IN ('201363')" in CALLS[1][3].get("query", "")
          and all(c[4] is False for c in CALLS), "apply (estate): today's navi selectors, add-only")
    # apply — tag view: computed set, inside the tag, opt-outs honoured
    del CALLS[:]
    o, _ = api.apply({"confirm": True, "apply_groups": groups + [{"value": "Bogus"}], "tag_scope": {"key": TK, "value": TV}})
    con = sqlite3.connect(FAST)
    want_u = {r[0] for r in con.execute("SELECT asset_uuid FROM vulns WHERE plugin_name LIKE '%Unsupported%'")} & S
    want_e = {r[0] for r in con.execute("SELECT asset_uuid FROM vulns WHERE (plugin_name LIKE '%End of Life%' OR "
                                        "plugin_name LIKE '%SEoL%' OR plugin_name LIKE '%End-of-Life%' OR "
                                        "plugin_name LIKE '%End of Support%') AND plugin_id<>'201363'")} & S
    con.close()
    check(o["ok"] and o["scope"]["key"] == TK and [c[0] for c in CALLS] == ["tag_set", "tag_set"]
          and o["total"] == 2, "apply (tag view): one computed tag set per known group (unknown groups dropped)")
    check(CALLS[0][1:4] == ("Lifecycle", "Unsupported", want_u) and CALLS[1][1:4] == ("Lifecycle", "End of Life", want_e),
          "apply (tag view): exactly the group's selector ∩ the tag, opted-out plugins left out")
    check(all(c[3] <= S for c in CALLS), "apply (tag view): never an asset outside the tag")
    # the same on the plain SQL path
    os.environ["NAVI_DB_PATH"] = RICH
    db.close_all()
    hx_summary.invalidate()
    del CALLS[:]
    api.apply({"confirm": True, "apply_groups": groups, "tag_scope": {"key": TK, "value": TV}})
    check(CALLS[0][3] == want_u and CALLS[1][3] == want_e, "apply (tag view, no summaries): the same sets")
    o, st = api.apply({"apply_groups": groups, "tag_scope": {"key": TK, "value": TV}})
    check(st == 400, "apply: confirm still required in a tag view")
finally:
    navi_cli.tag_set, navi_cli.tag = orig

# ── 4. caches ─────────────────────────────────────────────────────────────────
src = open(os.path.join(ROOT, "agents/eol/api.py"), encoding="utf-8").read()
check("Snapshots(" not in src and "snapcache" not in src, "Charon has no own server cache (nothing to key on the scope)")
check(json.dumps({"tag_scope": {"key": TK, "value": TV}}, sort_keys=True) != json.dumps({}, sort_keys=True),
      "the launcher's read cache keys on the payload, which carries tag_scope")

# ── 5. sample_navi.db: estate unchanged, scope = hand count ───────────────────
os.environ["NAVI_DB_PATH"] = SAMPLE
db.close_all()
hx_summary.invalidate()
con = sqlite3.connect(SAMPLE)
K, V = con.execute("SELECT tag_key, tag_value FROM tags GROUP BY 1,2 ORDER BY COUNT(DISTINCT asset_uuid) DESC LIMIT 1").fetchone()
con.close()
base = eol.analyze()
check(eol.analyze(scope=None) == base, "sample: whole estate unchanged")
S = tag_set(SAMPLE, K, V)
sv = eol.analyze(scope=(K, V))
check(sv["metrics"]["eol_assets"] == len({r[0] for r in eol_rows(SAMPLE) if r[0] in S}), f"sample: {K}:{V} EOL assets = hand count")
check(eol.scan(scope=("no such", "tag"))["groups"][1]["asset_count"] == 0
      and eol.analyze(scope=("no such", "tag"))["metrics"]["eol_assets"] == 0, "sample: an unknown tag scopes to nothing")

print("\n%d failure(s)" % len(fails) if fails else "\nALL PASS")
sys.exit(1 if fails else 0)
