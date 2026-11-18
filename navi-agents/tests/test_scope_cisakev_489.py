"""Regression tests — build 489: Laelaps (CISA KEV) by tag.

  · run honours tag_scope {key, value}: the KEV analysis (CVEs, due dates, crown jewels, vendors,
    timeline, remediated) and the xref view (KEV assets / findings, dates added) cover only the
    tag's assets. Every per-CVE / per-asset fact is the whole estate's; only the population shrinks.
  · No scope → byte-for-byte the same result as before (and the same as tag_scope: null).
  · tag_vulnerable / tag_dates / tag_due / tag_ransomware from a tag view tag ONLY assets carrying
    the tag — the set is re-read from navi.db on the server (a uuid list in the body is ignored).
  · Laelaps keeps no result cache of its own (only CISA's catalog, which is scope-free), and a
    scoped run never overwrites the whole estate's AGENT.result.
  · Both paths: the plain vulns scan and the hx_summary fast path.
Run: python3 tests/test_scope_cisakev_489.py"""
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
TMP = tempfile.mkdtemp(prefix="hounds-489-kev-")
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


from core import hx_summary, kev, launcher, navi_cli, tagscope  # noqa: E402
from agents.cisakev import agent as kagent, api  # noqa: E402

XREF = "CISA-KNOWN-EXPLOITED"
CVE_RE = re.compile(r"CVE-\d{4}-\d{3,}", re.I)

# make sure the lab db has some catalog KEV CVEs on tagged assets: the bundled catalog is the
# source of truth for "catalog CVEs"; build a tiny catalog upload from the CVEs in navi.db
con = sqlite3.connect(DB)
cves_in_db = sorted({c.upper() for (s,) in con.execute("SELECT cves FROM vulns WHERE TRIM(COALESCE(cves,''))<>''")
                     for c in CVE_RE.findall(s or "")})
CAT = {"catalogVersion": "test", "dateReleased": "2026-01-01", "vulnerabilities": [
    {"cveID": c, "vendorProject": "v%d" % (i % 4), "product": "p%d" % (i % 3), "vulnerabilityName": c,
     "dateAdded": "2024-0%d-01" % (1 + i % 9), "dueDate": ("2025-0%d-15" if i % 2 else "2027-0%d-15") % (1 + i % 9),
     "knownRansomwareCampaignUse": "Known" if i % 3 == 0 else "Unknown"} for i, c in enumerate(cves_in_db)]}
JT = json.dumps(CAT)
K_CAT = {v["cveID"] for v in CAT["vulnerabilities"]}

# a tag that holds KEV-catalog assets AND leaves some out
best = None
for k, v, n in con.execute("SELECT tag_key, tag_value, COUNT(DISTINCT asset_uuid) FROM tags "
                           "WHERE TRIM(COALESCE(tag_value,''))<>'' GROUP BY 1,2 HAVING COUNT(DISTINCT asset_uuid)>=3"):
    best = best or (k, v, n)
TK, TV, NT = best
TAG = {u for (u,) in con.execute("SELECT DISTINCT asset_uuid FROM tags WHERE tag_key=? AND tag_value=?", (TK, TV))}
ACR = {u: float(a or 0) for u, a in con.execute("SELECT uuid, acr FROM assets")}
con.close()
VROWS = []


def load_rows():
    c = sqlite3.connect(DB)
    has_state = "state" in {r[1] for r in c.execute("PRAGMA table_info(vulns)")}
    VROWS[:] = c.execute("SELECT asset_uuid, cves, xrefs, %s, plugin_id FROM vulns" % ("state" if has_state else "'open'")).fetchall()
    c.close()
print(f"lab: scope {TK} : {TV} ({NT} assets) · {len(K_CAT)} catalog CVEs")
SC = {"tag_scope": {"key": TK, "value": TV}}


def hand(uuids=None, plugin_level=False):
    """Hand count over the vulns table: KEV catalog assets (open findings), xref assets / findings (any
    state). plugin_level: the hx_summary rule — the KEV xref is a plugin attribute (any finding of a
    plugin that carries it counts)."""
    kev_assets, xa, xf, per = set(), set(), 0, {}
    kp = {pid for u, cv, xr, st, pid in VROWS if XREF in (xr or "")}
    for u, cv, xr, st, pid in VROWS:
        if uuids is not None and u not in uuids:
            continue
        if (pid in kp) if plugin_level else (XREF in (xr or "")):
            xa.add(u); xf += 1
        if (st or "open").lower() not in ("open", "reopened"):
            continue
        for c in {c.upper() for c in CVE_RE.findall(cv or "")}:
            if c in K_CAT:
                kev_assets.add(u); per.setdefault(c, set()).add(u)
    return kev_assets, xa, xf, per


def runp(p):
    p = dict(p, json_text=JT, approved=False)
    r = tagscope.check("cisakev", "run", p)
    assert r is None, r
    return api.run(p)[0]["result"]


def strip(x):
    return json.loads(json.dumps(x, sort_keys=True, default=str))


for phase in ("vulns scan (no state column)", "hx_summary + state + fixed"):
    if phase.startswith("hx"):
        # a navi.db like the real one: vulns.state (some findings fixed), a fixed table, the hx indexes
        c = sqlite3.connect(DB, isolation_level=None)
        try:
            c.execute("ALTER TABLE vulns ADD COLUMN state TEXT")
            c.execute("UPDATE vulns SET state = CASE WHEN rowid % 5 = 0 THEN 'fixed' WHEN rowid % 7 = 0 THEN 'reopened' ELSE 'open' END")
            c.execute("CREATE TABLE fixed(asset_uuid TEXT, cves TEXT, last_fixed TEXT)")
            c.execute("INSERT INTO fixed SELECT asset_uuid, cves, CASE WHEN rowid % 2 THEN '2025-01-01T00:00:00Z' ELSE '2028-01-01T00:00:00Z' END "
                      "FROM vulns WHERE state='fixed' AND TRIM(COALESCE(cves,''))<>''")
            c.execute("CREATE INDEX hx_v_plugin ON vulns(plugin_id, asset_uuid, state, severity)")
            c.execute("CREATE INDEX hx_v_asset ON vulns(asset_uuid, plugin_id, state, severity)")
            hx_summary.build(c)
        finally:
            c.close()
        hx_summary.invalidate()
        if not hx_summary.usable(DB):
            print("SKIP hx_summary phase — summaries not usable on this lab db")
            continue
    print(f"── {phase} ──")
    load_rows()
    # ── 1. whole estate unchanged ────────────────────────────────────────────
    est = runp({})
    est_null = runp({"tag_scope": None})
    direct = {**kagent.xref_view(), "kev": kev.analyze(json_text=JT, allow_live=False)}
    check(strip(est) == strip(est_null), "tag_scope: null = the whole estate, identical result")
    check(strip(est) == strip(direct), "no scope = the unscoped engine (same as before 489)")
    check("scope" not in est and "scope" not in est["kev"], "a whole-estate result carries no scope")
    if phase.startswith("hx"):
        check(hx_summary.usable(DB), "the hx_summary fast path is in use")
        rem_e = est["kev"]["metrics"]["remediated"]
        c = sqlite3.connect(DB)
        fx = c.execute("SELECT asset_uuid, cves FROM fixed").fetchall()
        c.close()
        hand_fx = lambda us: sum(1 for u, cv in fx if (us is None or u in us) and {x.upper() for x in CVE_RE.findall(cv or "")} & K_CAT)
        check(rem_e and rem_e["findings"] == hand_fx(None), "estate remediated KEV = hand count over fixed")
    PL = phase.startswith("hx")
    ka, xa, xf, per = hand(None, PL)
    check(est["kev"]["metrics"]["kev_assets"] == len(ka) and est["summary"]["kev_assets"] == len(xa),
          f"estate counts = hand counts ({len(ka)} KEV-catalog assets, {len(xa)} xref assets)")
    est_agent_result = strip(api.AGENT.result)

    # ── 2. scoped counts = hand counts over the tag ──────────────────────────
    sc = runp(SC)
    ka_t, xa_t, xf_t, per_t = hand(TAG, PL)
    m = sc["kev"]["metrics"]
    check(sc.get("scope", {}).get("assets") == NT and sc["kev"].get("scope", {}).get("label") == f"{TK} : {TV}",
          "a scoped result names its scope and its asset count")
    check(m["kev_assets"] == len(ka_t), f"scoped KEV assets = hand count over the tag ({len(ka_t)})")
    check(m["kev_cves"] == len(per_t), f"scoped KEV CVEs = hand count ({len(per_t)})")
    check(sc["summary"]["kev_assets"] == len(xa_t) and sc["summary"]["kev_findings"] == xf_t,
          f"scoped xref assets / findings = hand count ({len(xa_t)} / {xf_t})")
    check(all(c["assets"] == len(per_t[c["cve"]]) for c in sc["kev"]["cves"]), "each CVE's asset count is over the tag only")
    check(m["crown_assets"] == sum(1 for u in ka_t if ACR.get(u, 0) > kev.CROWN_ACR), "crown jewels counted over the tag")
    check(all(r["asset_uuid"] in TAG for r in sc["kev"]["crown"]), "every crown-jewel row is in the tag")
    check(sum(d["assets"] for d in sc["dates"]) <= sum(d["assets"] for d in est["dates"]), "dates added: no more than the estate")
    check(m["catalog_total"] == est["kev"]["metrics"]["catalog_total"], "the catalog itself is not scoped")
    check(0 < m["kev_assets"] < est["kev"]["metrics"]["kev_assets"], "the tag holds some, not all, KEV assets (a real test)")
    if phase.startswith("hx"):
        check(m["remediated"]["findings"] == hand_fx(TAG), "scoped remediated KEV = hand count over the tag's fixed rows")
    est_dates = {d["kev_date"]: d for d in est["dates"]}
    check(all(d["kev_date"] in est_dates and d["assets"] <= est_dates[d["kev_date"]]["assets"] for d in sc["dates"]),
          "each scoped date added is an estate date, with no more assets")

    # ── 3. per-asset / per-CVE values identical ──────────────────────────────
    E = {c["cve"]: c for c in est["kev"]["cves"]}
    same_keys = ("vendor", "product", "name", "date_added", "due_date", "days_left", "bucket", "ransomware")
    check(all(c["cve"] in E and all(c[k] == E[c["cve"]][k] for k in same_keys) for c in sc["kev"]["cves"]),
          "each KEV CVE's due date / bucket / ransomware flag is the whole estate's")
    EC = {r["asset_uuid"]: r for r in est["kev"]["crown"]}
    check(all(r["asset_uuid"] in EC and {k: r[k] for k in ("acr", "kev", "overdue", "ransomware", "cves")} ==
              {k: EC[r["asset_uuid"]][k] for k in ("acr", "kev", "overdue", "ransomware", "cves")} for r in sc["kev"]["crown"]),
          "each crown jewel's ACR / KEV / overdue / ransomware counts are its whole-estate values")
    check(strip(api.AGENT.result) == est_agent_result, "a scoped run never overwrites the estate's AGENT.result")
    check(not kev.analyze(json_text=JT, allow_live=False, scope=("no such key", "x"))["cves"],
          "an unknown tag scopes to nothing")

    # ── 4. scoped writes: server-side set, inside the tag ────────────────────
    calls = []

    def fake_tag_set(category, value, uuids=None, sql="", params=(), agent="", **kw):
        got = navi_cli.collect_uuids(sql, params) if sql else list(uuids or [])
        calls.append({"category": category, "value": value, "uuids": set(got), "sql": sql})
        return [{"ok": True, "job_id": len(calls)}] if got else []

    def fake_tag(category, value, **kw):
        calls.append({"category": category, "value": value, "estate": True, **kw})
        return {"ok": True, "job_id": len(calls)}

    o_ts, o_t = navi_cli.tag_set, navi_cli.tag
    navi_cli.tag_set, navi_cli.tag = fake_tag_set, fake_tag
    try:
        def call(action, body):
            body = dict(body, confirm=True, approved=False)
            r = tagscope.check("cisakev", action, body)
            return r if r else getattr(api, action)(body)

        evil = {"uuids": ["evil-uuid"], "asset_uuids": ["evil-uuid"]}
        calls.clear()
        o, st = call("tag_vulnerable", {**SC, **evil})
        tv = [x for x in calls if x["value"] == "Vulnerable"]
        check(st == 200 and o["ok"] and tv and not any(x.get("estate") for x in calls) and tv[0]["uuids"] == hand(TAG)[1],
              "scoped tag_vulnerable: exactly the tag's assets with a KEV-xref finding — navi --xrefs' rule — (no estate selector)")
        dates = [d["kev_date"] for d in sc["dates"]]
        calls.clear()
        o, st = call("tag_dates", {**SC, "dates": None, **evil})
        check(st == (200 if dates else 400) and all(x["uuids"] <= TAG and x["uuids"] for x in calls) and len(calls) == len(dates),
              "scoped tag_dates: one tag per date added on the tag's assets, inside the tag")
        calls.clear()
        dues = sorted({c["due_date"] for c in sc["kev"]["cves"] if c["due_date"]})
        o, st = call("tag_due", {**SC, "dues": dues, **evil})
        want = set().union(*[per_t[c["cve"]] for c in sc["kev"]["cves"]]) if sc["kev"]["cves"] else set()
        check(st == (200 if dues else 400) and set().union(*[x["uuids"] for x in calls] or [set()]) == want
              and all(x["uuids"] <= TAG for x in calls), "scoped tag_due: the tag's KEV assets only, recomputed in navi.db")
        calls.clear()
        rans = [c for c in sc["kev"]["cves"] if c["ransomware"]]
        o, st = call("tag_ransomware", {**SC, **evil})
        rw = set().union(*[per_t[c["cve"]] for c in rans]) if rans else set()
        check(st == (200 if rans else 400) and (not rans or calls[0]["uuids"] == rw) and all(x["uuids"] <= TAG for x in calls),
              "scoped tag_ransomware: the tag's ransomware-KEV assets only")
        check(not any("evil-uuid" in x.get("uuids", ()) for x in calls), "a uuid list in the body is never used")
        # the estate writes are what they were
        calls.clear()
        o, st = call("tag_vulnerable", {})
        check(calls and calls[0].get("estate") and calls[0].get("xrefs") == XREF and calls[0].get("remove") is False,
              "estate tag_vulnerable: unchanged (navi --xrefs, remove=False)")
        calls.clear()
        o, st = call("tag_due", {"dues": sorted({c["due_date"] for c in est["kev"]["cves"] if c["due_date"]})})
        got = set().union(*[x["uuids"] for x in calls] or [set()])
        check(got == ka, "estate tag_due: every KEV asset, as before")
        o, st = call("tag_due", {**SC, "dues": dues})
        o2 = api.tag_due({**SC, "dues": dues})
        check(o2[1] == 400, "scoped writes still need confirm")
        check(not navi_cli.writes_enabled(), "NAVI_ALLOW_WRITES stays off")
    finally:
        navi_cli.tag_set, navi_cli.tag = o_ts, o_t

# ── 5. the manifest covers every action the page calls ───────────────────────
pg = open(os.path.join(ROOT, "agents", "cisakev", "page.html"), encoding="utf-8").read()
called = set(re.findall(r"API\.post\('([a-z_]+)'", pg)) | set(re.findall(r"runAgentJob\('cisakev',\s*'([a-z_]+)'", pg))
man = json.load(open(os.path.join(ROOT, "agents", "cisakev", "manifest.json"), encoding="utf-8"))
pol = man.get("tag_scope") or {}
declared = set(pol.get("actions", [])) | set(pol.get("ignore", []))
check(called and called <= declared, f"every page-called action is declared ({sorted(called)})")
check(declared <= set(man["actions"]), "every declared action exists")
check({"run", "tag_vulnerable", "tag_dates", "tag_due", "tag_ransomware"} <= set(pol["actions"])
      and set(pol["ignore"]) == {"source", "nl"}, "reads and writes honour the scope; source / nl ignore it")
check("fetch(" not in pg, "no raw fetch() bypasses the scope")
check("mountTagScope({agent:'cisakev'" in pg and pg.index("mountAgentHeader(") < pg.index("mountTagScope("),
      "page mounts the tag filter after the header")
check(pg.count("tagScopeNote()") >= 4 and "Tag view: only assets tagged" in pg, "every confirm names the scope")
r = tagscope.check("cisakev", "source", dict(SC))
check(r is None, "source with a scope is allowed (scope dropped)")

# ── 6. no own cache mixes estate and tag ─────────────────────────────────────
src = open(os.path.join(ROOT, "core", "kev.py"), encoding="utf-8").read()
check(set(kev._CACHE) == {"t", "v"} and isinstance(kev._CACHE["v"], (tuple, type(None))),
      "core.kev caches only the (scope-free) CISA catalog")
a1 = kev.analyze(json_text=JT, allow_live=False)
a2 = kev.analyze(json_text=JT, allow_live=False, scope=(TK, TV))
a3 = kev.analyze(json_text=JT, allow_live=False)
check(strip(a1) == strip(a3) and a2["metrics"]["kev_assets"] <= a1["metrics"]["kev_assets"],
      "estate → tag → estate: the estate result is never served the tag's, nor the reverse")
check(("cisakev", "run") not in getattr(launcher, "_OPEN_ACTIONS", set()), "run is a normal (cached-by-payload, detached) run")

print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
