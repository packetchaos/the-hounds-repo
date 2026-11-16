"""Regression tests — build 465: ONE definition of "credentialed" across the pack.

credentialed = any plugin 19506 row says "Credentialed checks : yes" (not just the newest), or
141118 / 110095 is present. blind = scanned but not credentialed. Failure plugins (104410 …)
are issues, not the coverage measure. Every hound that reports credential coverage — Scan
Evaluation, Alerts, Identity, Exposure Score (blind), Attack Paths, On the Scent, Argos — must
agree. Run: python3 tests/test_credstate_465.py"""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-465-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def info(cred, date="2026/11/1 10:00", name="Weekly"):
    return ("Information about this scan : \nNessus version : 10.8.0\nScan name : %s\nScan policy used : Advanced\n"
            "Scanner IP : 10.0.0.5\nCredentialed checks : %s\nScan Start Date : %s\nScan duration : 600 sec\n"
            % (name, cred, date))


# asset → its findings (plugin_id, output)
A = {
    "yes": [("19506", info("yes, as 'svc' via ssh"))],
    "no": [("19506", info("no"))],
    "yes_then_no": [("19506", info("yes, as 'svc' via ssh", "2026/10/1 10:00")),       # credentialed scan…
                    ("19506", info("no", "2026/11/5 10:00", "Discovery"))],            # …then a newer discovery scan
    "ok141118": [("141118", "SSH: valid credentials provided")],
    "yes_104410": [("19506", info("yes, as 'svc' via ssh")), ("104410", "SMB: login failed for 'admin'")],
    "no_104410": [("19506", info("no")), ("104410", "SSH: login failed for 'root'")],
    "nocreds": [("110723", "No credentials were provided")],
    "never": [("10180", "ping")],
}
c = sqlite3.connect(DB)
c.execute("CREATE TABLE assets (uuid text, hostname text, ip_address text, acr text, last_found text)")
c.execute("CREATE TABLE vulns (asset_uuid text, plugin_id text, plugin_name text, output text, severity text, "
          "state text, last_found text, xrefs text, cves text)")
c.execute("CREATE TABLE tags (asset_uuid text, tag_key text, tag_value text)")
for i, (u, rows) in enumerate(A.items()):
    c.execute("INSERT INTO assets VALUES (?,?,?,?,?)", (u, "h-" + u, "10.0.1.%d" % (i + 1), "8", "2026-11-05"))
    for pid, out in rows:
        c.execute("INSERT INTO vulns (asset_uuid, plugin_id, plugin_name, output, severity, state, last_found) "
                  "VALUES (?,?,?,?,?,?,?)", (u, pid, "p" + pid, out, "Info", "open", "2026-11-05"))
c.commit()
c.close()

CRED = {"yes", "yes_then_no", "ok141118", "yes_104410"}
BLIND = {"no", "no_104410", "nocreds"}

from core import credstate  # noqa: E402
s = credstate.sets()
check(s["credentialed"] == CRED, "credstate: any 19506 yes (even with a newer 'no') or 141118 = credentialed (%s)" % sorted(s["credentialed"]))
check(s["blind"] == BLIND and "never" not in s["scanned"], "credstate: blind = scanned but not credentialed; never-scanned is not blind")
check(credstate.asset_blind("no") and not credstate.asset_blind("yes_then_no") and not credstate.asset_blind("never")
      and not credstate.asset_blind("yes_104410"), "credstate.asset_blind agrees, one asset at a time")

from core import scan_eval  # noqa: E402
ev = scan_eval.evaluate()
st = {x["asset_uuid"]: x for x in ev["assets"]}
check({u for u, x in st.items() if x["status"] == "ok"} == CRED, "Scan Evaluation: 'Credentialed' = the shared rule")
check(st["yes_104410"]["status"] == "ok" and st["yes_104410"]["issue"] == "failed",
      "Scan Evaluation: 19506 yes + 104410 = credentialed with a credential ISSUE (not blind)")
check(st["no_104410"]["status"] == "failed" and st["no"]["status"] == "uncredentialed" and st["nocreds"]["status"] == "uncredentialed"
      and st["never"]["status"] == "unknown", "Scan Evaluation: not credentialed → the reason (failed / uncredentialed); no data → unknown")
check(ev["metrics"]["blind"] == len(BLIND) and ev["metrics"]["credentialed"] == len(CRED) and ev["metrics"]["cred_issue"] == 1,
      "Scan Evaluation metrics: blind %d, credentialed %d" % (ev["metrics"]["blind"], ev["metrics"]["credentialed"]))

from core import alerts  # noqa: E402
a = alerts._chk_cred_coverage(DB, {})
check(a["value"] == round(100.0 * len(CRED) / len(A), 1) and a["note"].startswith("%d of %d assets credentialed" % (len(CRED), len(A))),
      "Alerts credential coverage: %s (was: every asset without a 104410)" % a["note"])

from core import identity  # noqa: E402
r = identity.scan()
check(r["credentialed"] == len(CRED) and r["blind"] == len(BLIND) and set(r["host_sets"]["uncredentialed"]) == BLIND,
      "Identity: credentialed %d / uncredentialed %d (the same sets)" % (r["credentialed"], r["blind"]))

from core import fused_score  # noqa: E402
o = fused_score.overview()
check(o["kpi"]["blind"] == len(BLIND), "Exposure Score 'blind' = scanned but not credentialed (%s)" % o["kpi"]["blind"])

ap = open(os.path.join(ROOT, "core", "attackpath.py"), encoding="utf-8").read()
check('m["uncredentialed"] = credstate.counts(db_path)["blind"]' in ap, "Attack Paths 'hosts scanned without credentials' = credstate blind")
ins = open(os.path.join(ROOT, "core", "insights.py"), encoding="utf-8").read()
check('"Credentialed", "count": cred_n' in ins and 'max(0, total - blind), "note": f"{blind} blind' not in ins.split("cred_n, cred_note = ")[0],
      "On the Scent funnel: 'Credentialed' counts credentialed assets, not 'total minus failures'")
ar = open(os.path.join(ROOT, "agents", "argos", "api.py"), encoding="utf-8").read()
check("plugin_id IN ('141118','110095') OR" in ar, "Argos: credentialed = any 19506 yes / 141118 / 110095, not only the newest scan")
print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
