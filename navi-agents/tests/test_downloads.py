"""Tests for Settings → Auto-approve downloads (core/downloads.py): default OFF, toggling it
through the Settings API (persisted to a TEMP config file, never the real one), the source
registry, and the server-side gate in the MITRE / CISA KEV run actions (urlopen mocked —
no network). Run: python3 tests/test_downloads.py  (or pytest)."""
import atexit
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-downloads-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)

# isolate BEFORE importing core: config store → temp file, setting unset, tiny navi.db
CFG = os.path.join(TMP, "hounds.config.json")
os.environ["HOUNDS_CONFIG"] = CFG
os.environ.pop("NAVI_AUTO_APPROVE_DOWNLOADS", None)
DB = os.path.join(TMP, "navi.db")
_c = sqlite3.connect(DB)
_c.executescript("""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, acr REAL);
CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, cves TEXT, xrefs TEXT,
                   state TEXT, first_found TEXT, severity TEXT);
INSERT INTO assets VALUES ('u1','h1','10.0.0.1',9);
INSERT INTO vulns VALUES ('u1','1','x','CVE-2099-0001','','open','2025-01-01T00:00:00Z','critical');
""")
_c.commit(); _c.close()
os.environ["NAVI_DB_PATH"] = DB

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


from core import config_store, downloads, kev, mitre  # noqa: E402
from agents.settings import api as settings_api  # noqa: E402
from agents.mitre import api as mitre_api  # noqa: E402
from agents.cisakev import api as kev_api  # noqa: E402

ENV = downloads.ENV

# ---------------------------------------------------------------- default OFF
check(ENV == "NAVI_AUTO_APPROVE_DOWNLOADS", "setting is NAVI_AUTO_APPROVE_DOWNLOADS")
check(config_store.path() == CFG, "config store points at the temp file (HOUNDS_CONFIG)")
check(ENV in config_store.MANAGED, "config store persists the setting (MANAGED)")
check(downloads.auto_approve() is False, "auto-approve is OFF by default")
check(downloads.allowed({}) == (False, ""), "OFF + no approval → no live download")
check(downloads.allowed({"approved": "yes"}) == (False, ""), "only approved:true (bool) counts as human approval")
check(downloads.allowed({"approved": True}) == (True, "user"), "OFF + approved:true → live, approved by user")
st, _ = settings_api.downloads_status({})
check(st["ok"] and st["auto_approve"] is False, "Settings downloads endpoint reports OFF")
f = next((x for x in settings_api._ENV_FIELDS if x["key"] == ENV), None)
check(bool(f) and f["label"] == "Auto-approve downloads" and f.get("bool"), "Settings field labelled 'Auto-approve downloads' (bool)")

# ---------------------------------------------------------------- registry
ids = {s["id"]: s for s in downloads.sources()}
check("mitre" in ids and ids["mitre"]["urls"] == [mitre.CSV_URL] and ids["mitre"]["agent"] == "mitre",
      "registry: MITRE ATT&CK→CVE CSV registered by core.mitre")
check("cisakev" in ids and ids["cisakev"]["urls"] == list(kev.FEED_URLS) and ids["cisakev"]["approval"],
      "registry: CISA KEV feed + mirror registered by core.kev")
try:
    from agents.software import api as _sw  # noqa: F401,E402
    sw = downloads.get("endoflife")
    check(bool(sw) and sw["approval"] is False and sw["agent"] == "software",
          "registry: endoflife.date listed with approval=False (no approval step)")
except Exception as e:
    check(False, f"registry: software api imports ({e})")
downloads.register("t_src", "Test", "https://example.org/x.json", agent="t")
check(downloads.get("t_src")["urls"] == ["https://example.org/x.json"], "register(): a str url becomes a list")
st, _ = settings_api.downloads_status({"id": "mitre"})
check(st["source"] and st["source"]["id"] == "mitre", "downloads endpoint returns the asked source")
st, _ = settings_api.status({})
check(any(s["id"] == "cisakev" for s in st["downloads"]["sources"]), "Settings status lists the sources")

# ---------------------------------------------------------------- server-side gate (no network)
CSV = "CVE ID,Primary,Secondary,Technique,Uncat\nCVE-2099-0001,T1190,,,\n"
KEVDOC = json.dumps({"catalogVersion": "test", "dateReleased": "2099-01-01",
                     "vulnerabilities": [{"cveID": "CVE-2099-0001", "dueDate": "2099-02-01",
                                          "dateAdded": "2099-01-01", "vendorProject": "V", "product": "P"}]})


def fake(body):
    return mock.MagicMock(side_effect=lambda *a, **k: io.BytesIO(body.encode()))


with mock.patch("urllib.request.urlopen", fake(CSV)) as m:
    o, _ = mitre_api.run({"scope": "navidb"})
    check(m.call_count == 0 and o["result"]["mapping_source"] == "bundled" and o["approved_by"] == "",
          "MITRE run, OFF + not approved → baked snapshot, urlopen never called")
    o, _ = mitre_api.run({"scope": "navidb", "approved": True})
    check(m.call_count == 1 and o["result"]["mapping_source"] == "live" and o["approved_by"] == "user",
          "MITRE run, OFF + approved:true → live download")

kev._CACHE.update(t=0.0, v=None)
with mock.patch("urllib.request.urlopen", fake(KEVDOC)) as m:
    o, _ = kev_api.run({})
    check(m.call_count == 0 and o["result"]["kev"]["source"] == "bundled", "KEV run, OFF + not approved → bundled, no network")
    o, _ = kev_api.run({"approved": True})
    check(m.call_count == 1 and o["result"]["kev"]["source"] == "live" and o["approved_by"] == "user",
          "KEV run, OFF + approved:true → live download")

# ---------------------------------------------------------------- toggle ON via Settings (persisted to temp file)
o, _ = settings_api.set_env({"env": {ENV: "1"}})
check(ENV in o.get("applied", []) and downloads.auto_approve(), "Settings set_env turns auto-approve ON (live)")
check(o["downloads"]["auto_approve"] is True, "set_env response reflects ON")
saved = json.load(open(CFG)) if os.path.exists(CFG) else {}
check(saved.get("env", {}).get(ENV) == "1", "ON is saved to the (temp) config file")
check(downloads.allowed({}) == (True, "settings"), "ON → live download, approved by settings")
s, _ = mitre_api.source({})
check(s["auto_approved"] is True and s["source_id"] == "mitre", "MITRE source action reports auto_approved")

kev._CACHE.update(t=0.0, v=None)
with mock.patch("urllib.request.urlopen", fake(CSV)) as m:
    o, _ = mitre_api.run({"scope": "navidb"})
    check(m.call_count == 1 and o["result"]["mapping_source"] == "live" and o["approved_by"] == "settings",
          "MITRE run, ON → downloads without approved:true")
with mock.patch("urllib.request.urlopen", mock.MagicMock(side_effect=OSError("offline"))):
    o, _ = mitre_api.run({"scope": "navidb"})
    check(o["result"]["mapping_source"] == "bundled", "MITRE run, ON + offline → falls back to the snapshot")
    o, _ = kev_api.run({})
    check(o["result"]["kev"]["source"] == "bundled" and o["approved_by"] == "settings",
          "KEV run, ON + offline → falls back to the bundled snapshot")

# ---------------------------------------------------------------- toggle OFF again
o, _ = settings_api.set_env({"env": {ENV: "0"}})
check(downloads.auto_approve() is False, "Settings set_env turns auto-approve OFF again")
check(json.load(open(CFG)).get("env", {}).get(ENV) == "0", "OFF is saved to the (temp) config file")

# ---------------------------------------------------------------- pages use the shared helper
js = open(os.path.join(ROOT, "web", "assets", "console.js"), encoding="utf-8").read()
check("async function downloadsAutoApproved(" in js, "console.js defines downloadsAutoApproved()")
for a in ("mitre", "cisakev"):
    h = open(os.path.join(ROOT, "agents", a, "page.html"), encoding="utf-8").read()
    check(f"downloadsAutoApproved('{a}')" in h and "approved:APPROVED" in h,
          f"{a} page checks the setting and sends approved with run")


# ---------------------------------------------------------------- a later run can't change what apply/tag uses
# (review fix: the live/snapshot choice used to live in one process-wide flag that any run —
#  e.g. the Contract's discovery, which calls run({}) — overwrote)
with mock.patch("urllib.request.urlopen", fake(CSV)) as m:
    mitre_api.run({"scope": "navidb", "approved": True})
    mitre_api.run({})                                        # Contract-style run: no approval
    n0 = m.call_count
    mitre_api.apply({"confirm": True, "approved": True, "actions": [{"cve": "CVE-2099-0001", "value": "x"}]})
    check(m.call_count > n0, "MITRE apply with approved:true uses the live mapping even after an unapproved run")
    n1 = m.call_count
    mitre_api.apply({"confirm": True, "actions": [{"cve": "CVE-2099-0001", "value": "x"}]})
    check(m.call_count == n1, "MITRE apply without approval never downloads")
kev_api._UPLOAD["text"] = "SENTINEL"
kev_api.run({})                                              # Contract-style run
check(kev_api._UPLOAD["text"] == "SENTINEL", "an empty (Contract) run doesn't wipe the page's uploaded KEV catalog")
mitre_api._LAST["csv"] = "SENTINEL"
mitre_api.run({})
check(mitre_api._LAST["csv"] == "SENTINEL", "an empty (Contract) run doesn't wipe the page's uploaded MITRE CSV")
for a2 in ("tag_due", "tag_ransomware"):
    check(f"API.post('{a2}',{{" in open(os.path.join(ROOT, "agents", "cisakev", "page.html"), encoding="utf-8").read()
          and "approved:APPROVED" in open(os.path.join(ROOT, "agents", "cisakev", "page.html"), encoding="utf-8").read(),
          f"KEV page sends approved with {a2}")


def test_downloads():
    """pytest entry point — every check above ran at import; fail with the list."""
    assert not fails, "\n".join(fails)


if __name__ == "__main__":
    print(f"\n{len(fails)} failure(s)")
    sys.exit(1 if fails else 0)
