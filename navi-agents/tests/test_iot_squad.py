"""Regression tests for the IoT Discovery Squad (Cerberus): registry discovery + signal fusion
without double-tagging, virtual NICs / hypervisors dropped, software-enum hosts excluded,
the page metrics (exposure, KEV, AES/ACR, identity-signal coverage), a db without the vulns
table, every result key the contract / release recipe read, and the gated writes.
Tiny synthetic navi.db in a temp dir; no navi, no network.
Run: python3 tests/test_iot_squad.py  (or pytest)."""
import atexit
import json
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-iot-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB
REG = os.path.join(TMP, "iot_detections.json")
shutil.copy(os.path.join(ROOT, "data", "iot_detections.json"), REG)
os.environ["IOT_REGISTRY_PATH"] = REG          # never touch the shipped registry

from core import navi_cli  # noqa: E402

TAGGED = []
navi_cli.tag = lambda *a, **k: (TAGGED.append((a, k)) or {"ok": True, "queued": True, "job_id": len(TAGGED)})
from core import iot_common as ic  # noqa: E402
from agents.iot_squad import api  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


KEV = "CISA-KNOWN-EXPLOITED:2023/01/01"
CAST, CAM, ESX, WIN, PRN, FIXED = ("u-cast", "u-cam", "u-esx", "u-win", "u-prn", "u-fixed")


def build(path, with_vulns=True):
    if os.path.exists(path):
        os.remove(path)
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT, aes TEXT, operating_system TEXT)")
    for u, h, ip, acr, aes, osn in [(CAST, "", "10.0.0.5", "6", "480", ""),
                                     (CAM, "cam-lobby", "10.0.0.9", "8", "720", "Linux Kernel 3.10"),
                                     (ESX, "esx01", "10.0.0.20", "9", "800", "VMware ESXi"),
                                     (WIN, "ws01", "10.0.0.30", "5", "400", "Microsoft Windows 10"),
                                     (PRN, "prn01", "10.0.0.40", "3", "200", ""),
                                     (FIXED, "", "10.0.0.50", "2", "100", "")]:
        c.execute("INSERT INTO assets VALUES (?,?,?,?,?,?)", (u, h, ip, acr, aes, osn))
    if with_vulns:
        c.execute("CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, output TEXT, "
                  "severity TEXT, xrefs TEXT, state TEXT)")
        rows = [
            # Chromecast: registry (66717 mDNS) AND signal-fusion (OUI Google + Device Type)
            (CAST, "66717", "mDNS Detection (Local Network)", "_googlecast._tcp Chromecast-Ultra", "Info", "", "open"),
            (CAST, "35716", "Ethernet Card Manufacturer Detection", "00:11:22 : Google, Inc.", "Info", "", "open"),
            (CAST, "54615", "Device Type", "Remote device type : embedded", "Info", "", "open"),
            (CAST, "99001", "Chromecast RCE", "", "Critical", KEV, "open"),
            (CAST, "99002", "Chromecast info leak", "", "High", "", "fixed"),        # fixed → not counted
            # Camera: signal fusion only (Device Type camera + Hikvision OUI) — no registry detection
            (CAM, "54615", "Device Type", "Remote device type : camera", "Info", "", "open"),
            (CAM, "35716", "Ethernet Card Manufacturer Detection", "44:19:b6 : Hangzhou Hikvision", "Info", "", "open"),
            (CAM, "99003", "Hikvision auth bypass", "", "High", "", "open"),
            (CAM, "99004", "Hikvision weak TLS", "", "High", "", "open"),
            # ESXi hypervisor: VMware OUI + Device Type hypervisor — infrastructure, not IoT
            (ESX, "54615", "Device Type", "Remote device type : hypervisor", "Info", "", "open"),
            (ESX, "35716", "Ethernet Card Manufacturer Detection", "00:50:56 : VMware, Inc.", "Info", "", "open"),
            # Windows host with the UniFi *app* in software enum — must not be called Ubiquiti
            (WIN, "22869", "Software Enumeration (SSH)", "Ubiquiti UniFi Controller 7.1", "Info", "", "open"),
            (WIN, "10863", "SSL Certificate Information", "Subject: Ubiquiti", "Info", "", "open"),
            (PRN, "11219", "Nessus SYN scanner", "Port 9100", "Info", "", "open"),
        ]
        c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?,?)", rows)
    c.execute("CREATE TABLE certs(asset_uuid TEXT, common_name TEXT, organization TEXT, organization_unit TEXT)")
    c.commit()
    c.close()


build(DB)
out, code = api.run({"use_pack": False})
res = out["result"]
check(code == 200 and out["ok"], "run returns ok")

# ---- every key the contract (_ad_iot_squad), the page and the release recipe read ----
for k in ("registry", "discovery", "carriers", "xterm", "qa", "tag_actions", "proposals"):
    check(k in res, f"result keeps '{k}'")
for k in ("available", "signal_coverage", "exposure"):
    check(k in res, f"result adds page-metric key '{k}'")
check(set(res["qa"]["coverage"]) >= {"carriers", "proposals", "floor", "assets", "combinations_tested"},
      "qa.coverage keeps its counters")
recipes = json.load(open(os.path.join(ROOT, "core", "release_recipes.json")))
rec = json.dumps(recipes)
check('"agent": "iot_squad", "action": "run", "body": {"use_pack": false}' in rec
      and '"agent": "iot_squad", "action": "registry", "body": {}' in rec,
      "release recipe still lists run {use_pack:false} + registry {} (what the page sends)")

det = res["discovery"]["detected"]
by_uuid = {}
for a in det:
    by_uuid.setdefault(a["asset_uuid"], []).append(a)
values = [a["value"] for a in res["tag_actions"]]

check(CAST in by_uuid and not any(a.get("fused") for a in by_uuid[CAST]), "Chromecast found by the registry")
check(CAM in by_uuid and all(a.get("fused") for a in by_uuid[CAM]), "camera found by signal fusion only")
check(ESX not in by_uuid, "VMware hypervisor is not reported as IoT")
check(WIN not in by_uuid, "Windows host with the UniFi app (software enum) excluded")
check(PRN not in by_uuid, "asset with no identity signal not reported")
cast_tags = [a for a in res["tag_actions"] if CAST in a["asset_uuids"]]
check(len(cast_tags) == 1 and cast_tags[0]["value"] == "Chromecast",
      "registry-confirmed device gets ONE Device Type tag (no second fusion-label tag)")
check(all(a["category"] == "Asset Inventory" and a["tag_value"].startswith("Device Type: ")
          for a in res["tag_actions"]), "tag actions use the unified Asset Inventory scheme")

# ---- page metrics ----
ex = {e["asset_uuid"]: e for e in res["exposure"]["assets"]}
sm = res["exposure"]["summary"]
check(set(ex) == set(by_uuid), "exposure rows exactly cover the discovered devices")
check(ex[CAST]["critical"] == 1 and ex[CAST]["high"] == 0, "fixed findings are not counted (state='fixed')")
check(ex[CAST]["kev"] == 1 and ex[CAM]["kev"] == 0, "CISA KEV detected from xrefs")
check(ex[CAM]["high"] == 2 and ex[CAM]["aes"] == 720 and ex[CAM]["acr"] == 8, "severity + AES/ACR per device")
check(sm["with_critical"] == 1 and sm["with_high"] == 1 and sm["with_kev"] == 1, "summary device counts")
check(sm["max_aes"] == 720 and sm["max_aes_uuid"] == CAM and sm["aes_high"] == 1, "highest-AES device (Argos link)")
sig = {s["plugin_id"]: s["assets"] for s in res["signal_coverage"]}
check(len(sig) == len(ic.IDENTITY_SIGNALS), "identity-signal coverage lists every signal plugin")
check(sig["54615"] == 3 and sig["35716"] == 3 and sig["66717"] == 1 and sig["22964"] == 0,
      "identity-signal coverage counts assets per plugin")

# ---- the contract adapter still plans from the run ----
from core import contract  # noqa: E402
items = contract._ad_iot_squad({})
check(items and all(s.get("category") == "Asset Inventory" and s.get("remove") is False
                    for it in items for s in it.get("specs", [])),
      "contract adapter plans add-only Asset Inventory specs from the run")

# ---- gated writes ----
TAGGED.clear()
o, c = api.tags_apply({"values": ["Chromecast"]})
check(c == 400 and not TAGGED, "tags_apply refuses without confirm")
api.AGENT.result = None                      # page cache replay after a server restart
o, c = api.tags_apply({"values": ["Chromecast"], "confirm": True})
check(c == 200 and o["ok"] and TAGGED and all(k.get("remove") is False for _, k in TAGGED),
      "tags_apply re-derives the run when the process has none, tags add-only")
o, c = api.detections_decide({"decisions": [{"iot_name": "X", "plugin_id": "1", "approve": False}]})
check(c == 400, "detections_decide refuses without confirm")
o, c = api.detections_export({})
check(c == 400, "detections_export refuses without confirm")
TAGGED.clear()
o, c = api.tag_candidate({"iot_name": "Chromecast", "asset_uuid": "x'; DROP", "confirm": True})
check(c == 200 and TAGGED and "''" in TAGGED[0][0][2] and TAGGED[0][1].get("agent") == "iot_squad"
      and TAGGED[0][1].get("remove") is False, "tag_candidate quotes the uuid, add-only, attributed")

# ---- a navi.db without the vulns table / no navi.db at all ----
EMPTY = os.path.join(TMP, "empty.db")
build(EMPTY, with_vulns=False)
os.environ["NAVI_DB_PATH"] = EMPTY
o, c = api.run({})
check(c == 200 and o["ok"] and o["result"]["available"] is False and o["result"]["tag_actions"] == []
      and "vulns" in o["result"]["missing"], "missing vulns table → empty result, no crash")
check(all(k in o["result"] for k in ("registry", "discovery", "carriers", "xterm", "qa", "proposals")),
      "empty result still carries every key")
os.environ["NAVI_DB_PATH"] = os.path.join(TMP, "nope.db")
o, c = api.run({})
check(c == 200 and not (o.get("result") or {}).get("tag_actions"), "no navi.db → no crash")
os.environ["NAVI_DB_PATH"] = DB

# ---- page contract: explicit-run, escaping, confirm before writes, today's design ----
page = open(os.path.join(ROOT, "agents", "iot_squad", "page.html"), encoding="utf-8").read()
check('id="secMetrics" data-nav="At a glance"' in page and "mountSectionNav()" in page
      and "setNavCount(" in page, "sticky jump nav + At a glance section")
check(page.count("confirm(") >= 3, "confirm() before tag apply, registry update, base export")
check("if(h.run) await runIot()" in page and "if(h.focus){ await runIot()" not in page,
      "?focus handoff no longer auto-runs (explicit-run)")
check("${p.kind}" not in page and "${p.source}" not in page and "flags.map(f=>`" not in page,
      "proposal kind/source and QA flags are escaped")
check("onclick=\"" not in page.split("<script>", 1)[1], "no inline onclick built from data")

# ---- review fixes (build 441)
_vo = os.path.join(TMP, "vulns_only.db")
_c = sqlite3.connect(_vo)
_c.execute("CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT, output TEXT)")
_c.commit(); _c.close()
from agents.iot_squad.agent import IoTSquadOrchestrator as _IA  # noqa: E402
try:
    _r = _IA()._run(_vo)
    check(_r.get("available") is False and "assets" in (_r.get("missing") or []),
          "a navi.db with vulns but no assets table returns the empty result (no crash)")
except Exception as e:
    check(False, "vulns-only navi.db crashed: %s" % e)
_ns = os.path.join(TMP, "numsev.db")
_c = sqlite3.connect(_ns)
_c.executescript("CREATE TABLE assets (uuid TEXT, hostname TEXT); CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, "
                 "severity TEXT, state TEXT, xrefs TEXT); INSERT INTO assets VALUES ('d1','cam');"
                 "INSERT INTO vulns VALUES ('d1','1','4','open',''),('d1','2','3','open',''),('d1','3','critical','open','')")
_c.commit(); _c.close()
_e = ic.device_exposure(["d1"], _ns)
_row = (_e.get("assets") or [{}])[0]
check(_row.get("critical") == 2 and _row.get("high") == 1, "numeric severities (4/3) count as critical/high (%s)" % _row)

print(f"\n{len(fails)} failure(s)")
sys.exit(1 if fails else 0)
