"""Regression tests — build 473: Asset Classification (Linnaeus) cloud + device types.

  · An asset is Cloud only with a REAL AWS / Azure / GCP id. navi writes a single space (or
    the text "None") for a cloud field Tenable did not return — the old truthiness test made
    every asset Cloud. One rule (core/cloud.py) for Linnaeus, On the Scent, Terminus, Argos.
  · Device Type covers physical equipment — Server, Desktop, Laptop, Camera, Printer, Switch,
    Firewall … — and maps each to the right class (a Server tag is not IoT any more); Nessus's
    own Device Type plugin (54615) names printers / cameras / switches before the OS does.
Run: python3 tests/test_classify_473.py"""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-473-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


c = sqlite3.connect(DB)
c.execute("CREATE TABLE assets (uuid text, hostname text, ip_address text, operating_system text, acr text, aes text, "
          "aws_id text, aws_ec2_name text, aws_ec2_region text, azure_vm_id text, azure_resource_id text, "
          "azure_subscription_id text, gcp_instance_id text, gcp_project_id text, url text)")
c.execute("CREATE TABLE vulns (asset_uuid text, plugin_id text, plugin_name text, output text, severity text, "
          "state text, xrefs text, cves text)")
c.execute("CREATE TABLE tags (asset_uuid text, tag_key text, tag_value text)")
BLANK = (" ", " ", " ", " ", " ", " ", "None", "None")
A = [("srv", "srv01", "Microsoft Windows Server 2022") + BLANK,
     ("prn", "printer-3", "Linux Kernel 4.4") + BLANK,
     ("cam", "lobby", "") + BLANK,
     ("ec2", "web-aws", "Ubuntu 22.04", "i-0abc123", " ", "us-east-1", " ", " ", " ", " ", " "),
     ("az", "vm-az", "", " ", " ", " ", "az-vm-1", " ", " ", " ", " ")]
for a in A:
    c.execute("INSERT INTO assets (uuid, hostname, operating_system, aws_id, aws_ec2_name, aws_ec2_region, azure_vm_id, "
              "azure_resource_id, azure_subscription_id, gcp_instance_id, gcp_project_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)", a)
c.executemany("INSERT INTO vulns (asset_uuid, plugin_id, plugin_name, output, severity, state) VALUES (?,?,?,?,?,?)",
              [("prn", "54615", "Device Type", "Remote device type : printer\nConfidence level : 95", "Info", "open"),
               ("cam", "54615", "Device Type", "Remote device type : camera\nConfidence level : 90", "Info", "open"),
               ("srv", "54615", "Device Type", "Remote device type : general-purpose\nConfidence level : 99", "Info", "open")])
c.commit()
c.close()

from core import cloud, classify  # noqa: E402
check([cloud.present(v) for v in (None, "", " ", "None", "null", "i-0abc", "az-vm-1")] == [False] * 5 + [True, True],
      "cloud.present: NULL / '' / ' ' / 'None' are absent; a real id is present")
r = classify.classify()
by = {x["uuid"]: x for x in r["assets"]}
check({u for u, x in by.items() if x["cls"] == "Cloud"} == {"ec2", "az"} and by["ec2"]["sub"] == "AWS" and by["az"]["sub"] == "Azure",
      "only assets with a real AWS / Azure id are Cloud (was: every asset)")
con = sqlite3.connect(DB)
n = con.execute("SELECT COUNT(*) FROM assets WHERE " + cloud.sql_is_cloud({"aws_id", "azure_vm_id", "gcp_project_id"})).fetchone()[0]
con.close()
check(n == 2, "SQL rule agrees (On the Scent's cloud count): %d" % n)

sig = {(x["facet"], x["value"]) for x in classify.os_signals()["cohorts"]}
check(("Device Type", "Printer") in sig and ("Device Type", "Camera") in sig,
      "Nessus Device Type names the printer and camera (a printer on embedded Linux is not 'OS: Linux')")
check(("OS", "Windows Server 2022") in sig or any(f == "OS" and "Windows" in v for f, v in sig), "general-purpose hosts still go by OS")

for label in ("Server", "Desktop", "Laptop", "Camera", "Printer", "Switch", "Router", "Firewall", "Wireless Access Point",
              "NAS", "VoIP", "UPS / Power", "PLC", "Hypervisor"):
    check(label in classify.DEVICE_TYPE_LABELS, "Device Type option: %s" % label)
want = {"Server": "Server", "Desktop": "Workstation", "Laptop": "Workstation", "Camera": "IoT", "Printer": "IoT",
        "Switch": "Network", "Firewall": "Network", "PLC": "OT", "Hypervisor": "Virtual Infrastructure",
        "HP LaserJet printer": "IoT", "PowerEdge Server": "Server", "APC Smart-UPS": "IoT", "Engineering Workstation": "OT"}
got = {v: (classify.device_type(v) or ("", ""))[1] for v in want}
check(got == want, "device type → class (word-matched: 'PowerEdge' is not a UPS) %s" % got)
check(classify._tag_class({"device type": "Server"})[0] == "Server"
      and classify._tag_class({"device type": "Server", "os": "Windows Server 2022"})[0] == "Windows"
      and classify._tag_class({"device type": "Payment terminal"})[0] == "Other"
      and classify._tag_class({"device type": "Camera"})[0] == "IoT", "Device Type tag → class (Server ≠ IoT; OS tag wins for a server)")

from agents.argos import api as argos  # noqa: E402
check(argos._decipher("Asset Inventory", "Device Type: Server")["band"] == "info"
      and argos._decipher("Asset Inventory", "Device Type: Camera")["hound"] == "Cerberus",
      "Argos: a Server device type is not weighted as an IoT signal")
from agents.classify import api as capi  # noqa: E402
o, _ = capi.signals({})
check("Server" in o["result"]["device_types"], "the page gets the Device Type options from the server")
pg = open(os.path.join(ROOT, "agents", "classify", "page.html"), encoding="utf-8").read()
check("function bindList(" in pg and "'dlDev'" in pg and "bindList(_fsel, document.getElementById('ucVal'))" in pg
      and "bindList(document.getElementById('sigfacet-'+i)" in pg, "page: value boxes suggest the device types")
print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
