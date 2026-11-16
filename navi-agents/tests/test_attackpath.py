"""Regression tests for the attack-path engine (core.attackpath).

Builds a realistic fixture navi.db (tests/attackpath_fixture.py) in a temp folder and checks
the engine against it: false positives that must stay out (Windows rollups, client-side bugs,
loose compliance keywords, same-name accounts), signals that must be present (KEV chains,
LAPS / relay / Kerberoast steps, internet exposure), and edge cases (missing columns, empty
DB, no compliance table, IPv6, deterministic remediation bundle).

Run:  python3 tests/test_attackpath.py        (or: python3 -m pytest tests/)
"""
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
sys.path.insert(0, HERE)
TMP = tempfile.mkdtemp(prefix="hounds-aptest-")
atexit.register(shutil.rmtree, TMP, True)
FIXTURE = os.path.join(TMP, "ap_full.db")

import attackpath_fixture  # noqa: E402

attackpath_fixture.build(FIXTURE)
os.environ["NAVI_DB_PATH"] = FIXTURE
from core import attackpath as ap  # noqa: E402

assets, _ = ap._load(FIXTURE)
shared = ap._accounts(assets, FIXTURE)
H = {a["host"]: a for a in assets.values()}
crown = frozenset(u for u, a in assets.items() if a["acr"] >= 7)
G = ap.build_graph(assets, shared, crown)
r = ap.analyze(FIXTURE)
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def edges_to(host, kind=None, frm=None):
    u = H[host]["uuid"]
    return [e for e in G.edges if e["to"].startswith(u + ":") and (kind is None or e["kind"] == kind)
            and (frm is None or e["frm"] == frm)]


def privesc_on(host):
    u = H[host]["uuid"]
    return [e for e in G.edges if e["kind"] == "privesc" and e["frm"] == u + ":user"]


# --- false positives that must stay out ---
check(not H["ws016"]["dc"], "Windows cumulative update mentioning Netlogon does not make ws016 a DC")
check(not H["ws018"]["dc"], "domain-SID user enumeration listing krbtgt does not make ws018 a DC")
check(not [e for e in edges_to("ws016", frm="ATTACKER") if any(ev.get("pid") == "139487" for ev in e["evidence"])],
      "rollup KB is not a network entry on ws016")
check(not edges_to("ws017", frm="ATTACKER"), "client-side Adobe Reader (port 0) is not a network entry")
check(not edges_to("lab02", frm="ATTACKER"), "OpenSSH ssh-agent client-side flaw is not a network entry")
check(not [e for e in edges_to("app06", frm="ATTACKER") if any(ev.get("pid") == "190001" for ev in e["evidence"])],
      "PHP deserialization DoS is not a network entry")
check(not [e for e in privesc_on("app08") if any(ev.get("pid") == "190002" for ev in e["evidence"])],
      "WordPress role escalation is not OS privilege escalation")
tom = [e for e in edges_to("lab03", frm="ATTACKER")]
check(tom and all(e["to"].endswith(":user") for e in tom), "Tomcat RCE ('such as system information') is user-level, not admin")
check("sudo" not in H["app07"]["controls"], "'Ensure sudo is installed' failing is not a sudo NOPASSWD enabler")
check("firewall" not in H["app07"]["controls"], "firewall LOGGING failure is not a firewall-off enabler")
check("smb_sign" not in H["ws019"]["controls"] or "Microsoft network server" in H["ws019"]["controls"]["smb_sign"]["check"],
      "SMB CLIENT signing failure is not a relay-target enabler")
check("llmnr" not in H["backup01"]["controls"], "NoNameReleaseOnDemand is not LLMNR")
lab = [p for p in r["paths"] if p["entry"].get("host", "").startswith("lab")]
check(not lab, "isolated LAB segment reaches no crown jewel")
for name, s in shared.items():
    check(name.lower() not in ("root", "postgres", "admin", "guest"), f"built-in account {name} is not a shared credential")

# --- signals that must be present ---
check(H["dc01"]["dc"] and H["dc02"]["dc"], "dc01/dc02 detected as DCs (Kerberos + LDAP ports / DC findings)")
check(edges_to("app04", "unauth", "ATTACKER"), "unauthenticated Redis is a network entry on app04")
check(edges_to("app04", "defcred", "ATTACKER"), "'password fields are not empty' failing + SSH is an entry")
check([e for e in G.edges if e["kind"] == "kerb"], "Kerberoast finding creates a domain-user → domain step")
check([e for e in G.edges if e["kind"] == "authrce" and any(ev.get("pid") == "151488" for ev in e["evidence"])],
      "PrintNightmare is an authenticated lateral exploit (not only privesc)")
vpn = [e for e in edges_to("vpn01", frm="ATTACKER")]
check(vpn and any(e["tech"] == "T1190" for e in vpn) and H["vpn01"]["public"], "public vpn01 is an internet-exposed entry (T1190)")
check(r["metrics"]["public_entries"] >= 1, "metrics count the internet-exposed entry")
check("Local Administrator (no LAPS)" in shared, "local Administrator is a shared credential where LAPS failed")
check(all("not verified" in e["label"] for e in G.edges if e["kind"] == "harvest" and not e["frm"].startswith(H["ws001"]["uuid"])
          and "Administrator" not in e["label"]), "custom-account harvest steps say reuse is not verified")
pdb = [p for p in r["paths"] if p["target"]["host"] == "payments-db"]
check(any(p["entry"].get("host") == "vpn01" for p in pdb), "vpn01 (internet) reaches payments-db via svc_deploy")
dc_steps = [s for p in r["paths"] for s in p["steps"] if s["kind"] == "dc"]
check(dc_steps and all(s["to"].split(":")[0] in (H["dc01"]["uuid"], H["dc02"]["uuid"]) for s in dc_steps),
      "every DC-takeover step lands on a real DC host")
m = r["metrics"]
check(m["crown_reachable"] == len({p["target"]["uuid"] for p in r["paths"] if p["primary"]}), "crown_reachable = crown jewels with a best route")
check(r["fixes"] and r["bundle"] and r["fixes"][0]["fix"] == r["bundle"][0]["fix"], "top single fix = first bundle pick")
for p in r["paths"]:
    for s in p["steps"]:
        if s["frm"].startswith("seg:"):
            fails.append("segment hub leaked into a step"); break
# ================= second review: edge cases =================


def variant(name, sql_list):
    p = os.path.join(TMP, name + ".db"); shutil.copy(FIXTURE, p)
    c = sqlite3.connect(p)
    for q in sql_list:
        c.executescript(q)
    c.commit(); c.close()
    return p


def run_on(p, **kw):
    return ap.analyze(db_path=p, **kw)


da_dc02 = [e for e in G.edges if e["frm"] == "domain" and e["to"] == H["dc02"]["uuid"] + ":admin"]
check(bool(da_dc02), "domain admin reaches other domain controllers (domain → dc02)")
check(all(f["exposure_cut_pct"] >= 0 for f in r["fixes"]), "no fix shows a negative exposure cut")
check({b["fix"] for b in r["bundle"]} <= {f["fix"] for f in r["fixes"]}, "every bundle pick is also in the fixes list")
check(set(r["reachable"]) == {p["target"]["uuid"] for p in r["paths"] if p["primary"]}, "result lists every reachable crown jewel")

p = variant("noacr", ["CREATE TABLE a2 AS SELECT uuid,hostname,fqdn,ip_address,operating_system,network,url FROM assets;"
                      "DROP TABLE assets; ALTER TABLE a2 RENAME TO assets;"])
rr = run_on(p)
check(rr["metrics"]["assets"] > 0 and rr["metrics"]["fallback_targets"], "missing assets.acr: assets still load, fallback targets used")
p = variant("nocves", ["ALTER TABLE vulns DROP COLUMN cves;", "ALTER TABLE vulns DROP COLUMN xrefs;"])
rr = run_on(p)
check(rr["metrics"]["paths"] > 0, "missing vulns.cves/xrefs: paths still found")
p = variant("noport", ["ALTER TABLE vulns DROP COLUMN port;"])
rr = run_on(p)
check(rr["metrics"]["entries"] > 3 and rr["metrics"]["paths"] > 5, "missing vulns.port: ways in still found (reachability assumed)")
p = variant("scanadmin", ["UPDATE vulns SET output=\"Credentialed checks : yes, as 'Administrator' via smb\" WHERE plugin_id='19506' "
                          "AND asset_uuid IN (SELECT uuid FROM assets WHERE operating_system LIKE '%Windows%');"])
sh = ap._accounts(ap._load(p)[0], p)
check("Local Administrator (no LAPS)" in sh, "scanning as Administrator keeps the no-LAPS shared credential")
p = variant("empty", ["DELETE FROM vulns; DELETE FROM compliance; DELETE FROM assets;"])
rr = run_on(p)
check(rr["ok"] and rr["metrics"]["paths"] == 0, "empty navi.db: no crash, no paths")
p = variant("nocomp", ["DROP TABLE compliance;"])
rr = run_on(p)
check(rr["ok"] and rr["metrics"]["paths"] > 0, "no compliance table: still runs")
check(ap._segment("::ffff:10.20.5.7") == "10.20.5.0/24", "IPv4-mapped IPv6 uses the IPv4 /24")
outs = set()
for seed in ("1", "2", "3", "4"):
    o = subprocess.run([sys.executable, "-c", "import sys,json; sys.path.insert(0, sys.argv[1]); "
                        "from core import attackpath as ap; print(json.dumps([b['fix'] for b in ap.analyze(sys.argv[2])['bundle']]))",
                        ROOT, FIXTURE],
                       env={**os.environ, "PYTHONHASHSEED": seed}, capture_output=True, text=True).stdout.strip()
    outs.add(o)
check(len(outs) == 1, "remediation bundle is deterministic across hash seeds")


# ================= account reuse only — password reuse is never inferred =================
from core import identity  # noqa: E402

idn = identity.scan(db_path=FIXTURE)
sd = next(a for a in idn["accounts"] if a["user"] == "svc_deploy")
check(any(f.startswith("account reuse") for f in sd["flags"]), "svc_deploy on many hosts is ACCOUNT reuse")
check(not any("password reuse" in f for a in idn["accounts"] for f in a["flags"]), "no account is ever flagged password reuse")
check(not {"password_reuse", "password_reuse_hosts", "shadow_hosts"} & set(idn["counts"]), "no password-reuse counts")
check(not any("confirmed" in e["label"] for e in G.edges if e["kind"] in ("login", "harvest")), "no 'confirmed' credential steps")
# even identical /etc/shadow-format lines on several hosts don't turn account reuse into password reuse
SAME = "$6$Zq8wXy1a$SAMEhashSAMEhashSAMEhashSAMEhashSAMEhash0123456789abcdefABCDEF/."
ins = ("INSERT INTO compliance(asset_uuid, check_name, status, actual_value) SELECT uuid, "
       "'Shadow file review', 'WARNING', 'svc_deploy:{h}:19700:0:99999:7:::' FROM assets WHERE hostname IN ({hs});")
p = variant("shadow", [ins.format(h=SAME, hs="'app01','app02','payments-db'")])
idn = identity.scan(db_path=p)
sd = next(a for a in idn["accounts"] if a["user"] == "svc_deploy")
check(not any("password reuse" in f for f in sd["flags"]) and "pw_check" not in sd,
      "shadow-format data never produces password reuse")
blob = json.dumps(idn, default=str)
check("SAMEhash" not in blob and "$6$" not in blob, "no hash-like value appears in identity output")
rr = ap.analyze(db_path=p)
check("SAMEhash" not in json.dumps(rr, default=str) and "pw_confirmed" not in rr["metrics"],
      "attack-path output has no hash values and no password-reuse metric")
Gs = ap.build_graph(*(lambda a: (a, ap._accounts(a, p), frozenset(u for u, x in a.items() if x["acr"] >= 7)))(ap._load(p)[0]))
creds = [e for e in Gs.edges if e["kind"] == "login" and "svc_deploy" in e["label"]]
check(creds and all("account reuse" in e["label"] and e["p"] < 0.6 for e in creds),
      "svc_deploy logins stay low-likelihood account-reuse steps")
nolog = variant("nologin", ["UPDATE vulns SET output=replace(output, 'Start script : /bin/bash\nUID : 1001', "
                            "'Start script : /usr/sbin/nologin\nUID : 1001') WHERE plugin_id='95928';"])
sd2 = next((a for a in identity.scan(db_path=nolog)["accounts"] if a["user"] == "svc_deploy"), {"flags": []})
check(not any(f.startswith("account reuse") for f in sd2["flags"]), "a nologin account is not flagged as reuse")


def test_attackpath_regressions():
    """pytest entry point — every check above ran at import; fail with the list."""
    assert not fails, "\n".join(fails)


if __name__ == "__main__":
    print(f"\n{len(fails)} failure(s)")
    sys.exit(1 if fails else 0)
