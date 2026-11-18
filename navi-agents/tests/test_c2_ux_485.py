"""Amarok (C2) redesign, Phase 1 — build 485 regression tests.

Covers what the UI, security and Linux reviewers reproduced or required:
  * wrong-host regressions — remediation fallback to another list, stale single-host field, campaign silent
    truncation, contradictory deploy confirm, hand-off widening, credit on non-proposed hosts, ARM left on
  * the expect_count / expect_targets_sha256 409 check (sec C4b) and confirm text == describe(body) (C4c)
  * crown jewels never the canary and always last; sudo-password hosts excluded by default (owner D1/D3)
  * typed-count thresholds (owner D2, sec C1/C2)
  * the honesty fixes — rc 126/127 is "check could not run", nothing says "verified" without a fixed-version
    compare, unknown state on a timed-out step, live os-release family, status-aware pkgver, updates error,
    disk excludes squashfs/overlay; key CHANGED / unknown state / first-use trust survive a reload (C6/C7)

Uses tests/c2_fakenavi.py only — never a real navi, never a host. The UI part starts this repo's own server
on a free loopback port and drives it with Playwright (Chromium); it is skipped (and said so) only when
Playwright is not installed.

Run: python3 tests/test_c2_ux_485.py   → exit 0 on pass
"""
import atexit
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-c2ux-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
for k in list(os.environ):
    if k.startswith(("NAVI_", "HOUNDS_", "ANTHROPIC_", "OPENAI_", "FAKE_NAVI")):
        os.environ.pop(k, None)
FAKE = os.path.join(HERE, "c2_fakenavi.py")
os.chmod(FAKE, 0o755)
DB = os.path.join(TMP, "navi.db")
ENV = {"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
       "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"), "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"),
       "NAVI_BIN": FAKE, "FAKE_NAVI_LOG": os.path.join(TMP, "argv.log"), "NAVI_TAG_GAP_MS": "0", "NAVI_CWD": TMP,
       "FAKE_NAVI_STATE": os.path.join(TMP, "fixed")}
os.environ.update(ENV)

OUT = ("Installed package : openssl_1.1.1f-1ubuntu2.16\n  Fixed package     : openssl_1.1.1f-1ubuntu2.20\n")
con = sqlite3.connect(DB)
con.executescript("""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, operating_system TEXT, acr TEXT);
CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, output TEXT, cves TEXT, state TEXT, severity TEXT);
CREATE TABLE plugins(plugin_id TEXT, plugin_name TEXT, solution TEXT, description TEXT, synopsis TEXT);
CREATE TABLE ssh(username TEXT, password TEXT, key_file TEXT);
INSERT INTO ssh VALUES('svc','','/k');
INSERT INTO plugins VALUES('99001','Ubuntu 20.04 : OpenSSL vulnerabilities (USN-0000-1)','Update the affected libssl1.1 and openssl packages.','x','y');
""")
for u, h, ip, acr in (("u1", "web01", "10.9.0.1", "5"), ("u2", "web02", "10.9.0.2", "5"), ("u3", "web03", "10.9.0.3", "5"),
                      ("u6", "web06", "10.9.0.6", "5"), ("u8", "web08", "10.9.0.8", "5"), ("u10", "web10", "10.9.0.10", "5"),
                      ("u11", "web11", "10.9.0.11", "10"), ("u12", "web12", "10.9.0.12", "4"), ("u14", "web14", "10.9.0.14", "4")):
    con.execute("INSERT INTO assets VALUES(?,?,?,?,?)", (u, h, ip, "Ubuntu 20.04", acr))
    con.execute("INSERT INTO vulns VALUES(?,?,?,?,?,?,?)", (u, "99001", "Ubuntu 20.04 : OpenSSL vulnerabilities (USN-0000-1)",
                                                           OUT, "CVE-2024-1111", "OPEN", "high"))
con.commit()
con.close()

fails = []


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def gates(on):
    for k in ("NAVI_ALLOW_WRITES", "NAVI_REMOTE_CODE_EXECUTION"):
        if on:
            os.environ[k] = "1"
        else:
            os.environ.pop(k, None)


from core import c2_catalog, c2log, navi_cli, version  # noqa: E402
from agents.c2 import api as c2  # noqa: E402


def seed_preflight(ips=None):
    """build 486 verify round (sec F3): deploy FAILS CLOSED without a recent pre-flight that read the host's live OS.
    These Phase 1 tests deploy straight from the API, so each lab host gets the minimal record a real pre-flight
    leaves (live os-release = Ubuntu 20.04 / apt). Test setup only — no assertion depends on it."""
    from core import c2_catalog as _cc
    for ip in ips or [f"10.9.0.{i}" for i in range(1, 21)]:
        c2._pf_put(ip, cred={"status": "ok", "sudo": "sudo_ok"},
                   checks={"status": "ok", "checks": {"osrel": {"status": "ok", "facts": {
                       "family": "apt", "os_id": "ubuntu", "version_id": "20.04",
                       "group": _cc.group_of("ubuntu", "20.04", "apt")}},
                       # verify round 2 (sec M7): eligibility is enforced server-side — a real pre-flight also reads
                       # the plan's packages (an unread plan package is a hard exclusion)
                       "pkgstate": {"status": "ok", "facts": {"pkgs": {
                           n_: {"state": "installed", "versions": ["1.1.1f-1ubuntu2.16"], "held": False}
                           for n_ in ("openssl", "libssl1.1")}, "krun": "5.4.0-150-generic"}}}})


seed_preflight()


def wait_run(rid, secs=40):
    t0 = time.time()
    while time.time() - t0 < secs:
        b, _ = c2.run_status({"run_id": rid})
        if b.get("run") and b["run"]["status"] not in ("queued", "running"):
            return b["run"]
        time.sleep(0.1)
    return (c2.run_status({"run_id": rid})[0] or {}).get("run") or {}


def sha(lst):
    return hashlib.sha256("\n".join(lst).encode()).hexdigest()


gates(True)
check(version.BUILD >= 485, "core/version.py BUILD is 485 or later")

# ============ 1. sec C4(b): expect_count / expect_targets_sha256 → 409, nothing runs ============
before = len(c2log.rows({}, 100000)["rows"])
for act, body in (("command", {"target": "10.9.0.1", "command": "id"}),
                  ("run_checks", {"targets": ["10.9.0.1", "10.9.0.12"], "checks": ["os"]}),
                  ("cred_test", {"targets": ["10.9.0.1", "10.9.0.12"]}),
                  ("path_check", {"targets": ["10.9.0.1"], "path": "/etc/hostname"}),
                  ("campaign", {"hosts": ["10.9.0.1", "10.9.0.12"], "command": "id", "armed": True})):
    b, code = getattr(c2, act)(dict(body, confirm=True, expect_count=5))
    check(code == 409 and b.get("mismatch"), f"C4 {act}: a wrong expect_count → 409")
    tl = body.get("targets") or body.get("hosts") or [body["target"]]
    b, code = getattr(c2, act)(dict(body, confirm=True, expect_count=len(tl), expect_targets_sha256=sha(list(reversed(tl)) + ["x"])))
    check(code == 409, f"C4 {act}: a wrong expect_targets_sha256 (other members / order) → 409")
check(len(c2log.rows({}, 100000)["rows"]) == before, "C4 a 409 runs nothing (no C2-log row)")
b, code = c2.command({"target": "10.9.0.1", "command": "id", "confirm": True, "expect_count": 1, "expect_targets_sha256": sha(["10.9.0.1"])})
check(code == 200 and b.get("ok") and b.get("run_id") and (b.get("c2_log") or {}).get("id"),
      "C4 a matching expectation runs; single commands are registered runs with a C2-log receipt (API 4)")
check(c2.targets_sha256(["a", "b"]) == sha(["a", "b"]), "targets_sha256 = sha256 of the newline-joined ordered list")
# deploy + rollback honour it too
g, _ = c2.plan_ai({"selector": "99001", "targets": ["10.9.0.1"], "use_llm": False})
b, code = c2.deploy({"plan_id": g["plan_id"], "targets": ["10.9.0.1"], "confirm": True, "expect_count": 2})
check(code == 409, "C4 deploy: a wrong expect_count → 409")

# ============ 2. campaign silent truncation (sec R4 / ui P1-3) ============
b, code = c2.campaign({"hosts": ["10.9.0.1", "10.9.0.12", "10.9.0.14"], "command": "id", "armed": True, "confirm": True, "max_hosts": 2})
check(code == 400 and b.get("over_cap") and "nothing ran" in b["error"], "campaign over max_hosts is REFUSED, not truncated")
b, code = c2.campaign({"hosts": ["10.9.0.1", "10.9.0.12", "10.9.0.14"], "command": "id", "armed": True, "confirm": True,
                       "max_hosts": 2, "allow_truncate": True})
r = wait_run(b["run_id"])
check(b.get("truncated") and b.get("dropped") == ["10.9.0.14"] and r.get("dropped_count") == 1,
      "allow_truncate (never sent by the page) returns {truncated, dropped} and keeps it on the run record")
b, code = c2.campaign({"hosts": ["10.9.0.1", "10.9.0.12"], "command": "id", "armed": "true", "confirm": True})
check(code == 400, "campaign still needs armed === true")

# ============ 3. halt on a CHANGED host key (state-changing kinds) + separate count ============
b, _ = c2.campaign({"hosts": ["10.9.0.3", "10.9.0.1", "10.9.0.12"], "command": "id", "armed": True, "confirm": True,
                    "canary": False, "stop_on_failure": False})
r = wait_run(b["run_id"])
check(r["status"] == "halted" and [h["status"] for h in r["hosts"]] == ["hostkey_mismatch", "skipped", "skipped"]
      and r.get("hostkey_changed") == 1, "a campaign with no stop rule still HALTS on a changed host key (API 3)")
b, _ = c2.run_checks({"targets": ["10.9.0.3", "10.9.0.1", "10.9.0.12"], "checks": ["os"], "confirm": True, "canary": False})
r = wait_run(b["run_id"])
check(r["status"] == "done" and r.get("hostkey_changed") == 1, "read-only runs continue but count the changed key separately")

# ============ 4. sec C6/C7: safety states from the C2 log (survive a reload) ============
st = c2log.host_states(["10.9.0.3", "10.9.0.1"])
check(st.get("10.9.0.3", {}).get("key") == "changed", "C6 key CHANGED is read back from the log")
check(any(k["target"] == "10.9.0.3" and not k["acked"] for k in c2log.key_changed_hosts()), "C6 glance lists it for the banner")
tb, _ = c2.targets({"targets": ["10.9.0.3"]})
check(tb["targets"][0]["log_state"].get("key") == "changed", "C6 the targets read carries the log state per host")
b, code = c2.ack({"target": "10.9.0.3", "confirm": "yes"})
check(code == 400, "ack needs confirm === true")
b, _ = c2.ack({"target": "10.9.0.3", "confirm": True})
check(b["ok"] and c2log.host_states(["10.9.0.3"])["10.9.0.3"]["acked"] and c2log.verify_chain()["ok"],
      "C6 the acknowledgement is an `ack` row in the hash-chained log; the state stays CHANGED")
check(c2log.host_states(["10.9.0.3"])["10.9.0.3"]["key"] == "changed", "C6 acknowledging never clears the exclusion")
gl, _ = c2.glance({})
check(gl["week"] == len([x for x in c2log.rows({}, 100000)["rows"] if x["status"] not in ("blocked", "refused", "ack")]),
      "an ack row is not counted as a command")
# TOFU: first successful contact under accept-new by a read-only check
b, _ = c2.run_checks({"targets": ["10.9.0.14"], "checks": ["os"], "confirm": True})
s14 = c2log.host_states(["10.9.0.14"])["10.9.0.14"]
check(s14.get("tofu") and s14.get("tofu_read_only") and s14.get("key") == "new", "C7 first contact under accept-new by a read-only check is flagged")
b, _ = c2.cred_test({"targets": ["10.9.0.14"], "confirm": True, "strict": True, "preflight": True})
check(b["run_id"].startswith("pre-") and c2log.host_states(["10.9.0.14"])["10.9.0.14"].get("key") == "known",
      "strict pre-flight login: run id 'pre-…', host key now known")
# strict pre-flight on an unknown key is refused (no TOFU)
b, _ = c2.cred_test({"targets": ["10.9.0.7"], "confirm": True, "strict": True})
check(b["run"]["hosts"][0]["status"] == "hostkey_unknown", "L-2 cred_test strict:true uses strict host keys (no TOFU)")
b, _ = c2.run_checks({"targets": ["10.9.0.7"], "checks": ["os"], "confirm": True, "strict": True})
check(b["run"]["hosts"][0]["status"] == "hostkey_unknown", "L-2 run_checks strict:true uses strict host keys")

# ============ 5. honesty fixes (linux C1/C3, U6) ============
g, _ = c2.plan_ai({"selector": "99001", "targets": ["10.9.0.1"], "use_llm": False})
d, _ = c2.deploy({"plan_id": g["plan_id"], "targets": ["10.9.0.1"], "confirm": True, "stage": "canary"})
h = d["run"]["hosts"][0]
check(h["verdict"] == "fixed" and h["message"].startswith("✓ Fixed") and "version compare" in h["message"],
      "Fixed only with a fixed-version compare (before → after ≥ fixed)")
# owner decision 3 on the SERVER too: the canary stage is one host and never a crown jewel
_cj, _cc = c2.deploy({"plan_id": g["plan_id"], "targets": ["10.9.0.11"], "confirm": True, "stage": "canary"})
check(_cc == 400 and "crown jewel is never the canary" in _cj.get("error", ""), "D3 server refuses a crown-jewel canary")
_c2_, _c2c = c2.deploy({"plan_id": g["plan_id"], "targets": ["10.9.0.1", "10.9.0.2"], "confirm": True, "stage": "canary"})
check(_c2c == 400 and "exactly one host" in _c2_.get("error", ""), "D3 server refuses a multi-host canary stage")
pl = {x["plan_id"]: x for x in c2.plans({})[0]["plans"]}
check(pl[g["plan_id"]]["status"] == "deployed (canary)" and pl[g["plan_id"]]["runs"][0]["stage"] == "canary",
      "API 8 per-run plan status: deployed (canary)")
nofix = {"summary": "x", "steps": [{"n": 1, "purpose": "u", "command": "sudo apt-get install --only-upgrade -y openssl"}]}
g2, _ = c2.plan_ai({"selector": "99001", "targets": ["10.9.0.12"], "use_llm": False})
v2, _ = c2.plan_validate({"plan_id": g2["plan_id"], "plan": nofix, "targets": ["10.9.0.12"]})
d2, _ = c2.deploy({"plan_id": g2["plan_id"], "targets": ["10.9.0.12"], "confirm": True})
h2 = d2["run"]["hosts"][0]
check(h2["status"] == "changed" and h2["verdict"] == "unproven" and "fix not proven" in h2["message"]
      and "verified" not in h2["message"], "linux C3: no fixed-version compare → 'Steps ran — fix not proven', never 'verified'")
real_push = navi_cli.push


def fake127(**kw):
    r = real_push(**kw)
    if "dpkg-query" in (kw.get("command") or ""):
        r.update(exit_code=127, status="failed", output="C2_OUT\nsh: dpkg-query: not found")
    return r


navi_cli.push = fake127
try:
    res = c2._remediate_host(c2._PLANS[g["plan_id"]]["plan"], "t-127", "test", "h")("10.9.0.12")
finally:
    navi_cli.push = real_push
check(res["status"] == "failed" and res["verdict"] == "check_failed" and "rc 127" in res["message"],
      "linux C1: precheck rc 127 → 'Check could not run' (an error), never not_applicable")
# fix round linux F7: a precheck that times out reached the host — it is not "Not reached", and it changed nothing
d7, _ = c2.deploy({"plan_id": g["plan_id"], "targets": ["10.9.0.6"], "confirm": True})
h7 = d7["run"]["hosts"][0]
check(h7["verdict"] == "precheck_timeout" and "Precheck timed out — nothing changed" in h7["message"]
      and not c2log.host_states(["10.9.0.6"]).get("10.9.0.6", {}).get("unknown_state"),
      "FIX linux F7: precheck timeout → 'Precheck timed out — nothing changed (read-only)', no unknown state")
d3, _ = c2.deploy({"plan_id": g2["plan_id"], "targets": ["10.9.0.6"], "confirm": True})
h3 = d3["run"]["hosts"][0]
check(h3["verdict"] == "unknown_state" and h3.get("unknown_state") and "Unknown state" in h3["message"],
      "a timed-out change step → Unknown state")
check(c2log.host_states(["10.9.0.6"])["10.9.0.6"].get("unknown_state"), "C6 unknown state is read back from the log")
gplan = c2._PLANS[g2["plan_id"]]
gplan["plan"]["steps"][0]["rollback"] = "sudo apt-get install -y --allow-downgrades openssl=1.1.1f-1ubuntu2.16"
c2._RUNS[d3["run_id"]]["plan"]["steps"][0]["rollback"] = "sudo apt-get install -y --allow-downgrades openssl=1.1.1f-1ubuntu2.16"
rb, code = c2.rollback({"plan_id": g2["plan_id"], "run_id": d3["run_id"], "targets": ["10.9.0.6"], "confirm": True})
check(code == 409 and rb.get("unknown_state"), "rollback refused on an unknown-state host (server side too)")
c2.cred_test({"targets": ["10.9.0.6"], "confirm": True, "strict": True, "preflight": True})
check(c2log.host_states(["10.9.0.6"])["10.9.0.6"].get("unknown_state") is True, "a failed pre-flight does not clear unknown state")
d4, _ = c2.deploy({"plan_id": g["plan_id"], "targets": ["10.9.0.10"], "confirm": True})
check(d4["run"]["hosts"][0]["verdict"] in ("not_installed", "already_fixed", "not_affected")
      and d4["run"]["hosts"][0]["status"] == "not_applicable", "a precheck that says no → a precise 'nothing to do' verdict")
# catalog one-liners (linux C13) + live family (linux C2)
cat = c2_catalog.BY_ID
check("-x squashfs -x overlay" in cat["disk"]["cmd"] and "-x squashfs -x overlay" in cat["inode"]["cmd"], "C13 disk/inode exclude squashfs + overlay")
check('C2""_UPDATES=error' in cat["updates"]["cmd"] and '"${r:-0}" = 1' in cat["updates"]["cmd"], "C13 updates: dnf/yum r=1 → C2_UPDATES=error")
check("${{db:Status-Abbrev}}" in cat["pkgver"]["cmd"], "C13 pkgver is status-aware (${db:Status-Abbrev})")
sh = subprocess.run(["sh", "-c", "printf 'rc  openssl 1.1\\n' | awk 'substr($1,2,1)==\"i\" {print $2\" \"$3; f=1} END {if (!f) print \"C2\" \"_PKG=not_installed\"}'"],
                    capture_output=True, text=True).stdout.strip()
check(sh == "C2_PKG=not_installed", "C13 an 'rc' (deinstalled) package counts as not installed")
check(c2_catalog.facts("os", 'ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.3"')["family"] == "dnf"
      and c2_catalog.facts("os", "ID=ubuntu\nVERSION_ID=20.04")["family"] == "apt"
      and c2_catalog.facts("os", "")["family"] == "unknown", "C2 live family from os-release; unreadable → unknown (never guessed)")
pv = c2_catalog.facts("pkgver", "openssl 1.1.1f-1ubuntu2.16")
check(pv["installed"] == "1.1.1f-1ubuntu2.16" and "installed" not in c2_catalog.facts("pkgver", "pkgver output x"),
      "pkgver facts: installed version parsed only when it looks like a version")
check(c2_catalog.facts("ident", "    (root) /usr/bin/apt-get")["sudo_rules"] == "narrow", "D1.3 narrow sudoers detected from sudo -n -l")
# hand-off attribution (API 7, C5)
check(c2._src({"source": "Laelaps"}) == "handoff:Laelaps" and c2._src({"source": "Laelaps", "source_kind": "after_handoff"}) == "c2 (after handoff:Laelaps)"
      and c2._src({}) == "c2", "C5 recorded values: handoff:<h> | c2 (after handoff:<h>) | c2")
# precheck classifies a HOSTNAME that is in navi.db (API 6)
b, _ = c2.precheck({"target": "web01", "command": "id"})
check(b["host"] and b["host"]["hostname"] == "web01" and not any("not found" in w for w in b["warnings"]), "API 6 precheck finds a hostname in navi.db")
# upload / push_file sha256 (API 5)
b, _ = c2.upload({"filename": "fix.sh", "content_b64": "ZWNobyBoaQo=", "confirm": True})
check(b["sha256"] == hashlib.sha256(b"echo hi\n").hexdigest(), "API 5 upload returns the content sha256")
p, _ = c2.push_file({"target": "10.9.0.1", "path": b["path"], "confirm": True})
check(p["sha256"] == b["sha256"] and p.get("run_id") and p.get("remote_path", "").startswith("~/"), "API 5 push_file returns sha256 + remote path + run id")
try:
    os.remove(b["path"])
except OSError:
    pass

# ============ 5b. fix round — one regression per FAIL ============
# linux M3 (server side): deploy refuses a host whose last change step timed out
g6, _ = c2.plan_ai({"selector": "99001", "targets": ["10.9.0.6"], "use_llm": False})
b, code = c2.deploy({"plan_id": g6["plan_id"], "targets": ["10.9.0.6"], "confirm": True})
check(code == 409 and b.get("unknown_state") == ["10.9.0.6"], "FIX linux M3: deploy refuses an unknown-state host (409)")
# linux F1: a clean pre-flight after the timeout clears it for rollback too (the log decides, as targets does)
c2log.record("10.9.0.6", "id", "ok", run_id="pre-test-clean", source="c2", agent="c2", mode="cred_test", catalog_id="cred",
             hostkey_policy="strict", asset_uuid="u6")
seed_preflight(["10.9.0.6"])        # 486 verify round 2: the clean pre-flight's stored record too (sec M7 reads it)
rb, code = c2.rollback({"plan_id": g2["plan_id"], "run_id": d3["run_id"], "targets": ["10.9.0.6"], "dry_run": True})
cleared = not c2log.host_states(["10.9.0.6"]).get("10.9.0.6", {}).get("unknown_state")
rb2, code2 = c2.rollback({"plan_id": g2["plan_id"], "run_id": d3["run_id"], "targets": ["10.9.0.6"], "confirm": True})
check(cleared and not rb2.get("unknown_state") and code2 == 200 and rb2.get("run_id"),
      "FIX linux F1: after a clean pre-flight the downgrade is no longer refused as 'unknown state' (it runs)")
# sec F1: one host, many names — a CHANGED key on the IP excludes the hostname target, and the reverse, and via the uuid
tb, _ = c2.targets({"targets": ["web03"]})
check(tb["targets"][0]["log_state"].get("key") == "changed", "FIX sec F1: a CHANGED key recorded on 10.9.0.3 excludes target 'web03'")
c2log.record("web06", "id", "hostkey_mismatch", run_id="t-alias", source="c2", agent="c2", mode="read_only", catalog_id="os",
             hostkey_policy="accept-new")
tb, _ = c2.targets({"targets": ["10.9.0.6"]})
check(tb["targets"][0]["log_state"].get("key") == "changed", "FIX sec F1: a CHANGED key recorded on 'web06' excludes 10.9.0.6")
c2log.record("web14.corp.example", "id", "hostkey_mismatch", run_id="t-uuid", source="c2", agent="c2", mode="read_only",
             catalog_id="os", hostkey_policy="accept-new", asset_uuid="u14")
tb, _ = c2.targets({"targets": ["10.9.0.14"]})
check(tb["targets"][0]["log_state"].get("key") == "changed", "FIX sec F1: a CHANGED key under another name of the same asset uuid excludes it")
# sec F3: the chained C2-log row carries the file CONTENT's sha256
b, _ = c2.upload({"filename": "fix2.sh", "content_b64": "ZWNobyBmaXgK", "confirm": True})
p, _ = c2.push_file({"target": "10.9.0.1", "path": b["path"], "confirm": True})
row = c2log.rows({"run_id": p["run_id"]}, 10)["rows"][0]
check(row["command"].endswith("sha256=" + hashlib.sha256(b"echo fix\n").hexdigest())
      and row["command_sha256"] == hashlib.sha256(hashlib.sha256(b"echo fix\n").hexdigest().encode()).hexdigest()
      and b["path"] not in row["command"] and c2log.verify_chain()["ok"],
      "FIX sec F3: the C2-log row is 'scp <name> sha256=<content hash>' and hashes the content hash, not the path")
try:
    os.remove(b["path"])
except OSError:
    pass
# linux F2: the sudo rule's COMMAND list decides, not the run-as user
for txt, want in (("    (root) NOPASSWD: ALL", "all"), ("    (ALL : ALL) ALL", "all"), ("    (ALL) /usr/bin/systemctl restart nginx", "narrow"),
                  ("    (ALL) NOPASSWD: /usr/bin/apt-get", "narrow"), ("    (root) SETENV: NOPASSWD: /bin/ls, ALL", "all")):
    check(c2_catalog.facts("ident", txt)["sudo_rules"] == want, f"FIX linux F2: {txt.strip()!r} → {want}")
# linux F4: Amazon Linux 1 is yum
check(c2_catalog.os_family("amzn", "centos rhel fedora", "2018.03") == "yum" and c2_catalog.os_family("amzn", "", "2") == "yum"
      and c2_catalog.os_family("amzn", "", "2023") == "dnf", "FIX linux F4: AL1 2018.03 and AL2 → yum, AL2023 → dnf")
# linux M2: zypper errors are reported
check("case $z in 0|10[0-6]) ;; *) r=1;; esac" in c2_catalog.BY_ID["updates"]["cmd"], "FIX linux M2: zypper rc ∉ {0,100–106} → C2_UPDATES=error")
# linux F5: no version compare across families (an rpm build vs a dpkg fixed version)
_rocky = ('C2_BEGIN=os\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.3"\nC2_END=os rc=0\n'
          'C2_BEGIN=pkgver\nopenssl-3.0.7-24.el9.x86_64\nC2_END=pkgver rc=0\n')
navi_cli.push = lambda **kw: {"status": "ok", "ok": True, "output": _rocky, "exit_code": 0}
try:
    built5 = c2_catalog.build(["os", "pkgver"], {"name": "openssl"})
    r5 = c2._diag_host("t-f5", built5, "c2", 0, "test", fixed={"fixed_version": "1.1.1f-1ubuntu2.20", "compare": "dpkg"}, pkg="openssl")("10.9.0.12")
finally:
    navi_cli.push = real_push
check(r5["checks"]["pkgver"]["facts"].get("vs_fixed") == "n/a", "FIX linux F5: a dnf host is not dpkg-compared (vs_fixed n/a)")
# linux M3: plan_ai compares versions pre-flight already read (no SSH)
gm, _ = c2.plan_ai({"selector": "99001", "targets": ["10.9.0.1"], "use_llm": False, "installed": {
    "10.9.0.1": {"version": "1.1.1f-1ubuntu2.16", "family": "apt"}, "10.9.0.12": {"version": "1.1.1f-1ubuntu2.20", "family": "apt"},
    "10.9.0.13": {"version": "openssl-3.0.7-24.el9.x86_64", "family": "dnf"}}})
check(gm["vs_fixed"] == {"10.9.0.1": "older", "10.9.0.12": "at_least", "10.9.0.13": "n/a"}, f"FIX linux M3: plan_ai vs_fixed from read versions ({gm['vs_fixed']})")
# linux F8 / sec 5: any multi-host run stops new SSH attempts after 3 failed logins
b, _ = c2.campaign({"hosts": ["10.9.0.2", "10.9.0.2", "10.9.0.2", "10.9.0.1"], "command": "id", "armed": True, "confirm": True,
                    "canary": False, "stop_on_failure": False})
r8 = wait_run(b["run_id"])
check(r8["status"] == "halted" and [h["status"] for h in r8["hosts"]] == ["auth_failed"] * 3 + ["skipped"] and "failed logins" in r8["message"],
      "FIX linux F8: a campaign with no stop rule halts after 3 auth failures (lockout protection)")
rid = c2log.new_run("t8")
c2._run_new(rid, "diag", "t", ["a", "b", "c", "d", "e"])
calls = []
o8 = c2._loop(rid, ["a", "b", "c", "d", "e"], lambda ip: calls.append(ip) or {"target": ip, "status": "auth_failed"}, canary=False)
check(o8.get("halted") and calls == ["a", "b", "c"], "FIX linux F8: read-only runs (no stop rule) stop new SSH attempts after 3 failed logins")
calls.clear()
rid = c2log.new_run("t8")
c2._run_new(rid, "diag", "t", ["a", "b", "c", "d", "e"])
c2._loop(rid, ["a", "b", "c", "d", "e"], lambda ip: calls.append(ip) or {"target": ip, "status": "auth_failed"}, canary=False, max_auth_failures=5)
check(len(calls) == 5, "FIX linux F8: the operator can raise the limit")
# sec note: the unarmed error no longer mentions the removed ARM switch; the SSH user is read locally
b, _ = c2.campaign({"hosts": ["10.9.0.1", "10.9.0.12"], "command": "id", "confirm": True})
check("flip ARM" not in b["error"] and "typed host count" in b["error"], "sec note: unarmed campaign error names the typed count")
check(c2.status({})[0]["ssh"].get("user") == "svc" and "password" not in json.dumps(c2.status({})[0]["ssh"].get("user")),
      "'As' line: the navi SSH user name is read locally (navi.db ssh table)")

# ============ 6. page source pins ============
page = open(os.path.join(ROOT, "agents", "c2", "page.html"), encoding="utf-8").read()
check("armSwitch" not in page and "ARM this campaign" not in page, "ARM switch gone (replaced by the typed count)")
check("remHostList" not in page and "remTargets" not in page, "no second remediation host list / fallback")
check("cmdHost" not in page and "fileHost" not in page, "no separate single-host fields")
check(re.search(r"armed:true", page) and "a.api==='campaign'&&typedOk?{armed:true}:{}" in page, "C1 armed:true only after a typed confirm")
check(not re.search(r"\son[a-z]+=[\"']", page.split("<script>")[1]), "no inline on*= handlers built in the page script")

# ============ 7. UI (Playwright, own server, fake navi) ============
try:
    from playwright.sync_api import sync_playwright
except Exception:
    sync_playwright = None
    print("SKIP UI checks — Playwright is not installed")
if sync_playwright:
    s_ = socket.socket()
    s_.bind(("127.0.0.1", 0))
    PORT = s_.getsockname()[1]
    s_.close()
    senv = dict(os.environ, PORT=str(PORT), NAVI_TAGLOG_DB=os.path.join(TMP, "srv_taglog.db"), FAKE_NAVI_STATE=os.path.join(TMP, "srvfixed"))
    srv = subprocess.Popen([sys.executable, "app_stdlib.py", "--port", str(PORT)], cwd=ROOT, env=senv,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    atexit.register(srv.terminate)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", PORT), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    URL = f"http://127.0.0.1:{PORT}/agents/c2/page.html"
    with sync_playwright() as pw:
        br = pw.chromium.launch()
        pg = br.new_page(viewport={"width": 1400, "height": 1000})
        errs, dialogs, reqs = [], [], []
        pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.on("dialog", lambda d: (dialogs.append(d.message), d.accept()))
        pg.on("request", lambda r: reqs.append((r.url.split("/")[-1], r.post_data)) if r.method == "POST" and "/api/c2/" in r.url else None)

        def last(api):
            x = [json.loads(b) for a, b in reqs if a == api]
            return x[-1] if x else None

        def set_targets(v):
            if pg.is_hidden("#setEditor"):
                pg.click("#editSet")
            pg.fill("#freeTargets", v)
            pg.wait_for_timeout(900)

        def review(k):
            if pg.query_selector(f"#wwh_{k} [data-review]"):
                pg.click(f"#wwh_{k} [data-review]")
                pg.wait_for_timeout(150)

        def tab(t):
            pg.click(f'#secNav button[data-go="v-{t}"]')
            pg.wait_for_timeout(150)

        pg.goto(URL)
        pg.wait_for_load_state("networkidle")
        pg.wait_for_timeout(500)
        acts = {a for a, _ in reqs}
        check(not acts & {"run_checks", "cred_test", "path_check", "command", "campaign", "deploy", "rollback", "push_file", "plan_ai"},
              f"nothing runs on page open (calls: {sorted(acts)})")

        # --- remediation never falls back to another list (sec R1 / ui P1-1)
        tab("rem")
        pg.fill("#remSel", "99001")
        pg.click("#remFind")
        pg.wait_for_timeout(800)
        check(pg.evaluate("SCOPE.length") == 0 and pg.query_selector_all("#findOut .fa:checked") == [],
              "R1 Find never pre-ticks and never fills the Target set")
        pg.click('#stepper button[data-s="6"]')
        pg.wait_for_timeout(200)
        check(pg.is_disabled("#btn_canary") and "Generate a plan" in pg.text_content("#why_canary"),
              "R1 deploy is disabled with a reason — there is no other host list to fall back to")

        # --- stale single-host field (sec R7 / ui P1-4) + C3
        set_targets("10.9.0.1")
        tab("cmd")
        pg.fill("#cmdText", "id")
        pg.wait_for_timeout(700)
        review("cmd")
        check("10.9.0.1" in pg.text_content("#btn_cmd"), "single command names its one host")
        set_targets("10.9.0.12")
        check(pg.is_disabled("#btn_cmd") and "Target set changed (1 → 1 hosts)" in pg.text_content("#why_cmd"),
              "C3 a Target-set change clears the preview and re-locks the button")
        review("cmd")
        pg.click("#btn_cmd")
        pg.wait_for_timeout(900)
        b = last("command")
        check(b and b["target"] == "10.9.0.12" and b["expect_count"] == 1, "R7 the command goes to the CURRENT single host, never a stale one")
        check(dialogs and "10.9.0.12" in dialogs[-1] and "10.9.0.1 " not in dialogs[-1], "the confirm names the host that ran")

        # --- campaign: real count, typed count n>=2, ARM never left on (ui P1-6), crown last + never canary
        set_targets("10.9.0.11\n10.9.0.1\n10.9.0.12")
        review("cmd")
        body = pg.evaluate("SHOWN.cmd.body")
        check(body["hosts"][0] == "10.9.0.1" and body["hosts"][-1] == "10.9.0.11", "D3 crown jewel is never the canary and runs last (campaign)")
        check(pg.is_disabled("#btn_cmd") and pg.is_visible("#typedIn_cmd"), "C1 multi-host free-form needs the typed count")
        pg.fill("#typedIn_cmd", "2")
        check(pg.is_disabled("#btn_cmd"), "C1 a wrong typed count keeps the button locked")
        pg.fill("#typedIn_cmd", "3")
        check(not pg.is_disabled("#btn_cmd"), "C1 the right typed count unlocks it")
        pg.click("#btn_cmd")
        pg.wait_for_timeout(1500)
        cb = last("campaign")
        check(cb and cb.get("armed") is True and cb["expect_count"] == 3 and "allow_truncate" not in cb, "campaign: armed only after typing; real count; never allow_truncate")
        check(pg.input_value("#typedIn_cmd") == "" and pg.is_disabled("#btn_cmd"), "ui P1-6 nothing stays armed after the run")
        pg.fill("#optMax", "2")
        pg.dispatch_event("#optMax", "change")
        pg.wait_for_timeout(300)
        check(pg.is_disabled("#btn_cmd") and "Max hosts is 2 but the Target set has 3" in pg.text_content("#why_cmd"),
              "R4 the page refuses over max hosts (never truncates)")
        pg.fill("#optMax", "200")
        pg.dispatch_event("#optMax", "change")
        pg.select_option("#canarySel", "10.9.0.12")
        pg.wait_for_timeout(300)
        check(pg.evaluate("SHOWN.cmd.body.hosts[0]") == "10.9.0.12", "operator canary moves to index 0")
        check(pg.evaluate("(()=>{ const o=document.querySelector('#canarySel option[value=\"10.9.0.11\"]'); return o&&o.disabled; })()"),
              "D3 a crown jewel can't be picked as the canary")

        # --- typed-count thresholds (owner D2 + C1/C2)
        t = pg.evaluate("""()=>{ const mk=(i,o)=>Object.assign({target:'10.0.0.'+i,kind:'private',in_inventory:true,asset:{acr:5,crown:false}},o||{});
          const ten=[...Array(10)].map((_,i)=>mk(i)), eleven=[...Array(11)].map((_,i)=>mk(i));
          return {one:typedFor([mk(1)],{freeform:true}).need, two:typedFor([mk(1),mk(2)],{freeform:true}).need,
            ten:typedFor(ten,{big:true}).need, eleven:typedFor(eleven,{big:true}).need,
            crown:typedFor([mk(1,{asset:{acr:9,crown:true}})],{}).need, pub:typedFor([mk(1,{kind:'public'})],{}).need,
            off:typedFor([mk(1,{in_inventory:false,asset:null})],{}).need, forced:typedFor([mk(1)],{freeform:true,forced:true}).need}; }""")
        check(t == {"one": False, "two": True, "ten": False, "eleven": True, "crown": True, "pub": True, "off": True, "forced": True},
              f"D2/C1/C2 typed thresholds: 1 private=no, n≥2 free-form=yes, plans >10=yes, crown/public/off-inventory/forced=yes ({t})")

        # --- hand-off: no widening (sec R3), proposed not merged, credit only for its own hosts (R2/C5)
        pg.evaluate("""sessionStorage.setItem('c2_handoff', JSON.stringify({intent:'remediate', plugin_id:'99001', source:'Laelaps',
            targets:[{ip:'10.9.0.1',uuid:'u1'},{ip:'10.9.0.11',uuid:'u11'},{ip:'10.9.0.0/28'},{ip:'10.9.0.20 10.9.0.21'},{ip:'10.9.0.12',uuid:'u-other'}]}))""")
        reqs.clear()
        pg.goto(URL)
        pg.wait_for_load_state("networkidle")
        pg.wait_for_timeout(900)
        bar = pg.text_content("#handoff")
        check("Request from Laelaps" in bar and "2 entries ignored" in bar and pg.evaluate("SCOPE.length") == 0,
              "R3 CIDR / multi-host entries are ignored and counted; nothing is merged into the Target set")
        check(pg.evaluate("HANDOFF.hosts.find(e=>e.target==='10.9.0.12').drift").startswith("IP now belongs to asset u12"),
              "UUID drift: a host whose IP now maps to another asset is flagged and left out")
        check("Use these 2 as the Target set" in bar, "the drifted host is not in the one-click Use")
        check(not {a for a, _ in reqs} & {"run_checks", "cred_test", "deploy", "plan_ai", "command"}, "the hand-off never runs anything")
        pg.click("#hoUse")
        pg.wait_for_timeout(900)
        check(sorted(pg.evaluate("SCOPE.map(e=>e.target)")) == ["10.9.0.1", "10.9.0.11"], "Use replaces the set with exactly the proposed hosts")
        pg.click('#stepper button[data-s="4"]')
        pg.uncheck("#remAi")
        pg.click("#remGen")
        pg.wait_for_timeout(900)
        pb = last("plan_ai")
        check(pb.get("source") == "Laelaps" and "source_kind" not in pb, "C5 its own hosts + intent + payload → credited to the hand-off")
        set_targets("10.9.0.1\n10.9.0.11\n10.9.0.12")
        tab("ins")
        review("login")
        lb = pg.evaluate("SHOWN.login.body")
        check(lb.get("source") == "Laelaps" and lb.get("source_kind") == "after_handoff",
              "R2/C5 a set with a host the hound never proposed → c2 (after handoff:…)")
        pg.click("#btn_login")
        pg.wait_for_timeout(1500)
        con2 = sqlite3.connect(os.path.join(TMP, "srv_taglog.db"))
        srcs = {r[0] for r in con2.execute("SELECT source FROM c2_log WHERE catalog_id='cred'")}
        con2.close()
        check(srcs == {"c2 (after handoff:Laelaps)"}, f"R2 the C2 log records 'c2 (after handoff:Laelaps)' ({srcs})")

        # --- pre-flight: sudo-password host excluded by default; include tick names it in the confirm
        set_targets("10.9.0.1\n10.9.0.8\n10.9.0.2\n10.9.0.11")
        tab("rem")
        pg.click('#stepper button[data-s="1"]')
        pg.fill("#remSel", "99001")
        pg.click("#remFind")
        pg.wait_for_timeout(700)
        pg.click('#stepper button[data-s="3"]')
        review("preflight")
        pg.click("#btn_preflight")
        pg.wait_for_timeout(4000)
        el = pg.evaluate("eligibleEnts().map(e=>e.target)")
        check("10.9.0.8" not in el and "10.9.0.2" not in el and "10.9.0.1" in el, f"D1 sudo-needs-password and auth-failed hosts are excluded ({el})")
        check(pg.query_selector('#pfOut [data-incl="10.9.0.8"]') is not None, "D1 a per-host include tick is offered")
        pg.click('#stepper button[data-s="4"]')
        pg.click("#remGen")
        pg.wait_for_timeout(900)
        pg.click('#stepper button[data-s="3"]')
        pg.click('#pfOut [data-incl="10.9.0.8"]')
        pg.wait_for_timeout(200)
        pg.click('#stepper button[data-s="6"]')
        pg.check("#oneRun")
        pg.wait_for_timeout(200)
        review("canary")
        a = pg.evaluate("({body:SHOWN.canary.body, conf:describe(SHOWN.canary).ctext, typed:SHOWN.canary.typed})")
        check(a["body"]["targets"][0] != "10.9.0.11" and a["body"]["targets"][-1] == "10.9.0.11", "D3 one-run deploy: crown not canary, last")
        check("navi will type the stored sudo password on: web08 10.9.0.8" in a["conf"], "D1 the confirm names the included sudo-password host")
        check(a["typed"]["need"] and "Undo is NOT possible" in (a["typed"].get("undoNone") or ""), "C2 crown → typed count, with the no-undo line")
        # --- contradictory deploy confirm (sec R5 / ui P1-2): confirm == describe(body), sent body == shown body
        pg.uncheck("#oneRun")
        review("canary")
        shown = pg.evaluate("({conf:describe(SHOWN.canary).ctext, body:JSON.stringify(SHOWN.canary.body)})")
        check("canary only" in pg.text_content("#wwh_canary") and "stop after" not in shown["conf"], "R5 the deploy preview states the fixed policy only")
        n_d = len(dialogs)
        pg.click("#btn_canary")
        pg.wait_for_timeout(2500)
        check(len(dialogs) > n_d and dialogs[-1] == shown["conf"], "C4c the native confirm text == describe(body)")
        db_ = last("deploy")
        db_.pop("confirm", None)
        check(db_ == json.loads(shown["body"]), "C4 the request body == the frozen previewed body")
        check(db_["targets"] == [pg.evaluate("CANARY_RUN.target")] and db_["stage"] == "canary", "canary call targets the canary only")
        # fix round, page side
        f2 = pg.evaluate("""()=>{ DG={plan_id:'p',run_id:'r',hosts:['10.9.0.11','10.9.0.1'],sequence:[],unknown:[]}; const a=buildDowngrade();
            return {t:a.body.targets, ex:a.excluded.map(x=>x.e.target+': '+x.why), scope:SCOPE.map(e=>e.target)}; }""")
        check("10.9.0.11" not in f2["t"] and all(t in f2["scope"] for t in f2["t"]) and any(x.startswith("10.9.0.11: not in the Target set") for x in f2["ex"])
              if "10.9.0.11" not in f2["scope"] else True, f"FIX sec F2: a downgrade acts only on Target-set hosts ({f2})")
        pg.evaluate("""()=>{ CANARY=''; }""")
        f2b = pg.evaluate("""()=>{ const keep=SCOPE; SCOPE=SCOPE.filter(e=>e.target!=='10.9.0.11'); DG={plan_id:'p',run_id:'r',hosts:['10.9.0.11','10.9.0.1'],sequence:[],unknown:[]};
            const a=buildDowngrade(); SCOPE=keep; return {t:a.body.targets, ex:a.excluded.map(x=>x.e.target+': '+x.why)}; }""")
        check(f2b["t"] == ["10.9.0.1"] and f2b["ex"] == ["10.9.0.11: not in the Target set (add it to downgrade it)"],
              f"FIX sec F2: a crown jewel removed from the set is never downgraded by a placeholder entry ({f2b})")
        f3 = pg.evaluate("""()=>{ const e=SCOPE[0]; const keep=PREFLIGHT; PREFLIGHT={at:Date.now(), sig:scopeSig(), stale:'', hosts:{}};
            PREFLIGHT.hosts[e.target]={cred:{status:'ok',sudo:'sudo_ok'}, checks:{status:'ok',checks:{os:{facts:{family:'apt'}},disk:{facts:{}},ident:{facts:{sudo_rules:'all'}},pkgver:{facts:{installed:'1.1.1f-1ubuntu2.16',held:true,vs_fixed:'older'}}}}};
            const r=hostElig(e); PREFLIGHT=keep; return r; }""")
        check(f3["ok"] is False and f3["reason"].startswith("Held (apt-mark hold)"), "FIX linux F3: a held package is ineligible up front")
        f6 = pg.evaluate("""()=>{ const d=document.createElement('div'); d.id='tmpd'; document.body.appendChild(d);
            renderDiag({run_id:'x',status:'done',done:1,total:1,errors:1,hosts:[{target:'10.9.0.6',status:'timeout',checks:{os:{status:'skipped',facts:{}},mem:{status:'skipped',facts:{}}}}]},'tmpd');
            const t=d.textContent; d.remove(); return t; }""")
        check("result not received (session timed out)" in f6 and "not run" not in f6, "FIX linux F6: an Inspect timeout collapses to one 'result not received' line")
        check("reads the installed version; affected if" in open(os.path.join(ROOT, "agents", "c2", "page.html"), encoding="utf-8").read(),
              "FIX linux M1: precheck label says the version compare decides")
        tab("ins")
        review("checks")
        check("stops after 3 failed logins (account lockout)" in pg.text_content("#wwh_checks") and pg.evaluate("SHOWN.checks.body.max_auth_failures") == 3,
              "FIX linux F8: the Inspect preview states the lockout brake and sends it")
        check("SSH user svc" in pg.text_content("#wwh_checks"), "'As' line names the SSH user")
        check(not errs, f"no page errors ({errs[:2]})")
        br.close()
    srv.terminate()

gates(False)
print(f"\n{len(fails)} failure(s)")
sys.exit(1 if fails else 0)
