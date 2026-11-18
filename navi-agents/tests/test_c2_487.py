#!/usr/bin/env python3
"""Build 487 — owner decision 7 (OWNER_DECISIONS.md, 2026-11-18, "yes on both"):

  7a. `dnf needs-restarting -r` — a READ-ONLY probe, exact tokens, in precheck / verify / pre-flight only, never a plan
      or rollback step; pre-flight's reboot check uses it on dnf-family hosts when the standalone needs-restarting is
      absent (so linux R1's "reboot state unknown" goes away there).
  7b. yum `--setopt=exit_on_lock=1` — ONE exact token, only directly after `yum`, only on yum-family hosts (CentOS/RHEL 7,
      AL1/AL2), only before install / update / upgrade / downgrade (and in read-only yum checks). Plans and static
      templates for the yum family carry it; a step that exits on the lock is "Package manager busy — nothing changed
      (retry)" — never "Unknown state", rollback not blocked, a re-pre-flight lets it proceed. Every other --setopt
      stays denied.

Fake navi only (tests/c2_fakenavi.py: 10.9.1.24 CentOS 8 without the standalone tool, 10.9.1.25 CentOS 7 whose
yum-cron takes the lock after pre-flight). Run: python3 tests/test_c2_487.py → exit 0 on pass.
"""
import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
TMP = tempfile.mkdtemp(prefix="hounds-c2-487-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
for k in list(os.environ):
    if k.startswith(("NAVI_", "HOUNDS_", "ANTHROPIC_", "OPENAI_", "FAKE_NAVI")):
        os.environ.pop(k, None)
FAKE = os.path.join(HERE, "c2_fakenavi.py")
os.chmod(FAKE, 0o755)
import c2_phase2_fixture as FX  # noqa: E402

DB = FX.build(os.path.join(TMP, "navi.db"))
ENV = {"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"), "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"),
       "NAVI_HISTORY_DIR": os.path.join(TMP, "hist"), "NAVI_TAGLOG_DB": os.path.join(TMP, "taglog.db"),
       "NAVI_BIN": FAKE, "FAKE_NAVI_LOG": os.path.join(TMP, "argv.log"), "NAVI_TAG_GAP_MS": "0", "NAVI_CWD": TMP,
       "FAKE_NAVI_STATE": os.path.join(TMP, "fixed"), "NAVI_ALLOW_WRITES": "1", "NAVI_REMOTE_CODE_EXECUTION": "1"}
os.environ.update(ENV)
fails = []


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def argv_lines():
    try:
        return [json.loads(x) for x in open(ENV["FAKE_NAVI_LOG"]) if x.strip()]
    except OSError:
        return []


def reset_argv():
    open(ENV["FAKE_NAVI_LOG"], "w").close()


from core import c2_catalog, c2_remediate as R, c2_verdict as V, c2log, version  # noqa: E402
from agents.c2 import api as c2  # noqa: E402


def wait_run(rid, secs=90):
    t0 = time.time()
    while time.time() - t0 < secs:
        b, _ = c2.run_status({"run_id": rid})
        if b.get("run") and b["run"]["status"] not in ("queued", "running"):
            return b["run"]
        time.sleep(0.1)
    return (c2.run_status({"run_id": rid})[0] or {}).get("run") or {}


# ============ 1. version ============
check(version.BUILD == 487, "core/version.py BUILD is 487")
_root_readme = os.path.join(ROOT, "ROOT_README.md")
if not os.path.exists(_root_readme):
    _root_readme = os.path.join(os.path.dirname(ROOT), "README.md")
for f_ in ("INSTALL.md", "README.md", _root_readme):
    t_ = open(os.path.join(ROOT, f_) if not os.path.isabs(f_) else f_, encoding="utf-8").read()
    check("1.43.487" in t_ and "1.43.486" not in t_, f"{os.path.basename(f_)} names 1.43.487")

# ============ 2. owner decision 7b — yum --setopt=exit_on_lock=1 ============
fxD = json.load(open(os.path.join(HERE, "fixtures", "c2_plugin_output", "real_D_centos7_rsyslog_zstream.json"), encoding="utf-8"))


def src_of(fam):
    return {"plugins": [{"plugin_id": fxD["plugin_id"], "plugin_name": fxD["plugin_name"], "solution": fxD["solution"],
                         "synopsis": "", "description": ""}],
            "hosts": [{"ip": "x", "family": fam, "outputs": {fxD["plugin_id"]: fxD["output"]}}], "families": [fam]}


Y, D_ = src_of("yum"), src_of("dnf")
T = R.YUM_LOCK_OPT
check(T == "--setopt=exit_on_lock=1", "the one allowed --setopt is the exact token --setopt=exit_on_lock=1")
for cmd in (f"sudo yum {T} -y update 'rsyslog'", f"sudo yum {T} -y upgrade rsyslog", f"sudo yum {T} update -y rsyslog"):
    check(R.check_command(cmd, "step", Y) == [], f"7b allowed (step, yum family): {cmd}")
ri = R.check_command(f"sudo yum {T} -y install rsyslog", "step", Y)
check(ri and not any("setopt" in r_ or "option / macro" in r_ for r_ in ri),
      f"7b the token is accepted before `install`, but `yum install` itself stays refused by the existing rule ({(ri or ['-'])[0][:60]})")
check(R.check_command(f"sudo yum {T} -y downgrade rsyslog-8.24.0-41.el7_7.2", "step", Y, rollback=True, step_pkgs={"rsyslog"}) == [],
      "7b allowed (rollback downgrade, yum family)")
for cmd in (f"yum {T} -q list updates rsyslog", f"sudo -n yum {T} --assumeno update rsyslog", f"yum {T} -q list --showduplicates rsyslog",
            f"yum {T} versionlock list", f"yum {T} -q info rsyslog"):
    check(R.check_command(cmd, "read", Y) == [], f"7b allowed (read-only yum check): {cmd}")
DENY = {
    "wrong position (after -y)": f"sudo yum -y {T} update rsyslog",
    "wrong position (end)": f"sudo yum -y update rsyslog {T}",
    "wrong sub-command (remove)": f"sudo yum {T} -y remove rsyslog",
    "wrong sub-command (erase)": f"sudo yum {T} -y erase rsyslog",
    "wrong sub-command (distro-sync)": f"sudo yum {T} -y distro-sync rsyslog",
    "space-separated --setopt exit_on_lock=1": "sudo yum --setopt exit_on_lock=1 -y update rsyslog",
    "=True": "sudo yum --setopt=exit_on_lock=True -y update rsyslog",
    "=0": "sudo yum --setopt=exit_on_lock=0 -y update rsyslog",
    "=1;x (shell operator)": "sudo yum --setopt=exit_on_lock=1;x -y update rsyslog",
    "trailing garbage =1x": "sudo yum --setopt=exit_on_lock=1x -y update rsyslog",
    "duplicate": f"sudo yum {T} {T} -y update rsyslog",
    "another --setopt beside it": f"sudo yum {T} --setopt=gpgcheck=0 -y update rsyslog",
    "another --setopt alone": "sudo yum --setopt=gpgcheck=0 -y update rsyslog",
    "dnf --setopt=exit_on_lock=1": f"sudo dnf {T} -y upgrade rsyslog",
    "zypper": f"sudo zypper {T} --non-interactive update rsyslog",
    "apt-get": f"sudo apt-get {T} install --only-upgrade -y rsyslog",
    "path-qualified yum": f"sudo /usr/bin/yum {T} -y update rsyslog",
    "uppercase": "sudo yum --SETOPT=exit_on_lock=1 -y update rsyslog",
    "quoted with a space": "sudo yum '--setopt=exit_on_lock=1 ' -y update rsyslog",
}
for lab, cmd in DENY.items():
    check(R.check_command(cmd, "step", Y) != [], f"7b denied: {lab}: {cmd[:70]}")
check(R.check_command(f"sudo yum -q {T} list updates rsyslog", "read", Y) != [] and R.check_command(f"dnf {T} -q list --upgrades rsyslog", "read", Y) != [],
      "7b denied in a read check at a wrong position / on dnf")
wf = R.check_command(f"sudo yum {T} -y update rsyslog", "step", D_)
check(wf and "yum-family hosts" in wf[0], f"7b denied for the WRONG family (a dnf-family source: EL8+'s yum is dnf) ({(wf or ['-'])[0][:70]})")
check(R.check_command(f"yum {T} -q list updates rsyslog", "read", D_) != [], "7b denied in a read check for the wrong family")
# plans / templates / catalog carry it
pY, pD = R.template_plan(Y, "yum"), R.template_plan(D_, "dnf")
check(pY["steps"][-1]["command"].startswith(f"sudo yum {T} -y update ") and R.validate(pY, Y)["deployable"]
      and (not pY["steps"][-1].get("rollback") or pY["steps"][-1]["rollback"].startswith(f"sudo yum {T} -y downgrade ")),
      f"7b the yum template step (and its downgrade) carries the token and validates ({pY['steps'][-1]['command'][:60]})")
check(T not in pD["steps"][-1]["command"] and pD["steps"][-1]["command"].startswith("sudo dnf -y upgrade "), "7b dnf plans never carry it")
tpl = {t_["os"]: t_["cmd"] for t_ in c2._remediation_templates("rsyslog")}
check(any(T in v_ for k_, v_ in tpl.items() if "CentOS 7" in k_) and not any(T in v_ for k_, v_ in tpl.items() if "CentOS 7" not in k_),
      "7b the static yum template carries it (only the yum one)")
check(R.check_command(tpl["RHEL / CentOS 7 · Amazon Linux 1 / 2"], "step", Y) == [], "7b …and that static template validates")
for cid in ("pkgcand", "rbavail", "pkgsim", "holds"):
    check(f"yum {T}" in c2_catalog.BY_ID[cid]["cmd"], f"7b the read-only yum probe in catalog check {cid} carries it")
check(T in R.SYSTEM or "exit_on_lock" in R.SYSTEM, "7b the model is told the yum form (the validator remains the backstop)")
# step failure on the lock
YC = f"sudo yum {T} -y update 'rsyslog'"
YLOCK = ("Existing lock /var/run/yum.pid: another copy is running as pid 4321.\n"
         "Another app is currently holding the yum lock; exiting as configured by exit_on_lock")
k_, w_ = V.classify_step_failure(YLOCK, 200, YC)
check(k_ == "pm_busy" and "Package manager busy" in w_ and "nothing changed (retry)" in w_ and "pid 4321" in w_,
      f"7b yum's two lock lines (exit 200) → Package manager busy — nothing changed (retry) ({w_})")
check(V.classify_step_failure("Loaded plugins: fastestmirror", 1, YC)[0] == "", "7b an ordinary yum failure is not 'busy'")
# ---- fix round 487 (sec / linux V3-F1): "nothing changed" only on a TERMINAL lock refusal before any transaction
TRUE_BUSY = (
    ("yum + token, exit 200 alone (stderr not merged)", "", 200, YC),
    ("yum + token, the 'exiting as configured by exit_on_lock' line, rc 1", YLOCK, 1, YC),
    ("apt: the final E: Could not get lock (wait ran out)", "Waiting for cache lock: Could not get lock /var/lib/dpkg/lock-frontend. "
     "It is held by process 2345 (unattended-upgr)... 300s\nE: Could not get lock /var/lib/dpkg/lock-frontend. It is held by "
     "process 2345 (unattended-upgr)\nE: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another "
     "process using it?", 100, "sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install --only-upgrade -y 'openssl'"),
    ("zypper exit 7", "System management is locked by the application with pid 999 (zypper).\nClose this application before "
     "trying again.", 7, "sudo ZYPP_LOCK_TIMEOUT=300 zypper --non-interactive update 'openssl'"),
)
for lab, out_, rc_, cmd_ in TRUE_BUSY:
    k_, w_ = V.classify_step_failure(out_, rc_, cmd_)
    check(k_ == "pm_busy" and "nothing changed (retry)" in w_, f"V3-F1 true busy: {lab} → Package manager busy — nothing changed (retry)")
NOT_BUSY = (
    ("apt waits, then unpacks, then dpkg fails",
     "Waiting for cache lock: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 2345 (unattended-upgr)... 12s\n"
     "Preparing to unpack .../libssl1.1_1.1.1f-1ubuntu2.20_amd64.deb ...\nUnpacking libssl1.1:amd64 (1.1.1f-1ubuntu2.20) over "
     "(1.1.1f-1ubuntu2.16) ...\nSetting up libssl1.1:amd64 (1.1.1f-1ubuntu2.20) ...\ndpkg: error processing package openssl "
     "(--configure):\nE: Sub-process /usr/bin/dpkg returned an error code (1)", 100,
     "sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install --only-upgrade -y 'libssl1.1' 'openssl'", "lock_wait"),
    ("yum WITHOUT the token waits, then runs, then fails",
     "Existing lock /var/run/yum.pid: another copy is running as pid 4321.\nAnother app is currently holding the yum lock; "
     "waiting for it to exit...\nRunning transaction\n  Updating   : rsyslog-8.24.0-52.el7.x86_64   1/2\n"
     "error: unpacking of archive failed on file /usr/sbin/rsyslogd: cpio: rename", 1, "sudo yum -y update 'rsyslog'", "lock_wait"),
    ("dnf 'Waiting for process', then a scriptlet failure",
     "Waiting for process with pid 999 to finish.\nRunning transaction\n  Upgrading        : openssl-libs-1:1.1.1k-12.el8.x86_64  1/4\n"
     "Error in POSTIN scriptlet in rpm package openssl-libs\nError: Transaction failed", 1, "sudo dnf -y upgrade 'openssl-libs'", "lock_wait"),
    ("dnf 'Waiting for process' alone — dnf is NEVER busy", "Waiting for process with pid 999 to finish.", 1,
     "sudo dnf -y upgrade 'openssl'", "lock_wait"),
    ("'block device' exit 200 that is not a lock (no token)", "Error: failed to read block device /dev/sda1", 200,
     "sudo yum -y update 'rsyslog'", ""),
    ("'block device' exit 200 on a dnf step", "Error: failed to read block device /dev/sda1", 200, "sudo dnf -y upgrade 'x'", ""),
)
for lab, out_, rc_, cmd_, want in NOT_BUSY:
    k_, w_ = V.classify_step_failure(out_, rc_, cmd_)
    check(k_ == want and "nothing changed" not in w_
          and (want != "lock_wait" or ("after waiting for the package lock" in w_ and "partly changed" in w_ and "Run pre-flight" in w_)),
          f"V3-F1 NOT busy: {lab} → {want or 'an ordinary step failure'} ({w_[:60]})")
# ---- fix round 487 (linux M-3): yum change steps and downgrades normalise to carry the token
vN = R.validate({"steps": [{"n": 1, "command": "sudo yum -y update 'rsyslog'",
                            "rollback": "sudo yum -y downgrade 'rsyslog-8.24.0-41.el7_7.2'"}]}, Y)
check(vN["deployable"] and vN["plan"]["steps"][0]["command"] == f"sudo yum {T} -y update 'rsyslog'"
      and vN["plan"]["steps"][0]["rollback"].startswith(f"sudo yum {T} -y downgrade"),
      "M-3: a yum step and its downgrade WITHOUT the token are normalised to include it")
check(R.check_command("sudo yum -y update 'rsyslog'", "step", Y) == [], "M-3: …the validator still accepts the step without it")
vD = R.validate({"steps": [{"n": 1, "command": "sudo dnf -y upgrade 'rsyslog'"}]}, D_)
check(T not in vD["plan"]["steps"][0]["command"], "M-3: dnf steps are never given the token")
vY2 = R.validate({"steps": [{"n": 1, "command": f"sudo yum {T} -y update 'rsyslog'"}]}, Y)
check(vY2["plan"]["steps"][0]["command"].count(T) == 1 and R.plan_hash(vY2["plan"]) == vY2["hash"], "M-3: never inserted twice; the hash covers the normalised plan")
vW = R.validate({"steps": [{"n": 1, "command": f"sudo yum {T} -y update 'rsyslog'"}]}, D_)
check(not vW["deployable"], "M-3: the token in a plan for a dnf-family source is still refused (validate() sees the family)")
lk = c2_catalog.facts("pkgcand", "Existing lock /var/run/yum.pid: another copy is running as pid 4321.\nC2_PMRC=200")
check(lk["status"] == "locked", "7b a pre-flight repo check that hit the yum lock is 'locked' (busy), not a repo error")

# ============ 3. owner decision 7a — dnf needs-restarting -r ============
check(R.check_command("dnf needs-restarting -r", "read", Y) == [], "7a allowed: `dnf needs-restarting -r` as a read-only check")
for cmd, lab in (("dnf needs-restarting -r", "as a plan step"), ("sudo dnf needs-restarting -r", "as a plan step with sudo")):
    check(R.check_command(cmd, "step", Y) != [], f"7a denied {lab}")
check(R.check_command("dnf needs-restarting -r", "step", Y, rollback=True, step_pkgs={"rsyslog"}) != [], "7a denied as a rollback step")
for cmd in ("dnf needs-restarting", "dnf needs-restarting -r -s", "dnf needs-restarting -s", "dnf needs-restarting -r --refresh",
            "dnf -q needs-restarting -r", "yum needs-restarting -r", "dnf needs-restarting -r x"):
    check(R.check_command(cmd, "read", Y) != [], f"7a denied variant (exact tokens only): {cmd}")
v7 = R.validate({"steps": [{"n": 1, "command": "dnf needs-restarting -r"}]}, D_)
check(not v7["deployable"] and v7["rejected"], "7a an AI plan that uses it as a step is not deployable")
v7b = R.validate({"steps": [{"n": 1, "command": "sudo dnf -y upgrade rsyslog", "verify": {"command": "dnf needs-restarting -r"}}]}, D_)
check(v7b["deployable"] and v7b["plan"]["steps"][0]["verify"]["command"] == "dnf needs-restarting -r", "7a …but it is fine as a step's read-only verify")
rr = c2_catalog.BY_ID["rebootreq"]["cmd"]
check("dnf needs-restarting -r 2>&1" in rr and rr.index("command -v needs-restarting") < rr.index("dnf needs-restarting -r"),
      "7a pre-flight's reboot check uses `dnf needs-restarting -r` AFTER the standalone tool (only when it is absent)")
# real shell: a stub dnf (yes / no / plugin missing) and no dnf at all
stub = os.path.join(TMP, "stubbin")
os.makedirs(stub, exist_ok=True)
with open(os.path.join(stub, "dnf"), "w") as fh:
    fh.write('#!/bin/sh\n[ "$1 $2" = "needs-restarting -r" ] || exit 2\ncase "$DNFMODE" in nocmd) echo "No such command: '
             'needs-restarting. Please use /usr/bin/dnf --help"; exit 1;; yes) printf "Core libraries or services have been '
             'updated since boot-up:\\n  * glibc\\n\\nReboot is required to fully utilize these updates.\\n"; exit 1;; '
             'rpmdb) echo "Error: rpmdb open failed"; exit 1;; rc0odd) echo "something unexpected"; exit 0;; '
             '*) printf "No core libraries or services have been updated since boot-up.\\nReboot should not be necessary.\\n"; '
             'exit 0;; esac\n')
os.chmod(os.path.join(stub, "dnf"), 0o755)
# hermetic: hide the machine's own package tools, so the kernel-compare fallback can't answer from the
# test machine (an Ubuntu box with dpkg-query would otherwise decide "no reboot" for the "unknown" cases)
nopkg = os.path.join(TMP, "nopkgbin")
os.makedirs(nopkg, exist_ok=True)
for d_ in (stub, nopkg):
    for t_ in ("dpkg-query", "rpm", "zypper"):
        with open(os.path.join(d_, t_), "w") as fh:
            fh.write("#!/bin/sh\nexit 1\n")
        os.chmod(os.path.join(d_, t_), 0o755)
bcmd = c2_catalog.build(["rebootreq"], {})["chunks"][0]["command"]
res = {}
for mode, path in (("absent", nopkg + ":" + os.environ["PATH"]), ("no", stub + ":" + os.environ["PATH"]), ("yes", stub + ":" + os.environ["PATH"]),
                   ("nocmd", stub + ":" + os.environ["PATH"]), ("rpmdb", stub + ":" + os.environ["PATH"]),
                   ("rc0odd", stub + ":" + os.environ["PATH"])):
    o = subprocess.run(["bash", "-c", bcmd], capture_output=True, text=True, env=dict(os.environ, PATH=path, DNFMODE=mode), timeout=60).stdout
    res[mode] = c2_catalog.parse(o)["rebootreq"]["facts"]
has_standalone = bool(shutil.which("needs-restarting")) or os.path.exists("/var/run/reboot-required")
if not has_standalone:
    check(res["no"]["reboot"] == "no" and res["no"]["rtool"] == "dnf needs-restarting" and res["no"]["via"] == "tool",
          "7a real shell: dnf needs-restarting -r exit 0 → no reboot (decided by the tool)")
    check(res["yes"]["reboot"] == "yes" and res["yes"]["pending"], "7a real shell: exit 1 → reboot required")
    check(res["nocmd"]["reboot"] == "unknown" and not res["nocmd"]["rtool"], "7a real shell: dnf-plugins-core missing ('No such command') → still unknown")
    check(res["absent"]["reboot"] == "unknown", "7a real shell: no dnf at all → the earlier fallback")
    check(res["rpmdb"]["reboot"] == "unknown" and res["rc0odd"]["reboot"] == "unknown",
          "M-1: decided on dnf's TEXT — an rc-1 rpmdb error and an rc-0 unexpected text stay unknown")

# ============ 4. end to end on the fake navi ============
# 7a: CentOS 8 without the standalone tool now reports the reboot state
g24, _ = c2.plan_ai({"selector": "190001", "targets": ["10.9.1.24"], "use_llm": False})
b, _ = c2.preflight({"targets": ["10.9.1.24"], "plan_id": g24["plan_id"], "confirm": True, "queue": True})
h24 = wait_run(b["run_id"])["hosts"][0]
rb24 = ((h24.get("checks") or {}).get("rebootreq") or {}).get("facts") or (c2._PF["10.9.1.24"]["checks"]["checks"]["rebootreq"]["facts"])
check(h24["elig"]["ok"] and rb24["reboot"] == "no" and rb24["rtool"] == "dnf needs-restarting"
      and c2_catalog.health("rebootreq", rb24)["text"] == "no reboot pending",
      "7a EL8 host without the standalone needs-restarting: pre-flight REPORTS the reboot state (dnf needs-restarting -r: no)")
b, _ = c2.preflight({"targets": ["10.9.1.24"], "plan_id": g24["plan_id"], "confirm": True, "queue": True})
wait_run(b["run_id"])
d, code = c2.deploy({"plan_id": g24["plan_id"], "targets": ["10.9.1.24"], "confirm": True, "queue": True})
h = wait_run(d["run_id"])["hosts"][0] if d.get("run_id") else {"message": str(d)}
check(h.get("verdict") == "fixed" and "⟳ Not effective until reboot" in h["message"] and "Reboot state unknown" not in h["message"],
      f"7a …after glibc moved, dnf needs-restarting -r says reboot: ⟳ Not effective until reboot — not 'unknown' ({h['message'][:90]})")

# 7b: CentOS 7 — yum-cron takes the lock AFTER pre-flight
g25, _ = c2.plan_ai({"selector": "135313", "targets": ["10.9.1.25"], "use_llm": False})
check(g25["plan"]["steps"][-1]["command"].startswith(f"sudo yum {T} -y update"), "7b the CentOS 7 plan carries the token")
b, _ = c2.preflight({"targets": ["10.9.1.25"], "plan_id": g25["plan_id"], "confirm": True, "queue": True})
e25 = wait_run(b["run_id"])["hosts"][0]["elig"]
check(e25["ok"], f"7b 10.9.1.25 is idle at pre-flight → eligible ({e25.get('reason')})")
reset_argv()
d, code = c2.deploy({"plan_id": g25["plan_id"], "targets": ["10.9.1.25"], "confirm": True, "queue": True})
run25 = wait_run(d["run_id"])
h = run25["hosts"][0]
sent = [a_[a_.index("--command") + 1] for a_ in argv_lines() if "--command" in a_]
check(h["verdict"] == "pm_busy" and h["status"] == "failed" and "Package manager busy" in h["message"]
      and "nothing changed (retry)" in h["message"] and not h.get("unknown_state") and h["status"] != "timeout",
      f"7b the lock taken after pre-flight → Package manager busy — nothing changed (retry), never Unknown state ({h['message'][:90]})")
check(any(f"yum {T} -y update" in c_ for c_ in sent), "7b …the change step that ran carried --setopt=exit_on_lock=1")
st25 = c2log.host_states(["10.9.1.25"]).get("10.9.1.25", {})
check(not st25.get("unknown_state"), "7b the C2 log does not mark the host 'unknown state'")
rb_, code_ = c2.rollback({"plan_id": g25["plan_id"], "run_id": d["run_id"], "targets": ["10.9.1.25"], "dry_run": True})
check(code_ != 409 and not rb_.get("unknown_state"), f"7b rollback is NOT blocked by an unknown state ({code_})")
b, _ = c2.preflight({"targets": ["10.9.1.25"], "plan_id": g25["plan_id"], "confirm": True, "queue": True})
wait_run(b["run_id"])
c2._PLANS[g25["plan_id"]]["deployed_hashes"] = set()
d, code = c2.deploy({"plan_id": g25["plan_id"], "targets": ["10.9.1.25"], "confirm": True, "queue": True})
h = wait_run(d["run_id"])["hosts"][0] if d.get("run_id") else {"verdict": str(d)}
check(code == 200 and h["verdict"] == "fixed", f"7b a re-pre-flight lets it proceed: the second deploy is Fixed ({h.get('verdict')})")

# ---- V3-F1 end to end: the step's last word is a lock refusal but the packages MOVED → "partly changed", never
# "nothing changed"
u26, _ = c2.plan_ai({"selector": "300001", "targets": ["10.9.1.26"], "use_llm": False})
b, _ = c2.preflight({"targets": ["10.9.1.26"], "plan_id": u26["plan_id"], "confirm": True, "queue": True})
wait_run(b["run_id"])
d, code = c2.deploy({"plan_id": u26["plan_id"], "targets": ["10.9.1.26"], "confirm": True, "queue": True})
h = wait_run(d["run_id"])["hosts"][0] if d.get("run_id") else {"message": str(d), "verdict": ""}
check(h["verdict"] == "step_failed" and h.get("partly_changed") and "nothing changed" not in h["message"]
      and "may be partly changed" in h["message"] and "libssl1.1 1.1.1f-1ubuntu2.16 → 1.1.1f-1ubuntu2.20" in h["message"]
      and "Run pre-flight before retrying" in h["message"],
      f"V3-F1: the version re-read shows movement → 'the step failed after waiting for the package lock; partly changed' ({h['message'][:110]})")

print(f"\n{len(fails)} failure(s)")
sys.exit(1 if fails else 0)
