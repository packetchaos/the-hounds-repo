"""Amarok (C2) redesign, Phase 2 — build 486 regression tests (remediation correctness).

Covers DESIGN_SPEC §8 Phase 2 and the Linux / security sign-offs:
  * live OS family per host from /etc/os-release and ONE plan per (family, ID, major) group (linux P1-1, AL1 fix);
    the server-side family / plan-group / immutable-OS refusal in deploy (linux M3, second half)
  * Tenable's plugin-output formats, TABLE-DRIVEN: every file in tests/fixtures/c2_plugin_output/ is a case — a real
    sample from a navi.db drops in as a new file (real samples: pending, owner decision 6)
  * backports (distro build vs upstream-only fixed version; changelog evidence is "no evidence", never "not fixed")
  * before / after versions and the full verdict set, incl. "Upgraded, still vulnerable" and the multi-package rules
    (linux C6 / C7); kernels (install-only, newest installed, reboot flag); services on old libraries
  * the full pre-flight bundle per distro and its eligibility rules (bounded lock wait C4, holds, half-configured,
    /boot, candidate < fixed, simulation, immutable OS); dpkg prompt / lock options (C10 / C5 / C8)
  * the rollback-availability probe BEFORE deploy (C9); health verdicts separate from the exit code (P1-9 / P1-10)
  * the validator allow-list EXACTLY as linux C10 (owner decision 6): a test for every addition and for the denied
    neighbours (other --force-*, joined -o, -o on other verbs, ZYPP_LOCK_TIMEOUT 0 / -1 / 901 / before other commands,
    read-only probes rejected as plan steps)
  * navi's known_hosts read locally: fingerprints, "key NEW · recorded", strict-by-default fallback (sec L-1 / C7b)
  * scale: plugin output is read only for the plan's selected hosts × plugins (per-asset seeks), never estate-wide

Uses tests/c2_fakenavi.py only (10.9.1.x = the per-distro hosts) — never a real navi or host. The UI part starts this
repo's own server on a free loopback port and drives the remediation journey on a mixed-distro Target set with
Playwright; it is skipped (and said so) only when Playwright is not installed.

Run: python3 tests/test_c2_phase2_486.py   → exit 0 on pass
"""
import atexit
import glob
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
TMP = tempfile.mkdtemp(prefix="hounds-c2p2-")
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
       "FAKE_NAVI_STATE": os.path.join(TMP, "fixed")}
os.environ.update(ENV)
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


def argv_lines():
    try:
        return [json.loads(x) for x in open(ENV["FAKE_NAVI_LOG"]) if x.strip()]
    except OSError:
        return []


def reset_argv():
    open(ENV["FAKE_NAVI_LOG"], "w").close()


from core import c2_catalog, c2_remediate as R, c2_verdict as V, c2_hostkeys, c2log, db, version  # noqa: E402
from agents.c2 import api as c2  # noqa: E402


def wait_run(rid, secs=90):
    t0 = time.time()
    while time.time() - t0 < secs:
        b, _ = c2.run_status({"run_id": rid})
        if b.get("run") and b["run"]["status"] not in ("queued", "running"):
            return b["run"]
        time.sleep(0.1)
    return (c2.run_status({"run_id": rid})[0] or {}).get("run") or {}


check(version.BUILD >= 486, "core/version.py BUILD is 486 or later")
_root_readme = os.path.join(ROOT, "ROOT_README.md")  # a dev copy keeps the repo-root README here
if not os.path.exists(_root_readme):
    _root_readme = os.path.join(os.path.dirname(ROOT), "README.md")  # in the repo it is ../README.md
for f_ in ("INSTALL.md", "README.md", _root_readme):
    t_ = open(os.path.join(ROOT, f_), encoding="utf-8").read()
    check(f"1.43.{version.BUILD}" in t_ and "1.43.485" not in t_, f"{f_} names 1.43.{version.BUILD}")

# ============ 1. plugin-output formats — TABLE-DRIVEN over tests/fixtures/c2_plugin_output/*.json ============
FIX = sorted(glob.glob(os.path.join(HERE, "fixtures", "c2_plugin_output", "*.json")))
check(len(FIX) >= 8, f"{len(FIX)} plugin-output fixtures (rpm pair / multi / kernel, dpkg pair / multi / kernel, Debian, SUSE, upstream)")
shapes = set()
for fn in FIX:
    fx = json.load(open(fn, encoding="utf-8"))
    shapes.add((fx["fam"], fx["shape"]))
    e = fx["expect"]
    po = R.parse_output(fx["output"])
    got = [[p["name"], p["installed"], p["fixed"], p["authority"]] for p in po["pairs"]]
    check(got == e["pairs"], f"fixture {fx['id']}: package pairs parse ({got})")
    if e.get("kernel_running"):
        check(po["kernel"] and [po["kernel"]["running"], po["kernel"]["fixed"]] == e["kernel_running"],
              f"fixture {fx['id']}: running-kernel shape parses")
    if e.get("upstream"):
        check([[u["path"], u["installed"], u["fixed"]] for u in po["upstream"]] == e["upstream"],
              f"fixture {fx['id']}: upstream Path / Installed / Fixed version parse")
    src = {"plugins": [{"plugin_id": "1", "plugin_name": fx["plugin_name"], "plugin_family": fx["plugin_family"],
                        "solution": fx["solution"], "synopsis": "", "description": ""}],
           "hosts": [{"ip": "x", "family": e["family"], "outputs": {"1": fx["output"]}}], "families": [e["family"]]}
    meta = R.plan_meta(src, e["family"])
    check(meta["packages"] == e["packages"], f"fixture {fx['id']}: the plan's package set is {e['packages']} ({meta['packages']})")
    check(meta["kernel"] == e["kernel"], f"fixture {fx['id']}: kernel shape {'detected' if e['kernel'] else 'not claimed'}")
    if e.get("fixed_source"):
        check(meta["fixed_source"] == e["fixed_source"], f"fixture {fx['id']}: fixed version source is {e['fixed_source']}")
    plan = R.template_plan(src, e["family"])
    v = R.validate(plan, src)
    if e.get("kernel_workflow"):
        check(not plan["steps"] and "kernel workflow" in plan["summary"], f"fixture {fx['id']}: Debian/Ubuntu ABI kernel → kernel workflow, no steps")
    elif e["packages"]:
        check(v["deployable"] and not v["rejected"], f"fixture {fx['id']}: the per-family template validates ({v['rejected'][:1]})")
        if len(e["packages"]) > 1:
            check(all("'" + n + "'" in plan["steps"][-1]["command"] for n in e["packages"]),
                  f"fixture {fx['id']}: every paired package is upgraded in ONE transaction")
    if e.get("fixed_source") == "upstream":
        check(not (plan["precheck"] or {}).get("fixed_version") and "UPSTREAM" in plan["summary"],
              f"fixture {fx['id']}: an upstream-only fixed version is never version-compared (backport-unaware, said so)")
check({("rpm", "kernel_pair"), ("rpm", "multi_pair"), ("deb", "multi_pair"), ("deb", "kernel_pair"), ("deb", "upstream_version")} <= shapes,
      "fixtures cover rpm + deb × pair / multi / kernel and the upstream shape")
real = [json.load(open(f))["id"] for f in FIX if json.load(open(f)).get("real_sample")]
print(f"NOTE real-format samples from the owner's navi.db: {len(real)}")
# ---- real samples (real_samples.md, owner's navi.db, 2026-11-18): every one parses, compares, flags and refuses right
check(len(real) == 10, f"10 real-sample fixtures (A–H, I×2) are present ({len(real)})")
for fn in FIX:
    fx = json.load(open(fn, encoding="utf-8"))
    if not fx.get("real_sample"):
        continue
    e, fid = fx["expect"], fx["id"]
    check(fx["output"] in open(os.path.join(ROOT, "..", "real_samples.md"), encoding="utf-8").read()
          if os.path.exists(os.path.join(ROOT, "..", "real_samples.md")) else True, f"real {fid}: output kept verbatim")
    src = {"plugins": [{"plugin_id": fx["plugin_id"], "plugin_name": fx["plugin_name"], "plugin_family": fx["plugin_family"],
                        "solution": fx["solution"], "synopsis": "", "description": ""}],
           "hosts": [{"ip": "x", "family": e["family"], "outputs": {fx["plugin_id"]: fx["output"]}}], "families": [e["family"]]}
    meta = R.plan_meta(src, e["family"])
    plan = R.template_plan(src, e["family"])
    v = R.validate(plan, src)
    # family: from the os string only when it names one distro — a multi-line guess is never a family
    fam_os = R.distro_of(fx["os"])[0]
    check(fam_os == e.get("os_family", e["family"]), f"real {fid}: navi.db OS {fx['os']!r:.40} → family {fam_os}")
    for name, inst, fixd, _a in e["pairs"]:
        k = R.vcmp(inst, fixd, e["compare"])
        check(k == -1 and R.vcmp(fixd, inst, e["compare"]) == 1,
              f"real {fid}: {e['compare']} compare says {name} {inst} < {fixd} (family-native direction)")
        check(R.version_ok(inst, {"fixed_version": fixd, "compare": e["compare"]}) is False
              and R.version_ok(fixd, {"fixed_version": fixd, "compare": e["compare"]}) is True,
              f"real {fid}: version_ok — installed is vulnerable, the fixed build passes")
        check(meta["fixed"].get(name, {}).get("version") == fixd and meta["fixed"][name]["installed"] == inst
              and meta["fixed"][name]["source"] == "distro", f"real {fid}: plan meta carries {name} installed {inst} / fixed {fixd} (distro)")
    if e["packages"]:
        check(meta["requires_reboot"] == e["requires_reboot"], f"real {fid}: requires_reboot = {e['requires_reboot']}")
        check(v["deployable"] and plan["steps"] and all("'" + n + "'" in plan["steps"][-1]["command"] for n in e["packages"]),
              f"real {fid}: one validated transaction names every package with its own case ({plan['steps'][-1]['command'][-90:] if plan['steps'] else '-'})")
        mgr = {"apt": "apt-get install --only-upgrade", "yum": f"yum {R.YUM_LOCK_OPT} -y update",   # 487: owner decision 7b
               "dnf": "dnf -y upgrade"}[e["family"]]
        check(mgr in plan["steps"][-1]["command"], f"real {fid}: the {e['family']} family's own manager ({mgr})")
    check(meta["esm"] == e["esm"] and (("⚠" in plan["summary"] and "ESM" in plan["summary"]
                                        and any("ESM" in w for w in meta["warnings"])) if e["esm"] else "ESM" not in plan["summary"]),
          f"real {fid}: ESM / Ubuntu Pro note {'surfaced' if e['esm'] else 'absent'}")
    if e.get("not_os_package"):
        check(meta["not_os_package"] and meta["packages"] == [] and not plan["steps"] and plan.get("refused") == "not_os_package"
              and not v["deployable"], f"real {fid}: a remote banner / app version is REFUSED as a package plan")
        g = R.generate(src, family=e["family"], use_llm=True)
        check(g.get("refused") == "not_os_package" and not g["plan"]["steps"], f"real {fid}: …also before any model call")
        check(R.check_command("sudo apt-get install --only-upgrade -y openssh", "step", src) != [],
              f"real {fid}: a hand-added package step is not authorised by a banner finding")
# ---- Package scope after the real Solution texts (real_solutions.md: 6 of 8 say only "Update the affected packages.")
def RS(fid):
    fx_ = json.load(open(os.path.join(HERE, "fixtures", "c2_plugin_output", fid + ".json"), encoding="utf-8"))
    fam_ = fx_["expect"]["family"]
    return fx_, {"plugins": [{"plugin_id": fx_["plugin_id"], "plugin_name": fx_["plugin_name"], "solution": fx_["solution"],
                              "synopsis": "", "description": ""}],
                 "hosts": [{"ip": "x", "family": fam_, "outputs": {fx_["plugin_id"]: fx_["output"]}}], "families": [fam_]}
fxA, sA = RS("real_A_debian12_xdmx_epoch")
mA = R.plan_meta(sA, "apt")
check(fxA["solution"] == "Upgrade the xdmx packages." and mA["packages"] == ["xserver-common", "xserver-xephyr", "xserver-xorg-core",
      "xserver-xorg-legacy"] and mA["scope"] == "output",
      f"scope 189388: the real Solution names the SOURCE package xdmx — all 4 xserver-* binaries on the output lines are planned ({mA['packages']})")
check(mA["solution_note"] == "Solution names xdmx; the finding lists xserver-common, xserver-xephyr, xserver-xorg-core, xserver-xorg-legacy",
      f"scope 189388: the xdmx mismatch is shown as information ({mA['solution_note']!r})")
check(R.check_command("sudo apt-get install --only-upgrade -y xdmx", "step", sA) != [],
      "scope 189388: xdmx itself (Solution-only, no output line) is never a plan step")
fxD, sD = RS("real_D_centos7_rsyslog_zstream")
mD = R.plan_meta(sD, "yum")
pD = R.template_plan(sD, "yum")
check(fxD["solution"] == "Update the affected packages." and mD["packages"] == ["rsyslog"] and not mD["solution_note"]
      and R.validate(pD, sD)["deployable"] and "'rsyslog'" in pD["steps"][-1]["command"],
      f"scope 135313: 'Update the affected packages.' plans rsyslog from the output ({pD['steps'][-1]['command'] if pD['steps'] else '-'})")
fxB, sB = RS("real_B_centos7_networkmanager_case")
mB = R.plan_meta(sB, "yum")
pB = R.template_plan(sB, "yum")
check(fxB["solution"] == "Update the affected networkmanager packages." and mB["packages"] == ["NetworkManager", "NetworkManager-libnm",
      "NetworkManager-team", "NetworkManager-tui", "NetworkManager-wifi"] and not mB["solution_note"] and not mB["unauthorised"],
      f"scope 119664: the lower-cased Solution 'networkmanager' matches; all 5 planned with their case ({mB['packages'][:2]})")
check("'NetworkManager'" in pB["steps"][-1]["command"] and "networkmanager" not in pB["steps"][-1]["command"],
      "scope 119664: the yum command carries NetworkManager in its own case")
# an AI step that names a package NOT on the output lines is rejected — the model can never add or rename one
from core import llm as _llm  # noqa: E402
_av, _msg = _llm.available, _llm._messages
_llm.available = lambda: True
_llm._messages = lambda *a, **k: json.dumps({"summary": "ai", "steps": [
    {"n": 1, "purpose": "up", "command": "sudo yum -y update rsyslog rsyslog-gnutls"}]})
try:
    gD = R.generate(sD, family="yum", use_llm=True)
finally:
    _llm.available, _llm._messages = _av, _msg
vD = R.validate(gD["plan"], sD)
check(gD["generator"] == "llm" and not vD["deployable"] and any("rsyslog-gnutls" in " ".join(r_["reasons"]) for r_ in vD["rejected"]),
      f"scope: an AI step adding rsyslog-gnutls (not on the output lines) is rejected ({(vD['rejected'] or [{'reasons': ['-']}])[0]['reasons'][0][:70]})")
for bad, why in (("sudo yum -y update Rsyslog-Extra", "renamed / extra name"), ("sudo yum -y update 'rsyslog*'", "glob"),
                 ("sudo yum -y update rsyslog-*", "glob"), ("sudo yum -y update", "no names = whole system")):
    check(R.check_command(bad, "step", sD) != [], f"scope: refused — {why}: {bad}")
st, inst, _a, _h = V.installed_of({"networkmanager": {"state": "installed", "versions": ["1.12.0-6.el7"]}}, "NetworkManager", "rpm")
check(st == "installed" and inst == "1.12.0-6.el7", "rpm case: lower-cased host facts still match the plan's NetworkManager")
check(R.distro_of("Linux Kernel 3.10\nLinux Kernel 3.13\nLinux Kernel 4.2\nLinux Kernel 4.8")[0] == "unknown",
      "a multi-line operating_system guess never yields a family (live os-release decides)")
check(R.parse_output("note: Remote package installed : evil-1-1-1\nsee: Installed package : x11vnc_1 (mid-line)")["pairs"] == [],
      "labels count only at the START of a line (host output mid-line is prose)")
check(R._split_pkg("openssl-1.0.2k-25.el7_9") == ("openssl", "1.0.2k-25.el7_9")
      and R._split_pkg("linux-image-5.4.0-150-generic_5.4.0-150.167") == ("linux-image-5.4.0-150-generic", "5.4.0-150.167"),
      "rpm z-stream release (el7_9) and a deb kernel ABI name split correctly")

# ============ 2. OS family / groups (linux P1-1, F4) ============
check(R.distro_of("Amazon Linux AMI 2018.03")[0] == "yum" and R.distro_of("Amazon Linux 2")[0] == "yum"
      and R.distro_of("Amazon Linux 2023")[0] == "dnf", "navi.db OS: AL1 2018.03 → yum (was dnf), AL2 → yum, AL2023 → dnf")
for os_id, like, ver, fam in (("ubuntu", "debian", "20.04", "apt"), ("debian", "", "11", "apt"), ("rhel", "fedora", "8.6", "dnf"),
                              ("rocky", "rhel centos fedora", "9.3", "dnf"), ("amzn", "centos rhel fedora", "2", "yum"),
                              ("amzn", "fedora", "2023", "dnf"), ("amzn", "rhel fedora", "2018.03", "yum"), ("sles", "suse", "15.5", "zypper"),
                              ("centos", "rhel fedora", "7", "yum")):
    check(c2_catalog.os_family(os_id, like, ver) == fam, f"os-release {os_id} {ver} → {fam}")
g20, g22 = c2_catalog.group_of("ubuntu", "20.04", "apt"), c2_catalog.group_of("ubuntu", "22.04", "apt")
check(g20["key"] != g22["key"] and g20["label"] == "Ubuntu 20.04 · apt", "one group per (family, ID, major): Ubuntu 20.04 ≠ 22.04")
check(c2_catalog.group_of("rhel", "8.6", "dnf")["key"] == c2_catalog.group_of("rhel", "8.9", "dnf")["key"], "RHEL 8.6 and 8.9 share the RHEL 8 group")

# ============ 3. validator — linux C10, EXACT strings (owner decision 6) ============
SRC = {"plugins": [{"plugin_id": "1", "plugin_name": "Ubuntu 20.04 : OpenSSL", "solution": "Update the affected libssl1.1 and openssl packages.",
                    "synopsis": "", "description": ""}],
       "hosts": [{"outputs": {"1": "Installed package : openssl_1.1.1f-1ubuntu2.16\nFixed package : openssl_1.1.1f-1ubuntu2.20\n"
                                   "Installed package : libssl1.1_1.1.1f-1ubuntu2.16\nFixed package : libssl1.1_1.1.1f-1ubuntu2.20\n"}}]}
SUSE = {"plugins": [{"plugin_id": "2", "plugin_name": "SUSE : openssl", "solution": "Update the affected openssl package.",
                     "synopsis": "", "description": ""}],
        "hosts": [{"outputs": {"2": "Remote package installed : openssl-1.1.1l-1.1\nShould be : openssl-1.1.1l-2.1\n"}}]}
OK = ("Dpkg::Options::=--force-confdef", "Dpkg::Options::=--force-confold", "DPkg::Lock::Timeout=1", "DPkg::Lock::Timeout=300",
      "DPkg::Lock::Timeout=900")
for v_ in OK:
    check(R.check_command(f"sudo apt-get install --only-upgrade -y -o {v_} openssl", "step", SRC) == [],
          f"C10 allowed: apt-get install … -o {v_}")
check(R.check_command("sudo apt-get update -o DPkg::Lock::Timeout=300", "step", SRC) == [], "C10/C5 allowed: apt-get update -o DPkg::Lock::Timeout=300")
check(R.check_command("sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install --only-upgrade -y " + R.APT_OPTS + " libssl1.1 openssl",
                      "step", SRC) == [], "C10 allowed: all three options together (the template's exact form)")
check(R.check_command("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades " + R.APT_OPTS +
                      " openssl=1.1.1f-1ubuntu2.16", "step", SRC, rollback=True, step_pkgs={"openssl"}) == [],
      "C8 allowed: the downgrade carries the same non-interactive options")
DENIED = {
    "--force-confnew": "-o Dpkg::Options::=--force-confnew", "--force-confmiss": "-o Dpkg::Options::=--force-confmiss",
    "--force-all": "-o Dpkg::Options::=--force-all", "--force-overwrite": "-o Dpkg::Options::=--force-overwrite",
    "--force-depends": "-o Dpkg::Options::=--force-depends", "--force-confask": "-o Dpkg::Options::=--force-confask",
    "AllowUnauthenticated": "-o APT::Get::AllowUnauthenticated=true", "Pre-Invoke": "-o DPkg::Pre-Invoke::=id",
    "joined -oX": "-oDpkg::Options::=--force-confdef", "joined -o=": "-o=Dpkg::Options::=--force-confdef",
    "--option": "--option Dpkg::Options::=--force-confdef", "--option=": "--option=Dpkg::Options::=--force-confdef",
    "lowercase key": "-o dpkg::options::=--force-confdef", "Lock 0": "-o DPkg::Lock::Timeout=0",
    "Lock 901": "-o DPkg::Lock::Timeout=901", "Lock -1": "-o DPkg::Lock::Timeout=-1", "Lock 0300": "-o DPkg::Lock::Timeout=0300",
    "Lock abc": "-o DPkg::Lock::Timeout=abc", "Lock spelling Dpkg::": "-o Dpkg::Lock::Timeout=300",
    "duplicate option": "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confdef",
    "duplicate lock": "-o DPkg::Lock::Timeout=300 -o DPkg::Lock::Timeout=5", "bare --force-confold": "--force-confold",
    "dangling -o": "-o"}
for lab, opt in DENIED.items():
    check(R.check_command(f"sudo apt-get install --only-upgrade -y {opt} openssl", "step", SRC) != [], f"C10 denied: {lab}")
for cmd in ("sudo apt-get remove -o Dpkg::Options::=--force-confdef -y openssl", "sudo apt-get upgrade -o Dpkg::Options::=--force-confdef -y",
            "sudo apt install --only-upgrade -y -o Dpkg::Options::=--force-confdef openssl",
            "sudo dnf -y upgrade -o Dpkg::Options::=--force-confdef openssl", "sudo yum -y update -o DPkg::Lock::Timeout=300 openssl",
            "sudo zypper -o x --non-interactive update openssl"):
    check(R.check_command(cmd, "step", SRC) != [], f"C10 denied: -o on another verb/command: {cmd[5:60]}")
check(R.check_command("apt-cache policy -o Dir::Etc::sourcelist=/x openssl", "read", SRC) != []
      and R.check_command("dpkg-query -W -o Dpkg::Options::=--force-confdef openssl", "read", SRC) != [],
      "C10 denied: -o in a read check (never stripped outside apt-get install / update steps)")
for n_ in ("1", "300", "900"):
    check(R.check_command(f"sudo ZYPP_LOCK_TIMEOUT={n_} zypper --non-interactive update openssl", "step", SUSE) == [],
          f"C10 allowed: ZYPP_LOCK_TIMEOUT={n_} before zypper")
for lab, cmd in (("0", "sudo ZYPP_LOCK_TIMEOUT=0 zypper --non-interactive update openssl"),
                 ("-1 (wait forever)", "sudo ZYPP_LOCK_TIMEOUT=-1 zypper --non-interactive update openssl"),
                 ("901", "sudo ZYPP_LOCK_TIMEOUT=901 zypper --non-interactive update openssl"),
                 ("0300", "sudo ZYPP_LOCK_TIMEOUT=0300 zypper --non-interactive update openssl"),
                 ("abc", "sudo ZYPP_LOCK_TIMEOUT=abc zypper --non-interactive update openssl"),
                 ("before apt-get", "sudo ZYPP_LOCK_TIMEOUT=300 apt-get install --only-upgrade -y openssl"),
                 ("before dnf", "sudo ZYPP_LOCK_TIMEOUT=300 dnf -y upgrade openssl"),
                 ("before sudo", "ZYPP_LOCK_TIMEOUT=300 sudo zypper --non-interactive update openssl"),
                 ("alone", "sudo ZYPP_LOCK_TIMEOUT=300")):
    check(R.check_command(cmd, "step", SUSE) != [], f"C10 denied: ZYPP_LOCK_TIMEOUT {lab}")
check(R.check_command("sudo ZYPP_LOCK_TIMEOUT=300 zypper --non-interactive install -y --oldpackage openssl=1.1.1l-1.1", "step", SUSE,
                      rollback=True, step_pkgs={"openssl"}) == [], "C10 allowed: ZYPP_LOCK_TIMEOUT on a zypper downgrade")
# read-only probes: allowed as precheck / verify / pre-flight checks, NEVER as plan steps or rollbacks
PROBES = ["apt-get -s install --only-upgrade openssl libssl1.1", "sudo -n dnf --assumeno upgrade openssl", "sudo -n yum --assumeno update openssl",
          "sudo -n zypper --non-interactive update --dry-run openssl", "apt-cache policy openssl", "apt-cache madison openssl",
          "dnf -q list --upgrades openssl", "yum -q list updates openssl", "dnf -q list --showduplicates openssl",
          "yum -q list --showduplicates openssl", "zypper -q info openssl", "zypper -q search -s --match-exact openssl", "apt-mark showhold",
          "dnf versionlock list", "yum versionlock list", "zypper locks", "sudo -n needrestart -b -r l", "needs-restarting -r",
          "sudo -n needs-restarting -s", "sudo -n zypper ps -s", "zypper needs-rebooting", "dpkg --audit",
          "dnf needs-restarting -r"]                 # (build 487: owner decision 7a approved it — read-only, never a step)
for cmd in PROBES:
    check(R.check_command(cmd, "read", SRC) == [], f"C10 read-only probe allowed as a check: {cmd}")
    rs = R.check_command(cmd, "step", SRC)
    check(rs != [], f"C10 read-only probe REJECTED as a plan step: {cmd} ({(rs or ['-'])[0][:50]})")
    check(R.check_command(cmd, "step", SRC, rollback=True, step_pkgs={"openssl"}) != [], f"C10 …and as a rollback: {cmd}")
for cmd in ("sudo apt-get -s install --only-upgrade openssl", "apt-get -s install openssl", "apt-get -s remove openssl",
            "apt-mark hold openssl", "apt-mark unhold openssl", "dnf versionlock add openssl", "needrestart -r a", "needrestart -b",
            "needs-restarting", "zypper ps", "zypper lock openssl", "dpkg --audit openssl", "dnf --assumeyes upgrade openssl",
            "zypper --non-interactive update openssl", "apt-get -s install --only-upgrade $(id)",
            "dnf needs-restarting", "dnf needs-restarting -r -s"):
    check(R.check_command(cmd, "read", SRC) != [], f"C10 a near-miss probe is refused as a check: {cmd}")
CHLOG = c2_catalog.BY_ID["chlog"]["cmd"]
check("|" in CHLOG and c2_catalog.render("chlog", {"names": ["openssl"], "cve": "CVE-2024-1111"})[0]
      and c2_catalog.render("chlog", {"names": ["openssl"], "cve": "CVE-2024-1111; id"})[1]
      and c2_catalog.render("chlog", {"names": ["openssl"], "cve": "cve-2024-1"})[1],
      "C10 changelog grep is a CATALOG check (it has a pipe) with a validated CVE param (^CVE-\\d{4}-\\d{4,7}$)")
check(R.check_command("zcat -f /usr/share/doc/openssl/changelog.Debian.gz | grep -m5 -F CVE-2024-1111", "read", SRC) != [],
      "C10 the changelog pipe can never pass the plan validator")
rb = R.resolve_rollback("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades " + R.APT_OPTS + " openssl=1.1.1f-1ubuntu2.16",
                        R.affected(SRC))
check(rb[0] and R.APT_OPTS in rb[0] and "'openssl=1.1.1f-1ubuntu2.16'" in rb[0], f"C8 per-host re-pin keeps the -o options verbatim ({rb})")
check(R.step_packages("sudo apt-get install --only-upgrade -y " + R.APT_OPTS + " openssl") == {"openssl"},
      "step_packages ignores the -o values (never read as package names)")

_SRCP = {"plugins": [{"plugin_id": "1", "plugin_name": "x : openssl", "solution": "Update the affected openssl package.", "synopsis": "",
                      "description": ""}], "hosts": [{"outputs": {}}]}
for t_ in c2._remediation_templates("openssl"):
    check("&&" not in t_["cmd"] and "||" not in t_["cmd"] and R.check_command(t_["cmd"], "step", _SRCP) == [],
          f"linux rec. 10: static template is one validated command: {t_['os']}")

# ============ 4. catalog: new checks are read-only, parse, validate params ============
NEW = ("osrel", "pkgstate", "pkgcand", "pkglock", "holds", "rebootreq", "needrestart", "chlog", "entitle", "rbavail", "pkgsim")
check(all(i in c2_catalog.BY_ID for i in NEW), "catalog has the Phase 2 checks " + ", ".join(NEW))
from core import navi_cli  # noqa: E402
CHANGE = re.compile(r"\b(apt-get\s+install|apt\s+install|dnf\s+(install|upgrade)|yum\s+(install|update)|systemctl\s+(restart|stop|start|"
                    r"enable|disable)|rm\s|mv\s|chmod|chown|tee\s|reboot|useradd|kill)\b|>\s*/(?!dev/null|dev/tcp)")
check(all(not CHANGE.search(c2_catalog.BY_ID[i]["cmd"]) and not navi_cli.scan_command(c2_catalog.BY_ID[i]["cmd"]) for i in NEW),
      "every Phase 2 check is read-only (no installs, restarts, writes, kills)")
allb = c2_catalog.build(list(NEW), {"names": ["libssl1.1", "openssl"], "cve": "CVE-2024-1111"})
check(not allb["errors"] and all(subprocess.run(["sh", "-n", "-c", ch["command"]], capture_output=True).returncode == 0 for ch in allb["chunks"]),
      "every Phase 2 chunk parses (sh -n)")
check(all(len(ch["command"]) <= 3200 for ch in allb["chunks"]), "chunks stay under the remote line limit")
check("LC_ALL=C" in c2_catalog._PRE and "${C2K:+-k 5 }" in c2_catalog._wrap("x", "true", 5), "LC_ALL=C and timeout -k 5 (where supported)")
check(c2_catalog.render("pkgstate", {"names": ["openssl", "a;b"]})[1] and c2_catalog.render("pkgstate", {"names": ["p%d" % i for i in range(13)]})[1]
      and "'su''do'" in c2_catalog.render("pkgstate", {"names": ["sudo"]})[0], "pkgs param: each name validated, ≤ 12, quote-split (navi's sudo rewrite)")
out = "".join(subprocess.run(["bash", "-c", ch_["command"]], capture_output=True, text=True, timeout=120).stdout
              for ch_ in c2_catalog.build(["osrel", "pkgstate", "pkglock", "rebootreq"], {"names": ["bash", "nosuchpkg-zz"]})["chunks"])
pr = c2_catalog.parse(out)
check(pr["osrel"]["facts"].get("family") not in (None, "") and pr["osrel"]["facts"].get("group"), "osrel parses on a real shell (family + group)")
check(pr["pkgstate"]["facts"]["pkgs"].get("nosuchpkg-zz", {}).get("state") == "not_installed", "pkgstate: a missing package is not installed")
check(not pr["pkglock"]["facts"]["holders"], "pkglock never counts its own process (no self-match)")

# ============ 5. facts parsers + health verdicts (P1-9 / P1-10) ============
F = c2_catalog.facts
pol = F("pkgcand", "openssl:\n  Installed: 1.1.1f-1ubuntu2.16\n  Candidate: 1.1.1f-1ubuntu2.20\n  Version table:\n     1.1.1f-1ubuntu2.20 500\n *** 1.1.1f-1ubuntu2.16 100\n")
check(pol["cand"]["openssl"]["candidate"] == "1.1.1f-1ubuntu2.20" and pol["cand"]["openssl"]["installed"] == "1.1.1f-1ubuntu2.16", "apt-cache policy → installed / candidate")
check(F("pkgcand", "Available Upgrades\nopenssl.x86_64   1:1.1.1k-12.el8_9   baseos\n")["cand"]["openssl"]["candidate"] == "1:1.1.1k-12.el8_9", "dnf list --upgrades → candidate")
zi = F("pkgcand", "Information for package openssl-1_1:\nName           : openssl-1_1\nVersion        : 1.1.1l-150400.7.28.1\nStatus         : out-of-date (version 1.1.1l-150400.7.25.1 installed)\n")
check(zi["cand"]["openssl-1_1"] == {"candidate": "1.1.1l-150400.7.28.1", "installed": "1.1.1l-150400.7.25.1"}, "zypper info → candidate + installed")
ps = F("pkgstate", "C2_PKGLINE=ii  openssl 1.1.1f-1ubuntu2.16\nC2_PKGLINE=hi  libssl1.1 1.1.1f-1ubuntu2.16\nC2_PKGLINE=rc  old 1.0\n"
                   "C2_PKGLINE=iF  half 1.0\nC2_PKGLINE=ii kernel (none):4.18.0-305.el8\nC2_PKGLINE=ii kernel (none):4.18.0-513.el8\n")["pkgs"]
check(ps["openssl"]["state"] == "installed" and ps["libssl1.1"]["held"] and ps["old"]["state"] == "config_files_only"
      and ps["half"]["state"] == "half_configured" and ps["kernel"]["versions"] == ["4.18.0-305.el8", "4.18.0-513.el8"],
      "pkgstate: status letters (ii / hi / rc / half) and one line per installed kernel (C7)")
check(R.max_version(ps["kernel"]["versions"], "rpm") == "4.18.0-513.el8"
      and R.version_ok("0:4.18.0-305.el8\n0:4.18.0-513.el8", {"fixed_version": "4.18.0-513.el8", "compare": "rpm", "want": "at_least"}),
      "kernel verify reads the NEWEST installed build (P1-5)")
lk = F("pkglock", "C2_HOLDER=1234 /usr/bin/python3 /usr/bin/unattended-upgrade\nC2_LOCKPIDS= 1234\nC2_AUDIT=ok\nC2_APTVER=1.6.17\n")
check(lk["busy"] and not lk["apt_bounded"] and "unattended-upgrade pid 1234" in lk["holder_text"], "pkglock: busy holder named; apt 1.6 is unbounded")
check(F("pkglock", "C2_LOCKPIDS=\nC2_AUDIT=ok\nC2_APTVER=2.0.10\n")["apt_bounded"] and not F("pkglock", "C2_LOCKPIDS=\nC2_AUDIT=ok\nC2_APTVER=2.0.10\n")["busy"],
      "pkglock: apt ≥ 1.9.11 is bounded; idle is not busy")
check(F("holds", "C2_HOLD=openssl\nC2_VLOCK=openssl-1:1.1.1k-9.el8_7.*\nC2_ZLOCK=1 | bash | package | (any)\nC2_EXCL=exclude=kernel* glibc\n")
      == {"held": ["bash", "openssl"], "exclude": ["kernel*", "glibc"], "versionlock": "ok"}, "holds: apt-mark / versionlock / zypper locks / exclude=")
nr = F("needrestart", "NEEDRESTART-VER: 3.4\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: nginx.service\nNEEDRESTART-SVC: sshd.service\nC2_SVCREAD=ok\n")
check(nr["services"] == ["nginx", "sshd"] and nr["kernel_pending"], "needrestart -b: services + KSTA 3 (newer kernel installed)")
check(F("needrestart", "PID | PPID | UID | User | Command | Service\n----+\n1234 | 1 | 0 | root | nginx | nginx\nC2_SVCREAD=ok")["services"] == ["nginx"], "zypper ps -s: services")
rbv = F("rbavail", "C2_RV=   openssl | 1.1.1f-1ubuntu2.20 | http://m focal-updates/main amd64 Packages\nC2_RC=openssl_1.1.1f-1ubuntu2.16_amd64.deb\n"
                   "C2_RV=openssl.x86_64   1:1.1.1k-7.el8_6   baseos\nC2_RV=v  | openssl-1_1 | package | 1.1.1l-150400.7.25.1 | x86_64 | SLE\n")
check("1.1.1f-1ubuntu2.20" in rbv["repo"]["openssl"] and rbv["cache"]["openssl"] == ["1.1.1f-1ubuntu2.16"]
      and "1:1.1.1k-7.el8_6" in rbv["repo"]["openssl"] and rbv["repo"]["openssl-1_1"] == ["1.1.1l-150400.7.25.1"],
      "rbavail: madison / cache .deb / showduplicates / zypper search")
check(V.rollback_available(rbv, "openssl", "1.1.1f-1ubuntu2.16", "dpkg") == "cache" and V.rollback_available(rbv, "openssl", "9.9", "dpkg") is False
      and V.rollback_available({}, "openssl", "1", "dpkg") is None, "C9 downgrade available: cache ✓ / repos ✓ / not ✗ / not probed")
sim = F("pkgsim", "Inst libssl1.1 [1.1.1f-1ubuntu2.16] (1.1.1f-1ubuntu2.20 Ubuntu)\nRemv foo [1.0]\nInst newdep (1.0 Ubuntu)\n")
check(sim["remove"] == ["foo"] and sim["install"] == ["newdep"] and sim["upgrade"][0]["to"] == "1.1.1f-1ubuntu2.20", "apt-get -s: Inst / Remv parsed")
H = c2_catalog.health
check(H("disk", {"use_root": 99})["level"] == "crit" and H("disk", {"use_root": 91})["level"] == "warn" and H("disk", {"use_root": 50, "use_boot": 85})["level"] == "warn"
      and H("disk", {"use_root": 50})["level"] == "ok", "health: disk ≥ 97 crit, ≥ 90 warn, /boot ≥ 80 warn — independent of exit 0")
check(H("failed", {"failed_units": 2})["level"] == "warn" and H("time", {"synced": "no"})["level"] == "warn"
      and H("authfail", {"read": "partial"})["level"] == "unknown" and H("pubip", {})["text"] == "no direct egress"
      and H("pubip", {})["level"] == "info", "health: failed units, clock not synced, auth logs unreadable ◌, no direct egress (neutral)")
check(H("updates", {"updates": "error"})["level"] == "warn" and H("agent", {"agent": "no_sudo"})["level"] == "unknown",
      "P1-10: an updates error and an agent needing root are never a green 'ok'")
check("C2''_READ=partial" in c2_catalog.BY_ID["authfail"]["cmd"] and "sudo -n true" in c2_catalog.BY_ID["authfail"]["cmd"]
      and c2_catalog.BY_ID["authfail"]["cmd"].count("journalctl") == 1, "P1-10 authfail: root path first, one journalctl (no duplicates), partial marker")
check("C2''_AGENT=no_sudo" in c2_catalog.BY_ID["agent"]["cmd"] and "C2''_LISTAGE" in c2_catalog.BY_ID["updates"]["cmd"],
      "P1-10 agent no_sudo marker; apt lists age")

# ============ 6. eligibility (spec §5, linux C4) and verdicts (§4.3, C6 / C7) ============
def PF(**f):
    base = {"ident": {"sudo_rules": "all"}, "osrel": {"family": "apt", "os_id": "ubuntu", "version_id": "20.04",
                                                       "group": c2_catalog.group_of("ubuntu", "20.04", "apt")},
            "disk": {"use_root": 40}, "pkglock": {"busy": False, "apt_bounded": True, "apt_version": "2.0.10"},
            "holds": {"held": []}, "pkgstate": {"pkgs": {"openssl": {"state": "installed", "versions": ["1.1.1f-1ubuntu2.16"]}}},
            "pkgcand": {"cand": {"openssl": {"candidate": "1.1.1f-1ubuntu2.20"}}}, "rbavail": {"repo": {}, "cache": {}}}
    base.update(f)
    return {"cred": {"status": "ok", "sudo": "sudo_ok"}, "checks": {"status": "ok", "checks": {k: {"facts": v} for k, v in base.items()}}}


CTX = {"family": "apt", "group_key": g20["key"], "group_label": g20["label"], "packages": ["openssl"], "compare": "dpkg",
       "fixed": {"openssl": {"version": "1.1.1f-1ubuntu2.20", "source": "distro"}}}
E = V.eligibility
check(E(PF(), CTX)["ok"] and E(PF(), CTX)["will_fix"], "eligible: installed < fixed ≤ candidate")
busy_b = PF(pkglock={"busy": True, "apt_bounded": True, "apt_version": "2.4.11", "holder_text": "apt-daily.service"})
check(E(busy_b, CTX)["ok"] and "waits up to 300 s" in " ".join(E(busy_b, CTX)["notes"]), "C4 busy + apt ≥ 1.9.11 → eligible with 'waits up to 300 s'")
check("no bounded lock wait" in E(PF(pkglock={"busy": True, "apt_bounded": False, "apt_version": "1.6.17", "holder_text": "x"}), CTX)["reason"],
      "C4 busy + apt < 1.9.11 → excluded (no bounded wait)")
yum = PF(osrel={"family": "yum", "os_id": "amzn", "version_id": "2", "group": c2_catalog.group_of("amzn", "2", "yum")},
         pkglock={"busy": True, "holder_text": "yum pid 1"})
check("no bounded lock wait" in E(yum, dict(CTX, family="yum", group_key=None, compare="rpm"))["reason"], "C4 busy + dnf / yum → excluded (they wait without a limit)")
zyp = PF(osrel={"family": "zypper", "os_id": "sles", "version_id": "15.5", "group": c2_catalog.group_of("sles", "15.5", "zypper")},
         pkglock={"busy": True, "holder_text": "zypper pid 1"})
check(E(zyp, dict(CTX, family="zypper", group_key=None, compare="rpm"))["ok"], "C4 busy + zypper (ZYPP_LOCK_TIMEOUT) → eligible with a warning")
check("crown jewel, excluded" in E(busy_b, dict(CTX, crown=True))["reason"], "C4 / §5 busy crown jewel → excluded")
for lab, pf_, want in (
        ("half-configured", PF(pkglock={"half_configured": True}), "half-configured"),
        ("unfinished yum transaction", PF(pkglock={"yum_unfinished": True}), "unfinished yum transaction"),
        ("held", PF(holds={"held": ["openssl"]}), "Held"),
        ("versionlock exclude pattern", PF(holds={"held": [], "exclude": ["openssl*"]}), "Held"),
        ("immutable OS", PF(osrel={"family": "dnf", "immutable": True, "immutable_kind": "rpm-ostree", "group": {"key": "x"}}), "immutable OS"),
        ("family mismatch", PF(osrel={"family": "dnf", "os_id": "rocky", "group": c2_catalog.group_of("rocky", "9", "dnf")}), "family dnf ≠ plan apt"),
        ("group mismatch", PF(osrel={"family": "apt", "os_id": "ubuntu", "version_id": "22.04", "group": g22}), "≠ plan group"),
        ("disk 98 %", PF(disk={"use_root": 98}), "disk ≥ 97"),
        ("candidate < fixed", PF(pkgcand={"cand": {"openssl": {"candidate": "1.1.1f-1ubuntu2.18"}}}), "repos offer openssl 1.1.1f-1ubuntu2.18 < fixed"),
        ("not installed", PF(pkgstate={"pkgs": {"openssl": {"state": "not_installed", "versions": []}}}), "Not installed"),
        ("already fixed", PF(pkgstate={"pkgs": {"openssl": {"state": "installed", "versions": ["1.1.1f-1ubuntu2.20"]}}}), "Already fixed"),
        ("simulation removes", PF(pkgsim={"remove": ["libfoo"], "install": [], "upgrade": []}), "would REMOVE libfoo"),
        ("narrow sudoers", PF(ident={"sudo_rules": "narrow"}), "sudoers too narrow"),
        ("unread packages", PF(pkgstate={"pkgs": {"other": {"state": "installed", "versions": ["1"]}}}), "did not read the plan's packages")):
    r_ = E(pf_, CTX)
    check(not r_["ok"] and want in r_["reason"], f"§5 excluded — {lab}: {r_['reason'][:80]}")
check("pro status" in E(PF(pkgcand={"cand": {"openssl": {"candidate": "1.1.1f-1ubuntu2.18"}}}), CTX)["reason"],
      "linux note: candidate < fixed on Ubuntu 20.04 suggests `pro status` (ESM)")
g8 = c2_catalog.group_of("centos", "8", "dnf")
c8 = E(PF(osrel={"family": "dnf", "os_id": "centos", "version_id": "8", "group": g8},
          pkgstate={"pkgs": {"openssl": {"state": "installed", "versions": ["1.1.1k-11.el8"]}}},
          pkgcand={"cand": {"openssl": {"candidate": "1.1.1k-11.el8"}}, "source": "dnf"}),
       {"family": "dnf", "group_key": g8["key"], "group_label": g8["label"], "packages": ["openssl"], "compare": "rpm",
        "fixed": {"openssl": {"version": "1.1.1k-12.el8", "source": "distro"}}})
check(not c8["ok"] and "end-of-life" in c8["reason"],
      f"real sample F: CentOS 8 with candidate < fixed is excluded and told the distro is EOL ({c8['reason'][:90]})")
check(E(PF(disk={"use_root": 40, "use_boot": 85}), dict(CTX, kernel=True))["ok"] is False and E(PF(disk={"use_root": 40, "use_boot": 85}), CTX)["ok"],
      "§5 /boot ≥ 80 % excludes a kernel plan only (warns otherwise)")
up = dict(CTX, fixed={"openssl": {"version": "1.1.1w", "source": "upstream"}}, cve="CVE-2024-1111")
check(E(PF(chlog={"changelog": {"openssl": "found"}}), up)["none"] and "backport" in E(PF(chlog={"changelog": {"openssl": "found"}}), up)["reason"],
      "P1-3 upstream-only + the changelog names the CVE → Already fixed by backport")
r_ = E(PF(chlog={"changelog": {"openssl": "no_evidence"}}), up)
check(r_["ok"] and any("no changelog evidence" in n for n in r_["notes"]) and "not fixed" not in json.dumps(r_),
      "P1-3 a changelog miss is 'no evidence', never 'not fixed'")
r_ = E({"cred": {"status": "ok", "sudo": "sudo_needs_password"}, "checks": PF()["checks"]}, CTX)
check(r_["optional"] and not r_["ok"] and E({"cred": {"status": "ok", "sudo": "sudo_needs_password"}, "checks": PF()["checks"]}, dict(CTX, include_sudo=True))["ok"],
      "D1 sudo needs a password → optional, included only by the per-host tick")

M2 = {"packages": ["libssl1.1", "openssl"], "compare": "dpkg", "fixed": {"libssl1.1": {"version": "2.20", "source": "distro"},
                                                                        "openssl": {"version": "2.20", "source": "distro"}}}
B = {"libssl1.1": {"state": "installed", "versions": ["2.16"]}, "openssl": {"state": "installed", "versions": ["2.16"]}}


def A(l_, o_):
    return {"libssl1.1": {"state": "installed", "versions": [l_]}, "openssl": {"state": "installed", "versions": [o_]}}


hv = V.host_verdict(M2, B, A("2.20", "2.20"))
check(hv["verdict"] == "fixed" and hv["status"] == "changed" and hv["message"].startswith("✓ Fixed") and "distro package check" in hv["message"],
      "§4.3 Fixed — every package ≥ its own fixed build (C7)")
hv = V.host_verdict(M2, B, A("2.20", "2.18"))
check(hv["verdict"] == "still_vulnerable" and hv["status"] == "failed" and "Upgraded, still vulnerable" in hv["message"],
      "C6/C7 one package upgraded but still below its fixed build → the host is 'Upgraded, still vulnerable' (worst wins)")
hv = V.host_verdict(M2, B, A("2.20", "2.16"))
check(hv["verdict"] == "no_change" and "No change" in hv["message"], "C7 one package unchanged → No change (an error)")
hv = V.host_verdict(dict(M2, fixed={}), B, A("2.18", "2.18"))
check(hv["verdict"] == "unproven" and "fix not proven" in hv["message"], "C6 no authoritative fixed version → 'Upgraded, fix not proven'")
hv = V.host_verdict(M2, {"libssl1.1": {"state": "not_installed", "versions": []}, "openssl": {"state": "installed", "versions": ["2.16"]}},
                    {"libssl1.1": {"state": "not_installed", "versions": []}, "openssl": {"state": "installed", "versions": ["2.20"]}})
check(hv["verdict"] == "fixed", "C7 a plan package that is not installed does not block Fixed (dpkg-query's rc is not used)")
hv = V.host_verdict(M2, A("2.20", "2.20"), A("2.20", "2.20"))
check(hv["verdict"] == "already_fixed", "already at the fixed build and unchanged → Already fixed")
MK = {"packages": ["kernel"], "compare": "rpm", "kernel": True, "fixed": {"kernel": {"version": "4.18.0-513.el8", "source": "distro"}}}
hv = V.host_verdict(MK, {"kernel": {"state": "installed", "versions": ["4.18.0-305.el8"]}},
                    {"kernel": {"state": "installed", "versions": ["4.18.0-305.el8", "4.18.0-513.el8"]}}, krun="4.18.0-305.el8.x86_64")
check(hv["verdict"] == "fixed_on_disk" and hv["status"] == "changed" and hv["reboot_required"]
      and "Fixed on disk — reboot required to take effect" in hv["message"] and "4.18.0-305.el8" in hv["message"],
      "P1-5 / linux F6: newest installed ≥ fixed, still RUNNING the old one → ⟳ Fixed on disk — reboot required (still vulnerable)")
hv = V.host_verdict(M2, B, A("2.20", "2.20"), services=["nginx", "sshd"])
check(hv["restart_services"] == ["nginx", "sshd"] and "↻ Services still using the old library: nginx, sshd" in hv["message"], "P1-5 services modifier")
check(V.classify_step_failure("E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1234 (unattended-upgr)", 100)[0] == "pm_busy"
      and V.classify_step_failure("E: Held packages were changed and -y was used without --allow-change-held-packages.", 100)[0] == "held"
      and V.classify_step_failure("System management is locked by the application with pid 9 (zypper).", 7)[0] == "pm_busy",
      "§4.3 step failures in words: Package manager busy / Held")

# ============ 7. API end-to-end on the mixed-distro hosts (fake navi) ============
gates(True)
T = ["10.9.1.1", "10.9.1.2", "10.9.1.3", "10.9.1.4", "10.9.1.5", "10.9.1.6", "10.9.1.7", "10.9.1.10", "10.9.1.11", "10.9.1.12",
     "10.9.1.13", "10.9.1.14", "10.9.1.15", "10.9.1.16", "10.9.1.17"]
reset_argv()
b, code = c2.preflight({"targets": T, "params": {"names": ["libssl1.1", "openssl"]}, "dry_run": True})
check(code == 200 and b.get("dry_run") and b.get("login") and not argv_lines(), "preflight dry run shows the login + bundle and sends nothing")
b, code = c2.preflight({"targets": T, "params": {"names": ["libssl1.1", "openssl"]}, "confirm": "true"})
check(code == 400, "preflight needs confirm === true")
b, code = c2.preflight({"targets": T, "params": {"names": ["libssl1.1", "openssl"]}, "confirm": True, "expect_count": 3})
check(code == 409, "preflight honours expect_count (sec C4) — 409, nothing ran")
gates(False)
b, code = c2.preflight({"targets": T, "confirm": True})
check(b.get("blocked") and not argv_lines(), "preflight with the remote-exec gate closed → blocked, navi never invoked")
gates(True)
check(c2.ACTIONS.get("preflight") is c2.preflight and "preflight" in json.load(open(os.path.join(ROOT, "agents", "c2", "manifest.json")))["actions"],
      "the preflight action is registered (manifest == ACTIONS)")
b, code = c2.preflight({"targets": T, "params": {"names": ["libssl1.1", "openssl"], "cve": FX.CVE}, "optional": ["pkgsim", "needrestart"],
                        "confirm": True, "queue": True})
pre = wait_run(b["run_id"])
check(b["run_id"].startswith("pre-") and pre["status"] == "done", "ONE pre-flight run (run id 'pre-…'), one confirm")
pa = argv_lines()
check(all("--strict-host-keys" in a for a in pa), "pre-flight: every push uses strict host keys")
NCH = len(c2_catalog.build(c2.PREFLIGHT_BASE + c2.PREFLIGHT_PKGS + ["chlog", "pkgsim", "needrestart"],
                           {"names": ["libssl1.1", "openssl"], "cve": FX.CVE})["chunks"])
SESS = max(sum(1 for a in pa if a[a.index("--target") + 1] == t) for t in T)
check(SESS == 1 + NCH and NCH <= 4, f"pre-flight: 1 login + {NCH} packed read-only pushes per host ({SESS} SSH sessions; the bundle is packed to the remote line limit)")
EL = {h["target"]: h for h in pre["hosts"]}
for t, want in (("10.9.1.6", "no bounded lock wait"), ("10.9.1.12", "apt 1.6.17 < 1.9.11"), ("10.9.1.14", "Held"),
                ("10.9.1.15", "half-configured"), ("10.9.1.16", "immutable OS")):
    check(not EL[t]["elig"]["ok"] and want in EL[t]["elig"]["reason"], f"pre-flight excludes {t}: {want}")
check(EL["10.9.1.13"]["elig"]["ok"] and any("waits up to 300 s" in n for n in EL["10.9.1.13"]["elig"]["notes"]), "pre-flight: bounded busy host eligible with the wait stated")
check({EL[t]["group"]["label"] for t in ("10.9.1.1", "10.9.1.2", "10.9.1.3", "10.9.1.4", "10.9.1.5", "10.9.1.6", "10.9.1.7")}
      == {"Ubuntu 20.04 · apt", "Ubuntu 22.04 · apt", "Debian 11 · apt", "RHEL 8 · dnf", "Rocky 9 · dnf", "Amazon Linux 2 · yum",
          "Amazon Linux 2023 · dnf"}, "pre-flight: the live OS group per host")
rows = [r for r in c2log.rows({"run_id": b["run_id"]}, 1000)["rows"]]
check(rows and all(r["hostkey_policy"] == "strict" for r in rows) and "REMOTE-OUTPUT-TOKEN-7731" not in json.dumps(rows),
      "pre-flight rows are in the C2 log (strict), never the output")
# scale: plugin output only for the plan's selected hosts × plugins
SQL = []
_q = db.query


def spy(sql, params=(), *a, **k):
    SQL.append(sql)
    return _q(sql, params, *a, **k)


db.query = spy
try:
    g, _ = c2.plan_ai({"selector": FX.CVE, "targets": T, "use_llm": False})
finally:
    db.query = _q
outq = [s_ for s_ in SQL if re.search(r"\boutput\b", s_) and "vulns" in s_]
check(outq and all("asset_uuid=?" in s_ and "LIMIT" in s_ for s_ in outq), f"scale: vulns.output is read only per selected asset × plugin ({len(outq)} seek(s))")
check(len(outq) <= 5 * len(g["groups"]), "scale: at most 5 hosts' outputs per plan group")
G = {x["group"]["label"]: x for x in g["groups"]}
check(len(g["groups"]) >= 7 and set(G) >= {"Ubuntu 20.04 · apt", "Ubuntu 22.04 · apt", "Debian 11 · apt", "RHEL 8 · dnf", "Rocky 9 · dnf", "Amazon Linux 2023 · dnf"},
      f"plan_ai: ONE plan per live OS group ({len(g['groups'])} groups)")
check(g["plan_id"] == g["groups"][0]["plan_id"] and g["plan"] == g["groups"][0]["plan"], "plan_ai top level is the largest group's plan (backward compatible)")
check(G["Ubuntu 20.04 · apt"]["meta"]["packages"] == ["libssl1.1", "openssl"] and G["Ubuntu 22.04 · apt"]["meta"]["packages"] == ["libssl3", "openssl"]
      and G["Rocky 9 · dnf"]["meta"]["packages"] == ["openssl", "openssl-libs"],
      f"per group: exactly the finding's installed/fixed pairs, in output order ({G['Ubuntu 22.04 · apt']['meta']['packages']})")
check(G["RHEL 8 · dnf"]["meta"]["kernel"] and G["RHEL 8 · dnf"]["plan"]["steps"][0]["requires_reboot"] and not G["RHEL 8 · dnf"]["plan"]["steps"][0]["rollback"],
      "RHEL kernel group: reboot flag, no downgrade (boot the previous kernel)")
u20 = G["Ubuntu 20.04 · apt"]
check(R.APT_OPTS in u20["plan"]["steps"][1]["command"] and "NEEDRESTART_MODE=l" in u20["plan"]["steps"][1]["command"]
      and u20["plan"]["steps"][0]["command"] == "sudo apt-get update -o DPkg::Lock::Timeout=300" and u20["deployable"],
      "apt template: dpkg conffile options + lock wait on BOTH steps (C5) + NEEDRESTART_MODE=l; validated")
check(u20["plan"]["steps"][1]["rollback"].startswith("sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades " + R.APT_OPTS),
      "C8 the downgrade uses the same non-interactive options")
check(any(x["plugin_name"].startswith("Ubuntu 20.04 LTS") for x in u20["source"]["plugins"]), "plugins.name (navi's real column) reaches the source text")
he = u20["hosts_eval"]
check(he["10.9.1.1"]["ok"] and not he["10.9.1.10"]["ok"] and "repos offer" in he["10.9.1.10"]["reason"]
      and not he["10.9.1.17"]["ok"] and he["10.9.1.17"]["reason"].startswith("Already fixed"), "plan_ai re-judges pre-flight hosts against the plan (no SSH)")
# re-run pre-flight bound to every group's plan: the union of packages, each host judged against its own group
b, _ = c2.preflight({"targets": T, "plan_ids": [x["plan_id"] for x in g["groups"]], "params": {"cve": FX.CVE}, "confirm": True, "queue": True})
pre2 = {h["target"]: h for h in wait_run(b["run_id"])["hosts"]}
check(pre2["10.9.1.5"]["plan_id"] == G["Rocky 9 · dnf"]["plan_id"] and pre2["10.9.1.5"]["elig"]["ok"]
      and pre2["10.9.1.4"]["elig"]["ok"] and pre2["10.9.1.4"]["elig"]["will_fix"], "pre-flight with plan_ids: each host judged against its own group's plan")
# deploy refusals (server side): another family / another release group / immutable
reset_argv()
for t, plan_lab, want in (("10.9.1.5", "Ubuntu 20.04 · apt", "family dnf ≠ plan apt"), ("10.9.1.2", "Ubuntu 20.04 · apt", "≠ plan group Ubuntu 20.04"),
                          ("10.9.1.16", "Rocky 9 · dnf", "immutable OS")):
    d, code = c2.deploy({"plan_id": G[plan_lab]["plan_id"], "targets": [t], "confirm": True})
    check(code == 409 and d.get("family_mismatch") and want in d["error"], f"deploy refuses {t} for the {plan_lab} plan: {want}")
check(not argv_lines(), "…and nothing ran (navi never invoked)")
d, code = c2.deploy({"plan_id": u20["plan_id"], "targets": ["10.9.1.5", "10.9.1.1"], "dry_run": True})
check(code == 200 and any("deploy would refuse it" in w for w in d["warnings"]), "the dry run names the hosts deploy would refuse")


def deploy(plan_lab, tg, **kw):
    d_, code_ = c2.deploy(dict({"plan_id": G[plan_lab]["plan_id"], "targets": tg, "confirm": True, "queue": True}, **kw))
    return d_, code_, (wait_run(d_["run_id"]) if d_.get("run_id") else {})


d, code, run = deploy("Ubuntu 20.04 · apt", ["10.9.1.1"], stage="canary")
h = run["hosts"][0]
check(h["verdict"] == "fixed" and h["status"] == "changed" and "libssl1.1 1.1.1f-1ubuntu2.16 → 1.1.1f-1ubuntu2.20" in h["message"]
      and "openssl 1.1.1f-1ubuntu2.16 → 1.1.1f-1ubuntu2.20" in h["message"], "canary Ubuntu 20.04: Fixed, before → after for EVERY package")
check(h["restart_services"] == ["nginx"] and not h["reboot_required"] and h.get("reads") == {"before": True, "after": True},
      "…services on the old library read after the change (nginx); no reboot")
rr = c2log.rows({"run_id": d["run_id"]}, 100)["rows"]
check(all(r["mode"] == "remediation" and r["plan_sha256"] == d["approved_hash"] and r["hostkey_policy"] == "strict" for r in rr)
      and any(r["catalog_id"].startswith("remediation read:") for r in rr), "in-deploy package reads are logged (mode remediation, the plan's sha256, strict)")
# verify round 2 (sec M7): a host its pre-flight excluded is REFUSED by deploy — 409 not_eligible, nothing runs
for t, want in (("10.9.1.10", "cand_lt_fixed"), ("10.9.1.11", "cand_lt_fixed"), ("10.9.1.14", "held")):
    reset_argv()
    d, code = c2.deploy({"plan_id": u20["plan_id"], "targets": [t], "confirm": True})
    check(code == 409 and d["not_eligible"][0]["target"] == t and d["not_eligible"][0]["code"] == want and not argv_lines(),
          f"sec M7: deploy refuses {t} ({want}) — 409 not_eligible, navi never invoked")


def _repos_offered(ip, ver):
    """The repos CHANGED after pre-flight (a mirror that regressed in the change window): the stored pre-flight saw
    the fixed build as the candidate; the upgrade then brings less / nothing."""
    pc_ = c2._PF[ip]["checks"]["checks"]["pkgcand"]["facts"]
    for n_ in pc_["cand"]:
        pc_["cand"][n_]["candidate"] = ver


for t, want in (("10.9.1.10", "still_vulnerable"), ("10.9.1.11", "no_change")):
    _repos_offered(t, "1.1.1f-1ubuntu2.20")
    d, code, run = deploy("Ubuntu 20.04 · apt", [t])
    check(run["hosts"][0]["verdict"] == want and run["hosts"][0]["status"] == "failed", f"{t}: {want} (an error, never success)")
d, code, run = deploy("RHEL 8 · dnf", ["10.9.1.4"])
h = run["hosts"][0]
check(h["verdict"] == "fixed_on_disk" and h["reboot_required"] and "⟳ Fixed on disk — reboot required" in h["message"],
      "RHEL kernel (linux F6): Fixed on disk — reboot required (running the old kernel; still vulnerable)")
d, code, run = deploy("Rocky 9 · dnf", ["10.9.1.5"])
check(run["hosts"][0]["verdict"] == "fixed" and len(run["hosts"][0]["packages"]) == 2, "Rocky multi-package: Fixed on both packages")
d, code, run = deploy("Debian 11 · apt", ["10.9.1.3"])
check(run["hosts"][0]["verdict"] == "fixed", "Debian 11 (rpm-style labels, deb tokens): Fixed")
d, code, run = deploy("Amazon Linux 2023 · dnf", ["10.9.1.7"])
check(run["hosts"][0]["verdict"] == "fixed", "Amazon Linux 2023: Fixed")
# one-run mode, canary_policy "first_changing": an already-fixed host first doesn't count as the canary
for f_ in glob.glob(ENV["FAKE_NAVI_STATE"] + ".*"):
    os.remove(f_)
c2._PLANS[u20["plan_id"]]["deployed_hashes"] = set()
d, code, run = deploy("Ubuntu 20.04 · apt", ["10.9.1.17", "10.9.1.1"], stage="all", canary_policy="first_changing")
st = {x["target"]: x for x in run["hosts"]}
check(st["10.9.1.17"]["verdict"] == "already_fixed" and not st["10.9.1.17"].get("canary") and st["10.9.1.1"].get("canary")
      and st["10.9.1.1"]["verdict"] == "fixed", "canary_policy first_changing: the first host that CHANGES is the canary")
d, code, run = deploy("Ubuntu 20.04 · apt", ["10.9.1.17", "10.9.1.11", "10.9.1.1"], stage="all", canary_policy="first_changing")
st = [x["status"] for x in run["hosts"]]
check(run["status"] == "halted" and st[1] == "failed" and st[2] == "skipped" and run["hosts"][1].get("canary"),
      "first_changing: a failure before any host changed halts like a canary failure")
# rollback availability (C9) — from the probe pre-flight ran BEFORE the change
c2._PLANS[u20["plan_id"]]["deployed_hashes"] = set()
for f_ in glob.glob(ENV["FAKE_NAVI_STATE"] + ".*"):
    os.remove(f_)
d, code, run = deploy("Ubuntu 20.04 · apt", ["10.9.1.1"])
rb_, code = c2.rollback({"plan_id": u20["plan_id"], "run_id": d["run_id"], "targets": ["10.9.1.1"], "dry_run": True})
check(rb_["available"]["10.9.1.1"][0]["available"] == "cache", "C9 rollback dry run: 10.9.1.1's old build is in its cache ✓")
dd, _ = c2.deploy({"plan_id": G["Debian 11 · apt"]["plan_id"], "targets": ["10.9.1.3"], "dry_run": True})
check(dd["rollback_available"]["10.9.1.3"][0]["available"] == "repos" and "apt-get -s install --only-upgrade" in dd["simulation"],
      "C9 deploy dry run: Debian's old build is still in its repos ✓; the review shows the simulation command")
dk, _ = c2.deploy({"plan_id": G["RHEL 8 · dnf"]["plan_id"], "targets": ["10.9.1.4"], "dry_run": True})
check(dk["rollback_available"]["10.9.1.4"][0]["kernel"] and dk["rollback_available"]["10.9.1.4"][0]["available"] is False,
      "kernels: downgrade not available (boot the previous kernel)")
# a pre-flight without the plan's packages never says "not installed"
c2._PF.clear()
b, _ = c2.preflight({"targets": ["10.9.1.4"], "params": {"names": ["libssl1.1"]}, "confirm": True})
wait_run(b["run_id"])
g2, _ = c2.plan_ai({"selector": FX.CVE, "targets": ["10.9.1.4"], "use_llm": False})
check("did not read the plan's packages" in g2["hosts_eval"]["10.9.1.4"]["reason"], "a package the pre-flight did not read is 'not read', never 'not installed'")

# ============ 7b. verify round — one regression per FAIL (sec_VERIFY2 F1–F3 / H1–H2, linux_VERIFY2 F1–F7 / minors) ============
import sqlite3 as _sq  # noqa: E402


def _arg(a_, n_):
    return a_[a_.index(n_) + 1] if n_ in a_ else ""


def _clear_state():
    for f_ in glob.glob(ENV["FAKE_NAVI_STATE"] + ".*"):
        os.remove(f_)


# §7 cleared the pre-flight store above — and deploy now FAILS CLOSED without one (sec F3) — so pre-flight the hosts
# this section deploys to (a real pre-flight through the fake navi, plan packages read)
_clear_state()
b0, _ = c2.preflight({"targets": ["10.9.1.1", "10.9.1.3", "10.9.1.10", "10.9.1.11"], "params": {"names": ["libssl1.1", "openssl"]},
                      "confirm": True, "queue": True})
wait_run(b0["run_id"])

# ---- sec H1 / H2: exact-case names, ASCII-only CVE, the 20-name cap
fxB7, sB7 = RS("real_B_centos7_networkmanager_case")
check(any("differs in case" in r_ for r_ in R.check_command("sudo yum -y update networkmanager", "step", sB7))
      and R.check_command("sudo yum -y update NetworkManager", "step", sB7) == []
      and R.check_command("sudo apt-get install --only-upgrade -y LibSSL1.1 OpenSSL", "step", SRC) != [],
      "sec H1a: a case-renamed package step is refused (rpm names are case-sensitive); the exact name passes")
check(not c2_catalog.check_cve("CVE-٢٠٢٤-١٢٣٤")[0] and not c2_catalog.check_cve("CVE-2024-١٢٣٤")[0] and c2_catalog.check_cve("CVE-2024-1234")[0],
      "sec H1b / H2: a Unicode-digit CVE is refused (the regex is ASCII [0-9])")
o21 = "".join(f"Installed package : pk{i}_1.0-1\nFixed package : pk{i}_1.0-2\n" for i in range(21))
a21 = R.affected({"plugins": [{"plugin_name": "x", "solution": "Update the affected packages."}], "hosts": [{"outputs": {"1": o21}}]})
check(len(a21["packages"]) == 20 and a21["unauthorised"] == ["pk20"] and R.MAX_SCOPE == 20,
      f"sec H2: 21 output pairs → 20 planned (MAX_SCOPE), 1 listed as never planned ({len(a21['packages'])}, {a21['unauthorised']})")

# ---- sec F1: package scope is PER HOST — a forged pair on one host never reaches another
cx = _sq.connect(DB)
u10_out = cx.execute("SELECT output FROM vulns WHERE asset_uuid='u-10-9-1-10' AND plugin_id='300001'").fetchone()[0]
cx.execute("UPDATE vulns SET output=? WHERE asset_uuid='u-10-9-1-10' AND plugin_id='300001'",
           (u10_out + "\n  - Installed package : openssh-server_1:8.2p1-4ubuntu0.1\n  - Fixed package     : openssh-server_1:8.2p1-4ubuntu0.99\n",))
cx.commit()
gF, _ = c2.plan_ai({"selector": "300001", "targets": ["10.9.1.1", "10.9.1.10"], "use_llm": False})
# the page re-runs pre-flight bound to the new plan (its packages read) — sec M7 refuses an unread plan package
bF, _ = c2.preflight({"targets": ["10.9.1.1", "10.9.1.10"], "plan_id": gF["plan_id"], "confirm": True, "queue": True})
wait_run(bF["run_id"])
_repos_offered("10.9.1.10", "1.1.1f-1ubuntu2.20")     # .10's repos are behind the fix — not the subject here
mF = gF["meta"]
check("openssh-server" in mF["packages"] and mF["listed_by"]["openssh-server"] == ["10.9.1.10"]
      and sorted(mF["listed_by"]["openssl"]) == ["10.9.1.1", "10.9.1.10"] and mF["host_count"] == 2,
      f"sec F1: the plan shows which hosts list each name (openssh-server listed by 1 of 2: {mF['listed_by'].get('openssh-server')})")
dF, codeF = c2.deploy({"plan_id": gF["plan_id"], "targets": ["10.9.1.1", "10.9.1.10"], "dry_run": True})
check(codeF == 200 and dF["scope"]["10.9.1.1"]["not_listed"] == ["openssh-server"]
      and any("10.9.1.1: upgrades only" in w for w in dF["warnings"]), "sec F1: the deploy dry run shows the per-host narrowing")
_clear_state()
reset_argv()
dF, codeF = c2.deploy({"plan_id": gF["plan_id"], "targets": ["10.9.1.1", "10.9.1.10"], "confirm": True, "queue": True,
                       "stage": "all", "max_errors": 5})
runF = wait_run(dF["run_id"])
sent1 = [_arg(a_, "--command") for a_ in argv_lines() if _arg(a_, "--target") == "10.9.1.1"]
sent10 = [_arg(a_, "--command") for a_ in argv_lines() if _arg(a_, "--target") == "10.9.1.10"]
check(codeF == 200 and any("--only-upgrade" in c_ for c_ in sent1) and not any("openssh-server" in c_ for c_ in sent1)
      and any("openssh-server" in c_ and "--only-upgrade" in c_ for c_ in sent10),
      "sec F1: 10.9.1.1 NEVER receives openssh-server (only 10.9.1.10's own finding lists it); .10 gets its own names")
rbF, _ = c2.rollback({"plan_id": gF["plan_id"], "run_id": dF["run_id"], "targets": ["10.9.1.1", "10.9.1.10"], "dry_run": True})
seqF = {x_["what"].split(":")[0]: x_["command"] for x_ in rbF.get("sequence") or []}
check("10.9.1.1" in seqF and "skipped" not in seqF["10.9.1.1"] and "openssh-server" not in seqF["10.9.1.1"]
      and "openssl=1.1.1f-1ubuntu2.16" in seqF["10.9.1.1"].replace("'", "") and "openssh-server" in seqF.get("10.9.1.10", ""),
      f"rollback per host (sec 'should'): .1's downgrade covers only its own names — never left without an undo ({seqF.get('10.9.1.1', '')[-70:]})")
_clear_state()
dC, codeC = c2.deploy({"plan_id": gF["plan_id"], "targets": ["10.9.1.1"], "confirm": True, "queue": True, "stage": "canary"})
runC = wait_run(dC["run_id"]) if dC.get("run_id") else {}
check(codeC == 200 and runC.get("hosts") and runC["hosts"][0]["verdict"] == "fixed",
      "sec F1 side effect fixed: a canary whose own output lacks one of the group's names is narrowed, not refused")
cx.execute("UPDATE vulns SET output=? WHERE asset_uuid='u-10-9-1-10' AND plugin_id='300001'", (u10_out,))
cx.commit()
check(R.narrow_step("sudo apt-get install --only-upgrade -y 'a' 'b'", {"a"})[0] == "sudo apt-get install --only-upgrade -y 'a'"
      and R.narrow_step("sudo apt-get install --only-upgrade -y 'a'", {"a", "z"}) == ("sudo apt-get install --only-upgrade -y 'a'", ["a"], []),
      "sec F1: narrow_step only removes names (never adds one)")

# ---- sec F2: crown jewels last, server-side, in every changing stage
_repos_offered("10.9.1.11", "1.1.1f-1ubuntu2.20")     # .11's repos are behind the fix — not the subject here
cx.execute("UPDATE assets SET acr='10' WHERE ip_address='10.9.1.11'")
cx.commit()
for stg in ("all", "", "rollout"):
    _clear_state()
    reset_argv()
    d2, c2_code = c2.deploy({"plan_id": u20["plan_id"], "targets": ["10.9.1.11", "10.9.1.1"], "confirm": True, "queue": True,
                             "stage": stg, "max_errors": 5, "canary": False})
    if d2.get("run_id"):
        wait_run(d2["run_id"])
    order = [_arg(a_, "--target") for a_ in argv_lines()]
    check(c2_code == 200 and order and order[0] == "10.9.1.1" and order.index("10.9.1.11") > max(i for i, t_ in enumerate(order) if t_ == "10.9.1.1"),
          f"sec F2: stage {stg or '(none)'} — the crown jewel 10.9.1.11 runs LAST whatever order the request gave")
reset_argv()
d2, c2_code = c2.deploy({"plan_id": u20["plan_id"], "targets": ["10.9.1.11", "10.9.1.1"], "confirm": True, "stage": "all",
                         "expect_targets_sha256": c2.targets_sha256(["10.9.1.11", "10.9.1.1"]), "expect_count": 2})
check(c2_code == 409 and d2.get("mismatch") and not argv_lines(),
      "sec F2: a request that confirmed a crown-FIRST order is refused (409) — nothing ran")
cx.execute("UPDATE assets SET acr='5' WHERE ip_address='10.9.1.11'")
cx.commit()
cx.close()

# ---- sec F3: the family check fails CLOSED (no pre-flight / stale / unknown family) — before any contact or log row
n_log = len(c2log.rows({}, 100000)["rows"])
saved = c2._PF.pop("10.9.1.3", None)
reset_argv()
d3, c3 = c2.deploy({"plan_id": G["Debian 11 · apt"]["plan_id"], "targets": ["10.9.1.3"], "confirm": True})
check(c3 == 409 and d3.get("no_preflight") and not argv_lines() and len(c2log.rows({}, 100000)["rows"]) == n_log,
      "sec F3: no pre-flight → 409 no_preflight, navi never invoked, no C2-log row")
c2._pf_put("10.9.1.3", cred={"status": "ok"}, checks={"status": "ok", "checks": {"osrel": {"status": "ok", "facts": {"family": "unknown"}}}})
d3, c3 = c2.deploy({"plan_id": G["Debian 11 · apt"]["plan_id"], "targets": ["10.9.1.3"], "confirm": True})
check(c3 == 409 and d3.get("no_preflight") and "unknown" in d3["error"] and not argv_lines(), "sec F3: live family 'unknown' → 409 no_preflight")
if saved:
    c2._PF["10.9.1.3"] = dict(saved, ts=time.time() - c2.PF_VALID - 5)
d3, c3 = c2.deploy({"plan_id": G["Debian 11 · apt"]["plan_id"], "targets": ["10.9.1.3"], "confirm": True})
check(c3 == 409 and d3.get("no_preflight") and "30 min" in d3["error"] and not argv_lines(), "sec F3: a pre-flight older than 30 min → 409")
d3, c3 = c2.deploy({"plan_id": G["Debian 11 · apt"]["plan_id"], "targets": ["10.9.1.3"], "dry_run": True})
check(c3 == 200 and any("deploy would refuse it" in w and "10.9.1.3" in w for w in d3["warnings"]), "sec F3: the dry run lists the host deploy would refuse")
if saved:
    c2._PF["10.9.1.3"] = dict(saved, ts=time.time())

# ---- linux F1: Tenable omits the rpm epoch; the host read carries it (real samples B and F)
check(R.vs_fixed("1:1.12.0-6.el7", "1.12.0-8.el7_6", "rpm") == -1 and R.vs_fixed("1:1.12.0-8.el7_6", "1.12.0-8.el7_6", "rpm") == 0
      and R.vs_fixed("(none):1.12.0-6.el7", "1.12.0-8.el7_6", "rpm") == -1 and R.vs_fixed("1:9.9-1", "2:1.0-1", "rpm") == -1
      and R.vs_fixed("2:21.1.7-3+deb12u4", "2:21.1.7-3+deb12u5", "dpkg") == -1,
      "linux F1 rule: a fixed build without an epoch is compared version-release to version-release; a stated epoch counts; dpkg untouched")
for fid, fam_, epo in (("real_B_centos7_networkmanager_case", "yum", "1:"), ("real_F_centos8_openssl", "dnf", "1:")):
    fx_, s_ = RS(fid)
    m_ = R.plan_meta(s_, fam_)
    ver_id = "7" if fam_ == "yum" else "8"
    before_ = {n.lower(): {"state": "installed", "versions": [epo + m_["fixed"][n]["installed"]]} for n in m_["packages"]}
    pf_ = PF(osrel={"family": fam_, "os_id": "centos", "version_id": ver_id, "group": c2_catalog.group_of("centos", ver_id, fam_)},
             pkgstate={"pkgs": before_, "krun": "x"},
             pkgcand={"cand": {n.lower(): {"candidate": epo + m_["fixed"][n]["version"]} for n in m_["packages"]},
                      "source": "dnf / yum list --upgrades", "status": "ok"})
    e_ = E(pf_, {"family": fam_, "packages": m_["packages"], "compare": "rpm", "fixed": m_["fixed"]})
    check(e_["ok"] and e_["will_fix"] and "Already fixed" not in (e_["reason"] or ""),
          f"linux F1 real sample {fid[5]}: an epoch-1 host read is NOT 'Already fixed' — it will be fixed ({e_['reason'][:60]})")
    hv_ = V.host_verdict(dict(m_, compare="rpm"), before_, before_)
    check(hv_["verdict"] == "no_change" and hv_["status"] == "failed", f"linux F1 real sample {fid[5]}: an UNCHANGED host is No change (verify never passes)")
    check(V.before_state(dict(m_, compare="rpm"), before_) is None, f"linux F1 real sample {fid[5]}: the deploy-time read does not say Already fixed")
    pin = m_["fixed"][m_["packages"][0]]
    check(R.version_ok(epo + pin["installed"], {"fixed_version": pin["version"], "compare": "rpm", "want": "at_least"}) is False
          and R.version_ok(epo + pin["version"], {"fixed_version": pin["version"], "compare": "rpm", "want": "at_least"}) is True,
          f"linux F1 real sample {fid[5]}: precheck/verify version_ok with the epoch rule")

# ---- the CentOS hosts end to end (fake navi): real samples B / C / D
H7 = ["10.9.1.19", "10.9.1.20", "10.9.1.21", "10.9.1.22", "10.9.1.23"]
b6, _ = c2.preflight({"targets": H7, "params": {"names": ["NetworkManager", "kernel", "rsyslog"]}, "confirm": True, "queue": True})
wait_run(b6["run_id"])                    # pre-flight first (live groups), as the page does — then plan, then bind
gB, _ = c2.plan_ai({"selector": "119664", "targets": ["10.9.1.19"], "use_llm": False})
gK, _ = c2.plan_ai({"selector": "119662", "targets": ["10.9.1.20", "10.9.1.23"], "use_llm": False})
gD, _ = c2.plan_ai({"selector": "135313", "targets": ["10.9.1.21", "10.9.1.22"], "use_llm": False})
_clear_state()
P7 = {}
for g_, tg_ in ((gB, ["10.9.1.19"]), (gK, ["10.9.1.20", "10.9.1.23"]), (gD, ["10.9.1.21", "10.9.1.22"])):
    # one plan per OS group per pre-flight: these three findings share "CentOS 7 · yum", so each binds its own hosts
    b7, _ = c2.preflight({"targets": tg_, "plan_id": g_["plan_id"], "optional": ["pkgsim"], "confirm": True, "queue": True})
    P7.update({h["target"]: h for h in wait_run(b7["run_id"])["hosts"]})
e19, e20, e21, e22, e23 = (P7[t]["elig"] for t in H7)
check(e19["ok"] and e19["will_fix"], f"linux F1 end to end: CentOS 7 NetworkManager at epoch 1 is eligible and will be fixed ({e19['reason']})")
check(any("downgrade not possible" in n_ and "NetworkManager" in n_ for n_ in e19["notes"])
      and all(r_["rollback"] is False for r_ in e19["packages"]),
      "linux F2: the installed build (@anaconda) is NOT downloadable — downgrade not possible")
check(V.rollback_available(c2_catalog.facts("rbavail", "C2_RV=NetworkManager.x86_64   1:1.12.0-6.el7   @anaconda\nC2_RV=NetworkManager.x86_64   1:1.18.8-2.el7_9   updates"),
                           "NetworkManager", "1:1.12.0-6.el7", "rpm") is False
      and V.rollback_available(c2_catalog.facts("rbavail", "C2_RV=NetworkManager.x86_64   1:1.12.0-6.el7   base"),
                               "NetworkManager", "1:1.12.0-6.el7", "rpm") == "repos"
      and V.rollback_available(c2_catalog.facts("rbavail", "C2_RV=v  | openssl | package | 1.1-1 | x86_64 | (System Packages)"),
                               "openssl", "1.1-1", "rpm") is False,
      "linux F2: @installed and zypper (System Packages) rows never count; an enabled remote repo does")
check(e20["ok"] and any(n_.startswith("removes old kernel kernel 3.10.0-693.el7") and "install-only" in n_ for n_ in e20["notes"]),
      f"linux F3: real sample C on a CentOS 7 host at installonly_limit is deployable; the oldest-kernel removal is a note ({e20['reason']})")
sim7 = c2_catalog.facts("pkgsim", "Updating:\n NetworkManager  x86_64  1:1.18.8-2.el7_9  updates  1.9 M\n"
                                  "Removing for dependencies:\n NetworkManager-ppp  x86_64  1:1.12.0-6.el7  @anaconda  45 k\n"
                                  "Installing for dependencies:\n libndp  x86_64  1.2-9.el7  base  33 k\n\nTransaction Summary\n")
check(sim7["remove"] == ["NetworkManager-ppp"] and [u_["name"] for u_ in sim7["upgrade"]] == ["NetworkManager"] and sim7["install"] == ["libndp"],
      f"linux F3: yum EL7 'Removing for dependencies:' is a REMOVAL, not an upgrade ({sim7['remove']}, {sim7['upgrade']})")
eNM = E(PF(osrel={"family": "yum", "os_id": "centos", "version_id": "7", "group": c2_catalog.group_of("centos", "7", "yum")},
           pkgstate={"pkgs": {"networkmanager": {"state": "installed", "versions": ["1:1.12.0-6.el7"]}}, "krun": "3.10.0-957.el7.x86_64"},
           pkgcand={"cand": {}, "source": "dnf / yum list --upgrades", "status": "ok"}, pkgsim=sim7),
        {"family": "yum", "packages": ["NetworkManager"], "compare": "rpm", "fixed": {"NetworkManager": {"version": "1.12.0-8.el7_6", "source": "distro"}}})
check(not eNM["ok"] and "REMOVE NetworkManager-ppp" in eNM["reason"], "linux F3: any other removal still excludes the host")
check(not e21["ok"] and e21["reason"].startswith("repo check failed: Cannot find a valid baseurl")
      and "CentOS Linux 7 is end-of-life (2024-06-30)" in e21["reason"] and "repos offer" not in e21["reason"],
      f"linux F4: a dead mirror → 'repo check failed' + CentOS 7 EOL wording, never 'repos offer' ({e21['reason'][:90]})")
pto = PF(osrel={"family": "yum", "os_id": "centos", "version_id": "7", "group": c2_catalog.group_of("centos", "7", "yum")},
         pkgstate={"pkgs": {"rsyslog": {"state": "installed", "versions": ["8.24.0-41.el7_7.2"]}}, "krun": "x"}, pkgcand={})
pto["checks"]["checks"]["pkgcand"] = {"status": "timeout", "facts": {}}
eto = E(pto, {"family": "yum", "packages": ["rsyslog"], "compare": "rpm", "fixed": {"rsyslog": {"version": "8.24.0-52.el7", "source": "distro"}}})
check(not eto["ok"] and eto["reason"].startswith("repo check failed: the repo check timed out"), "linux F4: a repo-check TIMEOUT → 'repo check failed'")
check(V.candidate_of({"cand": {}, "source": "dnf / yum list --upgrades", "status": "repo_error"}, "rsyslog", "8.24.0-41") == ""
      and V.candidate_of({"cand": {}, "source": "dnf / yum list --upgrades", "status": "none"}, "rsyslog", "8.24.0-41") == "8.24.0-41",
      "linux F4: 'nothing newer' only when the repo check worked")
check("Ubuntu 18.04 standard support has ended" in V.eol_hint({"os_id": "ubuntu", "version_id": "18.04"})
      and "end-of-life" in V.eol_hint({"os_id": "centos", "version_id": "8"})
      and "-security" in V.eol_hint({"os_id": "debian", "version_id": "12"}) and "pro status" not in V.eol_hint({"os_id": "debian", "version_id": "12"}),
      "linux F4 / M1: EOL wording for CentOS 7 / 8 and Ubuntu 18.04 ESM; Debian gets the -security suite hint, never Ubuntu Pro")
check(not e22["ok"] and "yum-cron" in e22["reason"] and "no bounded lock wait" in e22["reason"],
      f"linux F7: a running yum-cron makes the host busy (unbounded yum lock) → excluded ({e22['reason'][:80]})")
lk7 = c2_catalog.facts("pkglock", "C2_HOLDER=77 /usr/bin/python3 /usr/bin/dnf-automatic /etc/dnf/automatic.conf --timer\nC2_LOCKPIDS=")
lk8 = c2_catalog.facts("pkglock", "C2_HOLDER=88 /usr/libexec/packagekitd\nC2_LOCKPIDS=")
check(lk7["busy"] and "dnf-automatic" in lk7["holder_text"] and not lk8["busy"] and lk8["present"] == ["packagekitd"]
      and all(x in c2_catalog.BY_ID["pkglock"]["cmd"] for x in ("[y]um-cron", "[d]nf-automatic", "[p]ackagekitd", "[u]nattended-upgrade")),
      "linux F7: the lock probe sees yum-cron, dnf-automatic and unattended-upgrades; packagekitd is present, not busy")
check(not e23["ok"] and e23.get("fixed_on_disk") and e23["reason"].startswith("Fixed on disk — reboot required to take effect")
      and "Already fixed" not in e23["reason"], f"linux F6: the fixed kernel installed but not booted → Fixed on disk ({e23['reason'][:80]})")
# linux F5: the reboot state from the rpm kernel list (no needs-restarting on this host) — 957.1.3 installed > running 957
f5a = c2_catalog.facts("rebootreq", "C2_REBOOT=unknown\nC2_KRUN=3.10.0-1160.119.1.el7.x86_64\nC2_KFMT=rpm\n"
                                    "C2_KLIST=3.10.0-1160.el7.x86_64\nC2_KLIST=3.10.0-1160.119.1.el7.x86_64")
f5b = c2_catalog.facts("rebootreq", "C2_REBOOT=no\nC2_KRUN=3.10.0-957.el7.x86_64\nC2_KFMT=rpm\nC2_KLIST=3.10.0-957.1.3.el7.x86_64")
f5c = c2_catalog.facts("rebootreq", "C2_REBOOT=unknown\nC2_KRUN=3.10.0-957.el7.x86_64\nC2_KFMT=rpm\nC2_KLIST=3.10.0-957.1.3.el7.x86_64\nC2_KLIST=3.10.0-957.el7.x86_64")
f5d = c2_catalog.facts("rebootreq", "C2_REBOOT=unknown\nC2_KRUN=3.10.0-957.el7.x86_64\nC2_KFMT=rpm")
check(not f5a["pending"] and f5a["knew"] == "3.10.0-1160.119.1.el7.x86_64", "linux F5: GA 1160.el7 + running 1160.119.1 → NOT pending (rpm comparator, not sort -V)")
check(not f5b["pending"], "linux F5: needs-restarting -r said no → the kernel list never overrides it")
check(f5c["pending"] and f5c["kernel_newer"], "linux F5: no reboot tool → newest installed kernel NEWER than running → pending")
check(not f5d["pending"] and not f5d["decided"] and c2_catalog.health("rebootreq", f5d)["text"].startswith("reboot state unknown"),
      "linux F5: cannot decide → 'reboot state unknown'")
check("sort -V" not in c2_catalog.BY_ID["rebootreq"]["cmd"] and "/boot/vmlinuz" not in c2_catalog.BY_ID["rebootreq"]["cmd"]
      and R.check_command("dnf needs-restarting -r", "read", SRC) == [] and R.check_command("dnf needs-restarting -r", "step", SRC) != [],
      "linux F5: no /boot sort -V guess; `dnf needs-restarting -r` is a read-only probe (owner decision 7a), never a step")
_clear_state()
d19, _c = c2.deploy({"plan_id": gB["plan_id"], "targets": ["10.9.1.19"], "confirm": True, "queue": True})
r19 = wait_run(d19["run_id"]) if d19.get("run_id") else {"hosts": [{"verdict": str(d19), "message": "", "steps": []}]}
h19 = r19["hosts"][0]
check(h19["verdict"] == "fixed" and "Already fixed" not in h19["message"] and "1:1.12.0-6.el7 → 1:1.12.0-8.el7_6" in h19["message"]
      and "'NetworkManager'" in " ".join(s_["command"] for s_ in h19["steps"]),
      f"linux F1 end to end: real sample B deploys and is Fixed (epoch read on the host) ({h19['message'][:80]})")
_clear_state()
d23, _c = c2.deploy({"plan_id": gK["plan_id"], "targets": ["10.9.1.23"], "confirm": True, "queue": True})
h23 = wait_run(d23["run_id"])["hosts"][0]
check(h23["verdict"] == "fixed_on_disk" and h23["status"] == "not_applicable" and h23["ran_upto"] == 0
      and "Fixed on disk" in h23["message"], "linux F6 at deploy: the installed-not-booted kernel → Fixed on disk, nothing installed")
d20, _c = c2.deploy({"plan_id": gK["plan_id"], "targets": ["10.9.1.20"], "confirm": True, "queue": True})
h20 = wait_run(d20["run_id"])["hosts"][0]
check(h20["verdict"] == "fixed_on_disk" and h20["status"] == "changed" and h20["reboot_required"],
      "linux F3 / F6: real sample C on CentOS 7 deploys; the new kernel is Fixed on disk until the reboot (still vulnerable)")

# ---- linux minors
MM2 = {"packages": ["libssl1.1", "openssl"], "compare": "dpkg",
       "fixed": {"libssl1.1": {"version": "1.1.1f-1ubuntu2.20", "source": "distro"}, "openssl": {"version": "1.1.1f-1ubuntu2.20", "source": "distro"}}}
check(V.before_state(MM2, {"libssl1.1": {"state": "installed", "versions": ["1.1.1f-1ubuntu2.20"]},
                           "openssl": {"state": "installed", "versions": ["1.1.1f-1ubuntu2.16"]}}) is None
      and V.before_state(MM2, {"libssl1.1": {"state": "installed", "versions": ["1.1.1f-1ubuntu2.20"]},
                               "openssl": {"state": "installed", "versions": ["1.1.1f-1ubuntu2.20"]}})["verdict"] == "already_fixed",
      "linux M2: the multi-package read decides — one package at the fix is never 'Already fixed' for the host")
page2 = open(os.path.join(ROOT, "agents", "c2", "page.html"), encoding="utf-8").read()
check("fixed_on_disk:'Fixed on disk — reboot required'" in page2 and 'id="acceptFod"' in page2 and "verdict==='fixed_on_disk') return ACCEPT_FOD" in page2
      and 'id="scopeHosts"' in page2 and "esc(n)" in page2,
      "page: Fixed on disk is its own verdict (⑦ needs an explicit tick); the plan card shows per-host scope (escaped)")
check(R.check_command("sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install --only-upgrade -y openssl", "step", SRC) != []
      and R.check_command("sudo DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install --only-upgrade -y openssl", "step", SRC) == [],
      "linux M3: NEEDRESTART_MODE=a (auto-restart) is refused in plan steps; only =l")
_sz = json.load(open(os.path.join(HERE, "fixtures", "c2_plugin_output", "suse_pair_documented.json"), encoding="utf-8"))
zs = R.template_plan({"plugins": [{"plugin_id": "1", "plugin_name": _sz["plugin_name"], "solution": _sz["solution"]}],
                      "hosts": [{"ip": "x", "family": "zypper", "outputs": {"1": _sz["output"]}}], "families": ["zypper"]}, "zypper")
check(zs["steps"][-1]["expect_exit"] == [0, 102, 103, 106], "linux M4: zypper exit 102 / 103 / 106 are not step failures (the version compare decides)")
check(c2_catalog.group_of("opensuse-tumbleweed", "20241101", "zypper")["key"] == "zypper|opensuse-tumbleweed|",
      "linux M5: openSUSE Tumbleweed snapshots form ONE plan group")
check(c2_catalog.facts("pkgsim", "sudo: a password is required")["read"] == "no_sudo"
      and any("simulation not read" in n_ for n_ in E(PF(pkgsim=c2_catalog.facts("pkgsim", "sudo: a password is required")), CTX)["notes"]),
      "linux M6: a simulation refused by sudo is 'not read', never 'no removals'")

# ============ 7c. verify round 2 — sec M7 (server-side eligibility), linux R1 / R2, kernel "Fixed", rollback per host ============
_clear_state()
b8, _ = c2.preflight({"targets": ["10.9.1.1", "10.9.1.12", "10.9.1.14", "10.9.1.17"], "params": {"names": ["libssl1.1", "openssl"]},
                      "confirm": True, "queue": True})
wait_run(b8["run_id"])
G18 = G.get("Ubuntu 18.04 · apt")
if G18:
    reset_argv()
    d_, c_ = c2.deploy({"plan_id": G18["plan_id"], "targets": ["10.9.1.12"], "confirm": True})
    check(c_ == 409 and d_["not_eligible"][0]["code"] == "pm_busy_unbounded" and not argv_lines(),
          "sec M7: a busy package manager with no bounded wait (apt 1.6) → 409 not_eligible, navi never invoked")
n_log = len(c2log.rows({}, 100000)["rows"])
reset_argv()
d_, c_ = c2.deploy({"plan_id": u20["plan_id"], "targets": ["10.9.1.1", "10.9.1.14"], "confirm": True})
check(c_ == 409 and [m_["target"] for m_ in d_["not_eligible"]] == ["10.9.1.14"] and d_["not_eligible"][0]["code"] == "held"
      and "10.9.1.14 — Held" in d_["error"] and not argv_lines() and len(c2log.rows({}, 100000)["rows"]) == n_log,
      "sec M7: ONE ineligible host (held) refuses the WHOLE request — named with its reason; no contact, no log row")
rec1 = c2._PF["10.9.1.1"]
sim_saved = rec1["checks"]["checks"].get("pkgsim")
rec1["checks"]["checks"]["pkgsim"] = {"status": "ok", "facts": {"remove": ["libfoo1"], "removed": [{"name": "libfoo1", "version": "1.0"}],
                                                                 "install": [], "upgrade": [], "read": "ok"}}
d_, c_ = c2.deploy({"plan_id": u20["plan_id"], "targets": ["10.9.1.1"], "confirm": True})
check(c_ == 409 and d_["not_eligible"][0]["code"] == "sim_removes" and not argv_lines(), "sec M7: a simulated removal → 409 (no override)")
if sim_saved is None:
    rec1["checks"]["checks"].pop("pkgsim", None)
else:
    rec1["checks"]["checks"]["pkgsim"] = sim_saved
rec1["cred"] = dict(rec1.get("cred") or {}, sudo="sudo_needs_password")
d_, c_ = c2.deploy({"plan_id": u20["plan_id"], "targets": ["10.9.1.1"], "confirm": True})
check(c_ == 409 and d_["not_eligible"][0]["code"] == "sudo_password", "sec M7: a sudo-password host WITHOUT include_sudo → 409")
d_, c_ = c2.deploy({"plan_id": u20["plan_id"], "targets": ["10.9.1.1"], "confirm": True, "include_sudo": "10.9.1.1"})
check(c_ == 409 and d_["not_eligible"][0]["code"] == "sudo_password", "sec M7: include_sudo must be a per-host LIST (no bulk / string form)")
d_, c_ = c2.deploy({"plan_id": u20["plan_id"], "targets": ["10.9.1.1"], "confirm": True, "queue": True, "include_sudo": ["10.9.1.1"]})
runS = wait_run(d_["run_id"]) if d_.get("run_id") else {}
check(c_ == 200 and runS.get("hosts") and runS["hosts"][0]["verdict"] == "fixed",
      "sec M7: …WITH the host in include_sudo it runs (the one override, owner decision 1)")
rec1["cred"] = dict(rec1["cred"], sudo="sudo_ok")
reset_argv()
d_, c_ = c2.deploy({"plan_id": u20["plan_id"], "targets": ["10.9.1.14"], "confirm": True, "include_sudo": ["10.9.1.14"]})
check(c_ == 409 and d_["not_eligible"][0]["code"] == "held" and not argv_lines(), "sec M7: include_sudo naming a HELD host → still 409")
_clear_state()
d_, c_ = c2.deploy({"plan_id": u20["plan_id"], "targets": ["10.9.1.17"], "confirm": True, "queue": True})
run17 = wait_run(d_["run_id"]) if d_.get("run_id") else {}
check(c_ == 200 and run17["hosts"][0]["status"] == "not_applicable" and run17["hosts"][0]["verdict"] == "already_fixed",
      "sec M7: a 'nothing to do' host (Already fixed: E.none) runs as not_applicable")
d_, c_ = c2.deploy({"plan_id": u20["plan_id"], "targets": ["10.9.1.1", "10.9.1.14"], "dry_run": True})
check(c_ == 200 and d_["not_eligible"] and any("not eligible (held)" in w for w in d_["warnings"]), "sec M7: the dry run lists the not-eligible hosts")
check(all(isinstance(V.eligibility(PF(**kw_), CTX).get("code"), str) and V.eligibility(PF(**kw_), CTX)["code"] == want_
          for kw_, want_ in (({}, "ok"), ({"holds": {"held": ["openssl"]}}, "held"), ({"disk": {"use_root": 98}}, "disk"),
                             ({"pkglock": {"half_configured": True}}, "half_configured"),
                             ({"pkgcand": {"cand": {"openssl": {"candidate": "1.1.1f-1ubuntu2.18"}}}}, "cand_lt_fixed"),
                             ({"pkgstate": {}}, "not_read"), ({"ident": {"sudo_rules": "narrow"}}, "sudo_narrow"))),
      "sec M7: eligibility() returns a STABLE code (ok / held / disk / half_configured / cand_lt_fixed / not_read / sudo_narrow)")
check(c2.OVERRIDABLE == {"sudo_password"}, "sec M7: sudo_password is the ONLY overridable code")
# rollback: the operational subset
_clear_state()
d_, c_, runR = deploy("Ubuntu 20.04 · apt", ["10.9.1.1"])
lk_saved = rec1["checks"]["checks"]["pkglock"]["facts"].get("half_configured")
rec1["checks"]["checks"]["pkglock"]["facts"]["half_configured"] = True
reset_argv()
rb_, c_ = c2.rollback({"plan_id": u20["plan_id"], "run_id": d_["run_id"], "targets": ["10.9.1.1"], "confirm": True})
check(c_ == 409 and rb_["not_eligible"][0]["code"] == "half_configured" and not argv_lines(),
      "sec M7 (rollback): half-configured packages → 409 not_eligible, nothing ran")
rec1["checks"]["checks"]["pkglock"]["facts"]["half_configured"] = lk_saved
rb_, c_ = c2.rollback({"plan_id": u20["plan_id"], "run_id": d_["run_id"], "targets": ["10.9.1.1"], "dry_run": True})
check(c_ == 200 and rb_["sequence"] and "skipped" not in rb_["sequence"][0]["command"], "sec M7 (rollback): an eligible host's downgrade proceeds")

check("include_sudo:sudoPw.map(e=>e.target)" in page2 and "include_sudo:dgSudo" in open(os.path.join(ROOT, "agents", "c2", "page.html"), encoding="utf-8").read(),
      "sec M7: the page sends the per-host sudo include INSIDE the frozen deploy / downgrade body")
# ---- linux R1: the kernel-only reboot fallback never says "no reboot pending" for library updates (real sample E)
fxE, sE = RS("real_E_centos7_systemd")
mE = R.plan_meta(sE, "yum")
bE = {n.lower(): {"state": "installed", "versions": [mE["fixed"][n]["installed"]]} for n in mE["packages"]}
aE = {n.lower(): {"state": "installed", "versions": ["219-78.el7_9.9"]} for n in mE["packages"]}
rbE = c2_catalog.facts("rebootreq", "C2_REBOOT=unknown\nC2_KRUN=3.10.0-1160.119.1.el7.x86_64\nC2_KFMT=rpm\n"
                                    "C2_KLIST=3.10.0-1160.el7.x86_64\nC2_KLIST=3.10.0-1160.119.1.el7.x86_64")
hvE = V.host_verdict(dict(mE, compare="rpm"), bE, aE, reboot=rbE)
check(mE["requires_reboot"] and hvE["verdict"] == "fixed" and "⟳ Reboot state unknown — systemd" in hvE["message"]
      and "needs-restarting (yum-utils" in hvE["message"] and hvE.get("reboot_state") == "unknown",
      "linux R1: real sample E on CentOS 7 without yum-utils → never a bare ✓ Fixed: '⟳ Reboot state unknown — systemd … lacks needs-restarting'")
hE = c2_catalog.health("rebootreq", rbE)["text"]
check("no reboot pending" not in hE and "library reboot triggers not checked" in hE and "needs-restarting" in hE,
      f"linux R1: the health line for the fallback is not 'no reboot pending' ({hE[:70]})")
rbT = c2_catalog.facts("rebootreq", "C2_REBOOT=no\nC2_KRUN=3.10.0-1160.119.1.el7.x86_64\nC2_KFMT=rpm\nC2_KLIST=3.10.0-1160.119.1.el7.x86_64")
check("Reboot state unknown" not in V.host_verdict(dict(mE, compare="rpm"), bE, aE, reboot=rbT)["message"]
      and c2_catalog.health("rebootreq", rbT)["text"] == "no reboot pending", "linux R1: with the tool present the tool decides (no caveat)")
rbD = c2_catalog.facts("rebootreq", "C2_REBOOT=unknown\nC2_KRUN=5.10.0-26-amd64\nC2_KFMT=deb\nC2_KLIST=5.10.0-26-amd64")
check("update-notifier-common" in c2_catalog.health("rebootreq", rbD)["text"], "linux R1: the deb family names its tool (update-notifier-common)")
# ---- linux R2: a kernel flavour the list does not cover → reboot state unknown
for krun_ in ("5.4.17-2136.330.7.1.el7uek.x86_64", "6.6.1-1.el7.elrepo.x86_64", "4.18.0-513.24.1.rt7.326.el8_9.x86_64"):
    fR = c2_catalog.facts("rebootreq", f"C2_REBOOT=unknown\nC2_KRUN={krun_}\nC2_KFMT=rpm\nC2_KLIST=3.10.0-1160.119.1.el7.x86_64")
    check(not fR["decided"] and not fR["pending"] and c2_catalog.health("rebootreq", fR)["text"].startswith("reboot state unknown")
          and "not in the package list" in c2_catalog.health("rebootreq", fR)["text"],
          f"linux R2: running {krun_.split('-')[0]}… not in the kernel list → reboot state unknown")
check(all(k_ in c2_catalog.BY_ID["rebootreq"]["cmd"] for k_ in ("kernel-uek", "kernel-ml", "kernel-lt", "kernel-rt")),
      "linux R2: the rpm query also lists kernel-uek / -ml / -lt / -rt")
# ---- a kernel plan reads plain "Fixed" when the host already runs a fixed kernel
hvK = V.host_verdict(MK, {"kernel": {"state": "installed", "versions": ["4.18.0-305.el8"]}},
                     {"kernel": {"state": "installed", "versions": ["4.18.0-305.el8", "4.18.0-513.el8"]}}, krun="4.18.0-513.el8.x86_64")
check(hvK["verdict"] == "fixed" and hvK["message"].startswith("✓ Fixed") and "Fixed on disk" not in hvK["message"] and not hvK["reboot_required"],
      "kernel plan: running a fixed kernel after the change → plain ✓ Fixed (no Fixed-on-disk, no reboot flag)")
check(V.before_state(MK, {"kernel": {"state": "installed", "versions": ["4.18.0-513.el8"]}}, "4.18.0-513.el8.x86_64")["verdict"] == "already_fixed",
      "kernel plan: already running the fixed kernel before the change → Already fixed (not Fixed on disk)")

# ============ 8. known_hosts (sec L-1 / C7b) ============
check(c2.status({})[0]["known_hosts"]["located"] is (shutil.which("ssh") is not None) and "known_hosts" in c2.glance({})[0],
      "status / glance report whether navi's known_hosts is located (ssh -G)")
KHF = os.path.join(TMP, "known_hosts")
os.environ["NAVI_SSH_KNOWN_HOSTS"] = KHF
b, _ = c2.run_checks({"targets": ["10.9.1.7"], "checks": ["os"], "confirm": True})
hk = b["run"]["hosts"][0].get("hostkey") or {}
check(hk.get("recorded_now") and hk["fingerprints"][0]["fingerprint"].startswith("SHA256:"), "accept-new first contact → key NEW · recorded now, with its SHA256 fingerprint")
b, _ = c2.run_checks({"targets": ["10.9.1.7"], "checks": ["os"], "confirm": True})
check(not b["run"]["hosts"][0]["hostkey"]["recorded_now"] and b["run"]["hosts"][0]["hostkey"]["fingerprints"], "second contact: known, not 'recorded now'")
import base64, hashlib, hmac  # noqa: E401,E402
salt = os.urandom(20)
with open(KHF, "a") as fh:
    fh.write("|1|%s|%s ssh-ed25519 %s\n" % (base64.b64encode(salt).decode(), base64.b64encode(hmac.new(salt, b"10.9.1.99", hashlib.sha1).digest()).decode(),
                                            base64.b64encode(b"k").decode()))
    fh.write("[10.9.1.98]:2222 ssh-ed25519 %s\n" % base64.b64encode(b"k2").decode())
check(c2_hostkeys.lookup("10.9.1.99") and not c2_hostkeys.lookup("10.9.1.97") and c2_hostkeys.lookup("10.9.1.98", 2222) and not c2_hostkeys.lookup("10.9.1.98"),
      "hashed (|1|salt|hmac) and [host]:port entries match exactly")
os.environ.pop("NAVI_SSH_KNOWN_HOSTS")
c2_hostkeys._LOC.update(ts=0, v=None)

# ============ 9. page source pins ============
page = open(os.path.join(ROOT, "agents", "c2", "page.html"), encoding="utf-8").read()
check("API.post('preflight'" in page or "startRun('preflight'" in page, "the page runs pre-flight as ONE server action")
check(all(k in page for k in ("still_vulnerable:'Upgraded, still vulnerable'", "no_change:'No change'", "held:'Held'", "pm_busy:'Package manager busy'")),
      "the page knows the full verdict set")
check("canary_policy:'first_changing'" in page and "data-grp" in page and "plan_ids:GROUPS.map" in page, "one-run sends first_changing; group tabs; per-group pre-flight")
check("khStrict()?{strict:true}:{}" in page and "Not effective until reboot" not in page.split("<script>")[0], "known_hosts fallback → strict for Health / Path / Login")
check("not checked here yet" not in page and "arrives with Phase 2" not in page, "no Phase 1 'not checked here yet' claims left")
check('id="notOsPkg"' in page and 'id="esmNote"' in page and "esc((m.warnings||[])[0]" in page,
      "real samples: the plan card refuses a banner finding and surfaces the ESM note (escaped)")
check('id="solNote"' in page and "esc(m.solution_note)" in page and "m.scope==='output'" in page,
      "scope: the plan card shows the Solution-vs-finding note (escaped, information only) and the package-scope rule")
check(not re.search(r"\son[a-z]+=[\"']", page.split("<script>")[1]), "no inline on*= handlers built in the page script")

# ============ 10. UI — the remediation journey on a mixed-distro Target set (Playwright, own server, fake navi) ============
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
            x = [json.loads(b_) for a_, b_ in reqs if a_ == api]
            return x[-1] if x else None

        def review(k):
            if pg.query_selector(f"#wwh_{k} [data-review]"):
                pg.click(f"#wwh_{k} [data-review]")
                pg.wait_for_timeout(150)

        pg.goto(URL + "#rem")
        pg.wait_for_load_state("networkidle")
        pg.wait_for_timeout(500)
        check(not {a for a, _ in reqs} & {"preflight", "run_checks", "cred_test", "deploy", "plan_ai", "command"}, "nothing runs on page open")
        MIX = ["10.9.1.1", "10.9.1.17", "10.9.1.2", "10.9.1.4", "10.9.1.5", "10.9.1.6", "10.9.1.14"]
        pg.click("#editSet")
        pg.fill("#freeTargets", "\n".join(MIX))
        pg.wait_for_timeout(900)
        pg.fill("#remSel", FX.CVE)
        pg.click("#remFind")
        pg.wait_for_timeout(700)
        # ③ first: the live os-release of every host (one confirm), then ④ groups by it
        pg.click('#stepper button[data-s="3"]')
        review("preflight")
        pg.click("#btn_preflight")
        pg.wait_for_timeout(7000)
        pg.click('#stepper button[data-s="4"]')
        pg.uncheck("#remAi")
        pg.click("#remGen")
        pg.wait_for_timeout(1500)
        check(pg.evaluate("GROUPS.length") >= 5 and pg.evaluate("GROUPS.every(g=>g.group.live)") and pg.query_selector_all("#remOut [data-grp]"),
              "④ one plan per LIVE OS group, with a tab per group")
        check("did not read the plan" in pg.text_content("#remOut") or "Re-run pre-flight" in pg.text_content("#remOut")
              or pg.evaluate("eligibleEnts().length") > 0, "④ says when the plans name packages the pre-flight did not read")
        pg.click('#stepper button[data-s="3"]')
        review("preflight")
        pfb = pg.evaluate("SHOWN.preflight.body")
        check(len(pfb.get("plan_ids") or []) == pg.evaluate("GROUPS.length") and "libssl1.1" in pfb["params"]["names"] and "kernel" in pfb["params"]["names"],
              "③ pre-flight reads the union of every group's packages, bound to every plan")
        pg.click("#btn_preflight")
        pg.wait_for_timeout(9000)
        txt = pg.text_content("#pfOut")
        check("no bounded lock wait" in txt and "Held" in txt and "Already fixed" in txt, "③ table: busy (unbounded) / held / already-fixed reasons shown")
        check(len(dialogs) == 2 and "strict host keys" in dialogs[-1], "pre-flight: ONE confirm per run")
        el = pg.evaluate("eligibleEnts().map(e=>e.target)")
        check(el == ["10.9.1.1"], f"active group Ubuntu 20.04: eligible = [10.9.1.1] ({el})")
        pg.click('#stepper button[data-s="6"]')
        pg.wait_for_timeout(300)
        review("canary")
        lab = pg.text_content("#btn_canary")
        check("Ubuntu 20.04 · apt" in lab and "10.9.1.1" in lab, f"⑥ the deploy button names the host and the plan group ({lab})")
        n0 = len(dialogs)
        pg.click("#btn_canary")
        pg.wait_for_timeout(5000)
        check(len(dialogs) > n0 and "DEPLOY to the canary only" in dialogs[-1], "canary: native confirm")
        v = pg.text_content("#canaryOut")
        check("✓ Fixed" in v and "↻ Services still using the old library: nginx" in v and "Fixed 1" in v, "⑥ verdict line first, services modifier, run banner")
        # RHEL group: kernel → reboot flag
        gi = pg.evaluate("GROUPS.findIndex(g=>g.group&&g.group.label==='RHEL 8 · dnf')")
        pg.click('#stepper button[data-s="4"]')
        pg.wait_for_timeout(200)
        pg.click(f'#remOut [data-grp="{gi}"]')
        pg.wait_for_timeout(500)
        check("Not available for kernels" in pg.text_content("#remOut") or "boot the previous kernel" in pg.text_content("#remOut"),
              "④ RHEL kernel plan: undo not available for kernels")
        pg.click('#stepper button[data-s="6"]')
        pg.wait_for_timeout(300)
        review("canary")
        check(pg.evaluate("SHOWN.canary.body.targets") == ["10.9.1.4"] and "RHEL 8 · dnf" in pg.text_content("#btn_canary"), "switching group: the canary is that group's host")
        pg.click("#btn_canary")
        pg.wait_for_timeout(5000)
        check("Fixed on disk — reboot required" in pg.text_content("#canaryOut"), "RHEL kernel canary (linux F6): Fixed on disk — reboot required shown")
        pg.click('#stepper button[data-s="8"]')
        pg.wait_for_timeout(300)
        check("Hosts not effective until reboot: 1" in pg.text_content("#v8sum"), "⑧ reboot summary per group")
        db_ = last("deploy")
        db_.pop("confirm", None)
        check(db_["targets"] == ["10.9.1.4"] and db_["stage"] == "canary", "the sent body is the canary of the active group")
        check(not errs, f"no page errors ({errs[:2]})")
        br.close()
    srv.terminate()

gates(False)
print(f"\n{len(fails)} failure(s)")
sys.exit(1 if fails else 0)
