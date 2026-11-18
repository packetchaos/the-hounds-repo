#!/usr/bin/env python3
"""A fake `navi` for the Command & Control tests and manual checks (NAVI_BIN=<this file>).

It logs its argv as one JSON line to $FAKE_NAVI_LOG and answers `navi action push` the way
the real navi does (plugins/action.py push()/connect()/explain_ssh_failure()), with the SAME
per-host wording, chosen by target:

  10.9.0.1   ok — catalog bundles get realistic per-check sections; remediation commands
             (dpkg-query / apt-get / rpm) answer like an Ubuntu host that gets fixed
  10.9.0.2   auth failure        "connection failed: permission denied"
  10.9.0.3   HOST KEY CHANGED    (security event)
  10.9.0.4   port closed         "Connection refused"
  10.9.0.5   unreachable         "No route to host" (retryable transport failure)
  nosuch.invalid  DNS failure
  10.9.0.6   command timeout     "timed out waiting for the command to finish"
  10.9.0.7   unknown host key under --strict-host-keys (ok without it)
  10.9.0.8   ok, but sudo needs a password
  10.9.0.9   any non-catalog command → [FAIL] exit 2
  10.9.0.10  remediation precheck exits 1 (host not affected)
  10.9.0.11  remediation step exits 100 (fails: "Could not get lock" → Package manager busy)
  anything else → ok (generic)

build 486 — Phase 2 per-distro hosts (answers for os-release, the pre-flight probes — pkgstate, pkgcand, pkglock,
holds, rebootreq, needrestart, rbavail, chlog, entitle, pkgsim — and the remediation commands, per family):
  10.9.1.1   Ubuntu 20.04 (apt 2.0.10)  libssl1.1 + openssl 1.1.1f-1ubuntu2.16 → .20; nginx on the old library;
             the old build is in /var/cache/apt/archives (downgrade available: cache)
  10.9.1.2   Ubuntu 22.04 (apt 2.4.11)  libssl3 + openssl 3.0.2-0ubuntu1.10 → .12; a reboot is already pending
  10.9.1.3   Debian 11 (apt 2.2.4)      libssl1.1 + openssl 1.1.1n-0+deb11u4 → u5; old build still in the repos
  10.9.1.4   RHEL 8.6 (dnf)             kernel 4.18.0-305.el8 → 513.el8 (install-only; still RUNNING 305 after)
  10.9.1.5   Rocky 9.3 (dnf)            openssl + openssl-libs 1:3.0.7-24.el9 → 25.el9
  10.9.1.6   Amazon Linux 2 (yum)       openssl; yum is BUSY (no bounded lock wait → excluded)
  10.9.1.7   Amazon Linux 2023 (dnf)    openssl 1:3.0.8-1.amzn2023.0.9 → .0.11
  10.9.1.8   Amazon Linux AMI 2018.03 (yum)  openssl 1.0.2k-16.159.amzn1 → 16.161.amzn1
  10.9.1.9   SLES 15 SP5 (zypper)       openssl-1_1 1.1.1l-150400.7.25.1 → .28.1
  10.9.1.10  Ubuntu 20.04  the repos offer only 2.18 < fixed 2.20 (excluded; if deployed: Upgraded, still vulnerable)
  10.9.1.11  Ubuntu 20.04  the repos offer nothing newer (excluded; if deployed: No change)
  10.9.1.12  Ubuntu 18.04 (apt 1.6.17)  BUSY: unattended-upgrade — old apt ignores DPkg::Lock::Timeout → excluded
  10.9.1.13  Ubuntu 22.04 (apt 2.4.11)  BUSY: apt-daily.service — bounded wait → eligible with a warning
  10.9.1.14  Ubuntu 20.04  openssl HELD (apt-mark hold)
  10.9.1.15  Ubuntu 20.04  half-configured packages (dpkg --audit)
  10.9.1.16  Fedora CoreOS 39 (rpm-ostree, immutable)
  10.9.1.17  Ubuntu 20.04  already at the fixed build 1.1.1f-1ubuntu2.20
  10.9.1.18  Ubuntu 20.04  kernel finding in the "Running Kernel level of …" shape
build 486 verify round — CentOS hosts in the shapes the owner's estate has (real samples B / C / D):
  10.9.1.19  CentOS 7.6 (yum)  NetworkManager ×5 at EPOCH 1 (rpm prints 1:1.12.0-6.el7; Tenable's output has no epoch)
             → 1:1.12.0-8.el7_6; --showduplicates lists the installed build only as @anaconda (downgrade NOT available)
  10.9.1.20  CentOS 7.9 (yum)  kernel 3.10.0-957.el7 → 957.1.3.el7 at installonly_limit: the simulation shows
             "Removing: kernel 3.10.0-693.el7" (the oldest kernel — a note, not an exclusion); no reboot tool, so
             the rpm kernel list decides the reboot state
  10.9.1.21  CentOS 7.7 (yum)  rsyslog; mirrorlist.centos.org is dead — the repo check fails (PMRC=1, "Cannot find a
             valid baseurl") → "repo check failed" + CentOS 7 end-of-life wording
  10.9.1.22  CentOS 7.7 (yum)  rsyslog; yum-cron is running (python … /usr/sbin/yum-cron) → busy, unbounded → excluded
  10.9.1.23  CentOS 7.6 (yum)  the fixed kernel 3.10.0-957.1.3.el7 is INSTALLED but the host still runs 957.el7 →
             "Fixed on disk — reboot required" (never "Already fixed")
build 487 (owner decision 7):
  10.9.1.24  CentOS Linux 8 (dnf)  glibc / glibc-common 2.28-164.el8 → 2.28-189.el8 (a SYNTHETIC finding); NO standalone
             needs-restarting — `dnf needs-restarting -r` answers: no before the change, yes after glibc moved (glibc is
             on dnf-plugins-core's reboot list: kernel, kernel-rt, glibc, linux-firmware, systemd, dbus, dbus-broker,
             dbus-daemon, microcode_ctl — openssl-libs is NOT, unlike EL7 yum-utils)
  10.9.1.25  CentOS 7.7 (yum)  rsyslog; idle at pre-flight, then yum-cron takes /var/run/yum.pid: the FIRST change step
             with --setopt=exit_on_lock=1 prints yum's two lock lines and exits 200 (nothing changed); without the token it would hang
             (navi timeout → Unknown state); later attempts proceed (the lock is gone)
  10.9.1.26  Ubuntu 20.04  (487 fix round) the apt step ends with "E: Could not get lock …" (exit 100) although the
             packages DID move — the version re-read must turn "busy, nothing changed" into "partly changed"
  10.9.0.1 / .8 / .10 / .11 answer the new probes as Ubuntu 20.04 too (.10: openssl not installed); every other
  host keeps the generic answers.
NAVI_SSH_KNOWN_HOSTS=<file> → like OpenSSH under accept-new, a reached host's key is appended on first contact
(deterministic per host), so the console's fingerprint detection can be exercised.

Remote output always contains REMOTE-OUTPUT-TOKEN-7731 so a test can prove output is never
stored in the C2 log. FAKE_NAVI_NOCREDS=1 → navi's "no ssh credentials" message.
FAKE_NAVI_SLEEP=<s> delays every push (abort tests). Never runs the command it is given.
"""
import json
import os
import re
import sys
import time

argv = sys.argv[1:]
log = os.environ.get("FAKE_NAVI_LOG")
if log:
    with open(log, "a") as f:
        f.write(json.dumps(argv) + "\n")


def opt(name):
    if name in argv:
        i = argv.index(name)
        return argv[i + 1] if i + 1 < len(argv) else ""
    return None


if argv[:2] != ["action", "push"]:
    print("ok")
    sys.exit(0)

target = opt("--target") or ""
if os.environ.get("FAKE_NAVI_SLEEP"):
    time.sleep(float(os.environ["FAKE_NAVI_SLEEP"]))
cmd = opt("--command")
file = opt("--file")
strict = "--strict-host-keys" in argv
TOKEN = "REMOTE-OUTPUT-TOKEN-7731"

if os.environ.get("FAKE_NAVI_NOCREDS"):
    print("\nPlease use the 'navi config ssh' command to enter your ssh credentials.\n")
    sys.exit(0)

if file:
    print("\n>> Pushing file '{}' to {}:~/".format(os.path.basename(file), target))
else:
    print("\n>> Running on {}: {}".format(target, cmd))


def conn_fail(reason):
    print("  [!] {}: connection failed: {}".format(target, reason))
    sys.exit(0)


if target == "10.9.0.2":
    conn_fail("permission denied")
if target == "10.9.0.3":
    conn_fail("Could not establish connection to host (HOST KEY CHANGED since navi last connected to this address "
              "- possible impersonation or a rebuilt host. Verify the host, then run ssh-keygen -R {} to clear the "
              "old key)".format(target))
if target == "10.9.0.4":
    conn_fail("Could not establish connection to host (ssh: connect to host {} port 22: Connection refused)".format(target))
if target == "10.9.0.5":
    conn_fail("Could not establish connection to host (ssh: connect to host {} port 22: No route to host)".format(target))
if target == "nosuch.invalid":
    conn_fail("Could not establish connection to host (ssh: Could not resolve hostname nosuch.invalid: "
              "Name or service not known)")
if target == "10.9.0.7" and strict:
    conn_fail("Could not establish connection to host (host key is not in known_hosts and --strict-host-keys is set "
              "- add it deliberately, or run once without --strict-host-keys)")
if target == "10.9.0.6":
    print("  [!] {}: timed out waiting for the command to finish".format(target))
    print("  [?] {}: command ran but the exit status could not be read".format(target))
    sys.exit(0)

if file:
    print("  [OK] {}: copied".format(target))
    sys.exit(0)

CANNED = {
    "ident": "uid=1001(svc) gid=1001(svc) groups=1001(svc),27(sudo)\nsvc\nweb01.example.local\n"
             "User svc may run the following commands on web01:\n    (ALL) NOPASSWD: ALL",
    "os": 'PRETTY_NAME="Ubuntu 20.04.6 LTS"\nNAME="Ubuntu"\nID=ubuntu\nLinux web01 5.4.0-150-generic x86_64 GNU/Linux',
    "uptime": " 10:01:02 up 12 days,  3:04,  1 user,  load average: 0.08, 0.03, 0.01\n0.08 0.03 0.01 1/123 4567",
    "disk": "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G   31G  9.0G  78% /",
    "mem": "               total        used        free\nMem:            3936        1210        1022",
    "failed": "UNIT LOAD ACTIVE SUB DESCRIPTION\n0 loaded units listed.",
    "time": "System clock synchronized: yes\nNTP service: active\nTime zone: Etc/UTC (UTC, +0000)\nSat Nov  8 10:01:02 UTC 2026",
    "pubip": "203.0.113.7",
    "routes": "lo UNKNOWN 127.0.0.1/8\neth0 UP 10.9.0.1/24\ndefault via 10.9.0.254 dev eth0",
    "dns": "nameserver 10.9.0.53",
    "ports": "Netid State Local Address:Port\ntcp LISTEN 0.0.0.0:22\ntcp LISTEN 0.0.0.0:443",
    "tconn": "200 0.231s",
}


def section(cid, out, rc=0):
    print("C2_BEGIN=" + cid)
    if out:
        print(out)
    print("")
    print("C2_END={} rc={}".format(cid, rc))


def _qnames(c):
    """The quoted package names a probe was given (for p in 'a' 'b'; apt-cache policy 'a' 'b' …). Each catalog check
    travels inside sh -c '<check>', so its own quotes arrive escaped as '"'"' — undo that first."""
    c = c.replace("'\"'\"'", "'")
    m = re.findall(r"for p in ((?:'[^']*' ?)+); do", c)
    src = " ".join(m) if m else " ".join(re.findall(r"(?:policy|--upgrades|updates|info|--showduplicates|--only-upgrade|"
                                                     r"--assumeno upgrade|--assumeno update|--dry-run) ((?:'[^']*' ?)+)", c))
    return list(dict.fromkeys(re.findall(r"'([A-Za-z0-9][A-Za-z0-9.+_:@-]*)'", src)))


NM = ["NetworkManager", "NetworkManager-libnm", "NetworkManager-team", "NetworkManager-tui", "NetworkManager-wifi"]
U20 = dict(os=("ubuntu", "debian", "20.04", "Ubuntu 20.04.6 LTS"), fam="apt", aptver="2.0.10", krun="5.4.0-150-generic",
           pkgs={"libssl1.1": ["1.1.1f-1ubuntu2.16", "1.1.1f-1ubuntu2.20"], "openssl": ["1.1.1f-1ubuntu2.16", "1.1.1f-1ubuntu2.20"]},
           repo={"libssl1.1": ["1.1.1f-1ubuntu2.20", "1.1.1f-1ubuntu2"], "openssl": ["1.1.1f-1ubuntu2.20", "1.1.1f-1ubuntu2"]})


def P(base, **kw):
    d = json.loads(json.dumps(base))
    d.update(kw)
    return d


PROFILES = {
    "10.9.1.1": P(U20, svc=["nginx"], cache={"libssl1.1": ["1.1.1f-1ubuntu2.16"], "openssl": ["1.1.1f-1ubuntu2.16"]}),
    "10.9.1.2": P(U20, os=("ubuntu", "debian", "22.04", "Ubuntu 22.04.4 LTS"), aptver="2.4.11", krun="5.15.0-91-generic",
                  knew="5.15.0-94-generic", reboot=True,
                  pkgs={"libssl3": ["3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.12"], "openssl": ["3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.12"]},
                  repo={"libssl3": ["3.0.2-0ubuntu1.12"], "openssl": ["3.0.2-0ubuntu1.12"]}),
    "10.9.1.3": P(U20, os=("debian", "", "11", "Debian GNU/Linux 11 (bullseye)"), aptver="2.2.4", krun="5.10.0-26-amd64",
                  pkgs={"libssl1.1": ["1.1.1n-0+deb11u4", "1.1.1n-0+deb11u5"], "openssl": ["1.1.1n-0+deb11u4", "1.1.1n-0+deb11u5"]},
                  repo={"libssl1.1": ["1.1.1n-0+deb11u5", "1.1.1n-0+deb11u4"], "openssl": ["1.1.1n-0+deb11u5", "1.1.1n-0+deb11u4"]}),
    "10.9.1.4": dict(os=("rhel", "fedora", "8.6", "Red Hat Enterprise Linux 8.6 (Ootpa)"), fam="dnf", krun="4.18.0-305.el8.x86_64",
                     pkgs={"kernel": ["4.18.0-305.el8", "4.18.0-513.el8"]}, kernel=True,
                     repo={"kernel": ["4.18.0-513.el8", "4.18.0-305.el8"]}),
    "10.9.1.5": dict(os=("rocky", "rhel centos fedora", "9.3", "Rocky Linux 9.3 (Blue Onyx)"), fam="dnf", krun="5.14.0-362.8.1.el9_3.x86_64",
                     pkgs={"openssl": ["1:3.0.7-24.el9", "1:3.0.7-25.el9"], "openssl-libs": ["1:3.0.7-24.el9", "1:3.0.7-25.el9"]},
                     repo={"openssl": ["1:3.0.7-25.el9", "1:3.0.7-24.el9"], "openssl-libs": ["1:3.0.7-25.el9", "1:3.0.7-24.el9"]},
                     svc=["sshd", "nginx"]),
    "10.9.1.6": dict(os=("amzn", "centos rhel fedora", "2", "Amazon Linux 2"), fam="yum", krun="4.14.322-246.539.amzn2.x86_64",
                     pkgs={"openssl": ["1.0.2k-24.amzn2.0.6", "1.0.2k-24.amzn2.0.7"]}, busy=("yum", 2211)),
    "10.9.1.7": dict(os=("amzn", "fedora", "2023", "Amazon Linux 2023"), fam="dnf", krun="6.1.61-85.141.amzn2023.x86_64",
                     pkgs={"openssl": ["1:3.0.8-1.amzn2023.0.9", "1:3.0.8-1.amzn2023.0.11"]}),
    "10.9.1.8": dict(os=("amzn", "rhel fedora", "2018.03", "Amazon Linux AMI 2018.03"), fam="yum", krun="4.14.336-178.554.amzn1.x86_64",
                     pkgs={"openssl": ["1.0.2k-16.159.amzn1", "1.0.2k-16.161.amzn1"]}),
    "10.9.1.9": dict(os=("sles", "suse", "15.5", "SUSE Linux Enterprise Server 15 SP5"), fam="zypper", krun="5.14.21-150500.55.39-default",
                     pkgs={"openssl-1_1": ["1.1.1l-150400.7.25.1", "1.1.1l-150400.7.28.1"]},
                     repo={"openssl-1_1": ["1.1.1l-150400.7.28.1", "1.1.1l-150400.7.25.1"]}),
    "10.9.1.10": P(U20, pkgs={"libssl1.1": ["1.1.1f-1ubuntu2.16", "1.1.1f-1ubuntu2.18"], "openssl": ["1.1.1f-1ubuntu2.16", "1.1.1f-1ubuntu2.18"]}),
    "10.9.1.11": P(U20, pkgs={"libssl1.1": ["1.1.1f-1ubuntu2.16", "1.1.1f-1ubuntu2.16"], "openssl": ["1.1.1f-1ubuntu2.16", "1.1.1f-1ubuntu2.16"]}),
    "10.9.1.12": P(U20, os=("ubuntu", "debian", "18.04", "Ubuntu 18.04.6 LTS"), aptver="1.6.17", busy=("unattended-upgrade", 1234)),
    "10.9.1.13": P(U20, os=("ubuntu", "debian", "22.04", "Ubuntu 22.04.4 LTS"), aptver="2.4.11", krun="5.15.0-91-generic",
                   pkgs={"libssl3": ["3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.12"], "openssl": ["3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.12"]},
                   unit="apt-daily.service"),
    "10.9.1.14": P(U20, held=["openssl"]),
    "10.9.1.15": P(U20, audit=True),
    "10.9.1.16": dict(os=("fedora", "", "39", "Fedora CoreOS 39"), fam="dnf", immutable="rpm-ostree", krun="6.5.6-300.fc39.x86_64",
                      pkgs={"openssl": ["1:3.1.1-4.fc39", "1:3.1.1-4.fc39"]}),
    "10.9.1.17": P(U20, pkgs={"libssl1.1": ["1.1.1f-1ubuntu2.20", "1.1.1f-1ubuntu2.20"], "openssl": ["1.1.1f-1ubuntu2.20", "1.1.1f-1ubuntu2.20"]}),
    "10.9.1.18": P(U20, pkgs={"linux-image-5.4.0-150-generic": ["5.4.0-150.167", "5.4.0-150.167"]}),
    "10.9.1.19": dict(os=("centos", "rhel fedora", "7", "CentOS Linux 7 (Core)"), fam="yum", krun="3.10.0-957.el7.x86_64",
                      pkgs={n: ["1:1.12.0-6.el7", "1:1.12.0-8.el7_6"] for n in NM},
                      rbrows={n: [("1:1.12.0-6.el7", "@anaconda"), ("1:1.18.8-2.el7_9", "updates")] for n in NM},
                      klist=["3.10.0-957.el7.x86_64"], rtool=False),
    "10.9.1.20": dict(os=("centos", "rhel fedora", "7", "CentOS Linux 7 (Core)"), fam="yum", krun="3.10.0-957.el7.x86_64",
                      pkgs={"kernel": ["3.10.0-957.el7", "3.10.0-957.1.3.el7"], "kernel-tools": ["3.10.0-957.el7", "3.10.0-957.1.3.el7"],
                            "kernel-tools-libs": ["3.10.0-957.el7", "3.10.0-957.1.3.el7"], "python-perf": ["3.10.0-957.el7", "3.10.0-957.1.3.el7"]},
                      kernel=True, klist=["3.10.0-693.el7.x86_64", "3.10.0-862.el7.x86_64", "3.10.0-957.el7.x86_64"], rtool=False,
                      sim=("Resolving Dependencies\n--> Running transaction check\nDependencies Resolved\n\n"
                           "================================================================================\n"
                           " Package              Arch      Version                 Repository   Size\n"
                           "================================================================================\n"
                           "Installing:\n kernel               x86_64    3.10.0-957.1.3.el7      updates      48 M\n"
                           "Updating:\n kernel-tools         x86_64    3.10.0-957.1.3.el7      updates     7.1 M\n"
                           " kernel-tools-libs    x86_64    3.10.0-957.1.3.el7      updates     7.0 M\n"
                           " python-perf          x86_64    3.10.0-957.1.3.el7      updates     7.1 M\n"
                           "Removing:\n kernel               x86_64    3.10.0-693.el7          @anaconda    59 M\n\n"
                           "Transaction Summary\n================================================================================\n"
                           "Install  1 Package\nUpgrade  3 Packages\nRemove   1 Package\nExiting on user command")),
    "10.9.1.21": dict(os=("centos", "rhel fedora", "7", "CentOS Linux 7 (Core)"), fam="yum", krun="3.10.0-1062.el7.x86_64",
                      pkgs={"rsyslog": ["8.24.0-41.el7_7.2", "8.24.0-52.el7"]}, deadmirror=True),
    "10.9.1.22": dict(os=("centos", "rhel fedora", "7", "CentOS Linux 7 (Core)"), fam="yum", krun="3.10.0-1062.el7.x86_64",
                      pkgs={"rsyslog": ["8.24.0-41.el7_7.2", "8.24.0-52.el7"]}, holder="4321 /usr/bin/python -tt /usr/sbin/yum-cron"),
    "10.9.1.23": dict(os=("centos", "rhel fedora", "7", "CentOS Linux 7 (Core)"), fam="yum", krun="3.10.0-957.el7.x86_64",
                      pkgs={"kernel": ["3.10.0-957.el7", "3.10.0-957.1.3.el7"], "kernel-tools": ["3.10.0-957.1.3.el7", "3.10.0-957.1.3.el7"],
                            "kernel-tools-libs": ["3.10.0-957.1.3.el7", "3.10.0-957.1.3.el7"], "python-perf": ["3.10.0-957.1.3.el7", "3.10.0-957.1.3.el7"]},
                      kernel=True, preinstalled=True, klist=["3.10.0-957.el7.x86_64", "3.10.0-957.1.3.el7.x86_64"], rtool=False),
    "10.9.1.24": dict(os=("centos", "rhel fedora", "8", "CentOS Linux 8"), fam="dnf", krun="4.18.0-348.7.1.el8_5.x86_64",
                      pkgs={"glibc": ["2.28-164.el8", "2.28-189.el8"], "glibc-common": ["2.28-164.el8", "2.28-189.el8"]},
                      klist=["4.18.0-348.7.1.el8_5.x86_64"], rtool="dnf"),
    "10.9.1.25": dict(os=("centos", "rhel fedora", "7", "CentOS Linux 7 (Core)"), fam="yum", krun="3.10.0-1062.el7.x86_64",
                      pkgs={"rsyslog": ["8.24.0-41.el7_7.2", "8.24.0-52.el7"]}, lockafter=True),
    "10.9.1.26": P(U20, lockmoved=True),
    "10.9.0.1": P(U20), "10.9.0.8": P(U20), "10.9.0.11": P(U20),
    "10.9.0.10": P(U20, pkgs={}),
}
PROF = PROFILES.get(target)
state = os.environ.get("FAKE_NAVI_STATE")
SF = (state + "." + target) if state else ""
fixed = bool(SF and os.path.exists(SF))


def inst(name):
    """installed version(s) of a profile package NOW (before / after the fake upgrade)."""
    v = (PROF or {}).get("pkgs", {}).get(name)
    if not v:
        return []
    if (PROF or {}).get("kernel") and (fixed or (PROF or {}).get("preinstalled")) and name == "kernel":
        return [v[0], v[1]]                      # install-only: the old kernel stays installed
    return [v[1] if fixed else v[0]]


def osrel():
    i, like, ver, pretty = PROF["os"]
    return ("C2_ID={}\nC2_IDLIKE={}\nC2_VER={}\nC2_PRETTY={}\nC2_KREL={}\nC2_ARCH=x86_64\nC2_IMMUTABLE={}"
            .format(i, like, ver, pretty, PROF.get("krun", ""), PROF.get("immutable", "no")))


def probe(cid, names):
    fam = PROF["fam"]
    deb = fam == "apt"
    if cid == "os":
        i, like, ver, pretty = PROF["os"]
        return 'PRETTY_NAME="{}"\nID={}\nID_LIKE="{}"\nVERSION_ID="{}"\nLinux h {} x86_64 GNU/Linux'.format(pretty, i, like, ver, PROF.get("krun", ""))
    if cid == "osrel":
        return osrel()
    if cid == "pkgstate":
        out = []
        for n in names:
            vs = inst(n)
            if not vs:
                out.append("C2_PKGLINE=un {} -".format(n))
                continue
            for v in vs:
                st = ("hi " if n in PROF.get("held", []) else "ii ") if deb else "ii"
                out.append("C2_PKGLINE={} {} {}".format(st, n, v if deb or ":" in v else "(none):" + v))
        return "\n".join(out + ["C2_KRUN=" + PROF.get("krun", "")])
    if cid == "pkgcand":
        if PROF.get("deadmirror"):
            return ("Could not retrieve mirrorlist http://mirrorlist.centos.org/?release=7&arch=x86_64&repo=os&infra=stock "
                    "error was\n14: curl#6 - \"Could not resolve host: mirrorlist.centos.org; Unknown error\"\n\n"
                    " One of the configured repositories failed (Unknown),\n and yum doesn't have enough cached data to continue.\n"
                    "Cannot find a valid baseurl for repo: base/7/x86_64\nC2_PMRC=1")
        out = []
        for n in names:
            v = PROF["pkgs"].get(n)
            if not v:
                continue
            cur, cand = inst(n)[-1], (v[1] if not fixed else inst(n)[-1])
            if deb:
                out += ["{}:".format(n), "  Installed: " + cur, "  Candidate: " + cand, "  Version table:",
                        (" *** " if cand == cur else "     ") + cand + " 500"]
            elif fam == "zypper":
                out += ["Information for package {}:".format(n), "Name           : " + n, "Version        : " + cand,
                        "Status         : " + ("up-to-date" if cand == cur else "out-of-date (version {} installed)".format(cur))]
            elif cand != cur:
                out += ["Available Upgrades", "{}.x86_64    {}    baseos".format(n, cand)]
        if not deb and fam != "zypper" and not out:
            out = ["Error: No matching Packages to list", "C2_PMRC=1"]
        elif not deb and fam != "zypper":
            out.append("C2_PMRC=0")
        return "\n".join(out)
    if cid == "pkglock":
        out = []
        b = PROF.get("busy")
        if b:
            out.append("C2_HOLDER={} /usr/bin/{} -y".format(b[1], b[0]))
        if PROF.get("holder"):
            out.append("C2_HOLDER=" + PROF["holder"])
        out.append("C2_LOCKPIDS=" + (" {}".format(b[1]) if b else ""))
        if PROF.get("unit"):
            out.append("C2_UNIT=" + PROF["unit"])
        if deb:
            out.append("C2_AUDIT=broken\nThe following packages are only half configured:\n libssl1.1" if PROF.get("audit") else "C2_AUDIT=ok")
            out.append("C2_APTVER=" + PROF.get("aptver", ""))
        return "\n".join(out)
    if cid == "holds":
        return "\n".join("C2_HOLD=" + h for h in PROF.get("held", [])) + ("" if deb else "\nC2_VLOCKRC=na")
    if cid == "rebootreq":
        # verify round (linux F5): the installed kernels come from the package database (KFMT / KLIST)
        kl = list(PROF.get("klist") or ([PROF.get("knew")] if PROF.get("knew") else []) or [PROF.get("krun", "")])
        if PROF.get("kernel") and fixed:
            kl.append(PROF["pkgs"]["kernel"][1] + ".x86_64")
        if PROF.get("rtool") is False:
            r = "unknown"                          # no needs-restarting / reboot-required: the kernel list decides
        elif PROF.get("rtool") == "dnf":
            # build 487: dnf needs-restarting -r — dnf-plugins-core's reboot list (openssl-libs is NOT on it)
            r = "yes" if fixed and set(PROF["pkgs"]) & {"kernel", "kernel-rt", "glibc", "linux-firmware", "systemd", "dbus",
                                                         "dbus-broker", "dbus-daemon", "microcode_ctl"} else "no"
            return ("C2_REBOOT={}\nC2_RTOOL=dnf needs-restarting\nC2_KRUN={}\nC2_KFMT=rpm\n".format(r, PROF.get("krun", ""))
                    + "\n".join("C2_KLIST=" + k for k in kl if k))
        else:
            r = "yes" if PROF.get("reboot") or (PROF.get("kernel") and fixed) else "no"
        return "C2_REBOOT={}\nC2_KRUN={}\nC2_KFMT={}\n".format(r, PROF.get("krun", ""), "deb" if deb else "rpm") + \
            "\n".join("C2_KLIST=" + (k[len("linux-image-"):] if k.startswith("linux-image-") else k) for k in kl if k)
    if cid == "needrestart":
        sv = PROF.get("svc", []) if fixed else []
        if deb:
            return "NEEDRESTART-VER: 3.4\nNEEDRESTART-KSTA: 1\n" + "".join("NEEDRESTART-SVC: {}.service\n".format(x) for x in sv) + "C2_SVCREAD=ok"
        return "".join("C2_SVC={}.service\n".format(x) for x in sv) + "C2_SVCREAD=ok"
    if cid == "rbavail":
        out = []
        for n in names:
            for v, rp in PROF.get("rbrows", {}).get(n, []):
                out.append("C2_RV={}.x86_64   {}   {}".format(n, v, rp))     # dnf / yum --showduplicates, incl. @installed
            for v in PROF.get("repo", {}).get(n, []):
                out.append("C2_RV=" + ("   {} | {} | http://mirror/ focal-updates/main amd64 Packages".format(n, v) if deb else
                                       ("v  | {} | package | {} | x86_64 | SLE-Updates".format(n, v) if fam == "zypper" else
                                        "{}.x86_64   {}   baseos".format(n, v))))
            for v in PROF.get("cache", {}).get(n, []):
                out.append("C2_RC={}_{}_amd64.deb".format(n, v.replace(":", "%3a")))
        return "\n".join(out)
    if cid == "chlog":
        return "\n".join("C2_CL={} no_evidence".format(n) for n in names)
    if cid == "pkgsim":
        if deb:
            return "\n".join("Inst {} [{}] ({} Ubuntu:20.04/focal-updates [amd64])".format(n, inst(n)[-1], PROF["pkgs"][n][1])
                             for n in names if inst(n) and PROF["pkgs"][n][1] != inst(n)[-1])
        if PROF.get("sim"):
            return PROF["sim"]
        return "Upgrading:\n" + "\n".join(" {}  x86_64  {}  baseos  1 M".format(n, PROF["pkgs"][n][1]) for n in names if inst(n))
    if cid == "disk":
        return "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G   31G  9.0G  78% /\n/dev/sda2       976M  402M  507M  45% /boot"
    if cid == "pkgver":
        n = (names or [""])[0]
        v = inst(n)
        return (n + " " + v[-1]) if v else "C2_PKG=not_installed"
    if cid == "entitle":
        return "SERVICE   ENTITLED  STATUS\nesm-infra  yes      enabled" if deb else "Overall Status: Current"
    return None


ids = re.findall(r'"C2""_BEGIN=([a-z0-9_]+)"', cmd or "")
kh = os.environ.get("NAVI_SSH_KNOWN_HOSTS")
if kh and not strict:
    # OpenSSH under StrictHostKeyChecking=accept-new: a reached host's key is recorded on first contact
    try:
        have = open(kh).read() if os.path.exists(kh) else ""
    except OSError:
        have = ""
    if not any(ln.split(" ", 1)[0] == target for ln in have.splitlines() if ln.strip()):
        import base64
        import hashlib
        key = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + hashlib.sha256(target.encode()).digest()).decode()
        with open(kh, "a") as fh:
            fh.write("{} ssh-ed25519 {}\n".format(target, key))
if ids:
    # the shell's echo of the command line (navi strips the NAVI_EXIT line; wrapped parts stay)
    print(cmd[:120])
    names = _qnames(cmd)
    if not names and "pkgver" in ids:
        names = re.findall(r"dpkg-query -W -f='[^']*' '([^']+)'", cmd.replace("'\"'\"'", "'"))[:1]
    for cid in ids:
        if cid == "cred":
            sudo = "needs_password" if target == "10.9.0.8" else "ok"
            section(cid, "svc\nuid=1001(svc) gid=1001(svc) groups=1001(svc)\nC2_SUDO=" + sudo)
        elif cid == "pathx":
            if "/etc/missing" in cmd:
                section(cid, "C2_PATH=missing")
            else:
                section(cid, "C2_PATH=exists\nC2_STAT=regular file|1234|root|root|644|1762560000\n"
                             "C2_SHA=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        elif cid == "updates":
            section(cid, "openssl/focal-updates 1.1.1f-1ubuntu2.20 amd64 [upgradable from: 1.1.1f-1ubuntu2.16]\n"
                         "C2_UPDATES=available", 0)
        elif PROF and probe(cid, names) is not None and not (cid == "os" and target.startswith("10.9.0.")):
            section(cid, probe(cid, names), 0)
        else:
            section(cid, CANNED.get(cid, cid + " output " + TOKEN), 0)
    print(TOKEN)
    print("  [OK] {}: exit 0".format(target))
    sys.exit(0)

# free-form / remediation commands
c = cmd or ""
if '"C2""_OUT"' in c:
    print("C2_OUT")                       # the marker C2 prints before a wrapped plan command
if target == "10.9.0.9":
    print("bash: oops " + TOKEN)
    print("  [FAIL] {}: exit 2".format(target))
    sys.exit(0)
if target == "10.9.0.10" and ("dpkg-query" in c or "rpm -q" in c):
    print("dpkg-query: no packages found matching openssl")
    print("  [FAIL] {}: exit 1".format(target))
    sys.exit(0)
if target == "10.9.0.11" and "--only-upgrade" in c:
    print("E: Could not get lock /var/lib/dpkg/lock-frontend " + TOKEN)
    print("  [FAIL] {}: exit 100".format(target))
    sys.exit(0)


def done(rc=0):
    print("  [{}] {}: exit {}".format("OK" if rc == 0 else "FAIL", target, rc))
    sys.exit(0)


if PROF and not target.startswith("10.9.0."):
    m = re.search(r"dpkg-query -W -f='\$\{Version\}\\n' '([^']+)'", c) or re.search(r"rpm -q --qf '[^']*' '([^']+)'", c)
    if m:
        vs = inst(m.group(1))
        if not vs:
            print("dpkg-query: no packages found matching " + m.group(1) if PROF["fam"] == "apt" else "package {} is not installed".format(m.group(1)))
            done(1)
        for v in vs:
            print(v if PROF["fam"] == "apt" or ":" in v else "(none):" + v)
        done(0)
    if re.search(r"apt-get update|apt-get install|dnf -y upgrade|yum (?:--setopt=exit_on_lock=1 )?-y update|"
                 r"zypper --non-interactive update|--allow-downgrades|dnf -y downgrade|"
                 r"yum (?:--setopt=exit_on_lock=1 )?-y downgrade|--oldpackage", c):
        if PROF.get("lockmoved") and "--only-upgrade" in c:
            if SF:
                open(SF, "w").close()                         # the packages moved …
            print("E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 2345 (unattended-upgr) " + TOKEN)
            done(100)                                         # … yet the step's last word is a lock refusal
        if PROF.get("lockafter") and not (SF and os.path.exists(SF + ".lockgone")):
            if SF:
                open(SF + ".lockgone", "w").close()           # yum-cron finishes; the next attempt gets the lock
            if "--setopt=exit_on_lock=1" in c:
                print("Existing lock /var/run/yum.pid: another copy is running as pid 4321. " + TOKEN)
                print("Another app is currently holding the yum lock; exiting as configured by exit_on_lock")
                done(200)
            print("Another app is currently holding the yum lock; waiting for it to exit...")
            print("  [!] {}: timed out waiting for the command to finish".format(target))
            sys.exit(0)
        b = PROF.get("busy")
        if b and PROF["fam"] == "apt" and PROF.get("aptver", "9") < "1.9":
            print("E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process {} ({})".format(b[1], b[0]))
            done(100)
        if "--only-upgrade" in c and any("'{}'".format(h) in c for h in PROF.get("held", [])):
            print("The following held packages will be changed:\n  openssl\nE: Held packages were changed and -y was used "
                  "without --allow-change-held-packages.")
            done(100)
        if re.search(r"--allow-downgrades|downgrade|--oldpackage", c):
            if SF and os.path.exists(SF):
                os.remove(SF)
            print("Downgrading … " + TOKEN)
            done(0)
        if "apt-get update" in c:
            print("Reading package lists... Done " + TOKEN)
            done(0)
        moved = [n for n, v in PROF["pkgs"].items() if v[1] != v[0] and "'{}'".format(n) in c]
        if moved and SF:
            open(SF, "w").close()
        for n in PROF["pkgs"]:
            if "'{}'".format(n) in c:
                v = PROF["pkgs"][n]
                print(("Unpacking {} ({}) over ({}) ...".format(n, v[1], v[0]) if v[1] != v[0] else
                       "{} is already the newest version ({}).".format(n, v[0])) + " " + TOKEN)
        done(0)
if "dpkg-query" in c:
    print("1.1.1f-1ubuntu2.20" if fixed else "1.1.1f-1ubuntu2.16")
elif "apt-get install" in c:
    print("Unpacking openssl (1.1.1f-1ubuntu2.20) over (1.1.1f-1ubuntu2.16) ... " + TOKEN)
    if state:
        open(state + "." + target, "w").close()
else:
    print("remote says hi " + TOKEN)
print("  [OK] {}: exit 0".format(target))
