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
  10.9.0.11  remediation step exits 100 (fails)
  anything else → ok (generic)

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


ids = re.findall(r'"C2""_BEGIN=([a-z0-9_]+)"', cmd or "")
if ids:
    # the shell's echo of the command line (navi strips the NAVI_EXIT line; wrapped parts stay)
    print(cmd[:120])
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
state = os.environ.get("FAKE_NAVI_STATE")
fixed = bool(state and os.path.exists(state + "." + target))
if "dpkg-query" in c:
    print("1.1.1f-1ubuntu2.20" if fixed else "1.1.1f-1ubuntu2.16")
elif "apt-get install" in c:
    print("Unpacking openssl (1.1.1f-1ubuntu2.20) over (1.1.1f-1ubuntu2.16) ... " + TOKEN)
    if state:
        open(state + "." + target, "w").close()
else:
    print("remote says hi " + TOKEN)
print("  [OK] {}: exit 0".format(target))
