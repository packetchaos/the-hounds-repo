#!/usr/bin/env python3
"""A stricter fake `navi` for tests/test_c2.py: it applies navi's REAL command handling
(plugins/action.py build_remote_command + clean_output_and_exit_code, copied verbatim) and then
RUNS the resulting line locally with `sh -c`, with $C2_STUB_BIN first on PATH so the package
tools (dpkg-query, apt-get, rpm, sudo, systemctl) are harmless stubs written by the test.

That reproduces what a real host sees: navi rewrites the FIRST `\\bsudo\\b` anywhere in the
command, appends `; echo NAVI_EXIT:$?` on the same line and drops every output line containing
NAVI_EXIT (so output without a trailing newline vanishes). Logs argv to $FAKE_NAVI_LOG.
"""
import json
import os
import re
import subprocess
import sys

NAVI_EXIT_SENTINEL = "NAVI_EXIT"
NAVI_SUDO_PROMPT = "NAVI_SUDO_PROMPT:"


def clean_output_and_exit_code(raw):
    exit_code = None
    match = re.search(NAVI_EXIT_SENTINEL + r":(\d+)", raw)
    if match:
        exit_code = int(match.group(1))
    cleaned = "\n".join(line.replace(NAVI_SUDO_PROMPT, "") for line in raw.splitlines()
                        if NAVI_EXIT_SENTINEL not in line).strip("\r\n")
    return cleaned, exit_code


def sudo_prompt_argument():
    head, tail = NAVI_SUDO_PROMPT[:9], NAVI_SUDO_PROMPT[9:]
    return "'{}''{}'".format(head, tail)


def build_remote_command(command, add_sentinel=True):
    needs_sudo = re.search(r"\bsudo\b", command) is not None
    effective = (re.sub(r"\bsudo\b", "sudo -k -p {}".format(sudo_prompt_argument()), command, count=1)
                 if needs_sudo else command)
    if add_sentinel:
        effective = "{} ; echo {}:$?".format(effective, NAVI_EXIT_SENTINEL)
    return effective, needs_sudo


a = sys.argv[1:]
if os.environ.get("FAKE_NAVI_LOG"):
    with open(os.environ["FAKE_NAVI_LOG"], "a") as f:
        f.write(json.dumps(a) + "\n")


def opt(n):
    return a[a.index(n) + 1] if n in a else None


t, cmd = opt("--target"), opt("--command")
print("\n>> Running on {}: {}".format(t, cmd))
eff, _ = build_remote_command(cmd)
env = dict(os.environ, PATH=os.environ.get("C2_STUB_BIN", "") + ":" + os.environ["PATH"], C2_TARGET=t or "")
raw = subprocess.run(["sh", "-c", eff], capture_output=True, text=True, env=env, timeout=60).stdout
out, ec = clean_output_and_exit_code(raw)
if out:
    print(out)
if ec is None:
    print("  [?] {}: command ran but the exit status could not be read".format(t))
elif ec == 0:
    print("  [OK] {}: exit 0".format(t))
else:
    print("  [FAIL] {}: exit {}".format(t, ec))
