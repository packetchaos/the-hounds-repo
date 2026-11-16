"""Regression tests for Tag Removal (Garmr) — build 450.

navi (≤ 8.8.2) exits 0 from `navi enrich tag --c C --v V -remove` whether or not it stripped
anything, and its -remove branch overwrites its asset list with every tag in Tenable, so its
LAST line is a junk "Your tag is being updated". The Hounds used to report every removal as
"tag cleared". Now a removal is judged by what navi printed for it:
  - "Your tag is being removed from all assets" + "Job UUID : …"   → ok (job ids reported)
  - "…removed…" + "The Query did not yield any results"             → NOT ok (navi.db has no assets)
  - no removal line at all (tag not found in Tenable)              → NOT ok
Also: the tail of navi's output is kept per job (tag_jobs.db `output`), is NOT shipped in the
job list (has_output flag only), is fetched on demand (explore action tag_job_output), and has
secrets scrubbed. Uses a fake NAVI_BIN that prints navi 8.8.2's exact lines — no Tenable.
Run: python3 tests/test_tagremoval.py"""
import atexit
import json
import os
import shutil
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-garmr-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ["HOUNDS_CONFIG"] = os.path.join(TMP, "cfg.json")
os.environ["NAVI_TAGLOG_DB"] = os.path.join(TMP, "taglog.db")
os.environ["NAVI_DB_PATH"] = os.path.join(TMP, "navi.db")
os.environ["NAVI_ALLOW_WRITES"] = "1"
open(os.environ["NAVI_DB_PATH"], "w").close()

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


FAKE = os.path.join(TMP, "navi")
MODE = os.path.join(TMP, "mode")
ARGV = os.path.join(TMP, "argv.json")
with open(FAKE, "w") as f:
    f.write('''#!/usr/bin/env python3
import json, sys, os
json.dump(sys.argv[1:], open(%r, "w"))
mode = open(%r).read().strip()
if mode == "removed":        # navi 8.8.2 when the tag exists and navi.db has its assets
    print("\\nYour tag is being removed from all assets\\n")
    print("Job UUID : 7d1f0c2a-1111-2222-3333-444455556666")
    print("Your tag is being updated\\n")          # the junk follow-on add (clobbered tag_list)
    print("0.81")
elif mode == "chunked":
    for i in range(2):
        print("\\nYour tag is being removed from all assets\\n")
        print("Job UUID : aaaaaaaa-0000-0000-0000-00000000000%%d" %% i)
    print("Your tag is being updated\\n")
elif mode == "nodb":         # tag exists in Tenable, navi.db has no assets for it
    print("\\nYour tag is being removed from all assets\\n")
    print("\\nYou may need to update the navi DB.  The Query did not yield any results\\n")
    print("Your tag is being updated\\n")
elif mode == "notfound":     # no Tenable tag by that exact name — only the junk add runs
    print("Your tag is being updated\\n")
    print("0.42")
elif mode == "secret":
    print("\\nYour tag is being removed from all assets\\n")
    print("Job UUID : bbbbbbbb-0000-0000-0000-000000000001")
    print("debug key sk-ant-THISISNOTAREALKEY0123456789abcdef")
''' % (ARGV, MODE))
os.chmod(FAKE, os.stat(FAKE).st_mode | stat.S_IXUSR)
os.environ["NAVI_BIN"] = FAKE

from core import navi_cli, tagq  # noqa: E402


def run(mode, cat="Scan Health", val="Cred Failure"):
    open(MODE, "w").write(mode)
    return navi_cli._tag_exec(cat, val, remove=True)


# ---- the verdict, end to end through the real _tag_exec ----------------------------------
r = run("removed")
check(json.load(open(ARGV)) == ["enrich", "tag", "--c", "Scan Health", "--v", "Cred Failure", "-remove"],
      "a pure removal runs exactly `navi enrich tag --c <cat> --v <val> -remove`")
check(r["ok"] and r["removal"]["jobs"] == ["7d1f0c2a-1111-2222-3333-444455556666"]
      and "removal submitted to Tenable (job 7d1f0c2a" in r["message"],
      "navi printed the removal + a Job UUID → ok, and the message names the Tenable job")
check("being updated" not in r["message"], "the junk trailing 'Your tag is being updated' is not the message any more")
r = run("chunked")
check(r["ok"] and len(r["removal"]["jobs"]) == 2 and "2 chunks" in r["message"], "chunked removal (>1999 assets) reports each job")
r = run("nodb")
check(not r["ok"] and "navi.db has no assets" in r["message"] and r["message"].startswith("tag NOT removed"),
      "navi.db has no assets for the tag → NOT ok, says to refresh navi.db")
r = run("notfound")
check(not r["ok"] and "found no tag with this exact category : value" in r["message"],
      "no Tenable tag by that name (only the junk add ran) → NOT ok — the old code said 'tag cleared'")

# ---- a pure function, for the edge cases ------------------------------------------------
v = navi_cli.removal_verdict("", "")
check(not v["ok"], "empty navi output is not a removal")
v = navi_cli.removal_verdict("Your tag is being removed from all assets\n", "")
check(not v["ok"] and "no job id" in v["reason"], "removal started but no Job UUID → not ok (keys / permissions)")

# ---- additions are unaffected --------------------------------------------------------------
open(MODE, "w").write("removed")
r = navi_cli._tag_exec("Owner", "Team", query="SELECT 1")
check(r["ok"] and "removal" not in r, "an add (remove=False) is not judged by the removal verdict")

# ---- the job ledger keeps navi's output (scrubbed), lists only a flag, serves it on demand --
open(MODE, "w").write("secret")
job = tagq.submit(navi_cli._tag_exec, {"category": "Scan Health", "value": "Cred Failure", "remove": True},
                  {"agent": "tagremoval", "op": "remove", "category": "Scan Health", "value": "Cred Failure"})
import time  # noqa: E402
for _ in range(200):
    j = next((x for x in tagq.list_jobs() if x["id"] == job["id"]), {})
    if j.get("status") in ("done", "error"):
        break
    time.sleep(0.05)
check(j.get("status") == "done" and j.get("has_output") is True, "the finished job is flagged has_output")
check("output" not in j and "result" not in j, "the job list does not ship navi's output (it can be KBs per job)")
out = tagq.job_output(job["id"])
check("Your tag is being removed from all assets" in out and "-remove" in out, "job_output returns navi's command + output")
check("sk-ant-THISISNOTAREALKEY" not in out, "a key-like string in navi's output is scrubbed before it is stored")
check(tagq.job_output("x") == "" and tagq.job_output(10 ** 9) == "", "job_output: bad / unknown id → ''")

from agents.explore import api as ex_api  # noqa: E402
body, st = ex_api.tag_job_output({"id": job["id"]})
check(st == 200 and "being removed" in body["output"] and "tag_job_output" in ex_api.ACTIONS,
      "explore action tag_job_output serves one job's output")

page = open(os.path.join(ROOT, "web", "tags-log.html"), encoding="utf-8").read()
check("data-out=" in page and "tag_job_output" in page and "esc((o&&o.output)" in page,
      "Tagging log: a 'navi output' button fetches it and shows it escaped")

if __name__ == "__main__":
    print("\n%d failure(s)" % len(fails))
    sys.exit(1 if fails else 0)
