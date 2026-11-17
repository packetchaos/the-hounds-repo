"""Regression tests for the second pre-release security sweep (review2 "sec").

1. The user-SQL pre-check lexer (agents/explore/api.py _bare, shared by the Software hound's
   run_sql) is linear on an unclosed '[' — before, each '[' rescanned the rest of the text
   (O(n²) inside `re`, which holds the GIL), so one ~300 KB request froze the whole console
   for ~17 s and an 80 MB one for days. Its answers for well-formed SQL are unchanged, and an
   unclosed '[' can't hide a ';' or a write keyword.
2. (unchanged controls, re-checked) Release the Hounds: turning the schedule on and Run now
   need confirm === true AND a loopback caller.

Run: python3 tests/test_review2_sec.py   (exit 0 = pass)
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="review2_sec_")
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
os.environ.setdefault("NAVI_TAGLOG_DB", os.path.join(TMP, "t.db"))
os.environ["HOUNDS_CONFIG"] = "off"

FAILS = []


def check(ok, msg):
    print(("PASS " if ok else "FAIL ") + msg)
    if not ok:
        FAILS.append(msg)


# ── 1. _bare is linear on an unclosed '[' ─────────────────────────────────────────────────
code = ("import sys,time; sys.path.insert(0, %r)\n"
        "from agents.explore.api import _bare\n"
        "t=time.time(); _bare('select ' + '[a' * 1000000); print(round(time.time()-t, 2))" % ROOT)
try:
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
    secs = float((r.stdout or "").strip() or "999")
    check(r.returncode == 0 and secs < 5, "_bare on 1,000,000 unclosed '[' finishes fast (%.2f s)" % secs)
except subprocess.TimeoutExpired:
    check(False, "_bare on 1,000,000 unclosed '[' finishes fast (timed out after 30 s — quadratic)")

from agents.explore.api import _bare, _safe_select           # noqa: E402
from agents.software import api as sw_api                     # noqa: E402

import re                                                    # noqa: E402
_OLD = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"|`(?:[^`]|``)*`|\[[^\]]*\]|--[^\n]*|/\*.*?(?:\*/|$)", re.S)


def _old_bare(s):          # the build-476 lexer, for well-formed input only
    return _OLD.sub(lambda m: "''" if m.group(0)[0] == "'" else (m.group(0) if m.group(0)[0] in '"`[' else " "), s)


for src in ("select [name] from assets where x like '%update%' -- drop\n limit 5",
            "select \"a;b\", `c` from t /* ; */ where y = 'it''s'",
            "select [a]] from t", "select [x;y], '[' from t where z like '%]%'",
            "with c as (select 1) select * from c /* unclosed"):
    check(_bare(src) == _old_bare(src), "_bare unchanged for well-formed SQL: %r" % src[:40])

for bad in ("select [x from t; delete from assets",
            "select [x from t ' ; drop table assets '",
            "select [x /* update */ from t"):
    s, err = _safe_select(bad)
    check(s is None and bool(err), "explore pre-check refuses %r (%s)" % (bad[:40], err))
    s, err = sw_api._safe_select(bad)
    check(s is None and bool(err), "software pre-check refuses %r" % bad[:40])

s, err = _safe_select("select hostname from assets where hostname like '%[%'")
check(err is None and s.endswith("LIMIT 500"), "a '[' inside a string literal still gets the LIMIT")

# ── 2. release pipeline gates (unchanged — re-checked) ────────────────────────────────────
from core import gates, release_pipeline                     # noqa: E402
from agents.contract import api as contract_api              # noqa: E402

ON = {"config": {"enabled": True, "daily": True}}
for p, want in ((dict(ON), 400), (dict(ON, confirm="true"), 400), (dict(ON, confirm=1), 400)):
    body, code_ = contract_api.release_save(p)
    check(code_ == want and not release_pipeline.config()["enabled"],
          "release_save ON with confirm=%r → %d" % (p.get("confirm"), code_))
    body, code_ = contract_api.release_run(p)
    check(code_ == want and release_pipeline.state().get("status") != "running",
          "release_run with confirm=%r → %d" % (p.get("confirm"), code_))
tok = gates.set_client("192.0.2.9", http=True)
try:
    body, code_ = contract_api.release_save(dict(ON, confirm=True))
    check(code_ == 403 and not release_pipeline.config()["enabled"], "release_save ON from a remote peer → 403")
    body, code_ = contract_api.release_run({"confirm": True})
    check(code_ == 403 and release_pipeline.state().get("status") != "running", "release_run from a remote peer → 403")
finally:
    gates.reset_client(tok)
release_pipeline.scheduler_stop()

print("\n%d failure(s)" % len(FAILS))
sys.exit(1 if FAILS else 0)
