"""Regression tests — builds 469–470: the Meet-the-Hound one-pagers and the in-app intro
come from ONE source (tools/hound_pages/<id>.json) and stay in sync.

  · every visible hound has a content file and a one-pager (web/hounds/<id>.html);
  · each one-pager is exactly what tools/hound_pages.py renders from its content file;
  · console.js's AGENT_INTRO is exactly what `tools/hound_pages.py --intro` generates;
  · no lore line repeats the mythology errors fixed in build 470.
Run: python3 tests/test_hound_pages_469.py"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import hound_pages as hp  # noqa: E402

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


visible = []
for a in sorted(os.listdir(os.path.join(ROOT, "agents"))):
    m = os.path.join(ROOT, "agents", a, "manifest.json")
    if os.path.exists(m) and not json.load(open(m, encoding="utf-8")).get("hidden"):
        visible.append(a)
missing = [a for a in visible if not os.path.exists(os.path.join(hp.SRC, a + ".json"))
           or not os.path.exists(os.path.join(hp.OUT, a + ".html"))]
check(not missing, "every visible hound has a content file and a one-pager (%d hounds; missing %s)" % (len(visible), missing))

stale = [a for a in visible if a not in missing
         and open(os.path.join(hp.OUT, a + ".html"), encoding="utf-8").read() != hp.render(a)]
check(not stale, "every one-pager matches its content file (re-run tools/hound_pages.py: %s)" % stale)

src = open(hp.CONSOLE, encoding="utf-8").read()
i = src.index(hp.INTRO_START)
j = src.index(hp.INTRO_END, i)
check(src[i:j] == hp.intro_block(src[i:j]), "AGENT_INTRO matches the content files (re-run tools/hound_pages.py --intro)")

for bad in ("Aztec dog-god", "Cavall Panoptes", "Tiresias</b>, the detective"):
    check(bad not in src, "hub lore no longer says %r" % bad)
for a in visible:
    c = json.load(open(os.path.join(hp.SRC, a + ".json"), encoding="utf-8"))
    need = {"codename", "discipline", "category", "tagline", "lore", "problem", "does", "capabilities", "how",
            "who", "better", "cta"}
    if need - set(c):
        check(False, "%s content file has every field (missing %s)" % (a, sorted(need - set(c))))
print("\n%d failure(s)" % len(fails))
sys.exit(1 if fails else 0)
