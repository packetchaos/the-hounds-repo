"""Draco — CIS benchmark control-index library.

Grounding for the natural-language authoring path: when someone asks for a whole
benchmark ("create a CIS Docker benchmark and tighten 5.x…"), Draco needs the
benchmark's control set to reproduce the right controls, in order, mapped to the
right frameworks — instead of drafting a handful from scratch.

What lives here is a *control index*, NOT Tenable/CIS check text: each control is
its number + a short imperative title + a topic + level + framework references (and
an optional one-line hint). The model (core.llm.benchmark_plan) turns that index
into concrete .audit checks and applies any per-control adjustments; with no model
key we still emit a structured scaffold so the file is a real starting point.

  IP note: these indexes carry control numbers, our own short titles, and framework
  mappings — not the copyrighted CIS recommendation/rationale prose. Verify against
  the official CIS Benchmark PDF before relying on the numbering for an assessment.

Library files: data/benchmarks/*.json (path via NAVI_BENCHMARKS_DIR).
Mirrors the core.iot_registry load pattern.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DIR = os.path.join(os.path.dirname(HERE), "data", "benchmarks")


def library_dir() -> str:
    return os.environ.get("NAVI_BENCHMARKS_DIR", DEFAULT_DIR)


def _load_file(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            b = json.load(f)
    except Exception:
        return None
    if not isinstance(b, dict) or not b.get("id") or not isinstance(b.get("controls"), list):
        return None
    b.setdefault("platform", "Unix")
    b.setdefault("aliases", [])
    b.setdefault("sections", [])
    b.setdefault("version", "")
    b.setdefault("note", "")
    return b


def _all() -> list:
    d = library_dir()
    out = []
    if not os.path.isdir(d):
        return out
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".json"):
            continue
        b = _load_file(os.path.join(d, fn))
        if b:
            out.append(b)
    return out


def catalog() -> list:
    """Lightweight list for the page — no control bodies."""
    out = []
    for b in _all():
        out.append({"id": b["id"], "name": b.get("name") or b["id"],
                    "platform": b.get("platform", "Unix"), "version": b.get("version", ""),
                    "aliases": b.get("aliases", []),
                    "sections": [s.get("title") for s in b.get("sections", [])],
                    "section_count": len(b.get("sections", [])),
                    "control_count": len(b.get("controls", [])),
                    "note": b.get("note", "")})
    return out


def get(bid: str) -> dict | None:
    bid = (bid or "").strip().lower()
    for b in _all():
        if b["id"].lower() == bid:
            return b
    return None


def match(text: str) -> dict | None:
    """Best benchmark for a free-text request. Scores on id/name/alias token overlap.
    'create a cis docker benchmark' -> the docker index."""
    t = (text or "").lower()
    if not t:
        return None
    best, best_score = None, 0
    for b in _all():
        score = 0
        terms = [b["id"].replace("_", " "), (b.get("name") or "")] + list(b.get("aliases", []))
        for term in terms:
            term = (term or "").lower().strip()
            if not term:
                continue
            if term in t:
                score = max(score, len(term))          # longest phrase hit wins
            else:
                toks = [w for w in term.split() if len(w) > 2 and w not in ("cis", "benchmark", "linux")]
                if toks and all(w in t for w in toks):
                    score = max(score, sum(len(w) for w in toks))
        if score > best_score:
            best, best_score = b, score
    return best


def section_filter(bench: dict, text: str) -> list:
    """If the request names a section (number or title keyword), return only those
    controls; else all. Lets 'CIS Docker runtime section' scope the draft."""
    controls = bench.get("controls", [])
    t = (text or "").lower()
    secs = bench.get("sections", [])
    picked = set()
    for s in secs:
        num = str(s.get("num", "")).strip()
        title = (s.get("title") or "").lower()
        if num and (f"section {num}" in t or f"section {num}." in t):
            picked.add(num)
        else:
            kws = [w for w in title.replace("/", " ").split() if len(w) > 3
                   and w not in ("configuration", "config", "docker", "and", "the", "file", "files")]
            if kws and any(w in t for w in kws) and ("section" in t or "only" in t):
                picked.add(num)
    if not picked:
        return controls
    return [c for c in controls if str(c.get("num", "")).split(".")[0] in picked] or controls
