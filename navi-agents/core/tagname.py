"""Tag names — the one place that decides what tag CATEGORY a Hound writes and reads.

Settings → **Test run** (``NAVI_TAG_TEST_RUN=1``) prefixes every tag CATEGORY the
Hounds create with ``<phrase>-`` (Settings → **Prefix phrase**, ``NAVI_TAG_PREFIX``,
default ``Hounds``), so a trial run is easy to tell apart and to clean up:

    Lifecycle : Unsupported   →   Hounds-Lifecycle : Unsupported

Rules (see CONTRIBUTING.md → "Test run"):
  • Only the category (Tenable tag key) is prefixed — never the value.
  • Never double-prefixed: a category already starting with the prefix is kept as is.
  • WRITES go through ``effective(category)`` — core.navi_cli.tag/_tag_exec do it for
    every add, so agents need no change. A REMOVAL (``remove=True``, Garmr / the
    contract's removal phase) is always EXACT — the name is used as given.
  • EXEMPT categories are never prefixed: ``NO`` (the ``NO : UPDATE`` ACR-protection tag
    navi's ``enrich acr`` honours by exact, case-sensitive match — a ``Hounds-NO`` tag would
    protect nothing). See core/acr_protect.py.
  • ACR (``navi enrich acr --c``) is exact too; a Hound that raises ACR on a tag it
    created itself (AI ACR Raise) passes ``effective(...)`` explicitly.
  • READS that recognise a Hound's own output or a signal (Owner, Lifecycle, CISA KEV…)
    match BOTH the base name and the configured prefixed name — always, whether the
    test run is on or off — so human-written tags still count and test-run tags are
    recognised until they are cleaned up. Helpers: ``names()``, ``sql_in()``,
    ``sql_lit()``, ``sql_base()``, ``base()``. Display always shows the real name.

The phrase is validated: 1–24 chars, letters / digits / space / underscore only (so it
is always safe inside a quoted SQL literal and a shell word). The "-" is ours.
"""
import os
import re

ENV_ON = "NAVI_TAG_TEST_RUN"
ENV_PHRASE = "NAVI_TAG_PREFIX"
DEFAULT_PHRASE = "Hounds"
SEP = "-"
MAX_LEN = 24
_TRUE = ("1", "true", "yes", "on", "y", "t", "enabled")
_OK_RE = re.compile(r"^[A-Za-z0-9 _]{1,%d}$" % MAX_LEN)

# Categories a Hound always writes EXACTLY, test run or not. "NO" is navi's ACR-protection
# category (tag NO : UPDATE → `navi enrich acr` skips the asset); navi matches it exactly and
# case-sensitively, so a prefixed name would silently protect nothing. Exact match only.
EXEMPT = frozenset({"NO"})


def is_exempt(category) -> bool:
    """True for a category that is never test-run prefixed (exact, case-sensitive)."""
    return category is not None and str(category) in EXEMPT


def normalize_phrase(raw):
    """(ok, phrase, error). Strips surrounding spaces and any trailing '-' the user typed
    (we always add the separator ourselves). Blank → the default phrase."""
    s = str("" if raw is None else raw).strip()
    s = s.rstrip("-– ").strip()
    if not s:
        return True, DEFAULT_PHRASE, ""
    if not _OK_RE.match(s):
        return False, s, ("Prefix phrase must be 1–%d characters: letters, digits, spaces or _ only "
                          "(the '-' separator is added for you)." % MAX_LEN)
    # a phrase that starts a real category ('Audit' vs 'Audit-Vuln Link') would make that
    # category look already-prefixed: it would never be prefixed, and its owner couldn't write it
    clash = [c for c in _known_categories() if c.lower().startswith((s + SEP).lower())]
    if clash:
        return False, s, ("'%s-' is how the category '%s' already starts — pick a phrase that "
                          "isn't the start of a Hound tag category." % (s, clash[0]))
    return True, s, ""


def _known_categories():
    try:
        from core import activity
        return sorted({c for cats in activity.DEFAULT_CATEGORIES.values() for c in cats if c})
    except Exception:
        return []


def enabled() -> bool:
    """Settings → Test run is ON (read live from the environment)."""
    return (os.environ.get(ENV_ON) or "").strip().lower() in _TRUE


def phrase() -> str:
    """The configured phrase (default 'Hounds'); an invalid stored value falls back."""
    ok, p, _ = normalize_phrase(os.environ.get(ENV_PHRASE))
    return p if ok else DEFAULT_PHRASE


def configured_prefix() -> str:
    """'<phrase>-' — what reads recognise, whether the test run is on or off."""
    return phrase() + SEP


def prefix() -> str:
    """The prefix WRITES apply right now: '<phrase>-' while the test run is on, else ''."""
    return configured_prefix() if enabled() else ""


def _has_prefix(category, pfx) -> bool:
    return bool(pfx) and str(category or "").lower().startswith(pfx.lower())


def effective(category):
    """The category a Hound WRITES. Unchanged when the test run is off, when blank, or
    when it already carries the prefix (never double-prefixed), or for an EXEMPT category."""
    if category is None or is_exempt(category):
        return category
    c = str(category)
    pfx = prefix()
    if not pfx or not c.strip() or _has_prefix(c, pfx):
        return category
    return pfx + c


def base(category):
    """The base name of a (possibly prefixed) category: 'Hounds-Owner' → 'Owner'.
    Anything else is returned unchanged."""
    c = "" if category is None else str(category)
    pfx = configured_prefix()
    return c[len(pfx):] if _has_prefix(c, pfx) and len(c) > len(pfx) else c


def is_prefixed(category) -> bool:
    c = "" if category is None else str(category)
    return _has_prefix(c, configured_prefix()) and len(c) > len(configured_prefix())


def names(*categories) -> list:
    """Every name a reader should match for these base categories: base + prefixed,
    order-preserving, de-duplicated."""
    out = []
    pfx = configured_prefix()
    for c in categories:
        if c is None:
            continue
        b = base(c)
        for n in (b, pfx + b):
            if n not in out:
                out.append(n)
    return out


def sql_in(col, *categories):
    """('<col> IN (?,?,…)', params) matching base + prefixed names."""
    ns = names(*categories)
    return "%s IN (%s)" % (col, ",".join("?" * len(ns))), tuple(ns)


def _lit(s):
    return "'" + str(s).replace("'", "''") + "'"


def sql_lit(col, *categories, lower=False):
    """'<col> IN ('Owner','Hounds-Owner')' with inline literals — for SQL built without
    params. lower=True lower-cases the literals (for lower(<col>) IN (…))."""
    ns = names(*categories)
    if lower:
        seen = []
        for n in ns:
            if n.lower() not in seen:
                seen.append(n.lower())
        ns = seen
    return "%s IN (%s)" % (col, ",".join(_lit(n) for n in ns))


def sql_base(col):
    """SQL expression for the BASE name of a tag-key column — strips the configured
    prefix (case-insensitive), so 'lower(<expr>) LIKE ''attack path%''' style tests
    work unchanged on prefixed tags."""
    pfx = configured_prefix()
    n = len(pfx)
    return ("(CASE WHEN lower(substr(%s,1,%d))=%s AND length(%s)>%d THEN substr(%s,%d) ELSE %s END)"
            % (col, n, _lit(pfx.lower()), col, n, col, n + 1, col))


def example(category="Lifecycle", value="EOL") -> str:
    """'Lifecycle : EOL → Hounds-Lifecycle : EOL' — the live example for Settings."""
    return "%s : %s → %s%s : %s" % (category, value, configured_prefix(), category, value)


def status() -> dict:
    """What /api/health, Settings and the pages read."""
    return {"enabled": enabled(), "phrase": phrase(), "prefix": prefix(),
            "configured_prefix": configured_prefix(), "default_phrase": DEFAULT_PHRASE,
            "env": ENV_ON, "env_phrase": ENV_PHRASE, "example": example()}
