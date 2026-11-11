"""Gated write path — shells out to the real `navi` CLI for tag writes.

Two gates protect every write, mirroring the navi-mcp write-gate convention:
  1. NAVI_ALLOW_WRITES=1 must be set in the server environment.
  2. The API caller must pass confirm=True (enforced in service.py / the UI).

Reads never come through here — they use db.py (read-only sqlite3).
"""
import os
import re
import shlex
import shutil
import subprocess
import time

from . import tagname

NAVI_BIN = os.environ.get("NAVI_BIN", "navi")

_TRUE = {"1", "true", "yes", "on", "y", "t", "enabled"}

# Repo root (the folder that holds app_stdlib.py / core/ / agents/).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Env-independent opt-in: drop any of these files in the repo root to enable writes,
# for when environment variables don't reach the server process (systemd, a .env that
# isn't loaded, a different shell, etc.). `touch ALLOW_WRITES` and restart.
_ENABLE_FILES = ("ALLOW_WRITES", ".allow_writes", "allow_writes")


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in _TRUE


def _enable_file() -> str:
    for fn in _ENABLE_FILES:
        p = os.path.join(_REPO_ROOT, fn)
        if os.path.exists(p):
            return p
    return ""


def allow_writes() -> bool:
    """Writes are allowed when the operator has opted in. Honored, in order:
      1. NAVI_ALLOW_WRITES / NAVI_MCP_ALLOW_WRITES env var set to any truthy value
         (1/true/yes/on) — not just the literal "1".
      2. An ALLOW_WRITES file in the repo root — an env-independent escape hatch for
         when environment variables don't reach the server process."""
    return (_truthy(os.environ.get("NAVI_ALLOW_WRITES"))
            or _truthy(os.environ.get("NAVI_MCP_ALLOW_WRITES"))
            or bool(_enable_file()))


def write_status() -> dict:
    """Everything the operator needs to see why writes are (not) allowed."""
    return {"writes_enabled": writes_enabled(),
            "allow_writes": allow_writes(),
            "reason": write_gate_reason(),
            "NAVI_ALLOW_WRITES": os.environ.get("NAVI_ALLOW_WRITES"),
            "NAVI_MCP_ALLOW_WRITES": os.environ.get("NAVI_MCP_ALLOW_WRITES"),
            "enable_file": _enable_file() or None,
            "navi_resolved": _resolve_navi(),
            "NAVI_BIN": os.environ.get("NAVI_BIN"),
            "repo_root": _REPO_ROOT,
            "read_navi_db": _read_db_path(),
            "navi_cli_cwd": _navi_cwd()}


def _read_db_path():
    try:
        from core import db
        p = db.db_path()
        return os.path.abspath(p) if p else None
    except Exception:
        return None


# Where navi commonly lands when it isn't on the server process's PATH (pipx / user
# installs / Homebrew / pyenv shims). Checked as a fallback so a narrow PATH doesn't
# wrongly report navi as missing.
_COMMON_NAVI = [
    os.path.expanduser("~/.local/bin/navi"),
    "/usr/local/bin/navi", "/usr/bin/navi", "/bin/navi",
    "/opt/homebrew/bin/navi", "/opt/navi/bin/navi",
    os.path.expanduser("~/.pyenv/shims/navi"),
]


def _resolve_navi():
    """Full path to the navi CLI, or None. Honors an explicit absolute NAVI_BIN,
    then PATH (shutil.which), then the common install locations."""
    b = os.environ.get("NAVI_BIN")
    if b and os.path.isabs(b) and os.path.exists(b):
        return b
    found = shutil.which(NAVI_BIN)
    if found:
        return found
    for p in _COMMON_NAVI:
        if os.path.exists(p):
            return p
    return None


def _navi_cwd():
    """The directory the navi CLI should run in — the folder that HOLDS the navi.db
    the repo reads (NAVI_DB_PATH). navi keeps a cwd-local navi.db, so running it here
    makes `navi enrich tag --query` hit the SAME database the agents discovered from
    (otherwise reads and writes target two different navi.db files and tags land on
    nothing). Overridable with NAVI_CWD."""
    override = os.environ.get("NAVI_CWD")
    if override and os.path.isdir(override):
        return override
    try:
        from core import db
        p = db.db_path()
        if p and p != ":memory:":
            d = os.path.dirname(os.path.abspath(p))
            if os.path.isdir(d):
                return d
    except Exception:
        pass
    return None


def write_gate_reason() -> str:
    """Precise reason writes can't run right now — '' means they can. Lets the UI
    show the RIGHT fix instead of always blaming the NAVI_ALLOW_WRITES flag."""
    if not allow_writes():
        return ("writes disabled on server — set NAVI_ALLOW_WRITES=1 (or NAVI_MCP_ALLOW_WRITES=1), "
                "or if the env var isn't reaching the server, create an empty file named "
                "ALLOW_WRITES in the repo root and restart")
    if not navi_available():
        return ("writes are enabled, but the navi CLI was not found — set NAVI_BIN to its full "
                "path, e.g. NAVI_BIN=/usr/local/bin/navi")
    return ""


def update_async(kinds=("assets",)) -> dict:
    """Kick `navi config update <kind>` in the BACKGROUND and return immediately —
    fire-and-forget. On large tenants a sync can take many minutes; we detach the
    process (new session, output discarded) so nothing waits on it. This is a local
    read-sync from Tenable into navi.db, not a tenant write, so it isn't write-gated."""
    if not navi_available():
        return {"ok": False, "started": [], "message": f"navi binary '{NAVI_BIN}' not on PATH"}
    started = []
    for k in kinds:
        try:
            subprocess.Popen([(_resolve_navi() or NAVI_BIN), "config", "update", k],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             cwd=_navi_cwd(), start_new_session=True)
            started.append(k)
        except Exception:
            pass
    return {"ok": bool(started), "started": started}


def optimize_async() -> dict:
    """Kick `navi config optimize` in the background — builds SQL indexes on navi.db
    so tag/query ops go from minutes to seconds on large datasets. Fire-and-forget."""
    if not navi_available():
        return {"ok": False, "message": f"navi binary '{NAVI_BIN}' not on PATH"}
    try:
        subprocess.Popen([(_resolve_navi() or NAVI_BIN), "config", "optimize"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         cwd=_navi_cwd(), start_new_session=True)
        return {"ok": True, "started": True}
    except Exception as e:
        return {"ok": False, "message": str(e)}


def navi_available() -> bool:
    return _resolve_navi() is not None


def writes_enabled() -> bool:
    """The gate the UI shows: the operator opted in. navi-CLI presence is verified at
    write time and surfaced as a precise per-tag error if it's genuinely missing — so
    enabling writes is never silently swallowed by a PATH quirk."""
    return allow_writes()


def _navi_summary(stdout, stderr):
    """The most informative line of navi's output — shown in the Tagging log so the
    operator sees what navi actually did (e.g. how many assets it tagged), not just
    a generic 'applied'."""
    text = (stdout or "").strip() or (stderr or "").strip()
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return ""
    # prefer a line that mentions assets/tag/created; else the last non-empty line
    for ln in reversed(lines):
        low = ln.lower()
        if any(k in low for k in ("asset", "tag", "created", "added", "job")):
            return ln[:300]
    return lines[-1][:300]


def removal_verdict(stdout, stderr=""):
    """Did `navi enrich tag ... -remove` really strip the tag? Read navi's own lines:
      "Your tag is being removed from all assets" — navi found the tag in Tenable and
          posted the unassign (followed by "Job UUID : <id>" per chunk of ≤1999 assets);
      "The Query did not yield any results" — navi.db holds no assets for that tag (stale
          navi.db, or the tag is already empty);
      neither — navi found no Tenable tag with that exact category : value.
    Returns {ok, jobs:[uuid…], reason}."""
    text = (stdout or "") + "\n" + (stderr or "")
    low = text.lower()
    started = "being removed from all assets" in low
    jobs = re.findall(r"job uuid\s*:\s*([0-9a-f-]{8,})", text, re.I)
    if started and "did not yield any results" in low and not jobs:
        return {"ok": False, "jobs": [], "reason": "navi.db has no assets carrying this tag, so navi had "
                "nothing to strip. Refresh navi.db (navi config update assets) and run the removal again."}
    if started and jobs:
        return {"ok": True, "jobs": jobs[:20], "reason": ""}
    if started:
        return {"ok": False, "jobs": [], "reason": "navi started the removal but Tenable returned no job id — "
                "check the navi output below (API keys / permissions / rate limit)."}
    return {"ok": False, "jobs": [], "reason": "navi found no tag with this exact category : value in Tenable "
            "(names are matched exactly, ignoring case) — it may already be deleted, or renamed."}


def _selector_summary(query, cve, plugin_name, scanid, plugin, output, route_id,
                      group="", xrefs="", xid="", cpe="", port="", regex=False):
    if cve:
        return "cve", cve
    if cpe:
        return "cpe", cpe
    if plugin_name:
        return "name", plugin_name
    if scanid:
        return "scanid", str(scanid)
    if plugin:
        m = "~=" if regex else "~"
        return ("plugin", f"{plugin}" + (f" output{m}{output}" if output else ""))
    if port:
        return "port", str(port)
    if route_id:
        return "route_id", str(route_id)
    if group:
        return "group", str(group)
    if xrefs:
        return "xref", str(xrefs) + (" / " + str(xid) if xid else "")
    return "query", _query_summary(query)


def _query_summary(q, cap=180):
    """Readable one-line summary of a --query selector for the Tagging log. A raw slice of a
    long `... IN ('a','b',… )` list looked like *broken* SQL (unclosed paren) in the log, so
    collapse the IN-list to its count instead of cutting it mid-token."""
    q = " ".join((q or "").split())
    if len(q) <= cap:
        return q
    m = re.search(r"\bIN\s*\(\s*'", q, re.I)
    if m:
        inner = q[m.end() - 1:]                      # from the first quote
        n = inner.count("','") + 1                   # quoted, comma-separated values
        head = q[:m.start()].rstrip()
        return f"{head} IN (… {n} values)"
    return q[:cap - 1] + "…"


def tag(category: str, value: str, query: str = "", remove: bool = False,
        cve: str = "", plugin_name: str = "", scanid: str = "",
        plugin: str = "", output: str = "", route_id: str = "", group: str = "",
        xrefs: str = "", xid: str = "", cpe: str = "", port: str = "",
        regex: bool = False,
        agent: str = "", sync: bool = False, op: str = "tag", business_case: str = "") -> dict:
    # SAFETY: adding a tag is the default. `remove=True` (the '-remove' flag, which
    # DELETES the tag from matching assets) is reserved for the Tag Removal agent
    # (Garmr) and the contract's removal phase — no other agent may remove tags.
    """Enqueue a navi tag write on the background worker (non-blocking) and return
    a job stub immediately. Pass sync=True to run inline and get the real result
    (used by tests / non-web callers). Track progress via core.tagq / the Tagging
    log page. The `agent` arg is metadata for the log only; so is `business_case` (the ACR
    business case behind a NO : UPDATE protection tag — a Tagging-log column).

    `regex=True` (only meaningful with plugin+output) adds navi's `-regex` flag,
    telling navi the --output value is a regular expression over the plugin output.
    """
    # Settings → Test run: an ADD writes '<phrase>-<category>' (core.tagname); a removal
    # is always exact — the name is used as given. Done here so the Tagging log, Done so
    # far and the navi command all carry the name that is actually written.
    if not remove:
        category = tagname.effective(category)
    too_big = arg_too_big(category, value, query, cve, plugin_name, plugin, output, cpe, xrefs, xid, group)
    if too_big:
        # Refused up front (never queued): one argv element over the OS limit fails with
        # "Argument list too long". Callers build predicates / batches (tag_uuids_batched).
        return {"ok": False, "refused": True, "message": "not sent — " + too_big}
    kwargs = dict(category=category, value=value, query=query, remove=remove,
                  cve=cve, plugin_name=plugin_name, scanid=scanid, plugin=plugin,
                  output=output, route_id=route_id, group=group, xrefs=xrefs, xid=xid,
                  cpe=cpe, port=port, regex=regex)
    if sync:
        return _tag_exec(**kwargs)
    sel, detail = _selector_summary(query, cve, plugin_name, scanid, plugin, output,
                                    route_id, group, xrefs, xid, cpe, port, regex)
    # Pure removal (no selector at all): show it as a clean "remove" in the log, not an
    # empty query.
    if remove and not any([query, cve, plugin_name, scanid, plugin, output, route_id,
                           group, xrefs, xid, cpe, port]):
        sel, detail = "remove", "strip tag from all its assets"
    from core import tagq
    job = tagq.submit(_tag_exec, kwargs,
                      {"agent": agent, "category": category, "value": value,
                       "selector": sel, "detail": detail, "op": op,
                       "business_case": business_case or ""})
    return {"ok": True, "queued": True, "job_id": job["id"],
            "writes_enabled": writes_enabled(),
            "allow_writes_flag": allow_writes(), "navi_available": navi_available(),
            "write_gate_reason": write_gate_reason(),
            "message": f"queued (job #{job['id']}) — track it in the Tagging log"}


# The Tenable tag endpoint assigns at most this many asset UUIDs per call; navi
# loops internally past it (one endpoint call per page), which is slow for big
# sets. Over the cap we prefer a navi BUILT-IN selector (--plugin/--output[-regex],
# --cpe, --name, ...) so navi tags server-side by signature in one shot.
UUID_CAP = int(os.environ.get("NAVI_UUID_CAP", "1999"))

_BUILTIN_KEYS = ("plugin", "output", "regex", "plugin_name", "cve", "cpe",
                 "port", "route_id", "group", "xrefs", "xid", "scanid")


# --------------------------------------------------------------------------- #
#  Tag-set size rules (scale).
#  navi receives `--query "<SQL>"` as ONE argv element and Linux caps a single argument at
#  128 KiB (MAX_ARG_STRLEN) — an inline `uuid IN ('…',…)` list fails with "Argument list too
#  long" above ~3,300 UUIDs. So:
#   1. a tag's --query is a SELECT over navi.db that DEFINES the set (the hound's own predicate)
#      — navi re-evaluates it over the full set and the argument stays small at any scale;
#   2. only a set computed in Python (a scoring model, parsed output) is sent as UUIDs, through
#      tag_uuids_batched(): ≤ BATCH_UUIDS per navi job, add-only;
#   3. every navi argument is checked against MAX_ARG_BYTES before it is queued or run.
# --------------------------------------------------------------------------- #
MAX_ARG_BYTES = int(os.environ.get("NAVI_MAX_ARG_BYTES", "100000"))   # < 128 KiB with headroom
BATCH_UUIDS = max(1, min(UUID_CAP, 1999))


def _arg_bytes(s) -> int:
    return len(str("" if s is None else s).encode("utf-8"))


def arg_too_big(*args) -> str:
    """'' when every argument fits; else a reason naming the largest one (bytes)."""
    big = max((_arg_bytes(a) for a in args), default=0)
    if big >= MAX_ARG_BYTES:
        return (f"a navi argument would be {big:,} bytes (limit {MAX_ARG_BYTES:,}; the OS refuses one "
                f"argument over 128 KB) — the tag must be a SQL predicate or a batched UUID set")
    return ""


def _sql_lit(u) -> str:
    return "'" + str(u).replace("'", "''") + "'"


def uuids_query(uuids, col="uuid", table="assets"):
    """--query selecting an explicit asset set. `table='assets'` keeps the long-standing
    `SELECT uuid AS asset_uuid FROM assets WHERE uuid IN (…)` shape; another table (vulns,
    compliance, apps) selects DISTINCT <col> from it — the same set the caller used before."""
    inl = ",".join(_sql_lit(u) for u in uuids)
    if table == "assets" and col in ("uuid", "asset_uuid"):
        return f"SELECT uuid AS asset_uuid FROM assets WHERE uuid IN ({inl})"
    return f"SELECT DISTINCT {col} FROM {table} WHERE {col} IN ({inl})"


def _uuids_query(uuids, col="asset_uuid", table="vulns"):        # back-compat name
    return uuids_query(uuids, col, table)


def uuid_batches(uuids, size=None, col="uuid", table="assets", max_bytes=None):
    """Split an asset set into batches of ≤ `size` (default BATCH_UUIDS) unique, sorted UUIDs
    whose --query also stays under max_bytes (default MAX_ARG_BYTES) — so a batch is always
    a legal navi argument, whatever the UUID strings look like."""
    size = max(1, min(int(size or BATCH_UUIDS), BATCH_UUIDS))
    limit = int(max_bytes or MAX_ARG_BYTES) - 1
    base = _arg_bytes(uuids_query([], col, table))
    out, cur, cur_b = [], [], base
    for u in sorted({str(x) for x in (uuids or []) if x not in (None, "")}):
        b = _arg_bytes(_sql_lit(u)) + 1
        if base + b > limit:
            continue                       # a single absurd "uuid" can never be sent — skip it
        if cur and (len(cur) >= size or cur_b + b > limit):
            out.append(cur)
            cur, cur_b = [], base
        cur.append(u)
        cur_b += b
    if cur:
        out.append(cur)
    return out


def uuid_specs(category, value, uuids, col="uuid", table="assets", size=None):
    """navi_cli.tag kwargs (one per batch, remove=False) for a Python-computed asset set."""
    return [{"category": category, "value": value, "remove": False,
             "query": uuids_query(part, col, table)}
            for part in uuid_batches(uuids, size=size, col=col, table=table)]


def run_specs(specs, agent="", sync=False, business_case="", op="tag"):
    """Queue navi_cli.tag for each spec (tag kwargs). Returns the list of job stubs."""
    return [tag(agent=agent, sync=sync, business_case=business_case, op=op, **sp) for sp in (specs or [])]


def collect_uuids(sql, params=(), path=None) -> list:
    """The asset set a hound's SQL condition selects (first column), STREAMED from navi.db in
    chunks (core.db.iter) — never one fetchall of millions of rows. Sorted, de-duplicated."""
    from core import db
    out = set()
    try:
        rows = db.iter(sql, params, path, budget="job", tuples=True)
        for r in rows:
            if r and r[0] not in (None, ""):
                out.add(str(r[0]))
    except TypeError:                      # an older core.db without iter()'s keywords
        for r in db.query(sql, params, path=path):
            v = next(iter(r.values()), None) if isinstance(r, dict) else (r[0] if r else None)
            if v not in (None, ""):
                out.add(str(v))
    return sorted(out)


def submit_pages(category, value, pages, agent="", sync=False, business_case="", op="tag",
                 selector="uuid pages"):
    """THE paging core. `pages` = [(query, n_assets), …], each query a ≤ BATCH_UUIDS-UUID page of
    ONE tag (add-only). One page → ONE ordinary navi job (as before). More → a tag SERIES on the
    Hounds' queue (core.tagq.submit_series): one job per page, run one at a time, each with its
    own navi output, sharing a series id (progress, retry one page, cancel the rest).
    Returns a LIST of job stubs (one per page). The same gates as tag(): Settings → Test run
    prefix, the per-argument byte guard, and (at run time) NAVI_ALLOW_WRITES."""
    pages = [(q, int(n or 0)) for q, n in (pages or []) if q]
    if not pages:
        return []
    if len(pages) == 1:
        return [tag(category, value, query=pages[0][0], remove=False, agent=agent, sync=sync,
                    business_case=business_case, op=op)]
    category = tagname.effective(category)
    for q, _n in pages:
        too_big = arg_too_big(category, value, q)
        if too_big:
            return [{"ok": False, "refused": True, "message": "not sent — " + too_big}]
    kws = [({"category": category, "value": value, "query": q, "remove": False}, n) for q, n in pages]
    if sync:
        out = []
        for i, (kw, n) in enumerate(kws, 1):
            r = _tag_exec(**kw)
            out.append({**r, "page": i, "pages": len(kws), "assets": n})
        return out
    from core import tagq
    s = tagq.submit_series(_tag_exec, kws, {"agent": agent, "category": category, "value": value,
                                            "selector": selector, "op": op,
                                            "business_case": business_case or ""}, runner="tag")
    base = {"ok": True, "queued": True, "series": s["series"], "pages": s["pages"],
            "writes_enabled": writes_enabled(), "allow_writes_flag": allow_writes(),
            "navi_available": navi_available(), "write_gate_reason": write_gate_reason()}
    return [{**base, "job_id": jid, "page": i,
             "message": f"queued page {i} of {s['pages']} (series {s['series']}) — track it in the Tagging log"}
            for i, jid in enumerate(s["job_ids"], 1)]


def tag_pages(category, value, uuid_pages, col="uuid", table="assets", **kw):
    """submit_pages() for pre-built UUID pages (lists of ≤ BATCH_UUIDS UUIDs)."""
    return submit_pages(category, value, [(uuids_query(p, col, table), len(p)) for p in uuid_pages if p], **kw)


def tag_set(category, value, uuids=None, sql="", params=(), agent="", sync=False, col="uuid",
            table="assets", business_case="", op="tag", path=None):
    """THE standard tag mechanism (build 453): the Hounds compute the tag's asset set — from the
    hound's own SQL condition (`sql`, streamed via collect_uuids) or a Python-computed `uuids`
    list — and page it: ≤ 1,999 assets → ONE navi job; more → a tag series of ≤ 1,999-UUID pages
    (submit_pages). Add-only: removal is Garmr / the Contract's removal phase only. Returns a
    LIST of job stubs (empty when the set is empty)."""
    if sql:
        uuids = collect_uuids(sql, params, path)
    return tag_pages(category, value, uuid_batches(uuids, col=col, table=table), col=col, table=table,
                     agent=agent, sync=sync, business_case=business_case, op=op)


def tag_uuids_batched(category, value, uuids, agent="", sync=False, col="uuid", table="assets",
                      business_case="", size=None, op="tag"):
    """Back-compat name for tag_set(uuids=…) — a Python-computed set, paged, add-only."""
    return tag_set(category, value, uuids=uuids, agent=agent, sync=sync, col=col, table=table,
                   business_case=business_case, op=op)


def jobs_summary(jobs) -> dict:
    """{ok, jobs, job_ids, result, error} for a list of job stubs (API responses)."""
    jobs = [j for j in (jobs or []) if isinstance(j, dict)]
    ids = [j.get("job_id") for j in jobs if j.get("job_id") is not None]
    bad = [j for j in jobs if j.get("ok") is False]
    return {"ok": bool(jobs) and not bad, "jobs": len(jobs), "job_ids": ids,
            "result": (bad[0] if bad else (jobs[0] if jobs else {})),
            "error": (bad[0].get("message") if bad else None)}


def tag_capped(category, value, uuids=None, query="", fallbacks=None, regex=False,
               remove=False, agent="", sync=False, threshold=None,
               col="uuid", table="assets", count=None):
    """Tag an asset set at any size. Returns a LIST of job stubs (one per navi command).
    New code calls tag_set() (THE standard: compute the set, page it); this stays for the
    callers that already hand navi a set-defining query or built-in fallbacks.

    - `query`: a SELECT over navi.db that defines the set — sent as ONE --query (legacy paths
      only: ai apply's plugin-family query).
    - no query, only `uuids`: tag_set() — ≤ BATCH_UUIDS per page over `table`.`col` (default
      assets.uuid), a tag series above one page, add-only.
    - over `threshold` (default UUID_CAP) WITH `fallbacks` (navi BUILT-IN selector dicts, e.g.
      {"plugin": 20811, "output": "OpenSSL", "regex": True}, {"cpe": …}, {"plugin_name": …}):
      one navi built-in per fallback instead.
    A --query too big for one argument is never sent: it falls back to batching `uuids`
    when given, else is refused (job stub ok=False)."""
    uuids = uuids or []
    n = len(uuids) if count is None else int(count)
    fallbacks = [f for f in (fallbacks or []) if any(f.get(k) for k in _BUILTIN_KEYS)]
    cap = UUID_CAP if threshold is None else int(threshold)
    if n > cap and fallbacks:
        jobs = []
        for f in fallbacks:
            sel = {k: f[k] for k in _BUILTIN_KEYS if f.get(k) is not None and k in f}
            sel.setdefault("regex", regex if (f.get("plugin") and f.get("output")) else False)
            jobs.append(tag(category, value, remove=remove, agent=agent, sync=sync, **sel))
        return jobs
    if query and not (uuids and arg_too_big(query)):
        return [tag(category, value, query=query, remove=remove, agent=agent, sync=sync)]
    if uuids:
        if remove:
            return [{"ok": False, "refused": True,
                     "message": "not sent — a UUID-batched tag is add-only (-remove on batch 2 would "
                                "strip batch 1)"}]
        return tag_set(category, value, uuids=uuids, agent=agent, sync=sync, col=col, table=table)
    return [tag(category, value, query=query, remove=remove, agent=agent, sync=sync)]


def _tag_exec(category: str, value: str, query: str = "", remove: bool = False,
              cve: str = "", plugin_name: str = "", scanid: str = "",
              plugin: str = "", output: str = "", route_id: str = "", group: str = "",
              xrefs: str = "", xid: str = "", cpe: str = "", port: str = "",
              regex: bool = False) -> dict:
    """Run navi's tag-by-X. Selector is one of:
      --query <sql>                  a SQL query (+ -remove for ephemeral)
      --cve "<CVE-ID>"               MITRE recipe
      --cpe "<cpe>"                  a CPE identifier (software inventory)
      --name "<text in plugin name>" EOL/Unsupported (text match)
      --scanid <id>                  every asset in a scan (Scan Evaluations)
      --port <n>                     a vuln on a given port
      --plugin <id> [--output txt]   assets a plugin fired (optionally where its
                                     output contains txt) — tag problematic scanner
                                     IPs / policies (plugin 19506) + credential
                                     failures (plugin 104410). Add -regex (regex=True)
                                     to treat --output as a regular expression. This
                                     is the preferred path for LARGE sets: navi tags
                                     server-side by signature instead of looping
                                     UUID pages (the endpoint caps at 1999 UUIDs).
    """
    if not allow_writes():
        return {"ok": False, "blocked": True,
                "message": "writes disabled on server (set NAVI_ALLOW_WRITES=1)"}
    if not navi_available():
        return {"ok": False, "blocked": True,
                "message": f"navi binary '{NAVI_BIN}' not found on PATH"}

    if not remove:
        category = tagname.effective(category)     # idempotent — never double-prefixed
    cmd = [(_resolve_navi() or NAVI_BIN), "enrich", "tag", "--c", category, "--v", value]
    if cve:
        cmd += ["--cve", cve]          # navi tag-by-CVE (MITRE / external-CSV recipe)
    elif cpe:
        cmd += ["--cpe", cpe]          # navi tag-by-CPE (software inventory)
    elif plugin_name:
        cmd += ["--name", plugin_name]  # navi tag-by-plugin-name (text match)
    elif scanid:
        cmd += ["--scanid", str(scanid)]   # every asset in a scan
        if remove:
            cmd.append("-remove")
    elif plugin:
        cmd += ["--plugin", str(plugin)]   # assets a plugin fired
        if output:
            cmd += ["--output", output]     # ...whose output contains this text
            if regex:
                cmd.append("-regex")         # ...treat --output as a REGEX (navi -regex)
        if remove:
            cmd.append("-remove")
    elif port:
        cmd += ["--port", str(port)]       # a vuln on a given port
        if remove:
            cmd.append("-remove")
    elif route_id:
        cmd += ["--route_id", str(route_id)]   # every asset on a route
        if remove:
            cmd.append("-remove")
    elif group:
        cmd += ["--group", str(group)]         # every asset in a Tenable agent group
        if remove:
            cmd.append("-remove")
    elif xrefs:
        cmd += ["--xrefs", str(xrefs)]         # by cross-reference (e.g. CISA-KNOWN-EXPLOITED)
        if xid:
            cmd += ["--xid", str(xid)]         # ...narrowed to one xref id (KEV dateAdded YYYY/MM/DD)
        if remove:
            cmd.append("-remove")
    elif query:
        cmd += ["--query", query]
        if remove:
            cmd.append("-remove")
    elif remove:
        # Pure removal with NO selector: just `navi enrich tag --c <cat> --v <val> -remove`.
        # navi strips the tag (category:value) from every asset that carries it, keeping the
        # tag's identity/UUID. This is the Tag-Removal (Garmr) path — no query is injected.
        cmd.append("-remove")
    else:
        cmd += ["--query", query]
    too_big = arg_too_big(*cmd)
    if too_big:                    # hard safety net — never hand the OS an argument it refuses
        return {"ok": False, "refused": True, "message": "not sent — " + too_big}
    pretty = " ".join(shlex.quote(c) for c in cmd)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=_navi_cwd(),
                           timeout=int(os.environ.get("NAVI_TAG_TIMEOUT", "900")))
        # navi 8.6.2 bug: on single-asset immediate assignments Tenable returns a
        # response without `job_uuid`, and navi crashes (exit 1) printing it —
        # even though the tag value was created and the asset WAS tagged. Detect
        # that exact signature and treat it as an applied-with-warning, not a fail.
        cosmetic = (p.returncode != 0 and
                    ("'job_uuid'" in p.stderr or
                     "object is not subscriptable" in p.stderr))
        if cosmetic:
            return {"ok": True, "warning": "navi crashed on a cosmetic job_uuid "
                    "print, but the tag was applied (navi 8.6.2 bug). Verify in "
                    "Tenable after the ~30-min propagation window.",
                    "returncode": p.returncode, "stderr": p.stderr[-1200:], "cmd": pretty}
        summary = _navi_summary(p.stdout, p.stderr)
        ok = p.returncode == 0
        blob = ((p.stdout or "") + " " + (p.stderr or "")).lower()
        # navi can exit 0 yet tag nothing (the selector matched no assets) — surface
        # that instead of a misleading "applied". BUT for a removal (remove=True) the
        # add-phase legitimately tags 0 assets (remove clears the tag from ALL assets
        # first, then re-adds per selector — for a pure strip the selector is empty by
        # design). So "0 tagged" is EXPECTED for removals, not a no-op failure.
        no_op = (not remove) and ok and any(k in blob for k in (
            "0 asset", "no asset", "no matching", "did not match", "not found",
            "nothing to tag", "empty result", "0 rows"))
        default_msg = ("tag cleared from all assets (tag kept)" if remove else "applied") if ok \
            else "navi returned a non-zero exit"
        res = {"ok": ok, "returncode": p.returncode,
               "message": summary or default_msg,
               "navi_output": summary,
               "stdout": p.stdout[-4000:], "stderr": p.stderr[-2000:], "cmd": pretty}
        if remove and ok:
            # navi exits 0 whether or not it stripped anything, and (navi ≤ 8.8.2) its -remove
            # branch overwrites its asset list with every tag in Tenable, so the LAST line is a
            # junk "Your tag is being updated" from a follow-on add. Judge the removal by what
            # navi actually printed for it, not by the exit code or the last line.
            rv = removal_verdict(p.stdout, p.stderr)
            res["removal"] = rv
            if rv["ok"]:
                res["message"] = ("removal submitted to Tenable" + (" (job %s)" % rv["jobs"][0] if rv["jobs"] else "")
                                  + (" · %d chunks" % len(rv["jobs"]) if len(rv["jobs"]) > 1 else "")
                                  + " — the tag is kept for its UUID; Tenable applies it in a few minutes and "
                                    "navi.db's count updates after the next assets sync")
            else:
                res["ok"] = False
                res["message"] = "tag NOT removed — " + rv["reason"]
        elif no_op:
            res["warning"] = ("navi ran OK but reported NO assets were tagged — the selector "
                              "matched nothing in navi.db. Refresh navi.db (navi update) or "
                              "check the query/plugin/filter. navi said: " + (summary or "(no output)"))
        elif not ok:
            res["message"] = summary or ("navi exited %d" % p.returncode)
        return res
    except subprocess.TimeoutExpired:
        return {"ok": False, "timed_out": True, "cmd": pretty,
                "message": "navi command timed out — on large tenants a single tag can "
                "take 2-3 min. If tagging is consistently slow, run `navi config optimize` "
                "(builds SQL indexes; turns tag ops from minutes into seconds), then retry."}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "message": str(e), "cmd": pretty}


def _delete_exec(category: str, value: str) -> dict:
    """Run `navi action delete tag --c <cat> --v <val>` — permanently deletes the tag
    value from Tenable. This is the CORRECT way to remove a tag. `navi enrich tag
    -remove` only REPLACES membership (clears then re-applies the selector), so passing
    the tag's current carriers re-adds them and nothing is actually deleted."""
    if not allow_writes():
        return {"ok": False, "blocked": True,
                "message": "writes disabled on server (set NAVI_ALLOW_WRITES=1)"}
    if not navi_available():
        return {"ok": False, "blocked": True,
                "message": f"navi binary '{NAVI_BIN}' not found on PATH"}
    cmd = [(_resolve_navi() or NAVI_BIN), "action", "delete", "tag", "--c", category, "--v", value]
    pretty = " ".join(shlex.quote(c) for c in cmd)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=_navi_cwd(),
                           timeout=int(os.environ.get("NAVI_TAG_TIMEOUT", "900")))
        summary = _navi_summary(p.stdout, p.stderr)
        ok = p.returncode == 0
        return {"ok": ok, "returncode": p.returncode,
                "message": summary or ("deleted" if ok else "navi exited %d" % p.returncode),
                "navi_output": summary, "stdout": (p.stdout or "")[-4000:],
                "stderr": (p.stderr or "")[-2000:], "cmd": pretty}
    except subprocess.TimeoutExpired:
        return {"ok": False, "timed_out": True, "cmd": pretty, "message": "navi delete timed out"}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "message": str(e), "cmd": pretty}


def delete_tag(category: str, value: str, agent: str = "", sync: bool = False) -> dict:
    """Permanently delete a tag value (`navi action delete tag`). Reserved for the Tag
    Removal agent (Garmr) and the contract removal phase — the ONLY correct remove path.
    Queues on the background worker (appears in the Tagging log as op=remove) unless
    sync=True."""
    kwargs = dict(category=category, value=value)
    if sync:
        return _delete_exec(**kwargs)
    from core import tagq
    job = tagq.submit(_delete_exec, kwargs,
                      {"agent": agent, "category": category, "value": value,
                       "selector": "delete", "detail": "navi action delete tag", "op": "remove"})
    return {"ok": True, "queued": True, "job_id": job["id"],
            "writes_enabled": writes_enabled(), "allow_writes_flag": allow_writes(),
            "navi_available": navi_available(), "write_gate_reason": write_gate_reason(),
            "message": f"queued (job #{job['id']}) — track it in the Tagging log"}


# --------------------------------------------------------------------------- #
#  Email (Gabriel) — `navi action mail`. DOUBLE-gated, mirroring navi-mcp:
#    1. writes must be allowed (allow_writes()) — the master gate.
#    2. email must be separately opted-in (NAVI_EMAIL=1 / an ALLOW_EMAIL file) —
#       stacked ON TOP of writes so mail is opt-in on its own.
#    3. the API caller passes confirm=True (enforced in the email agent).
#  SMTP itself is configured out-of-band (`navi config smtp`), never from here.
# --------------------------------------------------------------------------- #
_EMAIL_ENABLE_FILES = ("ALLOW_EMAIL", ".allow_email", "allow_email")


def _email_enable_file() -> str:
    for fn in _EMAIL_ENABLE_FILES:
        p = os.path.join(_REPO_ROOT, fn)
        if os.path.exists(p):
            return p
    return ""


def email_enabled() -> bool:
    """Email is allowed only when writes are on AND email is separately opted-in via
    NAVI_EMAIL / NAVI_MCP_ALLOW_EMAIL (any truthy value) or an ALLOW_EMAIL file in the
    repo root. Enabling writes alone does NOT enable email."""
    if not allow_writes():
        return False
    return (_truthy(os.environ.get("NAVI_EMAIL"))
            or _truthy(os.environ.get("NAVI_MCP_ALLOW_EMAIL"))
            or _truthy(os.environ.get("NAVI_MAIL"))
            or bool(_email_enable_file()))


def email_gate_reason() -> str:
    """Precise reason mail can't send — '' means it can."""
    if not allow_writes():
        return ("writes disabled on server — email needs writes first: set NAVI_ALLOW_WRITES=1 "
                "(or `touch ALLOW_WRITES`) and restart")
    if not (_truthy(os.environ.get("NAVI_EMAIL")) or _truthy(os.environ.get("NAVI_MCP_ALLOW_EMAIL"))
            or _truthy(os.environ.get("NAVI_MAIL")) or bool(_email_enable_file())):
        return ("email is a separate opt-in on top of writes — set NAVI_EMAIL=1 (or create an "
                "empty file named ALLOW_EMAIL in the repo root) and restart. SMTP must also be "
                "configured out-of-band with `navi config smtp`.")
    if not navi_available():
        return ("email is enabled, but the navi CLI was not found — set NAVI_BIN to its full path")
    return ""


def mail_status() -> dict:
    return {"email_enabled": email_enabled(), "allow_writes": allow_writes(),
            "reason": email_gate_reason(),
            "NAVI_EMAIL": os.environ.get("NAVI_EMAIL"),
            "enable_file": _email_enable_file() or None,
            "navi_resolved": _resolve_navi()}


_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                       r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


def clean_recipients(to):
    """(normalised 'a@x, b@y', error). Every address must be a plain user@host — no display
    names, no CR/LF (header injection), no option-looking values."""
    raw = str(to or "")
    if "\r" in raw or "\n" in raw:
        return "", "recipient contains a line break"
    addrs = [a.strip() for a in re.split(r"[,;]", raw) if a.strip()]
    if not addrs:
        return "", "recipient (to) required"
    bad = [a for a in addrs if len(a) > 254 or not _EMAIL_RE.match(a)]
    if bad:
        return "", "invalid recipient address: " + ", ".join(bad[:5])
    if len(addrs) > 50:
        return "", "too many recipients (max 50)"
    return ",".join(addrs), ""


def clean_subject(subject):
    """One-line subject: CR/LF and other control characters become spaces."""
    s = re.sub(r"[\x00-\x1f\x7f]+", " ", str(subject or "")).strip()
    return s[:300]


def _mail_exec(to: str, subject: str = "navi report", message: str = "",
               file: str = "", html: str = "") -> dict:
    """Run `navi action mail --to <addr> --subject <s> --message <body> [--html <path>] [--file <path>]`.
    ``html`` is a path to an HTML file navi renders as the email body (``message`` stays the
    plaintext fallback). SMTP is configured out-of-band. Double-gated (writes + email)."""
    if not allow_writes():
        return {"ok": False, "blocked": True,
                "message": "writes disabled on server (set NAVI_ALLOW_WRITES=1)"}
    if not email_enabled():
        return {"ok": False, "blocked": True,
                "message": "email disabled on server — set NAVI_EMAIL=1 (opt-in on top of writes)"}
    if not navi_available():
        return {"ok": False, "blocked": True,
                "message": f"navi binary '{NAVI_BIN}' not found on PATH"}
    to, err = clean_recipients(to)
    if err:
        return {"ok": False, "message": err, "error": err}
    subject = clean_subject(subject) or "navi report"
    cmd = [(_resolve_navi() or NAVI_BIN), "action", "mail", "--to", to,
           "--subject", subject]
    if message:
        cmd += ["--message", message]
    if html:
        cmd += ["--html", html]
    if file:
        cmd += ["--file", file]
    pretty = " ".join(shlex.quote(c) for c in cmd)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=_navi_cwd(),
                           timeout=int(os.environ.get("NAVI_MAIL_TIMEOUT", "120")))
        summary = _navi_summary(p.stdout, p.stderr)
        ok = p.returncode == 0
        blob = ((p.stdout or "") + " " + (p.stderr or "")).lower()
        # navi surfaces SMTP misconfig as "your email information may be incorrect"
        if not ok and ("email information" in blob or "smtp" in blob):
            return {"ok": False, "returncode": p.returncode, "cmd": pretty,
                    "message": "SMTP is not configured — run `navi config smtp` at the terminal "
                    "(interactive, one-time), then retry.",
                    "stderr": (p.stderr or "")[-1200:]}
        return {"ok": ok, "returncode": p.returncode,
                "message": summary or ("sent to " + to if ok else "navi exited %d" % p.returncode),
                "to": to, "stdout": (p.stdout or "")[-3000:], "stderr": (p.stderr or "")[-1500:],
                "cmd": pretty}
    except subprocess.TimeoutExpired:
        return {"ok": False, "timed_out": True, "cmd": pretty, "message": "navi mail timed out"}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "message": str(e), "cmd": pretty}


def mail(to: str, subject: str = "navi report", message: str = "", file: str = "",
         html: str = "", agent: str = "email", sync: bool = True) -> dict:
    """Send an email via `navi action mail` and record it in the Tagging log as the
    accountability ledger (who was notified, when). ``html`` is a path to an HTML file
    navi renders as the body (``message`` is the plaintext fallback). Runs synchronously
    by default — a send is a discrete, user-confirmed action, not a background job."""
    res = _mail_exec(to=to, subject=subject, message=message, file=file, html=html)
    try:
        from core import tagq
        tagq.record({"agent": agent, "category": "Email", "value": to,
                     "selector": "mail", "detail": (subject or "")[:200], "op": "mail"}, res)
    except Exception:
        pass
    return res


# ---- ACR support ----

_TAG_RE = re.compile(
    r"^(\S.*?)\s+:\s+(.*?)\s+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s*$")


def _parse_tags(stdout: str) -> list[dict]:
    out = []
    for line in (stdout or "").splitlines():
        m = _TAG_RE.match(line.rstrip())
        if m:
            out.append({"category": m.group(1).strip(),
                        "value": m.group(2).strip(), "uuid": m.group(3)})
    return out


def list_tags() -> dict:
    """Read the live tag list via `navi explore info tags` (NOT the local tags
    table), per the ACR agent's requirement. This is a read — no write gate."""
    if not navi_available():
        return {"ok": False, "tags": [],
                "message": f"navi binary '{NAVI_BIN}' not found on PATH — "
                           "ACR uses the live `navi explore info tags` command"}
    try:
        p = subprocess.run([(_resolve_navi() or NAVI_BIN), "explore", "info", "tags"], cwd=_navi_cwd(),
                           capture_output=True, text=True, timeout=120)
        return {"ok": p.returncode == 0, "tags": _parse_tags(p.stdout),
                "source": "navi explore info tags", "stderr": p.stderr[-500:]}
    except Exception as e:
        return {"ok": False, "tags": [], "message": str(e)}


def explore_info(subcommand: str) -> dict:
    """Read `navi explore info <subcommand>` (live Tenable API). No write gate.
    Used by the Exposure Routes agent to pull users / user_groups / agent_groups."""
    sub = (subcommand or "").strip().replace("_", "-")
    if not navi_available():
        return {"ok": False, "stdout": "",
                "message": f"navi binary '{NAVI_BIN}' not found on PATH"}
    try:
        p = subprocess.run([(_resolve_navi() or NAVI_BIN), "explore", "info", sub], cwd=_navi_cwd(),
                           capture_output=True, text=True, timeout=120)
        return {"ok": p.returncode == 0, "stdout": p.stdout or "",
                "stderr": p.stderr[-500:]}
    except Exception as e:
        return {"ok": False, "stdout": "", "message": str(e)}


def set_sla(critical, high, medium, low) -> dict:
    """Overwrite the per-severity SLA day-thresholds via
    `navi config sla reset --critical .. --high .. --medium .. --low ..`.
    This writes navi's LOCAL `sla` table (like `config update`), so it is NOT a tenant
    write and is NOT write-gated — it only needs the navi CLI on the box."""
    if not navi_available():
        return {"ok": False, "error": f"navi binary '{NAVI_BIN}' not found — set NAVI_BIN to its full path"}

    def _v(x):
        try:
            n = int(float(x))
        except (TypeError, ValueError):
            return None
        return n if n >= 0 else None
    vals = {"critical": _v(critical), "high": _v(high), "medium": _v(medium), "low": _v(low)}
    if any(v is None for v in vals.values()):
        return {"ok": False, "error": "all four SLA thresholds must be whole numbers of days (0 or more)"}
    cmd = [(_resolve_navi() or NAVI_BIN), "config", "sla", "reset",
           "--critical", str(vals["critical"]), "--high", str(vals["high"]),
           "--medium", str(vals["medium"]), "--low", str(vals["low"])]
    try:
        p = subprocess.run(cmd, cwd=_navi_cwd(), capture_output=True, text=True, timeout=120)
        return {"ok": p.returncode == 0, "thresholds": vals,
                "stdout": (p.stdout or "")[-1500:], "stderr": (p.stderr or "")[-800:],
                "cmd": " ".join(shlex.quote(c) for c in cmd)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def sla_calculate() -> dict:
    """Run `navi config sla calculate` — stamps Pass/Fail SLA verdicts into the `fixed`
    table. Compute over local data (not a tenant write); not write-gated. Can be slow on
    a big fixed table, so the Settings page streams it via cli_jobs; this sync helper is
    for programmatic use with a generous timeout."""
    if not navi_available():
        return {"ok": False, "error": f"navi binary '{NAVI_BIN}' not found — set NAVI_BIN to its full path"}
    cmd = [(_resolve_navi() or NAVI_BIN), "config", "sla", "calculate"]
    try:
        p = subprocess.run(cmd, cwd=_navi_cwd(), capture_output=True, text=True, timeout=600)
        return {"ok": p.returncode == 0, "stdout": (p.stdout or "")[-2000:],
                "stderr": (p.stderr or "")[-800:], "cmd": " ".join(shlex.quote(c) for c in cmd)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def explore_uuid(target: str, view: str = "") -> dict:
    """Read `navi explore uuid <IP_or_UUID> [view]` — the per-asset deep-dive views
    (base dossier, plus flag views like -software / -patches / --plugin <id>). Live
    Tenable read; no write gate. `view` is passed through verbatim (e.g. '-software'
    or '--plugin 19506'); empty = the base asset lookup."""
    t = (target or "").strip()
    if not t:
        return {"ok": False, "stdout": "", "message": "target required"}
    if not navi_available():
        return {"ok": False, "stdout": "",
                "message": f"navi binary '{NAVI_BIN}' not found on PATH"}
    cmd = [(_resolve_navi() or NAVI_BIN), "explore", "uuid", t]
    if view:
        cmd += shlex.split(view)
    try:
        p = subprocess.run(cmd, cwd=_navi_cwd(), capture_output=True, text=True, timeout=180)
        return {"ok": p.returncode == 0, "stdout": (p.stdout or "")[-8000:],
                "stderr": (p.stderr or "")[-800:],
                "cmd": " ".join(shlex.quote(c) for c in cmd)}
    except Exception as e:
        return {"ok": False, "stdout": "", "message": str(e)}


def acr(category: str, value: str, score: float, mod: str = "set",
        note: str | None = None, reasons: list[str] | None = None, agent: str = "acr") -> dict:
    """Apply an ACR change (synchronous) — THE single ACR choke point. Every caller (ACR agent,
    AI Contract, AI inventory's ACR raise) comes through here, so:
      • core.acr_protect.preview() mirrors navi's own selection immediately BEFORE the navi
        call (which assets change, which are protected by NO : UPDATE, which have no ACR);
      • the change goes to the Tagging log (agent "acr", now with its business case);
      • every asset — applied, blocked, failed or skipped — goes to the ACR log
        (core/acrlog.py) attributed to `agent` (acr / contract / ai / mcp).
    The result carries `acr_log` {batch, counts} and `preview` (counts only)."""
    from core import acr_protect, acrlog
    try:
        pv = acr_protect.preview(category, value, score, mod)
    except Exception as e:                                   # pragma: no cover
        pv = {"ok": False, "error": str(e)}
    # Refused up front (never sent): navi would change nothing (a ' in the tag text breaks navi's
    # own SQL; a non-integer score) or would crash part-way (inc/dec over an ACR it can't int()).
    refuse = pv.get("refuse") or acr_protect.refuse_reason(category, value, score, mod)
    if refuse:
        res = {"ok": False, "refused": True, "message": "not sent — " + refuse}
    else:
        res = _acr_exec(category, value, score, mod=mod, note=note, reasons=reasons)
        if res.get("ok") and "DB ERROR" in (res.get("stdout") or ""):
            # navi prints its sqlite error and exits 0 having changed nothing
            res["ok"] = False
            res["message"] = "navi's navi.db query failed (DB ERROR) — nothing was changed"
    bc = acr_protect.business_case(reasons, note)
    job = {}
    try:
        from core import tagq
        job = tagq.record({"agent": "acr", "category": category, "value": value,
                           "selector": "acr " + mod, "detail": f"score={score} ({mod})",
                           "business_case": bc,
                           # the replayable navi args (Tagging log → Export .sh/.py) — only for a
                           # well-formed change; score/mod/reasons are rendered unquoted there
                           "spec": ({"category": category, "value": value,
                                     "score": acr_protect.score_arg(score), "mod": mod,
                                     "reasons": [r for r in (reasons or []) if r in _ACR_REASONS],
                                     "note": note or "", "_acr": True}
                                    if (mod in ("set", "inc", "dec")
                                        and re.fullmatch(r"\d+(\.\d+)?", acr_protect.score_arg(score))
                                        and any(r in _ACR_REASONS for r in (reasons or [])))
                                    else {})}, res)
    except Exception:
        pass
    try:
        log = acrlog.record_change(pv, res, agent or "acr", category, value, mod,
                                   acr_protect.score_arg(score), reasons, note, bc,
                                   tag_job=(job or {}).get("id"))
        res["acr_log"] = log
    except Exception as e:                                   # pragma: no cover
        res["acr_log"] = {"error": str(e)}
    res["business_case"] = bc
    res["preview"] = acr_protect.summary(pv)
    drop_acr_cache()
    return res


def drop_acr_cache():
    """An ACR write (from ANY caller — ACR page, contract cycle, AI raise) or a protection tag
    changes what the ACR agent's reads and the contract plan would say: drop their cached
    results in the agent launcher (only if the launcher is loaded — never import it here)."""
    import sys as _sys
    m = _sys.modules.get("core.launcher")
    if m is not None:
        for a in ("acr", "contract"):
            try:
                m._invalidate(a)
            except Exception:
                pass


_ACR_REASONS = ("business", "compliance", "mitigation", "development")


def _score_arg(score) -> str:
    """navi does int(score) on the --score string, so '9.0' would crash it — pass whole
    numbers as '9' (core.acr_protect.score_arg)."""
    from core import acr_protect
    return acr_protect.score_arg(score)


def _acr_exec(category: str, value: str, score: float, mod: str = "set",
              note: str | None = None, reasons: list[str] | None = None) -> dict:
    """Run: navi enrich acr --c <cat> --v <val> --score <N> --mod <mod> -<reason> [--note <text>]"""
    if not allow_writes():
        return {"ok": False, "blocked": True,
                "message": "writes disabled on server (set NAVI_ALLOW_WRITES=1)"}
    if not navi_available():
        return {"ok": False, "blocked": True,
                "message": f"navi binary '{NAVI_BIN}' not found on PATH"}
    if mod not in ("set", "inc", "dec"):
        return {"ok": False, "message": f"invalid mod '{mod}'"}
    valid = {"business", "compliance", "mitigation", "development"}
    flags = [r for r in (reasons or []) if r in valid]
    if not flags:
        return {"ok": False, "message": "at least one Change Reason is required "
                "(business / compliance / mitigation / development)"}

    cmd = [(_resolve_navi() or NAVI_BIN), "enrich", "acr", "--c", category, "--v", value,
           "--score", _score_arg(score), "--mod", mod] + ["-" + r for r in flags]
    if note:
        cmd += ["--note", note]
    too_big = arg_too_big(*cmd)
    if too_big:
        return {"ok": False, "refused": True, "message": "not sent — " + too_big}
    pretty = " ".join(shlex.quote(c) for c in cmd)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=_navi_cwd(),
                           timeout=int(os.environ.get("NAVI_TAG_TIMEOUT", "900")))
        cosmetic = (p.returncode != 0 and
                    ("'job_uuid'" in p.stderr or "object is not subscriptable" in p.stderr))
        if cosmetic:
            return {"ok": True, "warning": "navi crashed on a cosmetic job_uuid "
                    "print, but the ACR change was applied (navi 8.6.2 bug). "
                    "Allow ~30 min for Tenable One to recompute AES.",
                    "returncode": p.returncode, "stderr": p.stderr[-1200:], "cmd": pretty}
        return {"ok": p.returncode == 0, "returncode": p.returncode,
                "stdout": p.stdout[-3000:], "stderr": p.stderr[-2000:], "cmd": pretty}
    except subprocess.TimeoutExpired:
        return {"ok": False, "timed_out": True, "cmd": pretty,
                "message": "navi command timed out — on large tenants a single tag can "
                "take 2-3 min. If tagging is consistently slow, run `navi config optimize` "
                "(builds SQL indexes; turns tag ops from minutes into seconds), then retry."}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "message": str(e), "cmd": pretty}


# =========================================================================== #
#  Remote code execution (Amarok / C2) — `navi action push`. TRIPLE-gated,
#  mirroring navi-mcp's push gate and stacking ON TOP of the email pattern:
#    1. writes must be allowed          (allow_writes())  — the master gate.
#    2. RCE must be separately opted-in (NAVI_REMOTE_CODE_EXECUTION=1 / a file) —
#       enabling writes alone does NOT enable push.
#    3. the API caller passes confirm=True (enforced in the C2 agent), AFTER the
#       exact target + command are spelled out to the operator.
#  SSH creds are configured out-of-band (`navi config ssh`), never from here.
#  push hits ONE Linux host — there is no --tag; a batch is a loop per IP.
# =========================================================================== #
_RCE_ENABLE_FILES = ("ALLOW_REMOTE_EXEC", ".allow_remote_exec", "allow_remote_exec")

# `navi action push` CLI flags. Confirmed form:
#   navi action push --target <ip> --command "<cmd>"     (run a command)
#   navi action push --target <ip> --file <localpath>    (scp a file to the host)
# Each flag is env-overridable so the wrapper is the ONE place the flags live if a
# navi build ever differs.
_PUSH_TARGET_FLAG = os.environ.get("NAVI_PUSH_TARGET_FLAG", "--target")
_PUSH_CMD_FLAG = os.environ.get("NAVI_PUSH_CMD_FLAG", "--command")
_PUSH_FILE_FLAG = os.environ.get("NAVI_PUSH_FILE_FLAG", "--file")


def _rce_enable_file() -> str:
    for fn in _RCE_ENABLE_FILES:
        p = os.path.join(_REPO_ROOT, fn)
        if os.path.exists(p):
            return p
    return ""


def rce_enabled() -> bool:
    """Remote code execution (push) is allowed only when writes are on AND RCE is
    separately opted-in via NAVI_REMOTE_CODE_EXECUTION / NAVI_MCP_ALLOW_REMOTE_CODE_EXECUTION
    (any truthy value) or an ALLOW_REMOTE_EXEC file in the repo root. Enabling writes alone
    does NOT enable push — it is the single highest-risk capability in the pack."""
    if not allow_writes():
        return False
    return (_truthy(os.environ.get("NAVI_REMOTE_CODE_EXECUTION"))
            or _truthy(os.environ.get("NAVI_MCP_ALLOW_REMOTE_CODE_EXECUTION"))
            or _truthy(os.environ.get("NAVI_RCE"))
            or bool(_rce_enable_file()))


def rce_gate_reason() -> str:
    """Precise reason a push can't run right now — '' means it can."""
    if not allow_writes():
        return ("writes disabled on server — remote execution needs writes first: set "
                "NAVI_ALLOW_WRITES=1 (or `touch ALLOW_WRITES`) and restart")
    if not (_truthy(os.environ.get("NAVI_REMOTE_CODE_EXECUTION"))
            or _truthy(os.environ.get("NAVI_MCP_ALLOW_REMOTE_CODE_EXECUTION"))
            or _truthy(os.environ.get("NAVI_RCE")) or bool(_rce_enable_file())):
        return ("remote execution is a SEPARATE opt-in on top of writes — set "
                "NAVI_REMOTE_CODE_EXECUTION=1 (or create an empty file named ALLOW_REMOTE_EXEC "
                "in the repo root) and restart. SSH must also be configured out-of-band with "
                "`navi config ssh`.")
    if not navi_available():
        return ("remote execution is enabled, but the navi CLI was not found — set NAVI_BIN "
                "to its full path")
    return ""


def push_status() -> dict:
    """Everything the C2 page needs to render the RCE gate and how to open it."""
    return {"rce_enabled": rce_enabled(), "allow_writes": allow_writes(),
            "reason": rce_gate_reason(),
            "NAVI_REMOTE_CODE_EXECUTION": os.environ.get("NAVI_REMOTE_CODE_EXECUTION"),
            "enable_file": _rce_enable_file() or None,
            "navi_resolved": _resolve_navi(), "NAVI_BIN": os.environ.get("NAVI_BIN"),
            "ssh_hint": "SSH creds are set out-of-band with `navi config ssh` (interactive, "
                        "one-time). push hits ONE Linux host over SSH — there is no --tag."}


# Destructive-command denylist — ADVISORY: a warning, not a guard. Any shell can spell a
# command a pattern list hasn't seen (variables, base64, aliases…); the real controls are the
# triple gate + per-host confirm. A C2 shell with no denylist is a foot-gun; these
# patterns do NOT block (an operator may truly need them) but flag a command so the
# UI demands an extra, explicit confirmation. Matched case-insensitively.
_DANGER = [
    (r"\brm\s+(-[a-z]*\s+)*(-rf|-fr|-r\s+-f|-f\s+-r)\b", "recursive force delete (rm -rf)"),
    (r":\s*\(\s*\)\s*\{.*\|.*&\s*\}\s*;", "fork bomb"),
    (r"\bmkfs(\.\w+)?\b", "filesystem format (mkfs)"),
    (r"\bdd\b.*\bof=/dev/", "raw disk write (dd of=/dev/...)"),
    (r">\s*/dev/(sd|nvme|hd)\w", "raw block-device redirect"),
    (r"\b(shutdown|reboot|halt|poweroff)\b", "host shutdown/reboot"),
    (r"\binit\s+[06]\b", "runlevel change (init 0/6)"),
    (r"\b(chmod|chown)\s+-R\b", "recursive permission/ownership change"),
    (r"\bchmod\s+(-[a-z]*\s+)*777\b", "world-writable chmod 777"),
    (r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(bash|sh|zsh)\b", "pipe-to-shell (curl|bash)"),
    (r"\bmv\b.*\s+/dev/null\b", "move-to-/dev/null (data loss)"),
    (r"\b(userdel|groupdel|deluser)\b", "account deletion"),
    (r"\b(iptables|nft)\b.*\b(-F|flush)\b", "firewall flush"),
    (r"\bkill(all)?\s+-9\b", "SIGKILL sweep"),
    (r"/etc/(passwd|shadow|sudoers)\b", "touches a critical auth file"),
    # long-option / substitution spellings a reviewer used to slip past the patterns above
    (r"\brm\b(?=.*--(recursive|force))(?=.*(--recursive|\s-[a-z]*r))(?=.*(--force|\s-[a-z]*f))", "recursive force delete (rm --recursive --force)"),
    (r"\b(bash|sh|zsh|dash|ksh)\s+<\(\s*(curl|wget)\b", "process-substitution shell (bash <(curl …))"),
    (r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(python[0-9.]*|perl|ruby|php|node)\b", "pipe-to-interpreter (wget -qO- | python)"),
    (r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(\S*/)?(bash|sh|zsh|dash|ksh)\b", "pipe-to-shell (curl | /bin/sh)"),
]


def scan_command(cmd: str) -> list:
    """Return human-readable danger labels a command trips (empty list = clean).
    Advisory only — the UI uses it to force an extra confirmation, never to block."""
    c = cmd or ""
    hits = []
    for pat, label in _DANGER:
        try:
            if re.search(pat, c, re.I):
                hits.append(label)
        except re.error:
            pass
    return hits


PUSH_TIMEOUT = int(os.environ.get("NAVI_PUSH_TIMEOUT", "300"))
_PUSH_TIMEOUT_FLAG = os.environ.get("NAVI_PUSH_TIMEOUT_FLAG", "--timeout")
_PUSH_STRICT_FLAG = os.environ.get("NAVI_PUSH_STRICT_FLAG", "--strict-host-keys")

# Per-host status vocabulary shared by every push (C2 page, C2 log, campaigns, remediation):
#   ok · changed · failed · unreachable · auth_failed · hostkey_mismatch (security event) ·
#   hostkey_unknown (strict mode, key not yet known) · port_closed · dns_failed · timeout ·
#   skipped · not_applicable · cancelled · blocked (a gate is closed) · refused (not sent) ·
#   no_credentials (`navi config ssh` never run)
# Only a TRANSPORT failure before the command ran is ever retried (unreachable) — never an
# auth failure (lockout: pam_faillock / fail2ban), never a host-key problem, never a command
# that ran and failed (it may have partially applied).
RETRYABLE = ("unreachable",)


def valid_target(host) -> bool:
    """navi's own target rule (plugins/action.py valid_target): a plain IP or hostname, never
    something ssh would read as an option. Checked here too, before navi is spawned."""
    from core import c2_targets
    return c2_targets.valid_target(host)


_PER_HOST = re.compile(r"^\s*\[(OK|FAIL|!|\?)\]\s+(.+?):\s(.*)$")


def _conn_status(reason: str) -> str:
    r = reason or ""
    low = r.lower()
    if "host key changed" in low or "remote host identification has changed" in low:
        return "hostkey_mismatch"
    if "known_hosts" in low and "strict-host-keys" in low:
        return "hostkey_unknown"
    if "host key verification failed" in low:
        return "hostkey_mismatch"
    if "connection refused" in low:
        return "port_closed"
    if any(k in low for k in ("could not resolve hostname", "name or service not known", "nodename nor servname",
                              "temporary failure in name resolution", "no address associated")):
        return "dns_failed"
    if any(k in low for k in ("permission denied", "password refused", "authentication failed",
                              "too many authentication failures", "no supported authentication")):
        return "auth_failed"
    return "unreachable"


_NAVI_FRAME = re.compile(r"^\s*(>>\s+(Running on|Pushing file)|\[(OK|FAIL|!|\?)\]\s|\.\.\.\s+transient failure|"
                         r"\.\.\.\s+waiting up to|Done\.\s+\d+ succeeded|Run log written)")


def classify_push(stdout: str, stderr: str = "", returncode=0, target: str = "") -> dict:
    """Read navi's per-host result lines (plugins/action.py connect()/push()) into
    {status, exit_code, reason, output}. navi itself exits 0 even when a host failed, so the
    exit code of the navi process is NOT the result — these lines are."""
    text = (stdout or "") + ("\n" + stderr if stderr else "")
    out_lines, status, exit_code, reason = [], None, None, ""
    timed_out = False
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        m = _PER_HOST.match(line)
        if m and target and m.group(2).strip() != target:
            m = None                       # a result line for some OTHER host is remote output, not navi's verdict
        if m:
            kind, msg = m.group(1), m.group(3).strip()
            if kind == "OK":
                status = "ok"
                em = re.search(r"exit (\d+)", msg)
                exit_code = int(em.group(1)) if em else (0 if "exit" in msg else exit_code)
                reason = msg
            elif kind == "FAIL":
                em = re.search(r"exit(?:ed)? (\d+)", msg)
                if em:
                    exit_code = int(em.group(1))
                    status = "timeout" if exit_code == 124 else "failed"
                else:
                    status = "failed"
                reason = msg
                if msg.startswith("scp exited"):
                    # scp prints ssh's own refusal just above navi's result line
                    low = text.lower()
                    if "remote host identification has changed" in low:
                        status, reason = "hostkey_mismatch", "scp refused: HOST KEY CHANGED — " + msg
                    elif re.search(r"no \S+ host key is known", low):
                        status, reason = "hostkey_unknown", "scp refused: host key not known (strict) — " + msg
                    elif "host key verification failed" in low:
                        status, reason = "hostkey_mismatch", "scp refused: host key verification failed — " + msg
            elif kind == "!":
                if msg.startswith("connection failed:"):
                    reason = msg[len("connection failed:"):].strip()
                    status = _conn_status(reason)
                elif "timed out waiting for the command" in msg:
                    timed_out, status, reason = True, "timeout", msg
                elif msg.startswith("error connecting"):
                    status, reason = "unreachable", msg + " (scp could not connect — nothing was copied)"
                elif msg.startswith("host key is not known"):
                    status, reason = "hostkey_unknown", msg
                else:
                    status, reason = (status if timed_out else "failed"), msg
            elif kind == "?":
                if not timed_out:
                    status, reason = "failed", msg
            continue
        if _NAVI_FRAME.match(line):
            continue
        out_lines.append(line)
    if status is None:
        if "navi config ssh" in text:
            status, reason = "no_credentials", "no SSH credentials in navi.db — run `navi config ssh`"
        elif "Refusing to run" in text:
            status, reason = "refused", "navi refused the target (not an IP address or hostname)"
        elif "No such option" in text or "no such option" in text:
            opt = re.search(r"[Nn]o such option:?\s*(\S+)", text)
            status, reason = "failed", ("this navi build does not support " + (opt.group(1) if opt else "a push option")
                                        + " — upgrade navi (pip install -U navi-pro)")
        elif "pexpect" in text or "pseudo-terminal" in text:
            status, reason = "failed", "navi push cannot run here (pexpect/pty missing) — run navi on Linux/macOS/WSL"
        else:
            status = "failed"
            reason = ("navi printed no per-host result" if returncode == 0
                      else "navi exited %s" % returncode)
    output = "\n".join(out_lines).strip("\n")
    return {"status": status, "exit_code": exit_code, "reason": reason[:500], "output": output}


def _push_exec(target: str, command: str = "", file: str = "", timeout=None, strict_host_keys: bool = False,
               retries: int = 0) -> dict:
    """Run `navi action push` on ONE host over SSH. Triple-gated. Provide EXACTLY one of
    command / file. Returns the classified per-host status (see classify_push) plus navi's
    raw output — a non-OK status means the change did NOT necessarily apply; re-verify.
    timeout → navi --timeout (seconds to wait for the command); strict_host_keys → navi
    --strict-host-keys (refuse a host whose key isn't already known); retries → re-run ONLY
    after a transport failure before the command started."""
    if not allow_writes():
        return {"ok": False, "blocked": True, "status": "blocked",
                "message": "writes disabled on server (set NAVI_ALLOW_WRITES=1)"}
    if not rce_enabled():
        return {"ok": False, "blocked": True, "status": "blocked",
                "message": "remote execution disabled on server — set NAVI_REMOTE_CODE_EXECUTION=1 "
                           "(a separate opt-in stacked on top of writes)"}
    if not navi_available():
        return {"ok": False, "blocked": True, "status": "blocked",
                "message": f"navi binary '{NAVI_BIN}' not found on PATH"}
    target = (target or "").strip()
    if not target:
        return {"ok": False, "status": "refused", "message": "target host IP required"}
    if not valid_target(target):
        return {"ok": False, "status": "refused", "target": target,
                "message": "refused: target is not a plain IP address or hostname (ssh would read it as an option)"}
    command = command or ""
    file = file or ""
    if bool(command) == bool(file):
        return {"ok": False, "status": "refused", "message": "provide EXACTLY one of command or file"}
    if file and not os.path.exists(file):
        return {"ok": False, "status": "refused", "message": f"file not found on the server: {file}"}
    cmd = [(_resolve_navi() or NAVI_BIN), "action", "push", _PUSH_TARGET_FLAG, target]
    if command:
        cmd += [_PUSH_CMD_FLAG, command]
    else:
        cmd += [_PUSH_FILE_FLAG, file]
    sub_timeout = PUSH_TIMEOUT
    if timeout:
        try:
            t = max(5, min(3600, int(timeout)))
            cmd += [_PUSH_TIMEOUT_FLAG, str(t)]
            sub_timeout = t + 90          # + SSH login + navi's failure probe (explain_ssh_failure)
        except (TypeError, ValueError):
            pass
    if strict_host_keys:
        cmd += [_PUSH_STRICT_FLAG]
    pretty = " ".join(shlex.quote(c) for c in cmd)
    try:
        retries = max(0, min(3, int(retries or 0)))
    except (TypeError, ValueError):
        retries = 0
    attempt = 0
    t0 = time.time()
    while True:
        attempt += 1
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, cwd=_navi_cwd(), timeout=sub_timeout)
        except subprocess.TimeoutExpired:
            return {"ok": False, "timed_out": True, "target": target, "cmd": pretty, "status": "timeout",
                    "attempts": attempt, "duration_ms": int((time.time() - t0) * 1000),
                    "message": f"push timed out after {sub_timeout}s — the command may still be "
                               "running on the host. Use non-interactive flags (e.g. -y, "
                               "DEBIAN_FRONTEND=noninteractive) and re-verify before retrying."}
        except Exception as e:  # pragma: no cover
            return {"ok": False, "target": target, "message": str(e), "cmd": pretty, "status": "failed",
                    "attempts": attempt, "duration_ms": int((time.time() - t0) * 1000)}
        c = classify_push(p.stdout, p.stderr, p.returncode, target)
        if c["status"] in RETRYABLE and attempt <= retries:
            time.sleep(min(10, 2 * attempt))
            continue
        break
    ok = c["status"] == "ok"
    summary = _navi_summary(p.stdout, p.stderr)
    res = {"ok": ok, "returncode": p.returncode, "target": target, "cmd": pretty,
           "status": c["status"], "exit_code": c["exit_code"], "reason": c["reason"], "output": c["output"][-16000:],
           "attempts": attempt, "duration_ms": int((time.time() - t0) * 1000),
           "hostkey_policy": "strict" if strict_host_keys else "accept-new",
           "navi_output": summary, "stdout": (p.stdout or "")[-4000:], "stderr": (p.stderr or "")[-2000:]}
    if ok:
        res["message"] = "exit 0" if c["exit_code"] == 0 else (c["reason"] or "pushed")
    elif c["status"] in ("unreachable", "auth_failed", "port_closed", "dns_failed", "no_credentials"):
        res["message"] = ("SSH push failed (" + c["status"] + ") — check the host is Linux + reachable and that "
                          "`navi config ssh` credentials are set. navi said: " + (c["reason"] or summary or "(no output)"))
    elif c["status"] == "hostkey_mismatch":
        res["message"] = ("HOST KEY CHANGED — possible impersonation or a rebuilt host. Nothing ran. Verify the host "
                          "out-of-band before clearing the old key. navi said: " + c["reason"])
    elif c["status"] == "hostkey_unknown":
        res["message"] = ("host key not yet known and strict host keys are on — run a 🔑 credential test first "
                          "(it records a new host's key), then retry.")
    else:
        res["message"] = c["reason"] or summary or ("navi exited %d" % p.returncode)
    return res


def _mode_for(command, file, catalog_id):
    if file:
        return "file"
    if catalog_id == "cred":
        return "cred_test"
    if catalog_id and not str(catalog_id).startswith(("remediation", "rollback")):
        return "read_only"
    if str(catalog_id or "").startswith("remediation"):
        return "remediation"
    if str(catalog_id or "").startswith("rollback"):
        return "rollback"
    return "change"


def push(target: str, command: str = "", file: str = "", agent: str = "c2",
         detail: str = "", sync: bool = True, *, source: str = "", run_id: str = "", mode: str = "",
         catalog_id: str = "", plan_sha256: str = "", timeout=None, strict_host_keys: bool = False,
         retries: int = 0) -> dict:
    """Execute one push — the SINGLE choke point for `navi action push` from any hound.
    Every call (blocked, refused, ok or failed) appends one row to the C2 command log
    (core/c2log.py: what ran where and when, the status — never the output, secrets masked,
    hash-chained) and the Tagging log keeps its op=push entry. Batch fan-out (loop per IP) is
    done by the caller, one call per host, so every host gets its own rows."""
    res = _push_exec(target=target, command=command, file=file, timeout=timeout,
                     strict_host_keys=strict_host_keys, retries=retries)
    asset = {}
    try:
        from core import c2_targets
        asset = c2_targets.lookup(target) or {}
    except Exception:
        asset = {}
    res["in_inventory"] = bool(asset)
    if asset:
        res["asset"] = {k: asset.get(k) for k in ("uuid", "hostname", "os")}
    try:
        from core import c2log
        logged_cmd = command if command else ("scp " + os.path.basename(file or ""))
        res["c2_log"] = c2log.record(
            target, logged_cmd, res.get("status") or ("ok" if res.get("ok") else "failed"),
            exit_code=res.get("exit_code"), duration_ms=res.get("duration_ms"), run_id=run_id,
            source=source or agent, agent=agent, mode=mode or _mode_for(command, file, catalog_id),
            catalog_id=catalog_id or ("file" if file else "free-form"), plan_sha256=plan_sha256,
            hostkey_policy=("strict" if strict_host_keys else "accept-new"), attempts=res.get("attempts") or 1,
            in_inventory=bool(asset), asset_uuid=asset.get("uuid") or "", hostname=asset.get("hostname") or "",
            sent_bytes=(command if command else file))
    except Exception as e:  # pragma: no cover — logging never breaks a push
        res["c2_log"] = {"error": str(e)}
    try:
        from core import tagq
        st = res.get("status") or ("ok" if res.get("ok") else "failed")
        from core import c2log as _c2l
        tagq.record({"agent": agent, "category": "C2 · push", "value": target,
                     "selector": ("file" if file else "command"),
                     "detail": _c2l.mask(detail or command or ("scp " + os.path.basename(file or "")))[:200], "op": "push"},
                    {"ok": res.get("ok"), "message": (st + (" · exit %s" % res["exit_code"]
                                                            if res.get("exit_code") is not None else "")
                                                      + (" · " + res["message"][:160] if res.get("message") and not res.get("ok") else ""))})
    except Exception:
        pass
    return res



def retry_page(job_id) -> dict:
    """Re-run ONE failed/cancelled page of a tag series, alone (the write gate is re-checked
    when it runs, like every tag job)."""
    from core import tagq
    tagq.register_runner("tag", lambda **kw: _tag_exec(**kw))
    return tagq.retry_page(job_id)


def cancel_series(series) -> dict:
    """Stop the rest of a tag series (pages still waiting → cancelled)."""
    from core import tagq
    return {"ok": True, "series": series, "cancelled": tagq.cancel_series(series)}
