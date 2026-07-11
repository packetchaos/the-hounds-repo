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
    return "query", (query or "")[:200]


def tag(category: str, value: str, query: str = "", remove: bool = False,
        cve: str = "", plugin_name: str = "", scanid: str = "",
        plugin: str = "", output: str = "", route_id: str = "", group: str = "",
        xrefs: str = "", xid: str = "", cpe: str = "", port: str = "",
        regex: bool = False,
        agent: str = "", sync: bool = False, op: str = "tag") -> dict:
    # SAFETY: adding a tag is the default. `remove=True` (the '-remove' flag, which
    # DELETES the tag from matching assets) is reserved for the Tag Removal agent
    # (Garmr) and the contract's removal phase — no other agent may remove tags.
    """Enqueue a navi tag write on the background worker (non-blocking) and return
    a job stub immediately. Pass sync=True to run inline and get the real result
    (used by tests / non-web callers). Track progress via core.tagq / the Tagging
    log page. The `agent` arg is metadata for the log only.

    `regex=True` (only meaningful with plugin+output) adds navi's `-regex` flag,
    telling navi the --output value is a regular expression over the plugin output.
    """
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
                       "selector": sel, "detail": detail, "op": op})
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


def _uuids_query(uuids, col="asset_uuid", table="vulns"):
    inl = ",".join("'" + str(u).replace("'", "''") + "'" for u in uuids)
    return f"SELECT DISTINCT {col} FROM {table} WHERE {col} IN ({inl})"


def tag_capped(category, value, uuids=None, query="", fallbacks=None, regex=False,
               remove=False, agent="", sync=False, threshold=None,
               col="asset_uuid", table="vulns", count=None):
    """Tag an asset set, automatically dodging the ~1999-UUID endpoint cap.

    - Small sets (<= threshold UUIDs): tag by the PRECISE --query (exact asset
      match — most accurate).
    - Large sets (> threshold): shift to navi BUILT-IN selectors supplied in
      `fallbacks` so navi does the paging server-side. Each fallback is a dict of
      navi selector kwargs, e.g. {"plugin": 20811, "output": "OpenSSL", "regex": True},
      {"cpe": "cpe:/a:openssl:openssl"}, or {"plugin_name": "Unsupported"}.

    `uuids` is the source of truth for the count and the small-set query (built
    from it if `query` is empty). If the set is over the cap but NO fallbacks were
    supplied, it still tags by --query (navi's internal loop handles it) — nothing
    breaks, it's just slower. Returns a LIST of job stubs (one per navi command).
    """
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
    q = query or (_uuids_query(uuids, col, table) if uuids else "")
    return [tag(category, value, query=q, remove=remove, agent=agent, sync=sync)]


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
            # Reassure rather than alarm: the strip happened; navi.db's own count only
            # updates on the next assets sync, so the tag may still show its old count.
            res["message"] = (summary or "removal applied") + \
                " — tag cleared (kept for its UUID); navi.db's count refreshes after the next assets sync"
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


def _mail_exec(to: str, subject: str = "navi report", message: str = "",
               file: str = "") -> dict:
    """Run `navi action mail --to <addr> --subject <s> --message <body> [--file <path>]`.
    SMTP is configured out-of-band. Double-gated (writes + email)."""
    if not allow_writes():
        return {"ok": False, "blocked": True,
                "message": "writes disabled on server (set NAVI_ALLOW_WRITES=1)"}
    if not email_enabled():
        return {"ok": False, "blocked": True,
                "message": "email disabled on server — set NAVI_EMAIL=1 (opt-in on top of writes)"}
    if not navi_available():
        return {"ok": False, "blocked": True,
                "message": f"navi binary '{NAVI_BIN}' not found on PATH"}
    to = (to or "").strip()
    if not to:
        return {"ok": False, "message": "recipient (to) required"}
    cmd = [(_resolve_navi() or NAVI_BIN), "action", "mail", "--to", to,
           "--subject", subject or "navi report"]
    if message:
        cmd += ["--message", message]
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
         agent: str = "email", sync: bool = True) -> dict:
    """Send an email via `navi action mail` and record it in the Tagging log as the
    accountability ledger (who was notified, when). Runs synchronously by default —
    a send is a discrete, user-confirmed action, not a background job."""
    res = _mail_exec(to=to, subject=subject, message=message, file=file)
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
        note: str | None = None, reasons: list[str] | None = None) -> dict:
    """Apply an ACR change (synchronous) and record it in the Tagging log so the
    contract builder captures ACR changes alongside tags."""
    res = _acr_exec(category, value, score, mod=mod, note=note, reasons=reasons)
    try:
        from core import tagq
        tagq.record({"agent": "acr", "category": category, "value": value,
                     "selector": "acr " + mod, "detail": f"score={score} ({mod})"}, res)
    except Exception:
        pass
    return res


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
           "--score", str(score), "--mod", mod] + ["-" + r for r in flags]
    if note:
        cmd += ["--note", note]
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
