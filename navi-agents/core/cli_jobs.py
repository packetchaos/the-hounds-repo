"""Streaming runner for long navi table-updates, so the Settings page can show a
live CLI window without leaving the app.

In-memory + session-only (like tagq/jobq): a Popen streams stdout line-by-line into
a buffer the frontend polls incrementally (via a `since` cursor). Only navi
read-syncs are allowed here — `navi config update <kind>` and `navi config optimize`.
Those refresh local navi.db tables from Tenable (a read into the local DB, not a
tenant write), so they are NOT write-gated; the kind allowlist blocks arbitrary
command execution.
"""
import itertools
import os
import re
import select
import subprocess
import threading
import time

from core import navi_cli

# Strip ANSI/OSC escapes — under a pty navi emits colors + cursor control we don't want.
_ANSI = re.compile(r"\x1b\[[0-9;?=]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")

try:
    import fcntl                           # POSIX only — used to size the pty
    import pty as _pty
    import struct
    import termios
    _HAS_PTY = True
except Exception:                          # Windows → fall back to a plain pipe
    _HAS_PTY = False


def _run_cwd():
    """The directory navi MUST run in — the folder that holds the navi.db the app
    reads. navi keeps a cwd-local navi.db, so a table update run from anywhere else
    (e.g. the bin dir the server happens to sit in) builds a SECOND navi.db there and
    the app never sees the result. Prefer navi_cli._navi_cwd(); fall back to the
    directory of NAVI_DB_PATH (absolutized)."""
    d = navi_cli._navi_cwd()
    if d and os.path.isdir(d):
        return d
    p = os.environ.get("NAVI_DB_PATH")
    if p:
        d2 = os.path.dirname(os.path.abspath(p))
        if os.path.isdir(d2):
            return d2
    return None

# Canonical table/update name -> the EXACT navi argv (after the navi binary).
# navi is not uniform: core syncs are `config update <kind>`, but the targeted builds
# (certs / software / epss) are `config <kind>` with NO "update", and plugins needs a
# size. `config update certificates` does not exist — it's `config certificates`.
COMMANDS = {
    "assets":       ["config", "update", "assets"],
    "tags":         ["config", "update", "assets"],   # tags are refreshed by the assets sync
    "vulns":        ["config", "update", "vulns"],
    "agents":       ["config", "update", "agents"],
    "was":          ["config", "update", "was"],       # Tenable WAS (web apps / findings)
    "routes":       ["config", "update", "route"],
    "paths":        ["config", "update", "paths"],
    "compliance":   ["config", "update", "compliance"],
    "fixed":        ["config", "update", "fixed"],
    "sla_calc":     ["config", "sla", "calculate"],    # stamp Pass/Fail SLA verdicts into fixed (Sköll)
    "plugins":      ["config", "update", "plugins", "--size", "10000"],
    "certificates": ["config", "certificates"],
    "software":     ["config", "software"],
    "epss":         ["config", "epss"],
    "full":         ["config", "update", "full"],
    "everything":   ["config", "update", "everything"],   # every table in one run
    "optimize":     ["config", "optimize"],
}

_JOBS = {}
_ORDER = []
_IDS = itertools.count(1)
_LOCK = threading.Lock()
MAX_LINES = 5000        # cap the buffer so a chatty sync can't balloon memory
KEEP_JOBS = 30          # retain the most recent N jobs


def _now():
    return time.time()


def _record(argv, label, kind=None):
    jid = next(_IDS)
    job = {"id": jid, "label": label, "cmd": " ".join(argv), "status": "running", "kind": kind,
           "returncode": None, "lines": [], "cur": "", "_cr": False, "cwd": None,
           "created": _now(), "started": _now(), "finished": None,
           "_local": _loopback()}
    with _LOCK:
        _JOBS[jid] = job
        _ORDER.append(jid)
        while len(_ORDER) > KEEP_JOBS:
            _JOBS.pop(_ORDER.pop(0), None)
    return job


def _reader(job, fd, proc):
    """Drain the child's output fd (a pty master, or a pipe on the fallback path) into
    the job buffer, emulating a terminal: '\\n' COMMITS the current line, '\\r' OVERWRITES
    it. That way a navi progress bar (which redraws one line with '\\r' every tick) stays
    a SINGLE live line instead of appending thousands over a multi-hour run — so the
    buffer can't balloon and the window never freezes at the truncation cap. Uses
    select + poll so it finishes the moment the process exits."""
    truncated = [False]
    carry = bytearray()          # holds a partial multibyte char across chunk boundaries

    def _commit(line):
        if len(job["lines"]) < MAX_LINES:
            job["lines"].append(line)
        elif not truncated[0]:
            job["lines"].append("… [older output trimmed — the run continues]")
            truncated[0] = True

    def feed(raw):
        carry.extend(raw)
        try:
            text = bytes(carry).decode("utf-8")
            del carry[:]
        except UnicodeDecodeError as e:          # keep the incomplete tail for next chunk
            text = bytes(carry[:e.start]).decode("utf-8", "replace")
            del carry[:e.start]
        if not text:
            return
        text = _ANSI.sub("", text)
        with _LOCK:
            cur = job["cur"]
            cr = job["_cr"]                       # saw a '\r' that might be part of '\r\n'
            for ch in text:
                if ch == "\r":
                    cr = True                    # defer — decide when we see the next char
                elif ch == "\n":
                    cr = False                   # '\r\n' or plain '\n' → commit the line
                    _commit(cur); cur = ""
                else:
                    if cr:                       # a LONE '\r' → carriage return, overwrite
                        cur = ""; cr = False
                    if ch == "\t":
                        cur += "    "
                    elif ch < " " or ch == "\x7f":
                        continue
                    else:
                        cur += ch
            job["cur"] = cur
            job["_cr"] = cr

    try:
        while True:
            try:
                r, _, _ = select.select([fd], [], [], 0.5)
            except (OSError, ValueError):
                break
            if r:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:                  # a pty master raises EIO at child exit
                    chunk = b""
                if chunk:
                    feed(chunk)
                    continue
                break                            # EOF
            if proc.poll() is not None:          # exited with nothing left to read
                try:
                    while True:
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            break
                        feed(chunk)
                except OSError:
                    pass
                break
    except Exception as e:                       # pragma: no cover
        with _LOCK:
            _commit("[reader error] " + str(e))
    with _LOCK:
        if job["cur"]:                           # flush the last unterminated line
            _commit(job["cur"]); job["cur"] = ""
    try:
        os.close(fd)
    except OSError:
        pass
    rc = proc.wait()
    if rc == 0:
        _after_sync(job)                         # before "done", so a poller sees the note first
    with _LOCK:
        job["returncode"] = rc
        job["status"] = "done" if rc == 0 else "error"
        job["finished"] = _now()


def _after_sync(job):
    """A console-launched assets/vulns sync (or navi's own `config optimize`, which runs a
    bare ANALYZE) can leave the Hounds' vulns indexes without their 'unordered' stat — re-apply
    it, only when those indexes exist. Cheap (catalog read + one UPDATE); never fatal."""
    try:
        from core import hx_optimize
        if job.get("kind") not in hx_optimize.SYNC_KINDS:
            return
        r = hx_optimize.reapply_unordered()
        msg = None
        _refresh_summaries(job)
        if r.get("applied"):
            msg = "Hounds: re-applied 'unordered' to the hx_ vulns index stats (Settings ▸ Optimize)."
        elif not r.get("ok"):
            msg = "Hounds: could not re-apply 'unordered' (%s) — run ⚡ Optimize in Settings." % r.get("error")
        if msg:
            with _LOCK:
                job["lines"].append(msg)
    except Exception:                            # pragma: no cover
        pass


def _loopback():
    try:
        from core import gates
        return bool(gates.client_is_loopback())
    except Exception:
        return False


def _refresh_summaries(job):
    """After a console-launched vulns/assets sync: when the Hounds' summary tables (hx_plugin /
    hx_asset) were built before, they are now stale — start ⚡ Optimize to rebuild them (indexes
    already exist, so it is ANALYZE + the summaries). Never when they were never built: the user
    hasn't opted in to writes on navi.db yet."""
    if job.get("kind") not in ("assets", "vulns", "full", "everything") or job.get("_no_refresh"):
        return
    try:
        from core import hx_optimize, hx_summary
        hx_summary.invalidate()
        st = hx_optimize.status()
        sm = st.get("summary") or {}
        if not sm.get("present") or sm.get("fresh"):
            return
        if not job.get("_local"):
            # Optimize writes navi.db (loopback + confirm when started by hand): a sync started
            # from a remote browser doesn't get to start it implicitly
            with _LOCK:
                job["lines"].append("Hounds: the summary tables are now stale — run ⚡ Optimize in "
                                    "Settings (from this machine) to refresh them; hounds use the "
                                    "slower path until then.")
            return

        def _go():
            for _ in range(60):                 # wait for this sync job to be marked done
                time.sleep(1)
                with _LOCK:
                    if job.get("status") != "running":
                        break
            r = hx_optimize.run()
            line = ("Hounds: refreshing the summary tables (⚡ Optimize) — hounds use the slower "
                    "path until it finishes." if r.get("ok") else
                    "Hounds: summary tables are stale and could not refresh (%s) — run ⚡ Optimize "
                    "in Settings." % r.get("error"))
            with _LOCK:
                job["lines"].append(line)
        threading.Thread(target=_go, daemon=True, name="hounds-summary-refresh").start()
    except Exception:                            # pragma: no cover
        pass


def hx_busy():
    """The running ⚡ Optimize job, if any — it holds navi.db's write lock for the whole build,
    so navi syncs launched from the console wait for it instead of failing 'database is locked'."""
    with _LOCK:
        for j in _JOBS.values():
            if j.get("status") == "running" and j.get("kind") == "hx_optimize":
                return j
    return None


def _start(sub_argv, label, answer=None, kind=None):
    """answer: bytes typed into navi's stdin right after it starts — only used to answer
    the y/N confirm of `-rebuild` (click.confirm), which the user already confirmed in
    the page. Anything else keeps navi's stdin a closed terminal / DEVNULL."""
    hx = hx_busy()
    if hx is not None:
        return {"ok": False, "error": "⚡ Optimize for the Hounds is building indexes (job #%s) and holds "
                "navi.db's write lock — wait for it to finish (or cancel it in Settings)." % hx["id"]}
    navi = navi_cli._resolve_navi()
    if not navi:
        return {"ok": False, "error": navi_cli.write_gate_reason()
                or "navi CLI not found — install navi or set NAVI_BIN to its path."}
    cwd = _run_cwd()
    argv = [navi] + sub_argv
    job = _record(argv, label, kind)
    job["cwd"] = cwd or "(server working dir — set NAVI_DB_PATH so navi runs where your navi.db lives)"
    with _LOCK:
        job["lines"].append("cwd: " + cwd if cwd else
                             "⚠ no navi.db location resolved — running in the server's working dir. "
                             "Set NAVI_DB_PATH (Settings ▸ Environment) so navi builds the right navi.db.")
    # Run navi under a PTY so it line-buffers and flushes its early lines immediately
    # (banner, "Requesting export", "Status: PROCESSING") — under a plain pipe navi
    # block-buffers and those sit hidden for the whole multi-minute Tenable wait. Crucially
    # we do NOT detach the session (start_new_session) — that was what wedged the export
    # mid-run. A normal process + a pty behaves just like your shell.
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    try:
        if _HAS_PTY:
            master, slave = _pty.openpty()
            try:
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 200, 0, 0))
            except Exception:
                pass
            try:
                proc = subprocess.Popen(
                    argv, stdin=slave, stdout=slave, stderr=slave,
                    cwd=cwd, env=env, close_fds=True)
            finally:
                os.close(slave)             # parent keeps only the master end
            fd = master
            if answer:
                try:
                    os.write(master, answer)    # the tty buffers it until click.confirm reads
                except OSError:
                    pass
        else:                               # Windows fallback: plain pipe
            proc = subprocess.Popen(
                argv, stdin=(subprocess.PIPE if answer else subprocess.DEVNULL), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, bufsize=0, cwd=cwd, env=env)
            if answer:
                try:
                    proc.stdin.write(answer)
                    proc.stdin.close()
                except Exception:
                    pass
            fd = proc.stdout.fileno()
    except Exception as e:
        with _LOCK:
            job["status"] = "error"
            job["returncode"] = -1
            job["lines"].append("[spawn error] " + str(e))
            job["finished"] = _now()
        return {"ok": False, "error": str(e), "job": _view(job)}
    threading.Thread(target=_reader, args=(job, fd, proc), daemon=True).start()
    return {"ok": True, "job": _view(job)}


def start_update(kind, refresh_summaries=True):
    """Start the navi command that rebuilds `kind`'s table, streaming its output.
    refresh_summaries=False: a chain of syncs (assets → vulns) refreshes the summary tables
    only after its LAST sync — Optimize holds navi.db's write lock, so refreshing in between
    would make the next sync refuse to start."""
    key = str(kind or "").strip().lower()
    argv = COMMANDS.get(key)
    if not argv:
        return {"ok": False, "error": "unknown update kind: " + (key or "(blank)")}
    r = _start(argv, "navi " + " ".join(argv), kind=key)
    if not refresh_summaries:
        jid = (r.get("job") or {}).get("id")
        with _LOCK:
            if jid in _JOBS:
                _JOBS[jid]["_no_refresh"] = True
    _tag_kind(r, key)
    return r


def _tag_kind(r, kind):
    """Remember which Settings button started a job, so the page can show it as running."""
    try:
        jid = (r.get("job") or {}).get("id")
        if jid is not None:
            with _LOCK:
                if jid in _JOBS:
                    _JOBS[jid]["kind"] = kind
    except Exception:
        pass


REBUILD_TABLES = {"both": ["config", "update", "full"],
                  "assets": ["config", "update", "assets"],
                  "vulns": ["config", "update", "vulns"]}
# derived from assets/vulns — stale after a rebuild (navi's own rebuild_reminder lists these)
REBUILD_DERIVED = ("certificates", "software", "routes", "paths")


def running():
    """Jobs still running (any kind) — a rebuild must not race another navi.db writer."""
    with _LOCK:
        busy = [j for j in _JOBS.values() if j.get("status") == "running"]
    return [_view(j) for j in busy]        # _view takes _LOCK itself (not re-entrant)


def rebuild_argv(tables, days):
    """`navi config update <full|assets|vulns> -rebuild --days N` — or (None, error)."""
    t = str(tables or "").strip().lower()
    if t not in REBUILD_TABLES:
        return None, "tables must be one of: both, assets, vulns"
    try:
        d = int(str(days).strip())
    except (TypeError, ValueError):
        return None, "days must be a whole number"
    if not 1 <= d <= 3650:
        return None, "days must be between 1 and 3650"
    return REBUILD_TABLES[t] + ["-rebuild", "--days", str(d)], None


def start_rebuild(tables="both", days=90, derived=True, hx=False):
    """DROP + re-create navi.db's assets and/or vulns tables and pull `days` days fresh,
    via navi's own `-rebuild` (it asks y/N; the page already confirmed, so we answer y).
    Clears assets that aged out of the window or fell off licensing — navi's normal sync
    only upserts, so they otherwise stay in navi.db forever. With derived=True, the
    tables navi says go stale after a rebuild (certs, software, routes, paths) are
    rebuilt one after another once it succeeds. With hx=True, ⚡ Optimize for the Hounds runs
    last (a -rebuild drops vulns and every index on it). Local navi.db only — nothing in Tenable."""
    argv, err = rebuild_argv(tables, days)
    if err:
        return {"ok": False, "error": err}
    busy = running()
    if busy:
        return {"ok": False, "error": "another navi job is running (%s) — wait for it to finish, "
                "a rebuild can't share navi.db with it" % busy[0].get("cmd", "?")}
    r = _start(argv, "navi " + " ".join(argv), answer=b"y\n", kind="rebuild")
    _tag_kind(r, "rebuild")
    jid = (r.get("job") or {}).get("id")
    if r.get("ok") and (derived or hx) and jid is not None:
        def _chain():
            while True:
                with _LOCK:
                    st = (_JOBS.get(jid) or {}).get("status")
                if st != "running":
                    break
                time.sleep(3)
            if st != "done":
                return                    # the rebuild failed or was cancelled — leave the rest alone
            for k in (REBUILD_DERIVED if derived else ()):
                rr = start_update(k, refresh_summaries=False)
                kid = (rr.get("job") or {}).get("id")
                while kid is not None:
                    with _LOCK:
                        if (_JOBS.get(kid) or {}).get("status") != "running":
                            break
                    time.sleep(3)
            if hx:                        # after the derived tables, so it never races a navi writer
                try:
                    from core import hx_optimize
                    rr = hx_optimize.run()
                    if not rr.get("ok"):
                        with _LOCK:
                            if jid in _JOBS:
                                _JOBS[jid]["lines"].append("⚡ Optimize for the Hounds not started: "
                                                           + str(rr.get("error")))
                except Exception as e:    # pragma: no cover
                    with _LOCK:
                        if jid in _JOBS:
                            _JOBS[jid]["lines"].append("⚡ Optimize for the Hounds failed to start: %s" % e)
        threading.Thread(target=_chain, daemon=True, name="navi-rebuild-derived").start()
        r["then"] = (["navi " + " ".join(COMMANDS[k]) for k in REBUILD_DERIVED] if derived else []) \
            + (["⚡ Optimize for the Hounds"] if hx else [])
    return r


def start_optimize():
    """Start `navi config optimize` streaming (builds SQL indexes)."""
    r = _start(COMMANDS["optimize"], "navi config optimize", kind="optimize")
    _tag_kind(r, "optimize")
    return r


def _view(job, since=0):
    """Snapshot for the client. `since` is a line cursor — only newer lines are sent."""
    with _LOCK:
        total = len(job["lines"])
        s = max(0, int(since or 0))
        out = job["lines"][s:] if s < total else []
        el = (job["finished"] or _now()) - (job["started"] or _now())
        return {"id": job["id"], "label": job["label"], "cmd": job["cmd"], "kind": job.get("kind"),
                "cwd": job.get("cwd"), "status": job["status"], "returncode": job["returncode"],
                "lines": list(out), "n_lines": total, "since": s, "cur": job.get("cur", ""),
                "elapsed": round(el, 1), "started": job["started"], "finished": job["finished"]}


def poll(jid, since=0):
    key = int(jid) if str(jid).isdigit() else None
    with _LOCK:
        job = _JOBS.get(key)
    if not job:
        return {"ok": False, "error": "no such job"}
    return {"ok": True, "job": _view(job, since)}


def recent():
    with _LOCK:
        jobs = [_JOBS[i] for i in _ORDER]
    return [{"id": j["id"], "label": j["label"], "status": j["status"], "kind": j.get("kind"),
             "returncode": j["returncode"], "n_lines": len(j["lines"]),
             "started": j["started"], "finished": j["finished"]} for j in reversed(jobs)]


def start_task(label, kind, fn, cmd=None):
    """Run an in-process Python job (⚡ Optimize for the Hounds) through the same job table,
    so the Settings CLI window, Recent runs and poll() show it like a navi run.
    fn(emit, live, cancel): emit(line) commits a line, live(text) sets the overwriting
    status line, cancel is a threading.Event set by cancel(job_id). Return value with
    ok False / cancelled → non-zero exit."""
    job = _record([cmd or label], label, kind)
    job["cwd"] = None
    ev = threading.Event()
    job["_cancel"] = ev

    def emit(line):
        with _LOCK:
            if len(job["lines"]) < MAX_LINES:
                job["lines"].append(str(line))

    def live(text):
        with _LOCK:
            job["cur"] = str(text or "")

    def body():
        rc = 0
        try:
            res = fn(emit, live, ev)
            if isinstance(res, dict) and res.get("cancelled"):
                rc = 130
            elif isinstance(res, dict) and res.get("ok") is False:
                rc = 1
        except Exception as e:
            emit("[error] %s: %s" % (type(e).__name__, e))
            rc = 1
        with _LOCK:
            job["cur"] = ""
            job["returncode"] = rc
            job["status"] = "done" if rc == 0 else ("cancelled" if rc == 130 else "error")
            job["finished"] = _now()

    threading.Thread(target=body, daemon=True, name="hounds-task-%s" % job["id"]).start()
    return {"ok": True, "job": _view(job)}


def cancel(jid):
    """Ask an in-process job to stop (navi subprocess jobs are not cancellable here)."""
    key = int(jid) if str(jid).isdigit() else None
    with _LOCK:
        job = _JOBS.get(key)
        ev = job.get("_cancel") if job else None
        st = job.get("status") if job else None
    if not job:
        return {"ok": False, "error": "no such job"}
    if ev is None:
        return {"ok": False, "error": "this job can't be cancelled from here"}
    if st != "running":
        return {"ok": True, "job": _view(job), "message": "already finished"}
    ev.set()
    return {"ok": True, "job": _view(job), "message": "cancelling — the index in progress is rolled back"}
