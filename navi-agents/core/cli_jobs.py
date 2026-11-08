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


def _record(argv, label):
    jid = next(_IDS)
    job = {"id": jid, "label": label, "cmd": " ".join(argv), "status": "running",
           "returncode": None, "lines": [], "cur": "", "_cr": False, "cwd": None,
           "created": _now(), "started": _now(), "finished": None}
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
    with _LOCK:
        job["returncode"] = rc
        job["status"] = "done" if rc == 0 else "error"
        job["finished"] = _now()


def _start(sub_argv, label):
    navi = navi_cli._resolve_navi()
    if not navi:
        return {"ok": False, "error": navi_cli.write_gate_reason()
                or "navi CLI not found — install navi or set NAVI_BIN to its path."}
    cwd = _run_cwd()
    argv = [navi] + sub_argv
    job = _record(argv, label)
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
        else:                               # Windows fallback: plain pipe
            proc = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, bufsize=0, cwd=cwd, env=env)
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


def start_update(kind):
    """Start the navi command that rebuilds `kind`'s table, streaming its output."""
    key = str(kind or "").strip().lower()
    argv = COMMANDS.get(key)
    if not argv:
        return {"ok": False, "error": "unknown update kind: " + (key or "(blank)")}
    r = _start(argv, "navi " + " ".join(argv))
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


def start_optimize():
    """Start `navi config optimize` streaming (builds SQL indexes)."""
    r = _start(COMMANDS["optimize"], "navi config optimize")
    _tag_kind(r, "optimize")
    return r


def _view(job, since=0):
    """Snapshot for the client. `since` is a line cursor — only newer lines are sent."""
    with _LOCK:
        total = len(job["lines"])
        s = max(0, int(since or 0))
        out = job["lines"][s:] if s < total else []
        el = (job["finished"] or _now()) - (job["started"] or _now())
        return {"id": job["id"], "label": job["label"], "cmd": job["cmd"],
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
