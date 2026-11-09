"""C2 command log — every command any hound runs on any host, one row per host per command.

The owner's rule: a log of WHAT ran WHERE and WHEN — never the reply. No stdout / stderr is
stored here, ever (the page shows output live; it is gone when the page is). Rows live in the
Tagging log's SQLite sidecar (``tag_jobs.db`` / ``NAVI_TAGLOG_DB``, see core/tagq.py) as the
``c2_log`` table, like core/acrlog.py.

Written ONLY from core.navi_cli.push() — the single choke point every `navi action push`
goes through, whichever hound asked (C2 itself, a hand-off, a remediation plan, …).

Tamper evidence: each row carries ``prev_hash`` (the previous row's hash) and ``row_hash`` =
sha256(prev_hash + canonical JSON of the row). ``verify_chain()`` recomputes the chain and
names the first row that does not match — an edited, deleted or re-ordered row breaks it.
Triggers refuse UPDATE / DELETE through SQLite itself (append-only); the chain catches
anything done around them.

Secrets: the command text is REDACTED before it is stored (``mask()``: password= / token= /
--password X / -pSECRET / Bearer … / user:pass@ URLs / private-key blocks / provider keys /
the navi.db ssh password). ``command_sha256`` is the hash of the exact bytes sent, so a row
can still be matched to a command you hold without the log holding the secret.
"""
import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import threading
import time
import uuid as _uuid

from . import tagq

STATUSES = ("ok", "changed", "failed", "unreachable", "auth_failed", "hostkey_mismatch", "hostkey_unknown",
            "port_closed", "dns_failed", "timeout", "skipped", "not_applicable", "cancelled", "blocked",
            "refused", "no_credentials")
_LOCK = threading.Lock()
_READY = None
FIELDS = ("ts", "run_id", "source", "agent", "operator", "target", "in_inventory", "asset_uuid", "hostname",
          "mode", "catalog_id", "command", "command_sha256", "plan_sha256", "status", "exit_code",
          "duration_ms", "hostkey_policy", "attempts")
GENESIS = "0" * 64


def _con():
    con = sqlite3.connect(tagq._DBPATH, timeout=10.0)
    con.execute("PRAGMA busy_timeout=10000")
    return con


def _ensure():
    global _READY
    if _READY:
        return True
    try:
        con = _con()
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("CREATE TABLE IF NOT EXISTS c2_log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, "
                        "run_id TEXT, source TEXT, agent TEXT, operator TEXT, target TEXT, in_inventory INTEGER, "
                        "asset_uuid TEXT, hostname TEXT, mode TEXT, catalog_id TEXT, command TEXT, "
                        "command_sha256 TEXT, plan_sha256 TEXT, status TEXT, exit_code INTEGER, duration_ms INTEGER, "
                        "hostkey_policy TEXT, attempts INTEGER, prev_hash TEXT, row_hash TEXT)")
            con.execute("CREATE INDEX IF NOT EXISTS c2_log_ts ON c2_log(ts)")
            con.execute("CREATE INDEX IF NOT EXISTS c2_log_target ON c2_log(target)")
            con.execute("CREATE INDEX IF NOT EXISTS c2_log_run ON c2_log(run_id)")
            con.execute("CREATE TRIGGER IF NOT EXISTS c2_log_no_update BEFORE UPDATE ON c2_log "
                        "BEGIN SELECT RAISE(ABORT, 'c2_log is append-only'); END")
            con.execute("CREATE TRIGGER IF NOT EXISTS c2_log_no_delete BEFORE DELETE ON c2_log "
                        "BEGIN SELECT RAISE(ABORT, 'c2_log is append-only'); END")
            # remediation plans (metadata, not part of the chain): generated → approved → deployed
            con.execute("CREATE TABLE IF NOT EXISTS c2_plans(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, "
                        "plan_id TEXT UNIQUE, source TEXT, selector TEXT, generator TEXT, generated_sha256 TEXT, "
                        "approved_sha256 TEXT, status TEXT, hosts INTEGER, updated REAL)")
            con.commit()
        finally:
            con.close()
        try:
            from core.security import private_file
            private_file(tagq._DBPATH)
        except Exception:
            pass
        _READY = True
    except Exception:
        _READY = False
    return _READY


def new_run(prefix="c2") -> str:
    return "%s-%d-%s" % (prefix, int(time.time() * 1000), _uuid.uuid4().hex[:6])


# ---- secret masking -------------------------------------------------------------------
MASK = "****"
_MASKS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
     "-----BEGIN PRIVATE KEY-----" + MASK + "-----END PRIVATE KEY-----"),
    (re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic|token)\s+)\S+"), r"\1" + MASK),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"), r"\1" + MASK),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+@"), r"\1" + MASK + "@"),
    (re.compile(r"(?i)(--?(?:password|passwd|pass|pwd|token|secret|api[-_]?key|apikey|access[-_]?key|secret[-_]?key|auth[-_]?token)"
                r"(?:=|\s+))(\"[^\"]*\"|'[^']*'|\S+)"), r"\1" + MASK),
    (re.compile(r"(?i)(\b[A-Z0-9_]*(?:password|passwd|pwd|token|secret|api_?key|apikey|access_?key|credential)[A-Z0-9_]*\s*[=:]\s*)"
                r"(\"[^\"]*\"|'[^']*'|\S+)"), r"\1" + MASK),
    (re.compile(r"(\bmysql\S*\s+(?:\S+\s+)*?-p)(\S+)"), r"\1" + MASK),
    (re.compile(r"(?i)(\becho\s+)(\"[^\"]*\"|'[^']*'|\S+)(\s*\|\s*sudo\s+-S\b)"), r"\1" + MASK + r"\3"),
    (re.compile(r"(?i)(\bsshpass\s+-p\s*)(\S+)"), r"\1" + MASK),
    (re.compile(r"(?i)((?:^|\s)(?:-u|--user|--proxy-user)(?:=|\s+))(\"[^\"]*\"|'[^']*'|[^\s:]+):(\S+)"), r"\1\2:" + MASK),
    (re.compile(r"(?i)(\b(?:docker|podman|nerdctl|helm)\s+(?:\S+\s+)*?login\b.*?\s(?:-p|--password)(?:=|\s+))(\S+)"), r"\1" + MASK),
    (re.compile(r"(?i)(\bredis-cli\b.*?\s(?:-a|--pass)(?:=|\s+))(\S+)"), r"\1" + MASK),
    (re.compile(r"(?i)(\b(?:printf|echo)\s+(?:'[^']*'\s+|\"[^\"]*\"\s+)?)(\"[^\"]*\"|'[^']*'|\S+)(\s*\|\s*(?:sudo\s+-S|chpasswd|passwd\s+--stdin))"), r"\1" + MASK + r"\3"),
    (re.compile(r"(<<<\s*)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1" + MASK),
    (re.compile(r"(?i)(\bsmbclient\b.*?\s-U\s*(?:\S+?)%)(\S+)"), r"\1" + MASK),
    (re.compile(r"(?i)(\bhtpasswd\b(?:\s+-\S+)*\s+-\S*b\S*\s+\S+\s+\S+\s+)(\S+)"), r"\1" + MASK),
    (re.compile(r"(?i)(\bopenssl\b.*?\s(?:-k|-kfile)\s+)(\S+)"), r"\1" + MASK),
    (re.compile(r"(?i)(-pass(?:in|out)?\s+(?:pass|env|file):)(\S+)"), r"\1" + MASK),
    (re.compile(r"(?i)(\bx-api-key\s*:\s*)(\S+)"), r"\1" + MASK),
    (re.compile(r"(?i)([?&](?:api_?key|token|access_token|key|secret|password|pwd|sig)=)([^&\s'\"]+)"), r"\1" + MASK),
    (re.compile(r"(?i)(--(?:http-|ftp-|proxy-)?password=)(\S+)"), r"\1" + MASK),
]


def mask(cmd) -> str:
    """Redact anything that looks like a secret in a command line (best-effort, conservative)."""
    s = str(cmd or "")
    for rx, rep in _MASKS:
        s = rx.sub(rep, s)
    try:
        from core import redact
        s = redact.scrub(s)
    except Exception:
        pass
    return s


# ---- hashing ----------------------------------------------------------------------------
def _canon(row) -> str:
    return json.dumps({k: row.get(k) for k in FIELDS}, sort_keys=True, separators=(",", ":"), default=str)


def _hash(prev, row) -> str:
    return hashlib.sha256((prev + "|" + _canon(row)).encode("utf-8")).hexdigest()


def sha256(text) -> str:
    return hashlib.sha256(str(text or "").encode("utf-8", "surrogatepass")).hexdigest()


def _operator():
    who = ""
    try:
        import getpass
        who = getpass.getuser()
    except Exception:
        who = os.environ.get("USER") or ""
    where = "local"
    try:
        from core import gates
        c = gates._CLIENT.get()
        if c and c.get("http") and not gates.client_is_loopback():
            where = "remote:" + str((c.get("peer") or ("?",))[0] if isinstance(c.get("peer"), (tuple, list))
                                    else c.get("peer"))
    except Exception:
        pass
    return (who or "?") + "@" + where


def record(target, command, status, *, exit_code=None, duration_ms=None, run_id="", source="", agent="",
           mode="", catalog_id="", plan_sha256="", hostkey_policy="", attempts=1, in_inventory=None,
           asset_uuid="", hostname="", sent_bytes=None) -> dict:
    """Append ONE row (never the output). Returns {"id", "row_hash"} or {"error"}."""
    if not _ensure():
        return {"error": "C2 log unavailable"}
    row = {"ts": round(time.time(), 3), "run_id": str(run_id or ""), "source": str(source or ""),
           "agent": str(agent or ""), "operator": _operator(), "target": str(target or ""),
           "in_inventory": (None if in_inventory is None else (1 if in_inventory else 0)),
           "asset_uuid": str(asset_uuid or ""), "hostname": str(hostname or ""), "mode": str(mode or ""),
           "catalog_id": str(catalog_id or ""), "command": mask(command)[:4000],
           "command_sha256": sha256(sent_bytes if sent_bytes is not None else command),
           "plan_sha256": str(plan_sha256 or ""), "status": str(status or ""),
           "exit_code": (None if exit_code is None else int(exit_code)),
           "duration_ms": (None if duration_ms is None else int(duration_ms)),
           "hostkey_policy": str(hostkey_policy or ""), "attempts": int(attempts or 1)}
    try:
        with _LOCK:
            con = _con()
            try:
                con.execute("BEGIN IMMEDIATE")          # serialises writers across processes too
                last = con.execute("SELECT row_hash FROM c2_log ORDER BY id DESC LIMIT 1").fetchone()
                prev = (last[0] if last and last[0] else GENESIS)
                h = _hash(prev, row)
                cur = con.execute("INSERT INTO c2_log(" + ",".join(FIELDS) + ",prev_hash,row_hash) VALUES("
                                  + ",".join("?" * (len(FIELDS) + 2)) + ")",
                                  tuple(row[k] for k in FIELDS) + (prev, h))
                n = con.execute("SELECT COUNT(*) FROM c2_log").fetchone()[0]
                con.commit()
                _write_head({"id": cur.lastrowid, "head": h, "rows": n})
                return {"id": cur.lastrowid, "row_hash": h}
            finally:
                con.close()
    except Exception as e:
        return {"error": str(e)}


def _head_path():
    return tagq._DBPATH + ".c2head"


def _write_head(d):
    """The chain head + row count, kept OUTSIDE the database (0600 sidecar) so deleting the
    newest rows or rewriting the whole table with a fresh, self-consistent chain is caught."""
    try:
        from core.security import private_open
        tmp = _head_path() + ".tmp"
        with private_open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, _head_path())
    except Exception:
        pass


def _read_head():
    try:
        with open(_head_path()) as f:
            return json.load(f)
    except Exception:
        return None


def verify_chain() -> dict:
    """Recompute every row's hash in id order. {ok, rows, broken_at, reason}."""
    if not _ensure():
        return {"ok": False, "rows": 0, "reason": "C2 log unavailable"}
    try:
        con = _con()
        try:
            con.row_factory = sqlite3.Row
            prev, n, last_id = GENESIS, 0, 0
            for r in con.execute("SELECT * FROM c2_log ORDER BY id ASC"):
                d = dict(r)
                n += 1
                if (d.get("prev_hash") or "") != prev:
                    return {"ok": False, "state": "broken", "rows": n, "broken_at": d["id"],
                            "reason": "prev_hash does not match the previous row (a row was removed or re-ordered)"}
                if _hash(prev, d) != d.get("row_hash"):
                    return {"ok": False, "state": "broken", "rows": n, "broken_at": d["id"], "reason": "row contents changed after it was written"}
                prev = d["row_hash"]
                last_id = d["id"]
            if n:
                seq = con.execute("SELECT seq FROM sqlite_sequence WHERE name='c2_log'").fetchone()
                if seq and int(seq[0]) != int(last_id):
                    return {"ok": False, "state": "broken", "rows": n, "broken_at": int(last_id) + 1,
                            "reason": f"the newest row(s) were removed (rows up to #{seq[0]} were written, the log ends at #{last_id})"}
            side = _read_head()
            if side:
                if n < int(side.get("rows") or 0):
                    return {"ok": False, "state": "broken", "rows": n, "broken_at": side.get("id"),
                            "reason": f"rows are missing ({side.get('rows')} were written, {n} remain)"}
                hit = con.execute("SELECT row_hash FROM c2_log WHERE id=?", (side.get("id"),)).fetchone()
                if not hit or hit[0] != side.get("head"):
                    return {"ok": False, "state": "broken", "rows": n, "broken_at": side.get("id"),
                            "reason": "the chain does not contain the recorded head — the log was rewritten"}
            elif n:
                return {"ok": False, "state": "unverifiable", "rows": n, "head": prev,
                        "reason": "unverifiable — head file missing (" + os.path.basename(_head_path()) + "): the rows chain "
                                  "together, but deleted newest rows or a full rewrite can't be ruled out"}
            return {"ok": True, "state": "intact" if n else "empty", "rows": n, "head": prev}
        finally:
            con.close()
    except Exception as e:
        return {"ok": False, "rows": 0, "reason": str(e)}


# ---- reads --------------------------------------------------------------------------------
def _q(sql, params=()):
    if not _ensure():
        return []
    try:
        con = _con()
        try:
            con.row_factory = sqlite3.Row
            return [dict(r) for r in con.execute(sql, params).fetchall()]
        finally:
            con.close()
    except Exception:
        return []


def _where(f):
    f = f or {}
    w, p = [], []
    for k in ("status", "source", "agent", "mode", "run_id", "catalog_id", "target", "hostkey_policy"):
        v = f.get(k)
        if v == "__none":
            w.append("(%s IS NULL OR %s = '')" % (k, k))
        elif v not in (None, ""):
            w.append("%s = ?" % k)
            p.append(str(v))
    if f.get("in_inventory") in ("0", "1", 0, 1, True, False):
        w.append("in_inventory = ?")
        p.append(1 if str(f.get("in_inventory")) in ("1", "True") else 0)
    for k, op in (("since", ">="), ("until", "<=")):
        if f.get(k) not in (None, ""):
            try:
                p.append(float(f[k]))
                w.append("ts %s ?" % op)
            except (TypeError, ValueError):
                pass
    q = str(f.get("q") or "").strip()
    if q:
        w.append("(target LIKE ? OR hostname LIKE ? OR asset_uuid LIKE ? OR command LIKE ? OR run_id LIKE ?)")
        p += ["%" + q + "%"] * 5
    return ((" WHERE " + " AND ".join(w)) if w else ""), tuple(p)


_COLS = "id, ts, run_id, source, agent, operator, target, in_inventory, asset_uuid, hostname, mode, catalog_id, " \
        "command, command_sha256, plan_sha256, status, exit_code, duration_ms, hostkey_policy, attempts, row_hash"


def rows(filters=None, limit=5000) -> dict:
    w, p = _where(filters)
    try:
        lim = max(1, min(100000, int(limit or 5000)))
    except (TypeError, ValueError):
        lim = 5000
    data = _q("SELECT " + _COLS + " FROM c2_log" + w + " ORDER BY id DESC LIMIT ?", p + (lim,))
    tot = _q("SELECT COUNT(*) n FROM c2_log" + w, p)
    return {"rows": data, "total": (tot[0]["n"] if tot else 0), "limit": lim}


def facets() -> dict:
    def g(col):
        return [{"v": r["v"], "n": r["n"]} for r in
                _q("SELECT %s v, COUNT(*) n FROM c2_log GROUP BY %s ORDER BY n DESC" % (col, col))]
    return {"status": g("status"), "source": g("source"), "mode": g("mode"), "agent": g("agent")}


def stats() -> dict:
    """At-a-glance numbers for the C2 page."""
    now = time.time()
    day0 = now - (now % 86400)          # UTC midnight
    wk = now - 7 * 86400

    def n(sql, p=()):
        r = _q(sql, p)
        return (r[0].get("n") or 0) if r else 0
    last = _q("SELECT ts, target, status, catalog_id, source FROM c2_log WHERE status NOT IN ('blocked','refused') "
              "ORDER BY id DESC LIMIT 1")
    plans = {r["status"]: r["n"] for r in _q("SELECT status, COUNT(*) n FROM c2_plans GROUP BY status")}
    RAN = " AND status NOT IN ('blocked','refused')"      # attempts that never reached a host
    return {"today": n("SELECT COUNT(*) n FROM c2_log WHERE ts>=?" + RAN, (day0,)),
            "week": n("SELECT COUNT(*) n FROM c2_log WHERE ts>=?" + RAN, (wk,)),
            "total": n("SELECT COUNT(*) n FROM c2_log"),
            "hosts_week": n("SELECT COUNT(DISTINCT target) n FROM c2_log WHERE ts>=?" + RAN, (wk,)),
            "failures_week": n("SELECT COUNT(*) n FROM c2_log WHERE ts>=? AND status NOT IN "
                               "('ok','changed','skipped','not_applicable','cancelled','blocked','refused')", (wk,)),
            "not_run_week": n("SELECT COUNT(*) n FROM c2_log WHERE ts>=? AND status IN ('blocked','refused')", (wk,)),
            "auth_failed_week": n("SELECT COUNT(*) n FROM c2_log WHERE ts>=? AND status='auth_failed'", (wk,)),
            "hostkey_changed": n("SELECT COUNT(*) n FROM c2_log WHERE status='hostkey_mismatch'"),
            "hostkey_changed_week": n("SELECT COUNT(*) n FROM c2_log WHERE ts>=? AND status='hostkey_mismatch'", (wk,)),
            "off_inventory_week": n("SELECT COUNT(*) n FROM c2_log WHERE ts>=? AND in_inventory=0" + RAN, (wk,)),
            "last": last[0] if last else None,
            "plans_pending": sum(v for k, v in plans.items() if k in ("generated", "approved")),
            "plans_deployed": plans.get("deployed", 0), "plans_failed": plans.get("failed", 0),
            "since_utc_midnight": day0}


_CSV_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(v):
    if isinstance(v, str) and v.startswith(_CSV_FORMULA):
        return "'" + v
    return v


def export_csv(filters=None) -> dict:
    w, p = _where(filters)
    data = _q("SELECT " + _COLS + ", prev_hash FROM c2_log" + w + " ORDER BY id ASC", p)
    buf = io.StringIO()
    wr = csv.writer(buf)
    hdr = ["id", "ts_utc", "run_id", "source", "agent", "operator", "target", "in_inventory", "asset_uuid", "hostname",
           "mode", "catalog_id", "status", "exit_code", "duration_ms", "hostkey_policy", "attempts", "command",
           "command_sha256", "plan_sha256", "prev_hash", "row_hash"]
    wr.writerow(hdr)
    for r in data:
        wr.writerow([csv_safe(x) for x in (
            r.get("id"), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r.get("ts") or 0)), r.get("run_id"),
            r.get("source"), r.get("agent"), r.get("operator"), r.get("target"), r.get("in_inventory"),
            r.get("asset_uuid"), r.get("hostname"), r.get("mode"), r.get("catalog_id"), r.get("status"),
            r.get("exit_code"), r.get("duration_ms"), r.get("hostkey_policy"), r.get("attempts"), r.get("command"),
            r.get("command_sha256"), r.get("plan_sha256"), r.get("prev_hash"), r.get("row_hash"))])
    return {"count": len(data), "csv": buf.getvalue(), "filename": "hounds-c2-log.csv"}


# ---- remediation plan registry --------------------------------------------------------------
def plan_upsert(plan_id, status, *, source="", selector="", generator="", generated_sha256="",
                approved_sha256="", hosts=None) -> bool:
    if not plan_id or not _ensure():
        return False
    now = time.time()
    try:
        with _LOCK:
            con = _con()
            try:
                ex = con.execute("SELECT id FROM c2_plans WHERE plan_id=?", (plan_id,)).fetchone()
                if ex:
                    sets, vals = ["status=?", "updated=?"], [status, now]
                    for k, v in (("approved_sha256", approved_sha256), ("hosts", hosts)):
                        if v not in (None, ""):
                            sets.append(k + "=?")
                            vals.append(v)
                    con.execute("UPDATE c2_plans SET " + ",".join(sets) + " WHERE plan_id=?", tuple(vals) + (plan_id,))
                else:
                    con.execute("INSERT INTO c2_plans(ts,plan_id,source,selector,generator,generated_sha256,"
                                "approved_sha256,status,hosts,updated) VALUES(?,?,?,?,?,?,?,?,?,?)",
                                (now, plan_id, source, selector, generator, generated_sha256, approved_sha256,
                                 status, hosts or 0, now))
                con.commit()
                return True
            finally:
                con.close()
    except Exception:
        return False


def plans(limit=50) -> list:
    return _q("SELECT * FROM c2_plans ORDER BY id DESC LIMIT ?", (int(limit),))
