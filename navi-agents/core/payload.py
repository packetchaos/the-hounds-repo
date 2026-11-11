"""The page payload contract — what a hound's ▶ Run sends to its page, and how the page
pages the rest (build 455).

A navi.db can hold millions of assets and hundreds of millions of findings. A page must
never receive "all of it": it gets the DECISION data on ▶ Run and asks the server for
more on demand. Every contract response has the same shape:

    {"ok": true,
     "summary": {...},                 # every headline number, computed over the FULL set
     "top":     [...],                 # ≤ TOP_MAX (200) ranked decision rows
     "total":   {"value": 123456, "exact": true, "as_of": "<iso time>"},
     "page":    {"next": "<opaque token>|null", "start": 0, "limit": 200},
     "drill":   {"action": "drill", "run": "<run id>", "section": "<name>"},
     "tag":     {"count": 123456, "key": "<what the server rebuilds the set from>"},
     "meta":    {"built_at", "build_sec", "truncated", "bytes"}}

Rules (tests/test_payload.py checks them):
  * no array longer than TOP_MAX rows and no asset-UUID arrays in a page payload — tags
    are requested by KEY and the server derives the asset set (core.navi_cli.tag_set);
  * a response is never larger than MAX_BYTES (~2 MB): cap() trims the longest lists and
    sets meta.truncated instead of ever shipping more;
  * paging is KEYSET (never OFFSET): the next-token carries the last row's sort key and is
    signed (HMAC) and bound to the run / section / sort / filters / search it was issued
    for, so a token can't be forged or replayed against another query;
  * totals are cheap: exact counts come from the stored result (counted once per run);
    a count over navi.db itself goes through capped_count() → "10,000+".

Where the full result lives — the RESULT STORE (ResultStore, `results.db` next to the
snapshot cache): a hound's run writes every row of each section ONCE (streamed, in
batches) with a few sort keys, filter flags, a lower-cased search text and the asset
uuid the row stands for. The `drill` action pages / searches / sorts that section and
the tag actions read the uuids back from it. Rows are ~100 B of keys plus the row's JSON
in a side table, so a section scan for a filtered page is ~ms per 10k rows; the default
sort (the hound's own ranking) is the primary key, so paging it is O(page). Each hound
keeps its last KEEP_RUNS runs (a page replayed from the page cache still pages the run
it showed); a run older than that answers {expired: true} and the page asks for ▶ Run.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import zlib

TOP_MAX = 200
MAX_BYTES = int(os.environ.get("NAVI_PAYLOAD_MAX_BYTES", str(2 * 1024 * 1024)))
COUNT_CAP = 10000
KEEP_RUNS = int(os.environ.get("NAVI_RESULTS_KEEP_RUNS", "2"))
_BATCH = 2000
_FLAG_SEP = "\x1f"
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{8,4000}\.[0-9a-f]{32}$")
_RUN_RE = re.compile(r"^[a-z0-9_]{1,40}-[0-9a-f]{16}$")
_NAME_RE = re.compile(r"^[a-z0-9_]{1,40}$")


# --------------------------------------------------------------------------- helpers
def now_iso(ts=None):
    import datetime
    return datetime.datetime.fromtimestamp(ts or time.time()).astimezone().isoformat(timespec="seconds")


def total(value, exact=True, as_of=None) -> dict:
    return {"value": int(value or 0), "exact": bool(exact), "as_of": as_of or now_iso()}


def fmt_total(t) -> str:
    """'1,234' or '10,000+' for a total() dict (or a bare int)."""
    if isinstance(t, dict):
        v, ex = int(t.get("value") or 0), t.get("exact", True)
    else:
        v, ex = int(t or 0), True
    return "{:,}{}".format(v, "" if ex else "+")


def capped_count(sql, params=(), cap=COUNT_CAP, path=None, budget="open"):
    """COUNT over navi.db without counting millions: probes at most cap+1 rows of `sql`
    (any SELECT) and returns (n, exact). Over the cap → (cap, False) → shown "10,000+".
    On a budget hit → (0, False)."""
    from core import db
    try:
        n = db.scalar("SELECT COUNT(*) FROM (%s LIMIT %d)" % (sql, int(cap) + 1), params, path=path,
                      budget=budget) or 0
    except Exception:
        return 0, False
    return (int(cap), False) if n > cap else (int(n), True)


def _jsize(o) -> int:
    return len(json.dumps(o, default=str, separators=(",", ":")).encode("utf-8"))


def _lists(o, path="", out=None, depth=0):
    """Every list inside o as (len, path-tuple, parent, key) — the trim candidates."""
    if out is None:
        out = []
    if depth > 12:
        return out
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(v, list):
                out.append((len(v), path + "." + str(k), o, k))
            if isinstance(v, (dict, list)):
                _lists(v, path + "." + str(k), out, depth + 1)
    elif isinstance(o, list):
        for i, v in enumerate(o[:TOP_MAX]):
            if isinstance(v, (dict, list)):
                _lists(v, path + "[]", out, depth + 1)
    return out


def cap(body, limit=None, max_rows=TOP_MAX):
    """Enforce the contract on a response dict IN PLACE and return it: every list ≤ max_rows,
    then, while the JSON is over `limit` bytes, halve the longest list. Sets meta.truncated /
    meta.trimmed when anything was cut, and meta.bytes. Never raises."""
    limit = MAX_BYTES if limit is None else int(limit)
    if not isinstance(body, dict):
        return body
    meta = body.setdefault("meta", {}) if isinstance(body.get("meta", {}), dict) else {}
    trimmed = set()
    for n, p, parent, k in _lists(body):
        if n > max_rows:
            parent[k] = parent[k][:max_rows]
            trimmed.add(p)
    size = _jsize(body)
    guard = 0
    while size > limit and guard < 64:
        guard += 1
        cands = sorted(((n, p, parent, k) for n, p, parent, k in _lists(body) if n > 1), key=lambda x: -x[0])
        if not cands:
            break
        n, p, parent, k = cands[0]
        parent[k] = parent[k][: max(1, n // 2)]
        trimmed.add(p)
        size = _jsize(body)
    if size > limit:                       # still over: one row too big — drop the rows themselves
        for n, p, parent, k in _lists(body):
            if n:
                parent[k] = []
                trimmed.add(p)
        size = _jsize(body)
    if trimmed:
        meta["truncated"] = True
        meta["trimmed"] = sorted(trimmed)[:20]
    meta["bytes"] = size
    body["meta"] = meta
    return body


def response(summary=None, top=None, total_=None, page=None, drill=None, tag=None, meta=None, **extra):
    """Build one contract response (and cap() it)."""
    body = {"ok": True, "summary": summary or {}, "top": list(top or [])[:TOP_MAX],
            "total": total_ if total_ is not None else total(len(top or [])),
            "page": page or {"next": None, "start": 0, "limit": TOP_MAX},
            "drill": drill, "tag": tag, "meta": dict(meta or {})}
    body.update(extra)
    return cap(body)


# --------------------------------------------------------------------------- tokens
_KEY = None
_KEY_LOCK = threading.Lock()


def _secret():
    """Per-install HMAC key (0600 file in the cache dir) so tokens survive a restart (a page
    replayed from the page cache keeps paging). Falls back to a per-process key."""
    global _KEY
    with _KEY_LOCK:
        if _KEY:
            return _KEY
        try:
            from core import snapcache
            from core.security import private_open
            fp = os.path.join(snapcache.CACHE_DIR, ".payload_token_key")
            os.makedirs(snapcache.CACHE_DIR, mode=0o700, exist_ok=True)
            if not os.path.exists(fp):
                with private_open(fp, "w") as f:
                    f.write(secrets.token_hex(32))
            with open(fp, encoding="utf-8") as f:
                k = f.read().strip()
            _KEY = bytes.fromhex(k) if len(k) >= 32 else secrets.token_bytes(32)
        except Exception:
            _KEY = secrets.token_bytes(32)
        return _KEY


def _b64(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(state: dict) -> str:
    raw = json.dumps(state, separators=(",", ":"), sort_keys=True, default=str).encode("utf-8")
    body = _b64(raw)
    sig = hmac.new(_secret(), body.encode("ascii"), hashlib.sha256).hexdigest()[:32]
    return body + "." + sig


class BadToken(ValueError):
    pass


def read_token(tok, bind: dict) -> dict:
    """Validate a next-token: shape, signature, and that it was issued for exactly `bind`
    (run, section, sort, filters, search). Returns its state or raises BadToken."""
    if not isinstance(tok, str) or not _TOKEN_RE.match(tok):
        raise BadToken("malformed page token")
    body, sig = tok.rsplit(".", 1)
    want = hmac.new(_secret(), body.encode("ascii"), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(want, sig):
        raise BadToken("page token signature mismatch")
    try:
        st = json.loads(_unb64(body))
    except Exception:
        raise BadToken("unreadable page token")
    if not isinstance(st, dict) or st.get("b") != _bind_hash(bind):
        raise BadToken("page token was issued for another query")
    if not isinstance(st.get("k"), list) or not isinstance(st.get("pos"), int):
        raise BadToken("bad page token")
    return st


def _bind_hash(bind):
    return hashlib.sha256(json.dumps(bind, sort_keys=True, default=str).encode()).hexdigest()[:20]


# --------------------------------------------------------------------------- the result store
_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(rid INTEGER PRIMARY KEY, run TEXT UNIQUE NOT NULL, hound TEXT NOT NULL,
    built_at REAL, done INTEGER DEFAULT 0, meta TEXT);
CREATE TABLE IF NOT EXISTS sections(run INTEGER, sec TEXT, total INTEGER, PRIMARY KEY(run, sec)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS rows(run INTEGER, sec TEXT, seq INTEGER, rk TEXT, uid TEXT,
    s1, s2, s3, s4, s5, s6, flags TEXT, txt TEXT, PRIMARY KEY(run, sec, seq)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS rowj(run INTEGER, sec TEXT, seq INTEGER, j TEXT, PRIMARY KEY(run, sec, seq)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS rows_rk ON rows(run, sec, rk) WHERE rk IS NOT NULL;
CREATE TABLE IF NOT EXISTS members(run INTEGER, grp TEXT, uid TEXT, PRIMARY KEY(run, grp, uid)) WITHOUT ROWID;
"""
_SCHEMA_V = 4
_SORT_COLS = ("s1", "s2", "s3", "s4", "s5", "s6")
_NK = len(_SORT_COLS)


def _pack(row):
    """A stored row: compact JSON text. (Per-row zlib was measured at ~30 µs a row — 11 s of a
    388k-row certificate run — for a poor ratio on ~400-byte rows, so rows stay plain; dropped
    runs hand their pages back via incremental_vacuum.)"""
    return json.dumps(row, default=str, separators=(",", ":"))


def _unpack(b):
    return json.loads(zlib.decompress(b) if isinstance(b, (bytes, bytearray)) else b)


class _Writer:
    """Streams one run's sections into the store. Use as a context manager."""

    def __init__(self, store, hound, run):
        import queue
        self.store, self.hound, self.run = store, hound, run
        self.counts, self._buf, self._jbuf, self._mbuf = {}, [], [], []
        self.meta = {}
        self.con = store._connect()
        cur = self.con.execute("INSERT INTO runs(run, hound, built_at, done, meta) VALUES(?,?,?,0,?)",
                               (run, hound, time.time(), "{}"))
        self.rid = cur.lastrowid            # the data tables key on this integer, not the run text
        # SQLite inserts run on a writer thread (sqlite3 releases the GIL while it works), so a
        # hound's Python loop and the store's disk writes overlap; the queue bounds memory.
        self._q = queue.Queue(maxsize=4)
        self._err = None
        self._t = threading.Thread(target=self._drain, name="payload-writer-" + run, daemon=True)
        self._t.start()

    def _drain(self):
        while True:
            job = self._q.get()
            if job is None:
                return
            if self._err is not None:
                continue
            try:
                rows, js, ms = job
                if rows:
                    self.con.executemany("INSERT INTO rows VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                    self.con.executemany("INSERT INTO rowj VALUES(?,?,?,?)", js)
                if ms:
                    self.con.executemany("INSERT OR IGNORE INTO members VALUES(?,?,?)", ms)
            except Exception as e:          # surfaced by close()
                self._err = e

    def add(self, sec, row, uid=None, flags=(), text="", keys=(), rk=None):
        """One row of section `sec`, in the hound's default (ranked) order. keys = up to 6 sort
        values (s1..s6), already oriented ASCENDING (negate a number to sort it descending)."""
        n = self.counts.get(sec, 0)
        self.counts[sec] = n + 1
        k = list(keys)[:_NK] + [None] * (_NK - min(_NK, len(keys)))
        fl = (_FLAG_SEP + _FLAG_SEP.join(str(f) for f in flags if f) + _FLAG_SEP) if flags else ""
        self._buf.append((self.rid, sec, n, None if rk is None else str(rk), uid, *k,
                          fl, (text or "").lower()[:2000]))
        self._jbuf.append((self.rid, sec, n, _pack(row)))
        if len(self._buf) >= _BATCH:
            self._flush()

    def members(self, grp, uids):
        for u in uids:
            if u:
                self._mbuf.append((self.rid, str(grp), str(u)))
        if len(self._mbuf) >= _BATCH * 5:
            self._flush()

    def _flush(self):
        if self._buf or self._mbuf:
            self._q.put((self._buf, self._jbuf, self._mbuf))
            self._buf, self._jbuf, self._mbuf = [], [], []

    def section(self, sec):
        """Declare a (possibly empty) section so its total is 0, not 'unknown'."""
        self.counts.setdefault(sec, 0)

    def close(self, ok=True):
        err = None
        try:
            self._flush()
            self._q.put(None)
            self._t.join()
            err = self._err
            if ok and err is None:
                for sec, n in self.counts.items():
                    self.con.execute("INSERT OR REPLACE INTO sections VALUES(?,?,?)", (self.rid, sec, n))
                self.con.execute("UPDATE runs SET done=1, meta=? WHERE rid=?",
                                 (json.dumps(self.meta, default=str), self.rid))
            self.con.commit()
        finally:
            self.con.close()
        if ok and err is None:
            self.store.prune(self.hound, keep_run=self.run)
        else:
            self.store.drop(self.run)
        if err is not None:
            raise err

    def __enter__(self):
        return self

    def __exit__(self, et, e, tb):
        self.close(ok=et is None)
        return False


class ResultStore:
    def __init__(self, path=None):
        self._path = path
        self._lock = threading.Lock()
        self._init = False

    def path(self):
        if self._path:
            return self._path
        from core import snapcache
        os.makedirs(snapcache.CACHE_DIR, mode=0o700, exist_ok=True)
        return os.path.join(snapcache.CACHE_DIR, "results.db")

    def _connect(self):
        p = self.path()
        con = sqlite3.connect(p, timeout=30, check_same_thread=False)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=OFF")
        if not self._init:
            with self._lock:
                if con.execute("PRAGMA user_version").fetchone()[0] != _SCHEMA_V:   # an older layout: start over
                    for t in ("rows", "rowj", "sections", "members", "runs"):
                        con.execute("DROP TABLE IF EXISTS %s" % t)
                    # dropped runs give their pages back to the disk (incremental_vacuum in drop())
                    con.execute("PRAGMA auto_vacuum=INCREMENTAL")
                    con.execute("VACUUM")
                    con.execute("PRAGMA user_version=%d" % _SCHEMA_V)
                con.executescript(_SCHEMA)
                self._init = True
                try:
                    from core.security import private_file
                    private_file(p)
                except Exception:
                    pass
        return con

    # -- writing
    def begin(self, hound) -> _Writer:
        if not _NAME_RE.match(str(hound or "")):
            raise ValueError("bad hound id")
        return _Writer(self, hound, "%s-%s" % (hound, secrets.token_hex(8)))

    def prune(self, hound, keep_run=None, keep=None):
        keep = KEEP_RUNS if keep is None else keep
        con = self._connect()
        try:
            rs = [r[0] for r in con.execute("SELECT run FROM runs WHERE hound=? ORDER BY built_at DESC", (hound,))]
            old = [r for r in rs if r != keep_run][max(0, keep - 1):]
        finally:
            con.close()
        for r in old:
            self.drop(r)

    def drop(self, run):
        con = self._connect()
        try:
            r = con.execute("SELECT rid FROM runs WHERE run=?", (run,)).fetchone()
            if r:
                for t in ("rows", "rowj", "sections", "members"):
                    con.execute("DELETE FROM %s WHERE run=?" % t, (r[0],))
            con.execute("DELETE FROM runs WHERE run=?", (run,))
            con.commit()
            try:
                con.execute("PRAGMA incremental_vacuum")
            except Exception:
                pass
        finally:
            con.close()

    # -- reading
    def run_info(self, run, hound=None):
        """{run, hound, built_at, meta} of a finished run (of `hound`, when given) or None."""
        if not isinstance(run, str) or not _RUN_RE.match(run):
            return None
        con = self._connect()
        try:
            r = con.execute("SELECT hound, built_at, done, meta FROM runs WHERE run=?", (run,)).fetchone()
        finally:
            con.close()
        if not r or not r[2] or (hound and r[0] != hound):
            return None
        try:
            meta = json.loads(r[3] or "{}")
        except Exception:
            meta = {}
        return {"run": run, "hound": r[0], "built_at": r[1], "meta": meta}

    def _rid(self, run):
        """The integer key of a run id (or -1: matches nothing)."""
        if not isinstance(run, str) or not _RUN_RE.match(run):
            return -1
        con = self._connect()
        try:
            r = con.execute("SELECT rid FROM runs WHERE run=?", (run,)).fetchone()
        finally:
            con.close()
        return r[0] if r else -1

    def set_meta(self, run, **fields):
        con = self._connect()
        try:
            r = con.execute("SELECT meta FROM runs WHERE run=?", (run,)).fetchone()
            m = json.loads((r and r[0]) or "{}")
            m.update(fields)
            con.execute("UPDATE runs SET meta=? WHERE run=?", (json.dumps(m, default=str), run))
            con.commit()
        finally:
            con.close()

    def section_total(self, run, sec):
        run = self._rid(run)
        con = self._connect()
        try:
            r = con.execute("SELECT total FROM sections WHERE run=? AND sec=?", (run, sec)).fetchone()
        finally:
            con.close()
        return None if r is None else int(r[0])

    @staticmethod
    def _where(run, sec, flags, q):
        w, a = ["r.run=?", "r.sec=?"], [run, sec]
        for f in flags or ():
            w.append("instr(r.flags, ?)>0")
            a.append(_FLAG_SEP + str(f) + _FLAG_SEP)
        if q:
            w.append("instr(r.txt, ?)>0")
            a.append(str(q).lower())
        return " AND ".join(w), a

    def page(self, run, sec, sort=None, flags=(), q="", limit=TOP_MAX, after=None, count=True):
        """One keyset page. sort = tuple of sort columns ('s1'..'s4'), ascending, seq is the
        tie-break; None = the hound's default order (seq). after = the previous page's last
        key list. Returns (rows, last_key or None, total, exact)."""
        run = self._rid(run)
        cols = [c for c in (sort or ()) if c in _SORT_COLS] + ["seq"]
        limit = max(1, min(int(limit or TOP_MAX), TOP_MAX))
        w, a = self._where(run, sec, flags, q)
        if after:
            if len(after) != len(cols):
                raise BadToken("page token does not match this sort")
            # NULL sort keys sort first in SQLite; coalesce so row-value comparison is total
            lhs = ",".join("coalesce(r.%s, -1e308)" % c if c != "seq" else "r.seq" for c in cols)
            w += " AND (%s) > (%s)" % (lhs, ",".join("?" * len(cols)))
            a += [(-1e308 if v is None else v) for v in after]
        order = ",".join("coalesce(r.%s, -1e308)" % c if c != "seq" else "r.seq" for c in cols)
        sel = ",".join("r." + c for c in cols)
        con = self._connect()
        try:
            got = con.execute("SELECT %s, j.j FROM rows r JOIN rowj j ON j.run=r.run AND j.sec=r.sec AND j.seq=r.seq "
                              "WHERE %s ORDER BY %s LIMIT %d" % (sel, w, order, limit + 1), a).fetchall()
            n, exact = None, True
            if count:
                if not flags and not q:
                    r = con.execute("SELECT total FROM sections WHERE run=? AND sec=?", (run, sec)).fetchone()
                    n = int(r[0]) if r else 0
                else:
                    w2, a2 = self._where(run, sec, flags, q)
                    n = con.execute("SELECT COUNT(*) FROM rows r WHERE " + w2, a2).fetchone()[0]
        finally:
            con.close()
        more = len(got) > limit
        got = got[:limit]
        rows = [_unpack(g[-1]) for g in got]
        last = [(-1e308 if v is None else v) for v in got[-1][:-1]] if (got and more) else None
        return rows, last, n, exact

    def row(self, run, sec, rk):
        """The row of `sec` whose key is rk, or None."""
        run = self._rid(run)
        con = self._connect()
        try:
            g = con.execute("SELECT j.j FROM rows r JOIN rowj j ON j.run=r.run AND j.sec=r.sec AND j.seq=r.seq "
                            "WHERE r.run=? AND r.sec=? AND r.rk=? LIMIT 1", (run, sec, str(rk))).fetchone()
        finally:
            con.close()
        return _unpack(g[0]) if g else None

    def update_row(self, run, sec, rk, row=None, flags=None, keys=None):
        """Rewrite one row (its JSON, flags and/or sort keys) — e.g. lifecycle data added later."""
        run = self._rid(run)
        con = self._connect()
        try:
            r = con.execute("SELECT seq FROM rows WHERE run=? AND sec=? AND rk=?", (run, sec, str(rk))).fetchone()
            if not r:
                return False
            if row is not None:
                con.execute("UPDATE rowj SET j=? WHERE run=? AND sec=? AND seq=?", (_pack(row), run, sec, r[0]))
            if flags is not None:
                fl = (_FLAG_SEP + _FLAG_SEP.join(str(f) for f in flags if f) + _FLAG_SEP) if flags else ""
                con.execute("UPDATE rows SET flags=? WHERE run=? AND sec=? AND seq=?", (fl, run, sec, r[0]))
            if keys is not None:                     # {"s5": value, …} — only the named columns
                for c, v in dict(keys).items():
                    if c in _SORT_COLS:
                        con.execute("UPDATE rows SET %s=? WHERE run=? AND sec=? AND seq=?" % c, (v, run, sec, r[0]))
            con.commit()
            return True
        finally:
            con.close()

    def iter_rows(self, run, sec, flags=(), q=""):
        """Every row of a section (JSON), streamed in the default order."""
        run = self._rid(run)
        w, a = self._where(run, sec, flags, q)
        con = self._connect()
        try:
            cur = con.execute("SELECT j.j FROM rows r JOIN rowj j ON j.run=r.run AND j.sec=r.sec AND j.seq=r.seq "
                              "WHERE %s ORDER BY r.seq" % w, a)
            while True:
                b = cur.fetchmany(1000)
                if not b:
                    break
                for g in b:
                    yield _unpack(g[0])
        finally:
            con.close()

    def uids(self, run, sec, flags=(), q=""):
        """The distinct asset uuids behind a section's (filtered) rows — what a tag key means."""
        run = self._rid(run)
        w, a = self._where(run, sec, flags, q)
        con = self._connect()
        try:
            return sorted({r[0] for r in con.execute("SELECT DISTINCT r.uid FROM rows r WHERE %s AND r.uid IS NOT NULL" % w, a)
                           if r[0]})
        finally:
            con.close()

    def count_any(self, run, sec, flags_any):
        """(rows, distinct uids) of a section's rows carrying ANY of the flags."""
        run = self._rid(run)
        if not flags_any:
            return 0, 0
        con = self._connect()
        try:
            con.execute("CREATE TEMP TABLE IF NOT EXISTS _f(f TEXT PRIMARY KEY)")
            con.execute("DELETE FROM _f")
            con.executemany("INSERT OR IGNORE INTO _f VALUES(?)", [(_FLAG_SEP + str(f) + _FLAG_SEP,) for f in flags_any])
            r = con.execute("SELECT COUNT(*), COUNT(DISTINCT r.uid) FROM rows r WHERE r.run=? AND r.sec=? AND "
                            "EXISTS (SELECT 1 FROM _f WHERE instr(r.flags, _f.f)>0)", (run, sec)).fetchone()
        finally:
            con.close()
        return int(r[0]), int(r[1])

    def distinct_keys(self, run, sec, flags=(), q="", cap=5000):
        """The distinct row keys (rk) of a filtered section, first-seen order, capped."""
        run = self._rid(run)
        w, a = self._where(run, sec, flags, q)
        con = self._connect()
        try:
            got = [r[0] for r in con.execute("SELECT r.rk FROM rows r WHERE %s AND r.rk IS NOT NULL "
                                             "GROUP BY r.rk ORDER BY MIN(r.seq) LIMIT %d" % (w, int(cap) + 1), a)]
        finally:
            con.close()
        return {"keys": got[:cap], "truncated": len(got) > cap}

    def group(self, run, grp):
        """The uuids stored for a member group (e.g. one framework / destination)."""
        run = self._rid(run)
        con = self._connect()
        try:
            return [r[0] for r in con.execute("SELECT uid FROM members WHERE run=? AND grp=? ORDER BY uid", (run, str(grp)))]
        finally:
            con.close()

    def group_count(self, run, grp):
        run = self._rid(run)
        con = self._connect()
        try:
            return con.execute("SELECT COUNT(*) FROM members WHERE run=? AND grp=?", (run, str(grp))).fetchone()[0]
        finally:
            con.close()


STORE = ResultStore()


# --------------------------------------------------------------------------- the drill action
_Q_MAX = 200
_FLAG_RE = re.compile(r"^[^\x00-\x1f]{1,160}$")


def drill(hound, p, sections, store=None, limit=None):
    """The shared server-side drill-down: page / search / sort one section of a stored run.

    sections = {sec: {"sorts": {name: ("s1","s2"...)}, "flags": callable(str)->bool | set}}
    p        = {run, section, sort?, filter?: [flag,…] | flag, q?, next?, limit?}
    Validates everything (the run must be this hound's, sort/filter names must be declared,
    the next-token must have been issued for this exact query) and returns a contract response.
    """
    store = store or STORE
    p = p or {}
    run, sec = p.get("run"), p.get("section")
    info = store.run_info(run, hound)
    if not info:
        return {"ok": False, "expired": True,
                "error": "this run's rows are no longer on the server — press ▶ Run again"}, 200
    spec = sections.get(sec) if isinstance(sec, str) else None
    if not spec:
        return {"ok": False, "error": "unknown section"}, 400
    sort_name = p.get("sort") or ""
    sorts = spec.get("sorts") or {}
    if sort_name and sort_name not in sorts:
        return {"ok": False, "error": "unknown sort"}, 400
    sort = tuple(sorts.get(sort_name) or ()) if sort_name else None
    flt = p.get("filter") or []
    if isinstance(flt, str):
        flt = [flt]
    if not isinstance(flt, list) or len(flt) > 6:
        return {"ok": False, "error": "bad filter"}, 400
    ok_flag = spec.get("flags") or set()
    for f in flt:
        if not isinstance(f, str) or not _FLAG_RE.match(f) or not (ok_flag(f) if callable(ok_flag) else f in ok_flag):
            return {"ok": False, "error": "unknown filter"}, 400
    q = p.get("q") or ""
    if not isinstance(q, str) or len(q) > _Q_MAX:
        return {"ok": False, "error": "bad search"}, 400
    q = q.strip()
    try:
        lim = max(1, min(int(p.get("limit") or limit or 50), TOP_MAX))
    except (TypeError, ValueError):
        lim = 50
    bind = {"run": run, "sec": sec, "sort": sort_name, "f": sorted(flt), "q": q.lower()}
    after, pos = None, 0
    if p.get("next"):
        try:
            st = read_token(p.get("next"), bind)
        except BadToken as e:
            return {"ok": False, "error": str(e)}, 400
        after, pos = st["k"], st["pos"]
    try:
        rows, last, n, exact = store.page(run, sec, sort=sort, flags=flt, q=q, limit=lim, after=after)
    except BadToken as e:
        return {"ok": False, "error": str(e)}, 400
    nxt = make_token({"b": _bind_hash(bind), "k": last, "pos": pos + len(rows)}) if last else None
    body = response(summary={}, top=rows,
                    total_=total(n, exact, now_iso(info["built_at"])),
                    page={"next": nxt, "start": pos, "limit": lim},
                    drill={"action": "drill", "run": run, "section": sec},
                    meta={"built_at": now_iso(info["built_at"])})
    return body, 200
