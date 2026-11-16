"""One definition of "credentialed" for every hound (build 465).

An asset is CREDENTIALED when the scanner actually logged in:
  · any plugin 19506 (Nessus Scan Information) row on it says  "Credentialed checks : yes"
    (an asset can carry more than one 19506 row — ANY yes counts, not just the newest), or
  · plugin 141118 (Target Credential Status – Valid Credentials Provided) or
    110095 (Target Credential Issues – No Issues Found) is on it.
An asset is SCANNED when a scan reported on it at all (19506 or any credential-status plugin).
BLIND = scanned but not credentialed — the scan could not see inside.

Credential-FAILURE plugins (104410 failed, 110385/102094 insufficient privilege, 117885
intermittent, 21745 patch assessment failed) are issues to fix, not the coverage measure: a
host where one credential failed but another logged in (19506 "yes" + 104410) IS credentialed.
Before this module the hounds disagreed — Alerts and On the Scent counted every asset without a
104410 as credentialed, Exposure Score / Attack Paths / Identity counted only failure plugins as
blind, and Scan Evaluation / Argos read only the newest 19506.
"""
import threading

SCAN_INFO = "19506"
CRED_OK_PLUGINS = ("141118", "110095")
FAIL_PLUGINS = {"104410": "failed", "110385": "insufficient", "102094": "insufficient",
                "117885": "intermittent"}
NOCRED_PLUGINS = ("110723",)                       # No Credentials Provided
SCANNED_PLUGINS = (SCAN_INFO,) + CRED_OK_PLUGINS + tuple(FAIL_PLUGINS) + NOCRED_PLUGINS

_MEMO = {}
_LOCK = threading.Lock()


def _open(vcols, alias=""):
    a = (alias + ".") if alias else ""
    return (" AND lower(COALESCE(%sstate,'open')) IN ('open','reopened')" % a) if "state" in vcols else ""


def cred_sql(vcols, alias=""):
    """SQL predicate over a vulns row: this finding proves a credentialed scan."""
    a = (alias + ".") if alias else ""
    return ("((%splugin_id IN ('141118','110095')%s) OR (%splugin_id='19506' AND %soutput LIKE "
            "'%%Credentialed checks : yes%%'))" % (a, _open(vcols, alias), a, a))


def _fp(db_path):
    """navi.db's identity for the memo: path + file mtime/size + hx fingerprint (rootpage, max
    rowid) — changes on every navi sync and on any write to the file."""
    import os
    from core import db, hx_summary
    try:
        p = db_path or db.db_path()
        st = os.stat(p)
        c = db.connect(p)
        try:
            return (p, st.st_mtime_ns, st.st_size, hx_summary.fingerprint(c))
        finally:
            c.close()
    except Exception:
        return None


def sets(db_path=None):
    """{"credentialed", "scanned", "blind", "failed", "insufficient", "intermittent"} → asset
    uuid sets. Two indexed reads (19506 + the credential-status plugins); memoised per navi.db
    fingerprint so every hound in one release reads them once."""
    from core import db
    fp = _fp(db_path)
    key = fp
    if fp is not None:
        with _LOCK:
            hit = _MEMO.get(key)
        if hit is not None:
            return hit
    vc = {r.get("name") for r in db.query('PRAGMA table_info("vulns")', path=db_path)}
    ph = ",".join("'%s'" % p for p in SCANNED_PLUGINS)
    cred, scanned, fails = set(), set(), {}
    for r in db.iter("SELECT DISTINCT asset_uuid, plugin_id FROM vulns WHERE plugin_id IN (%s)%s" % (ph, _open(vc)),
                     path=db_path):
        u, p = r.get("asset_uuid"), str(r.get("plugin_id"))
        if not u:
            continue
        scanned.add(u)
        if p in CRED_OK_PLUGINS:
            cred.add(u)
        elif p in FAIL_PLUGINS:
            fails.setdefault(FAIL_PLUGINS[p], set()).add(u)
    # 19506 rows: no state filter — Scan Evaluation reads every 19506 row the same way
    for r in db.iter("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='19506' AND output LIKE "
                     "'%Credentialed checks : yes%'", path=db_path):
        if r.get("asset_uuid"):
            cred.add(r["asset_uuid"])
    out = {"credentialed": cred, "scanned": scanned, "blind": scanned - cred,
           "failed": fails.get("failed", set()), "insufficient": fails.get("insufficient", set()),
           "intermittent": fails.get("intermittent", set())}
    if fp is not None:
        with _LOCK:
            if len(_MEMO) > 8:
                _MEMO.clear()
            _MEMO[key] = out
    return out


def asset_blind(uuid, db_path=None):
    """One asset: True = scanned but not credentialed (the same rule as sets()), via two
    (asset, plugin) index probes — for single-asset views (Argos, asset_score)."""
    from core import db
    vc = {r.get("name") for r in db.query('PRAGMA table_info("vulns")', path=db_path)}
    ph = ",".join("'%s'" % p for p in SCANNED_PLUGINS)
    pids = {str(r.get("plugin_id")) for r in db.query(
        "SELECT DISTINCT plugin_id FROM vulns WHERE asset_uuid=? AND plugin_id IN (%s)%s" % (ph, _open(vc)),
        (uuid,), path=db_path)}
    if not pids and not db.query("SELECT 1 FROM vulns WHERE asset_uuid=? AND plugin_id='19506' LIMIT 1", (uuid,), path=db_path):
        return False                                   # never scanned: unknown, not blind
    if pids & set(CRED_OK_PLUGINS):
        return False
    yes = db.query("SELECT 1 FROM vulns WHERE asset_uuid=? AND plugin_id='19506' AND output LIKE "
                   "'%Credentialed checks : yes%' LIMIT 1", (uuid,), path=db_path)
    return not yes


def counts(db_path=None):
    s = sets(db_path)
    return {k: len(v) for k, v in s.items()}
