"""Regression tests — build 474: navi's "missing field" placeholder.

  · navi's th_* exports write a single space (" ") for a field Tenable didn't return. core/db
    now hands every dict row back with whitespace-only text as None, so `hostname or ip`
    fallbacks (Python and the pages fed by the API) show the IP instead of a blank, and Argos
    shows no network rather than " ". The literal text "None" (navi's str(None)) is left
    alone, and tuples=True streams are returned raw.
  · Nemesis weak crypto: a blank `algorithm` no longer hides the signature algorithm, so an
    RSA key under 2048 bits is still flagged.
  · A placeholder-filled copy of navi.db scores the same as the clean one.
Run: python3 tests/test_placeholders_474.py"""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-474-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
CLEAN = os.path.join(TMP, "clean.db")
PH = os.path.join(TMP, "ph.db")
os.environ.update({"NAVI_DB_PATH": CLEAN, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def build(path, blank):
    """blank(v) -> what navi writes for a missing value: None (clean) or " " (placeholder)."""
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE assets (uuid text, hostname text, fqdn text, ip_address text, network text, "
              "operating_system text, acr text, aes text, last_licensed_scan_date text, url text)")
    c.execute("CREATE TABLE vulns (asset_uuid text, plugin_id text, plugin_name text, output text, "
              "severity text, state text, cves text, synopsis text)")
    c.execute("CREATE TABLE tags (asset_uuid text, tag_key text, tag_value text)")
    c.execute("CREATE TABLE certs (asset_uuid text, algorithm text, signature_algorithm text, "
              "key_length text, not_valid_after text)")
    c.executemany("INSERT INTO assets VALUES (?,?,?,?,?,?,?,?,?,?)", [
        ("u-1", "web01", "web01.corp.example", "10.0.0.1", "Default", "Linux", "7", "500", blank, blank),
        ("u-2", blank, blank, "10.0.0.2", blank, blank, blank, blank, blank, blank),
        ("u-3", blank, blank, "10.0.0.3", blank, "Windows", "9", "700", blank, blank),
    ])
    c.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?)", [
        ("u-1", "19506", "Nessus Scan Information", "Credentialed checks : yes", "info", "OPEN", "None", "None"),
        ("u-3", "10287", "Traceroute", "hop 1", "info", "OPEN", "None", "None"),
    ])
    # u-2: an RSA-1024 key whose `algorithm` navi left blank — only the signature names RSA
    c.executemany("INSERT INTO certs VALUES (?,?,?,?,?)", [
        ("u-2", blank, "SHA256 With RSA Encryption", "1024", "Dec 12 20:57:22 2099 GMT"),
        ("u-3", "ECDSA", "ECDSA With SHA256", "256", "Dec 12 20:57:22 2099 GMT"),
    ])
    c.commit()
    c.close()


build(CLEAN, None)
build(PH, " ")

from core import db  # noqa: E402

# ── 1. core/db row normalisation ──────────────────────────────────────────────
r = db.query("SELECT ' ' a, '   ' b, char(9) c, '' d, 'None' e, ' x ' f, 5 g, NULL h", path=PH)[0]
check(r["a"] is None and r["b"] is None and r["c"] is None, "db.query: whitespace-only text -> None")
check(r["d"] == "", "db.query: the empty string is left as ''")
check(r["e"] == "None", "db.query: the literal text 'None' is left alone")
check(r["f"] == " x " and r["g"] == 5 and r["h"] is None, "db.query: real values are untouched")
check(db.scalar("SELECT ' '", path=PH) is None, "db.scalar: a blank value -> None")
rows = list(db.iter("SELECT hostname, ip_address FROM assets ORDER BY uuid", path=PH))
check([x["hostname"] for x in rows] == ["web01", None, None], "db.iter (dict rows): blank hostname -> None")
check([x["hostname"] or x["ip_address"] for x in rows] == ["web01", "10.0.0.2", "10.0.0.3"],
      "hostname-or-IP fallback shows the IP for a blank hostname")
t = list(db.iter("SELECT hostname FROM assets ORDER BY uuid", path=PH, tuples=True))
check(t[1] == (" ",), "db.iter tuples=True stays raw (id streams, no per-row cost)")

# ── 2. Argos — no " " hostname / network ──────────────────────────────────────
os.environ["NAVI_DB_PATH"] = PH
from agents.argos import api as argos  # noqa: E402
a = (argos.lookup({"target": "u-2"})[0] or {}).get("asset") or {}
check(a.get("ip_address") == "10.0.0.2", "Argos resolves the blank-hostname asset by UUID")
check(a.get("hostname") in (None, ""), "Argos: blank hostname is missing, not ' '  (got %r)" % a.get("hostname"))
check(a.get("network") in (None, ""), "Argos: blank network is missing, not ' '  (got %r)" % a.get("network"))

# ── 3. Nemesis weak crypto — blank algorithm falls through to the signature ──
from core import fused_score  # noqa: E402


def signals(path):
    return {s["uuid"]: s for s, _sc in fused_score.iter_scored(db_path=path)}


sc, sp = signals(CLEAN), signals(PH)
check(sc.get("u-2", {}).get("crypto") == "pq", "Nemesis: RSA-1024 (algorithm NULL) is weak crypto")
check(sp.get("u-2", {}).get("crypto") == "pq", "Nemesis: RSA-1024 (algorithm ' ') is weak crypto")
check(sp.get("u-3", {}).get("crypto") is None, "Nemesis: a 256-bit ECDSA key is not weak")
check(sp.get("u-2", {}).get("host") == "10.0.0.2", "Nemesis: blank hostname labels the asset by IP")

# ── 4. clean vs placeholder copy score the same ──────────────────────────────
keys = ("crypto", "kev", "blind", "eol", "sla", "unowned", "host", "ip")
same = all({k: sc[u].get(k) for k in keys} == {k: sp[u].get(k) for k in keys} for u in sc)
check(set(sc) == set(sp) and same, "Nemesis: clean and placeholder-filled navi.db give the same signals")
ov_c = fused_score.overview(db_path=CLEAN).get("kpi") or {}
ov_p = fused_score.overview(db_path=PH).get("kpi") or {}
check(ov_c == ov_p, "Nemesis overview KPIs match on the clean and placeholder copies")

print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
