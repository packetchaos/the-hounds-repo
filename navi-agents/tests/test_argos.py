"""Regression tests for Argos' at-a-glance card (agents/argos/api.py _glance / _certs_for)
and core.fused_score.asset_score: past-SLA matches the SLA page (fractional days, operator
dispositions excluded), the RSA-only weak-key rule on navi's '1024 bits' text, the EPSS
asset-count cap, and the oldest-critical fallback when first_found is missing.
Tiny synthetic navi.db in a temp dir; no navi, no network.
Run: python3 tests/test_argos.py  (or pytest)."""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
TMP = tempfile.mkdtemp(prefix="hounds-argos-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
os.environ["NAVI_CACHE_DIR"] = os.path.join(TMP, "cache")
DB = os.path.join(TMP, "navi.db")
os.environ["NAVI_DB_PATH"] = DB

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


def ago(days):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - days * 86400))


c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT, acr TEXT, aes INTEGER);
CREATE TABLE vulns (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT, score REAL,
                    xrefs TEXT, state TEXT, first_found TEXT, last_found TEXT, cves TEXT);
CREATE TABLE tags (asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
CREATE TABLE vuln_paths (asset_uuid TEXT, plugin_id TEXT, path TEXT);
CREATE TABLE certs (asset_uuid TEXT, common_name TEXT, not_valid_after TEXT, signature_algorithm TEXT,
                    key_length TEXT, algorithm TEXT);
CREATE TABLE epss (cve TEXT, epss_value TEXT);""")
c.execute("INSERT INTO assets VALUES ('a1','web','10.0.0.1','5',0)")
c.execute("INSERT INTO assets VALUES ('a2','db','10.0.0.2','5',0)")
V = [("a1", "1", "high just past", "high", ago(30.5), "CVE-2024-0001"),   # 30.5 d > 30 → past (fractional)
     ("a1", "2", "high accepted", "high", ago(90), ""),                    # on an Accepted path → excluded
     ("a1", "3", "high fresh", "high", ago(29.5), ""),
     ("a2", "9", "crit", "critical", None, "")]                              # no first_found
for u, pid, pn, sev, ff, cv in V:
    c.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?)", (u, pid, pn, sev, 7.0, "", "open", ff, ago(1), cv))
c.execute("INSERT INTO vuln_paths VALUES ('a1','2','/opt/legacy')")
c.execute("INSERT INTO tags VALUES ('a1','Owner','/opt/legacy: Accepted')")
c.execute("INSERT INTO epss VALUES ('CVE-2024-0001','0.97')")
for cn, sig, kl, alg in [("rsa1024", "SHA-256 With RSA Encryption", "1024 bits", "RSA"),
                         ("ecdsa256", "ecdsa-with-SHA256", "256 bits", "ECDSA"),
                         ("rsa2048", "SHA-256 With RSA Encryption", "2048 bits", "RSA"),
                         ("sha1", "SHA-1 With RSA Encryption", "4096 bits", "RSA")]:
    c.execute("INSERT INTO certs VALUES ('a1',?,?,?,?,?)", (cn, "Dec 12 20:57:22 2030 GMT", sig, kl, alg))
c.commit()
c.close()

from core import fused_score as F  # noqa: E402
from agents.argos import api as A  # noqa: E402

g = A._glance("a1", [])
check(g["sla"]["past"] == 1, "past-SLA: 30.5 d high counts, 29.5 d doesn't, the Accepted-path one is excluded (got %s)"
      % g["sla"]["past"])
g2 = A._glance("a2", [])
check(g2["findings"]["critical"] == 1 and g2["sla"]["oldest_critical_days"] is None,
      "a critical with no first_found has no oldest age (the page says so instead of 'none')")

weak = {r["common_name"]: r["weak"] for r in A._certs_for("a1")}
check(weak == {"rsa1024": True, "ecdsa256": False, "rsa2048": False, "sha1": True},
      "weak certs: RSA < 2048 from '1024 bits', SHA-1; a 256-bit ECDSA key is not weak (%s)" % weak)

with_epss = F.asset_score("a1", DB)
no_epss = F.asset_score("a1", DB, epss_cap=1)
check(with_epss["factors"].get("expl", 0) > 0 and no_epss["factors"].get("expl", 0) == 0,
      "asset_score applies EPSS only under the same asset-count cap as the estate view")
check(F.asset_score("a1", DB, epss_cap=1)["score"] == next(
    r["score"] for r in F.overview(DB, epss_cap=1)["assets"] if r["uuid"] == "a1"),
    "…so Argos and the Exposure Score page agree above the cap")


def test_argos_regressions():
    assert not fails, "\n".join(fails)


if __name__ == "__main__":
    print(f"\n{len(fails)} failure(s)")
    sys.exit(1 if fails else 0)
