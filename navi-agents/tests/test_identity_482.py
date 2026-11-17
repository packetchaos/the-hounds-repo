"""Regression tests — build 482: Janus infers privilege from evidence, and reads every identity plugin.

  · "privileged" used to mean the account was NAMED root, administrator or admin. It now needs
    evidence: membership of Administrators / Domain Admins / the macOS admin group (10902 /
    10908 / 60019 / 71246), sudo / wheel / admin in the Linux / macOS user lists (95928 / 95929
    Groups), a protected operator group (10901 / 10903–10905), UID 0, or the built-in
    Administrator's RID 500 — and every privileged account says why.
  · Plugins that were missing or misread: 10902 / 10908 (their "  - DOMAIN\\name (User)" lines
    used to yield the DOMAIN as an account), 95929 (macOS user list), 71246, the Windows
    account-status lists 10911–10916 / 10895–10900 (now flags), the operator groups.
Run: python3 tests/test_identity_482.py"""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-482-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)
DB = os.path.join(TMP, "navi.db")
os.environ.update({"NAVI_DB_PATH": DB, "NAVI_CACHE_DIR": os.path.join(TMP, "cache"),
                   "HOUNDS_CONFIG": os.path.join(TMP, "cfg.json"), "NAVI_TAGLOG_DB": os.path.join(TMP, "t.db")})
fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


LIN, MAC, WIN, WIN2, RHEL = ("11111111-0000-0000-0000-00000000000%d" % i for i in range(1, 6))
# Linux 95928 in Tenable's layout: no UID line, Groups with one group per continuation line
P95928 = """
----------[ User Accounts ]----------

User         : casey
Home folder  : /home/casey
Start script : /bin/bash
Groups       : casey
               adm
               sudo

User         : admin
Home folder  : /home/admin
Start script : /bin/bash
Groups       : admin_users

User         : deploy
Home folder  : /home/deploy
Start script : /bin/bash
Groups       : deploy, wheel

----------[ System Accounts ]----------

User         : root
Home folder  : /root
Start script : /bin/bash
Groups       : root

User         : rootkit_scan
Home folder  : /var/lib/rk
Start script : /usr/sbin/nologin
Groups       : rootkit_scan
"""
# a REAL 95928 result from the owner's lab (build 483), plus a domain account and a sudo member
REAL95928 = ("\n-----------[ User Accounts ]-----------\n\n"
             "User         : ops\nHome folder  : /home/ops\nStart script : /bin/bash\nGroups       : ops\n               wheel\n\n"
             "----------[ System Accounts ]----------\n\n"
             "User         : root\nHome folder  : /root\nStart script : /bin/bash\nGroups       : root\n\n"
             "User         : bin\nHome folder  : /bin\nStart script : /sbin/nologin\nGroups       : bin\n\n"
             "User         : sync\nHome folder  : /sbin\nStart script : /bin/sync\nGroups       : root\n\n"
             "User         : shutdown\nHome folder  : /sbin\nStart script : /sbin/shutdown\nGroups       : root\n\n"
             "User         : halt\nHome folder  : /sbin\nStart script : /sbin/halt\nGroups       : root\n\n"
             "User         : operator\nHome folder  : /root\nStart script : /sbin/nologin\nGroups       : root\n\n"
             "User         : postfix\nHome folder  : /var/spool/postfix\nStart script : /sbin/nologin\nGroups       : mail\n"
             "               postfix\n\n"
             "User         : chrony\nHome folder  : /var/lib/chrony\nStart script : /sbin/nologin\nGroups       : chrony\n\n\n"
             "----------[ Domain Accounts ]----------\n\n"
             "User         : jdoe@corp.example\nHome folder  : /home/jdoe\nStart script : /bin/bash\nGroups       : domain users\n\n"
             "User         : svc_patch\nHome folder  : /home/svc_patch\nStart script : /bin/bash\nGroups       : sudo\n\n")
P95929 = """
----------[ User Accounts ]----------

User         : maria
Home folder  : /Users/maria
Start script : /bin/zsh
Groups       : staff
               admin

User         : guestuser
Home folder  : /Users/guestuser
Start script : /bin/zsh
Groups       : staff
"""
P10860 = """- Administrator
  SID : S-1-5-21-1-2-3-500
- svc_sql
  SID : S-1-5-21-1-2-3-1105
- admin
  SID : S-1-5-21-1-2-3-1106
- helpdesk
  SID : S-1-5-21-1-2-3-1107
"""
P10902 = """
The following users are members of the 'Administrators' group :
  - WIN-01\\Administrator (User)
  - CORP\\Domain Admins (Group)
  - CORP\\jsmith (User)
  - WIN-01\\svc_sql (User)
"""
P10908 = """
The following user is a member of the 'Domain Administrators' group :
  - CORP\\da_alice (User)
"""
P10904 = """
The following user is a member of the 'Backup Operators' group :
  - WIN-01\\helpdesk (User)
"""
P10916 = """
The following local user has a password that never expires :
  - svc_sql
Note that, in addition to the Administrator and Guest accounts, Nessus has only checked for local users with UIDs between 1000 and 1200.
"""
P10913 = """
The following local user account has been disabled :
  - Administrator
"""
P71246 = """
Group Name : Administrators
Group SID  : S-1-5-32-544
Members    :
  Name     : localadm
    Domain : WIN-02
    Class  : Win32_UserAccount

Group Name : Users
Group SID  : S-1-5-32-545
Members    :
  Name     : kiosk
    Domain : WIN-02
"""
c = sqlite3.connect(DB)
c.execute("CREATE TABLE assets (uuid text, hostname text, ip_address text, url text, acr text, last_found text)")
c.execute("CREATE TABLE vulns (asset_uuid text, plugin_id text, plugin_name text, output text, severity text, "
          "xrefs text, last_found text, state text)")
c.executemany("INSERT INTO assets VALUES (?,?,?,?,?,?)",
              [(LIN, "lin01", "10.0.0.1", "", "5", "2026-11-01"), (MAC, "mac01", "10.0.0.2", "", "5", "2026-11-01"),
               (WIN, "win01", "10.0.0.3", "", "5", "2026-11-01"), (WIN2, "win02", "10.0.0.4", "", "5", "2026-11-01"),
               (RHEL, "rhel01", "10.0.0.5", "", "5", "2026-11-01")])
V = [(LIN, "95928", "Linux User List Enumeration", P95928),
     (MAC, "95929", "macOS and Mac OS X User List Enumeration", P95929),
     (WIN, "10860", "SMB Use Host SID to Enumerate Local Users", P10860),
     (WIN, "10902", "Microsoft Windows 'Administrators' Group User List", P10902),
     (WIN, "10908", "Microsoft Windows 'Domain Administrators' Group User List", P10908),
     (WIN, "10904", "Microsoft Windows 'Backup Operators' Group User List", P10904),
     (WIN, "10916", "Microsoft Windows - Local Users Information : Passwords Never Expire", P10916),
     (WIN, "10913", "Microsoft Windows - Local Users Information : Disabled Accounts", P10913),
     (WIN2, "71246", "Enumerate Local Group Memberships", P71246),
     (RHEL, "95928", "Linux User List Enumeration", REAL95928)]
c.executemany("INSERT INTO vulns VALUES (?,?,?,?,'info','','2026-11-01','OPEN')", V)
c.commit()
c.close()

from core import identity  # noqa: E402

res = identity.scan(DB)
A = {a["user"]: a for a in res["accounts"]}
priv = lambda u: "privileged" in (A.get(u) or {}).get("flags", [])
why = lambda u: " | ".join((A.get(u) or {}).get("privilege") or [])

# ── names alone no longer make an admin ──────────────────────────────────────
check(not priv("admin"), "a Linux account NAMED admin (not in sudo / wheel / admin) is not privileged")
check("admin" in A and not priv("admin"), "a Windows account NAMED admin (RID 1106, in no admin group) is not privileged")
check(not priv("rootkit_scan") and not priv("guestuser"), "names containing root / admin don't count")
# ── evidence does ─────────────────────────────────────────────────────────────
check(priv("casey") and "sudo" in why("casey"), "casey: in the sudo group (95928 Groups continuation line) → privileged")
check(priv("deploy") and "wheel" in why("deploy"), "deploy: wheel in a comma list → privileged")
check(priv("root") and "POSIX superuser" in why("root"), "root on a Linux user list → privileged, said so")
check(priv("maria") and "admin" in why("maria") and "95929" in A["maria"]["plugins"],
      "maria: macOS admin group from 95929 (the macOS user list is now parsed)")
check(priv("Administrator") and "RID 500" in why("Administrator") and "Administrators" in why("Administrator"),
      "Administrator: RID 500 + the Administrators group")
check(priv("jsmith") and "member of Administrators" in why("jsmith"), "jsmith: Administrators group (10902) → privileged")
check(priv("da_alice") and "Domain Admins" in why("da_alice"), "da_alice: Domain Admins (10908) → privileged")
check(priv("svc_sql") and priv("helpdesk") and "operator" in why("helpdesk"),
      "svc_sql (Administrators) and helpdesk (Backup Operators, protected group) → privileged")
check(priv("localadm") and not priv("kiosk") and "kiosk" not in A,
      "71246: Administrators (S-1-5-32-544) member privileged; plain Users members not added")
# ── the owner's real 95928 layout ─────────────────────────────────────────────
check(priv("ops") and "wheel" in why("ops"), "real layout: ops in wheel (continuation line) → privileged")
check(not any(priv(u) for u in ("sync", "shutdown", "halt", "operator", "postfix", "chrony", "bin")),
      "real layout: the root GROUP (sync / shutdown / halt / operator) is not admin; nor are daemons")
check("mail" in A["postfix"]["groups"] and "postfix" in A["postfix"]["groups"], "real layout: postfix's two groups both read")
check(A["root"]["section"] == "system" and A["chrony"]["section"] == "system", "System Accounts section kept")
check(A.get("svc_patch", {}).get("section") == "domain" and priv("svc_patch") and "sudo" in why("svc_patch"),
      "Domain Accounts section recognised (not left as System); its sudo member is privileged")
check(A.get("svc_patch", {}).get("klass") == "human", "a domain account with a login shell classifies as a person")
check("jdoe@corp.example" in A and A["jdoe@corp.example"]["section"] == "domain", "a domain account keeps its realm")
hi = {x["user"]: x for x in identity.host_identities(RHEL, DB)}
check(hi.get("chrony", {}).get("klass") == "service", "Argos per-host view reads the same layout")
# ── 10902 used to give the DOMAIN as an account ─────────────────────────────
check("WIN-01" not in A and "CORP" not in A and "Domain" not in A and "Domain Admins" not in A,
      "no DOMAIN / nested-group names show up as accounts")
check(res.get("nested_admin_groups", {}).get("Administrators") == ["Domain Admins"],
      "a nested group in Administrators is reported, not listed as an account")
# ── account-status plugins become flags ───────────────────────────────────────
check("non-expiring pw" in A["svc_sql"]["flags"], "10916: svc_sql password never expires")
check("disabled" in A["Administrator"]["flags"] and "disabled" not in identity.INFO_FLAGS - {"disabled"},
      "10913: Administrator disabled (context, not counted as risk)")
check(res["counts"]["flagged"] == sum(1 for a in res["accounts"] if [f for f in a["flags"] if f not in identity.INFO_FLAGS]),
      "flagged count ignores context-only flags")
# ── catalogue + Argos per-host view ───────────────────────────────────────────
ids = {p for p, _n in identity.ENUM_PLUGINS}
check({"95929", "10902", "10908", "71246", "10916", "10913", "10900", "60019"} <= ids, "the plugin catalogue lists them")
hi = {x["user"]: x for x in identity.host_identities(WIN, DB)}
check({"Administrator", "jsmith", "da_alice", "svc_sql", "helpdesk"} <= set(hi) and "CORP" not in hi and "WIN-01" not in hi,
      "Argos: the host's group-list members, without DOMAIN names")
# ── the page row carries the reasons ──────────────────────────────────────────
from agents.identity import api  # noqa: E402
row = api._slim(A["jsmith"], "x")
check(row.get("privilege") and row.get("privileged_hosts") == 1, "page row: privilege reasons + host count")
pg = open(os.path.join(ROOT, "agents", "identity", "page.html"), encoding="utf-8").read()
check("Why privileged: " in pg and "root / Administrator on" not in pg, "page explains privilege instead of 'root / Administrator'")

print()
print("%d failure(s)" % len(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
