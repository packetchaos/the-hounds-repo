"""Identity inventory — NHI + human identities, via local-user enumeration plugins.

Parses usernames from
local-user enumeration plugins and classifies each as a non-human identity (NHI),
service account, human, or system account. Unlike a read-only view this module also
keeps the asset_uuid(s) behind each identity + the platform URL, so the Identity
agent can TAG the hosting assets via navi's tag-by-query selector.

Reads are read-only (core.db). Tag writes go through navi (core.navi_cli).
"""
import re

from core import db

# local-user / identity enumeration plugins (local-user enumeration plugins)
ENUM_PLUGINS = [
    ("95928", "Linux User List Enumeration"),
    ("83303", "Local Users — Passwords Never Expire"),
    ("10860", "SMB Enumerate Local Users"),
    ("10785", "SMB NativeLanManager Disclosure"),
    ("10914", "Local Users — Never Changed Password"),
    ("10915", "Local Users — Never Logged In"),
]
PARSE_PLUGINS = ("95928", "10860")

NHI = {"jenkins", "dockerroot", "pihole", "lighttpd", "www-data", "lxd",
       "cockpit-ws", "gitlab-runner", "prometheus", "grafana", "nginx", "apache"}
SVC = {"tns", "postfix", "tcpdump", "chrony", "tss", "pcp", "pollinate",
       "usbmux", "mysql", "postgres", "redis", "mongodb"}
HUM = {"root", "admin", "administrator"}

# ---------------------------------------------------------------------------
# EXTERNAL AUTHORITIES — deterministic classification of built-in / machine /
# system accounts, so the labels aren't just our hand-kept guess lists:
#   * Windows built-in accounts → Microsoft "Well-known SIDs" (KB243330 /
#     learn.microsoft.com/windows/win32/secauthz/well-known-sids). Identified by
#     the account's RID (trailing number of its SID) — constant across installs.
#   * AD machine & (g)MSA accounts → sAMAccountName ends in "$" (Active Directory
#     computer- and managed-service-account convention).
#   * Linux system accounts → UID below UID_MIN (default 1000) per
#     /etc/login.defs SYS_UID_MIN..SYS_UID_MAX (the `useradd -r` range); UID 0 = root.
# Each hit carries a citation string so the UI can show WHY, not just WHAT.
# ---------------------------------------------------------------------------
WELLKNOWN_RID = {           # domain/local RID (last SID segment) → (klass, name)
    "500": ("human",   "Administrator"),
    "501": ("service", "Guest"),
    "502": ("machine", "krbtgt (KDC service account)"),
    "503": ("service", "DefaultAccount"),
    "504": ("service", "WDAGUtilityAccount"),
}
WELLKNOWN_SID = {           # universal well-known SID (whole value) → (klass, name)
    "S-1-5-18": ("service", "LocalSystem"),
    "S-1-5-19": ("service", "LocalService"),
    "S-1-5-20": ("service", "NetworkService"),
}
WELLKNOWN_NAME = {          # built-in username fallback when no SID/UID is present
    "administrator": ("human",   "Windows built-in Administrator (well-known RID 500)"),
    "guest":         ("service", "Windows built-in Guest (well-known RID 501)"),
    "krbtgt":        ("machine", "krbtgt KDC service account (well-known RID 502)"),
    "defaultaccount": ("service", "Windows DefaultAccount (well-known RID 503)"),
    "wdagutilityaccount": ("service", "WDAG utility account (well-known RID 504)"),
    "system":        ("service", "LocalSystem (well-known SID S-1-5-18)"),
    "localsystem":   ("service", "LocalSystem (well-known SID S-1-5-18)"),
    "local service": ("service", "LocalService (well-known SID S-1-5-19)"),
    "network service": ("service", "NetworkService (well-known SID S-1-5-20)"),
}
UID_MIN = 1000              # login.defs default — UID below this = system account
_SID_RE = re.compile(r"\bS-1-5-\d+(?:-\d+){0,14}\b", re.I)


def authority_class(user, uid=None, sid=None):
    """Classify by EXTERNAL authority. Returns (klass, citation) or (None, "").

    Order: Windows well-known SID/RID → AD machine `$` → Linux UID convention →
    built-in username fallback. Only returns a class when an authority applies,
    so evidence-based heuristics still run for everything else.
    """
    u = (user or "").strip()
    lu = u.lower()
    s = (sid or "").strip().upper()
    if s:
        if s in WELLKNOWN_SID:
            k, name = WELLKNOWN_SID[s]
            return k, "Microsoft well-known SID %s (%s)" % (s, name)
        rid = s.rsplit("-", 1)[-1]
        if rid in WELLKNOWN_RID:
            k, name = WELLKNOWN_RID[rid]
            return k, "Microsoft well-known RID %s (%s)" % (rid, name)
    if u.endswith("$"):
        return "machine", "AD machine/(g)MSA account (sAMAccountName ends in $)"
    if isinstance(uid, int):
        if uid == 0:
            return "human", "UID 0 (root superuser)"
        if uid < UID_MIN:
            return "service", "Linux system account (UID %d < UID_MIN %d, login.defs)" % (uid, UID_MIN)
    if lu in WELLKNOWN_NAME:
        return WELLKNOWN_NAME[lu]
    return None, ""
# Well-known built-in / pseudo accounts that are NOT people. Anything enumerated that
# is NOT in these sets and does not match a system pattern is treated as a human.
SYS = {"daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp",
       "proxy", "backup", "list", "irc", "gnats", "nobody", "_apt", "messagebus",
       "syslog", "uuidd", "landscape", "fwupd-refresh", "sshd", "dnsmasq", "avahi",
       "avahi-autoipd", "colord", "geoclue", "rtkit", "saned", "epmd", "ntp", "statd",
       "polkitd", "dbus", "nscd", "sssd", "rpc", "rpcuser", "nslcd", "named", "clamav",
       "amavis", "opendkim", "spamd", "ftp", "nut", "gdm", "sddm", "lightdm", "kernoops",
       "whoopsie", "speech-dispatcher", "tpm", "systemd-coredump", "systemd-network",
       "systemd-resolve", "systemd-timesync", "_chrony", "_rpc", "dhcpd", "postgrey",
       # common Linux daemon / package accounts (previously fell through to "human")
       "abrt", "adm", "audio", "bluetooth", "brlapi", "brltty", "cdrom", "dialout",
       "disk", "floppy", "kmem", "plugdev", "staff", "tape", "tty", "utmp", "video",
       "operator", "input", "render", "sgx", "cdrw", "lpadmin", "netdev", "scanner",
       "dip", "sudo", "shadow", "ssl-cert", "crontab", "mlocate", "systemd-journal",
       "polkituser", "usbmuxd", "rpcuser", "halt", "shutdown", "adm", "flatpak",
       "pulse", "pulse-access", "gnome-initial-setup", "sssd", "chrony", "tss",
       "setroubleshoot", "cockpit-wsinstance", "unbound", "openvpn", "radvd", "qemu",
       "libvirt-qemu", "libvirt-dnsmasq", "vboxadd", "gluster", "ceph", "etcd",
       # Windows built-ins / pseudo
       "system", "local service", "network service", "defaultaccount",
       "wdagutilityaccount", "guest", "krbtgt", "trustedinstaller", "defaultuser0"}

# Shell / start-script signals — the strongest human-vs-service tell on Linux.
_NOLOGIN = ("nologin", "/bin/false", "/usr/bin/false", "/bin/true", "/bin/sync",
            "/sbin/shutdown", "/sbin/halt", "/dev/null")
_INTERACTIVE = ("/bin/bash", "/bin/sh", "/bin/zsh", "/bin/ksh", "/bin/fish",
                "/bin/dash", "/bin/tcsh", "/bin/csh", "/usr/bin/bash", "/usr/bin/zsh")


def _is_system(lu: str) -> bool:
    """True if the (lowercased) username is a built-in/pseudo system account."""
    if lu in SYS:
        return True
    if lu.startswith("systemd-") or lu.startswith("_"):
        return True
    if lu.endswith("$"):            # Windows machine / managed-service accounts
        return True
    return False


# Reject strings that are NOT accounts at all — env-var keys, cloud metadata, registry
# values, config keys (the noise that was showing up as "human" identities). Match on
# tell-tale suffixes/substrings of key:value dumps.
_NOT_ACCOUNT_SUFFIX = re.compile(
    r"(_id|_secret|_env|_tenant|_key|_token|_uri|_url|_region|_version|_level|"
    r"_revision|_name|_path|_home|_root|_dir|_count|_size|_port|_host)$")
_NOT_ACCOUNT_SUB = ("registry", "product", "processor", "comspec", "number_of",
                    "_execution_", "javapath", "systemroot", "programdata", "environment")
_STOP = {"the", "this", "list", "users", "note", "plugin", "user", "accounts", "account",
         "system", "groups", "group", "home", "folder", "start", "script", "uid", "gid",
         "name", "shell", "global", "variables", "path", "temp", "os", "username"}


def _valid_account(u: str) -> bool:
    """Filter out non-account tokens (env vars, registry keys, config values)."""
    lu = (u or "").strip().lower()
    if not lu or lu in _STOP or len(lu) < 2 or len(lu) > 32:
        return False
    if _NOT_ACCOUNT_SUFFIX.search(lu):
        return False
    if any(k in lu for k in _NOT_ACCOUNT_SUB):
        return False
    return True


# Strict user markers only — NO bare-indent catch-all (that scraped group names + env
# vars). Matches "User[name] : x", a leading "- x" bullet, or an /etc/passwd line.
_USER_RE = re.compile(r"(?:User(?:name)?\s*[:=]\s*|^\s*-\s+)([A-Za-z_][A-Za-z0-9_.\-]{1,31})\b")
_PASSWD_RE = re.compile(r"^([a-z_][a-z0-9_.\-]{1,31}):[^:]*:(\d+):\d+:[^:]*:([^:]*):(\S*)")


def _cols(table):
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}");')}
    except Exception:
        return set()


def _uset(sql, db_path):
    """Set of asset_uuids returned by a DISTINCT asset_uuid query (empty on error)."""
    try:
        return {r["asset_uuid"] for r in db.query(sql, path=db_path) if r.get("asset_uuid")}
    except Exception:
        return set()


def _scalar0(sql, db_path):
    try:
        return db.scalar(sql, path=db_path) or 0
    except Exception:
        return 0


def scan(db_path=None):
    """Content-based identity inventory (repo-native port of the live console).

    Discovers identities by CONTENT — plugin-name sweep + output markers + the
    high-value enumerators — classifies Human / Service-NHI / Machine, flags the
    risky ones, headlines the coverage gap (hosts scanned without credentials),
    and correlates identities to exploitable hosts.

    Returns {accounts, counts, blind, fresh, sshHosts, weakHosts, kevHostN,
    critHostN, dcHosts, adHosts}. Each account: {user, klass, hosts[],
    asset_uuids[], url, flags[], plugins[]}.
    """
    has_url = "url" in _cols("assets")
    amap = {}
    for a in db.query("SELECT uuid, hostname, ip_address" + (", url" if has_url else "") +
                      " FROM assets", path=db_path):
        amap[a["uuid"]] = {"host": (a.get("hostname") or a.get("ip_address") or "").strip() or "host",
                           "url": a.get("url")}

    fresh = ""
    try:
        row = db.query("SELECT MAX(last_found) f FROM vulns", path=db_path)
        fresh = (row[0].get("f") if row else "") or ""
    except Exception:
        fresh = ""

    acct = {}

    def _mk(u, info):
        a = acct.get(u)
        if a is None:
            a = acct[u] = {"user": u, "klass": "system", "hosts": [], "asset_uuids": [],
                           "url": info.get("url"), "flags": [], "plugins": [],
                           # evidence for human-vs-service classification
                           "section": "", "shell": "", "home": "", "uid": None,
                           "sid": "", "authority": ""}
        return a

    def _touch(u, info, au=None, pid=""):
        """Create/return an account and attach host + uuid + plugin provenance."""
        a = _mk(u, info)
        host = info.get("host", "host")
        if host not in a["hosts"]:
            a["hosts"].append(host)
        if au and au not in a["asset_uuids"]:
            a["asset_uuids"].append(au)
        if not a["url"]:
            a["url"] = info.get("url")
        if pid and pid not in a["plugins"]:
            a["plugins"].append(pid)
        return a

    # PHASE 1 — discover accounts. Plugin 95928 (Linux User List Enumeration) is parsed
    # STRUCTURALLY — it labels [ User Accounts ] vs [ System Accounts ] and gives each
    # account's Home folder + Start script (shell), the strongest human-vs-service signal.
    # Env-var dumps (92364) and /etc/group membership blocks are NOT identity sources, so
    # we no longer scrape them (that was the source of the bogus "human" rows).
    def _block_parse(output, info, au):
        section, cur = "", None
        for raw in (output or "").splitlines():
            line = raw.rstrip()
            low = line.lower()
            if "user accounts" in low and "[" in line:
                section = "user"; cur = None; continue
            if "system accounts" in low and "[" in line:
                section = "system"; cur = None; continue
            m = re.match(r"\s*User(?:name)?\s*[:=]\s*([A-Za-z_][A-Za-z0-9_.\-\$]{1,31})", line)
            if m:
                u = m.group(1)
                cur = _touch(u, info, au, "95928") if _valid_account(u) else None
                if cur:
                    cur["section"] = cur["section"] or section
                continue
            if cur is None:
                continue
            hm = re.match(r"\s*Home(?:\s*folder)?\s*[:=]\s*(\S+)", line)
            if hm and not cur["home"]:
                cur["home"] = hm.group(1)
            sm = re.match(r"\s*(?:Start script|Shell)\s*[:=]\s*(\S+)", line)
            if sm and not cur["shell"]:
                cur["shell"] = sm.group(1)
            um = re.match(r"\s*(?:UID|Uid)\s*[:=]\s*(\d+)", line)
            if um and cur["uid"] is None:
                try:
                    cur["uid"] = int(um.group(1))
                except ValueError:
                    pass

    try:
        rows95928 = db.query("SELECT asset_uuid, output FROM vulns WHERE plugin_id='95928' "
                             "AND output IS NOT NULL AND output<>''", path=db_path)
    except Exception:
        rows95928 = []
    for r in rows95928:
        _block_parse(r.get("output"), amap.get(r["asset_uuid"], {}), r.get("asset_uuid"))

    # Other enumerators (Windows local users, passwd, etc.) — strict markers only, and
    # NEVER plugin 92364 (env vars). Parse /etc/passwd lines for shell/home/uid too.
    known = ("10860", "83303", "10399", "56211", "72684", "130614", "110385", "10785")
    ph = ",".join("?" * len(known))
    disc_sql = (
        "SELECT asset_uuid, plugin_id, output FROM vulns WHERE plugin_id<>'95928' "
        "AND plugin_id<>'92364' AND output IS NOT NULL AND output<>'' AND ("
        "plugin_name LIKE '%user%enumerat%' OR plugin_name LIKE '%enumerate%user%' "
        "OR plugin_name LIKE '%local user%' OR plugin_name LIKE '%user list%' "
        "OR plugin_name LIKE '%users via%' OR plugin_name LIKE '%account%enumerat%' "
        "OR lower(plugin_name) LIKE '%passwd%' "
        "OR lower(output) LIKE '%service account%' "
        f"OR plugin_id IN ({ph}))")
    try:
        rows = db.query(disc_sql, tuple(known), path=db_path)
    except Exception:
        rows = []
    for r in rows:
        info = amap.get(r["asset_uuid"], {})
        au = r.get("asset_uuid")
        pid = str(r.get("plugin_id") or "")
        cur = None                       # last account touched — to attach a trailing SID
        for line in (r.get("output") or "").splitlines():
            pm = _PASSWD_RE.match(line.strip())
            if pm:
                u = pm.group(1)
                if not _valid_account(u):
                    cur = None
                    continue
                a = _touch(u, info, au, pid)
                try:
                    a["uid"] = a["uid"] if a["uid"] is not None else int(pm.group(2))
                except ValueError:
                    pass
                a["home"] = a["home"] or pm.group(3)
                a["shell"] = a["shell"] or pm.group(4)
                cur = a
                continue
            m = _USER_RE.search(line)
            if m and _valid_account(m.group(1)):
                cur = _touch(m.group(1), info, au, pid)
                continue
            # Windows enumerators print "SID : S-1-5-21-...-500" under the user — bind it
            sm = _SID_RE.search(line)
            if sm and cur is not None and not cur["sid"]:
                cur["sid"] = sm.group(0)

    # classify — evidence first (shell + section + home/uid), then known sets. The DEFAULT
    # for an unrecognized enumerated account is SERVICE (non-human): a person must be
    # positively identified (interactive shell + a real home / uid≥1000, or the plugin's own
    # "User Accounts" section), so daemon/package accounts stop being mislabelled human.
    for u, a in acct.items():
        lu = u.lower()
        shell = (a.get("shell") or "").lower()
        home = (a.get("home") or "").lower()
        uid = a.get("uid")
        sect = a.get("section")
        nologin = any(s in shell for s in _NOLOGIN)
        interactive = any(s in shell for s in _INTERACTIVE)
        human_home = home.startswith("/home/") or home.startswith("/users/") or home.startswith("c:\\users")
        real_uid = isinstance(uid, int) and uid >= 1000
        # AUTHORITY FIRST. Definitive external authorities (Microsoft well-known SID/RID,
        # AD machine `$` account, root UID 0) override everything. The generic Linux UID
        # convention still yields to our curated NHI list (jenkins/www-data etc. — a more
        # specific label than "system account"), so it is applied AFTER the NHI check.
        ak, acite = authority_class(u, uid, a.get("sid"))
        definitive = bool(ak) and not acite.startswith("Linux system account")
        if definitive:
            a["klass"] = ak
            a["authority"] = acite
            continue
        if u in NHI:
            a["klass"] = "nhi"
        elif ak:                                            # Linux system account (UID < 1000)
            a["klass"] = ak
            a["authority"] = acite
        elif u in SVC or _is_system(lu):
            a["klass"] = "service"
        elif nologin:
            a["klass"] = "service"                          # no interactive shell → service
        elif interactive and (human_home or real_uid):
            a["klass"] = "human"                            # positive human evidence
        elif sect == "user" and not nologin:
            a["klass"] = "human"                            # plugin put it under User Accounts
        elif sect == "system":
            a["klass"] = "service"
        elif human_home or real_uid:
            a["klass"] = "human"                            # real home / uid but shell unknown
        else:
            a["klass"] = "service"                          # DEFAULT: non-human unless proven

    # PHASE 2 — risk flags
    def _flag(a, fl):
        if fl not in a["flags"]:
            a["flags"].append(fl)

    # non-expiring passwords (83303)
    try:
        for r in db.query("SELECT output FROM vulns WHERE plugin_id='83303' "
                          "AND output IS NOT NULL AND output<>''", path=db_path):
            for line in (r.get("output") or "").splitlines():
                m = _USER_RE.search(line)
                if m and m.group(1) in acct:
                    _flag(acct[m.group(1)], "non-expiring pw")
    except Exception:
        pass
    # privileged names
    for a in acct.values():
        if a["user"].lower() in ("root", "administrator", "admin"):
            _flag(a, "privileged")
    # guest enabled (10860)
    if _scalar0("SELECT COUNT(*) FROM vulns WHERE plugin_id='10860' AND lower(output) LIKE '%guest%' "
                "AND lower(output) NOT LIKE '%disabled%'", db_path) and "guest" in acct:
        _flag(acct["guest"], "guest enabled")

    def _host_flag(sql, flag, klasses):
        s = _uset(sql, db_path)
        if s:
            for a in acct.values():
                if a["klass"] in klasses and any(u in s for u in a["asset_uuids"]):
                    _flag(a, flag)
        return len(s)

    sshHosts = _host_flag("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='149334'",
                          "ssh password auth", ("human", "service"))
    weakHosts = _host_flag(
        "SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='17651' AND ("
        "lower(output) LIKE '%complexity%disabled%' OR lower(output) LIKE '%minimum password length%: 0%' "
        "OR lower(output) LIKE '%maximum password age (days): 0%' OR lower(output) LIKE '%never expire%')",
        "weak pw policy", ("human",))

    # machine identities — SNMP default community (41028) + Windows host SIDs (10859)
    def _machine(pid, label, flag):
        uu = sorted(_uset("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='" + pid + "'", db_path))
        if uu:
            hs = list(dict.fromkeys((amap.get(u, {}).get("host", "host")) for u in uu))
            acct["__" + pid] = {"user": label, "klass": "machine", "hosts": hs[:30],
                                "asset_uuids": uu, "url": "", "flags": [flag], "plugins": [pid],
                                "sid": "", "authority": ""}
    _machine("41028", "SNMP default community", "default secret")
    _machine("10859", "Windows host SID", "machine identity")

    # account reuse across many hosts (lateral-movement risk)
    for a in acct.values():
        if a["klass"] != "machine":
            n = len(a["asset_uuids"])
            if n >= 5 and not any(x.startswith("reused") for x in a["flags"]):
                _flag(a, "reused ×" + str(n))

    # correlate identities to exploitable hosts (KEV / critical = crown jewels)
    def _corr(sql, flag):
        s = _uset(sql, db_path)
        if s:
            for a in acct.values():
                if a["klass"] != "machine" and any(u in s for u in a["asset_uuids"]):
                    _flag(a, flag)
        return len(s)

    kevHostN = _corr("SELECT DISTINCT asset_uuid FROM vulns WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%'",
                     "on KEV host")
    critHostN = _corr("SELECT DISTINCT asset_uuid FROM vulns WHERE lower(severity)='critical' OR severity='4'",
                      "on critical host")
    dcHosts = _host_flag(
        "SELECT DISTINCT asset_uuid FROM vulns WHERE lower(plugin_name) LIKE '%default cred%' "
        "OR lower(plugin_name) LIKE '%default password%' OR lower(plugin_name) LIKE '%blank password%' "
        "OR lower(plugin_name) LIKE '%anonymous%' OR lower(output) LIKE '%default credentials%' "
        "OR lower(output) LIKE '%blank password%'", "default/blank cred", ("human", "service", "nhi"))
    adHosts = _host_flag(
        "SELECT DISTINCT asset_uuid FROM vulns WHERE lower(plugin_name) LIKE '%kerberoast%' "
        "OR lower(plugin_name) LIKE '%as-rep%' OR lower(plugin_name) LIKE '%asrep%' "
        "OR lower(plugin_name) LIKE '%delegation%' OR lower(output) LIKE '%krbtgt%'",
        "AD attack path", ("human", "service", "nhi", "machine"))
    # SNMP write community (private) is worse than read (public)
    if _scalar0("SELECT COUNT(*) FROM vulns WHERE plugin_id='41028' AND lower(output) LIKE '%private%'",
                db_path) and "__41028" in acct:
        _flag(acct["__41028"], "write (private)")

    # coverage gap — reachable hosts scanned WITHOUT credentials
    blind = _scalar0("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE plugin_id IN ('110723','104410')", db_path)

    order = {"machine": 0, "nhi": 1, "human": 2, "service": 3}
    accounts = sorted(acct.values(), key=lambda x: (order.get(x["klass"], 9), x["user"]))
    counts = {"total": len(accounts),
              "nhi": sum(1 for a in accounts if a["klass"] == "nhi"),
              "human": sum(1 for a in accounts if a["klass"] == "human"),
              "service": sum(1 for a in accounts if a["klass"] == "service"),
              "machine": sum(1 for a in accounts if a["klass"] == "machine"),
              "flagged": sum(1 for a in accounts if a["flags"])}
    return {"accounts": accounts, "counts": counts, "blind": blind, "fresh": fresh,
            "sshHosts": sshHosts, "weakHosts": weakHosts, "kevHostN": kevHostN,
            "critHostN": critHostN, "dcHosts": dcHosts, "adHosts": adHosts}


def selector_for(asset_uuids):
    """navi tag-by-query SQL selecting the given assets (the identity's hosts)."""
    ids = [u for u in (asset_uuids or []) if u]
    if not ids:
        return ""
    inlist = ",".join("'" + str(u).replace("'", "''") + "'" for u in ids)
    return f"SELECT asset_uuid FROM vulns WHERE asset_uuid IN ({inlist})"
