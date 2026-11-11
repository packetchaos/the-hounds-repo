"""Identity inventory — NHI + human identities, via local-user enumeration plugins.

Parses usernames from
local-user enumeration plugins and classifies each as a non-human identity (NHI),
service account, human, or system account. Unlike a read-only view this module also
keeps the asset_uuid(s) behind each identity + the platform URL, so the Identity
agent can TAG the hosting assets via navi's tag-by-query selector.

Reads are read-only (core.db). Tag writes go through navi (core.navi_cli).
"""
import re

from core import db, hx_summary

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


_CHECK_EVERY = 200     # rows between db.checkpoint() calls in the Python parsing loops


def _cols(table, path=None):
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}");', path=path)}
    except Exception:
        return set()


def _uset(sql, db_path):
    """Set of asset_uuids returned by a DISTINCT asset_uuid query (empty on error)."""
    try:
        return {r["asset_uuid"] for r in db.query(sql, path=db_path) if r.get("asset_uuid")}
    except (db.QueryTimeout, db.TooManyRows):
        raise                                  # a budget / cancel stops the run (launcher → budget:true)
    except Exception:
        return set()


def _hx(db_path):
    """⚡ Optimize summaries usable for this navi.db (fresh hx_plugin / hx_asset)."""
    try:
        return hx_summary.usable(db_path)
    except Exception:
        return False


def _sqlit(xs):
    return ",".join("'" + str(x).replace("'", "''") + "'" for x in xs)


def _hx_plugins(cond, db_path):
    """plugin ids from hx_plugin matching cond (plugin-level attributes: lname, sevn, kev …)."""
    try:
        return [str(r["plugin_id"]) for r in db.query("SELECT plugin_id FROM hx_plugin WHERE " + cond, path=db_path)]
    except (db.QueryTimeout, db.TooManyRows):
        raise
    except Exception:
        return []


def _lname_any(terms):
    return "(" + " OR ".join("lname LIKE '%" + t.replace("'", "''") + "%'" for t in terms) + ")"


# the plugin-NAME arms of the scan's three name-or-output sweeps (lower-cased; SQLite LIKE is
# ASCII case-insensitive, so plugin_name LIKE '%x%' ≡ lname LIKE '%x%')
_DISC_NAME = ("user%enumerat", "enumerate%user", "local user", "user list", "users via",
              "account%enumerat", "passwd")
_DC_NAME = ("default cred", "default password", "blank password", "anonymous")
_AD_NAME = ("kerberoast", "as-rep", "asrep", "delegation")
_DC_OUT = ("default credentials", "blank password")
_AD_OUT = ("krbtgt",)
_SA_OUT = ("service account",)


def _arms():
    lo = "lower(output)"

    def arm(terms):
        return "(" + " OR ".join("%s LIKE '%%%s%%'" % (lo, t) for t in terms) + ")"
    return arm(_SA_OUT), arm(_DC_OUT), arm(_AD_OUT)


def signal_predicate(vcols):
    """The output predicate core/hx_signals pre-evaluates for this hound (None: not applicable)."""
    if "output" not in set(vcols or ()):
        return None
    sa, dc, ad = _arms()
    return "%s OR %s OR %s" % (sa, dc, ad)


def _output_pass(db_path):
    """ONE pass over vulns for every unrestricted OUTPUT arm of the scan (Phase 1 keeps the
    output parsing; this only folds three full-table sweeps into one). Returns
    (sa_rows [(rowid, asset_uuid, plugin_id, output)], dc_hosts, ad_hosts).
    Phase 1b: when ⚡ Optimize pre-evaluated this predicate (core/hx_signals), only the matching
    findings are read, by rowid — same rows, same order."""
    sa, dc, ad = _arms()
    hits = ""
    try:
        from core import hx_signals
        pred = "%s OR %s OR %s" % (sa, dc, ad)
        if hx_signals.usable_for("identity", pred, db_path):
            hits = hx_signals.rows_sql("identity") + " AND "
    except Exception:
        hits = ""
    sql = ("SELECT rowid AS rid, asset_uuid, plugin_id, %s AS sa, %s AS dc, %s AS ad, "
           "CASE WHEN %s AND output<>'' AND plugin_id<>'95928' AND plugin_id<>'92364' THEN output END AS output "
           "FROM vulns WHERE %s(%s OR %s OR %s)" % (sa, dc, ad, sa, hits, sa, dc, ad))
    sa_rows, dch, adh = [], set(), set()
    try:
        rows = db.query(sql, path=db_path)
    except (db.QueryTimeout, db.TooManyRows):
        raise
    except Exception:
        rows = []
    for r in rows:
        u = r.get("asset_uuid")
        if r.get("output") is not None:
            sa_rows.append((r["rid"], u, r.get("plugin_id"), r["output"]))
        if u and r.get("dc"):
            dch.add(u)
        if u and r.get("ad"):
            adh.add(u)
    return sa_rows, dch, adh


def _scalar0(sql, db_path):
    try:
        return db.scalar(sql, path=db_path) or 0
    except (db.QueryTimeout, db.TooManyRows):
        raise
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
    has_url = "url" in _cols("assets", db_path)
    amap = {}
    for i, a in enumerate(db.query("SELECT uuid, hostname, ip_address" + (", url" if has_url else "") +
                                   " FROM assets", path=db_path)):
        if not i % _CHECK_EVERY:
            db.checkpoint("identity: assets")
        amap[a["uuid"]] = {"host": (a.get("hostname") or a.get("ip_address") or "").strip() or "host",
                           "url": a.get("url")}

    fresh = ""
    hx = _hx(db_path)
    try:
        # data freshness: with the summaries, read it off assets (one row per asset) instead of
        # a full vulns scan — an asset's last_found is its newest finding's
        row = db.query("SELECT MAX(last_found) f FROM " + ("assets" if hx and "last_found" in _cols("assets", db_path)
                                                            else "vulns"), path=db_path)
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

    _seen = {}                           # user -> (host set, uuid set) mirroring the lists

    def _touch(u, info, au=None, pid=""):
        """Create/return an account and attach host + uuid + plugin provenance."""
        a = _mk(u, info)
        # membership via side sets (same ordered lists): `x not in list` made this O(hosts²) per
        # account — on 600k assets a "daemon" on every host never finished the 95928 parse
        seen = _seen.get(u)
        if seen is None:
            seen = _seen[u] = (set(a["hosts"]), set(a["asset_uuids"]))
        host = info.get("host", "host")
        if host not in seen[0]:
            seen[0].add(host)
            a["hosts"].append(host)
        if au and au not in seen[1]:
            seen[1].add(au)
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
    except (db.QueryTimeout, db.TooManyRows):
        raise
    except Exception:
        rows95928 = []
    # Python parsing of already-fetched rows: the SQL budget can't stop it, checkpoint() does
    for i, r in enumerate(rows95928):
        if not i % _CHECK_EVERY:
            db.checkpoint("identity: 95928 parse")
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
    out_pass = None
    try:
        if hx:
            # name arms + known ids → plugin ids from hx_plugin (only THOSE plugins' rows are
            # read); the output arm comes from the single shared output pass; merged in rowid
            # (= table-scan) order so first-seen evidence wins exactly as before
            pids = set(_hx_plugins(_lname_any(_DISC_NAME), db_path)) | set(known)
            pids -= {"95928", "92364"}
            got = {}
            pl = sorted(pids)
            for i in range(0, len(pl), 500):
                for r in db.query("SELECT rowid AS rid, asset_uuid, plugin_id, output FROM vulns WHERE plugin_id IN ("
                                  + _sqlit(pl[i:i + 500]) + ") AND output IS NOT NULL AND output<>''", path=db_path):
                    got[r["rid"]] = r
            out_pass = _output_pass(db_path)
            for rid, u, pid_, out in out_pass[0]:
                got.setdefault(rid, {"asset_uuid": u, "plugin_id": pid_, "output": out})
            rows = [got[k] for k in sorted(got)]
        else:
            rows = db.query(disc_sql, tuple(known), path=db_path)
    except (db.QueryTimeout, db.TooManyRows):
        raise
    except Exception:
        rows = []
    for i, r in enumerate(rows):
        if not i % _CHECK_EVERY:
            db.checkpoint("identity: enumerator parse")
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
        for i, r in enumerate(db.query("SELECT output FROM vulns WHERE plugin_id='83303' "
                                       "AND output IS NOT NULL AND output<>''", path=db_path)):
            if not i % _CHECK_EVERY:
                db.checkpoint("identity: 83303 parse")
            for line in (r.get("output") or "").splitlines():
                m = _USER_RE.search(line)
                if m and m.group(1) in acct:
                    _flag(acct[m.group(1)], "non-expiring pw")
    except (db.QueryTimeout, db.TooManyRows):
        raise
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

    host_sets = {}                       # flag -> host uuids (the page tags these directly)

    def _host_flag(sql, flag, klasses):
        s = sql if isinstance(sql, set) else _uset(sql, db_path)
        host_sets[flag] = sorted(s)
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

    # Nessus SCAN credentials (plugin 19506 "Nessus Scan Information"). The account used for
    # credentialed checks naturally lands on every host it scans — that's scanning, NOT lateral
    # movement — so a high host-count on the scan account is a false "reuse" alarm. Parse
    #   "Credentialed checks : yes, as 'root' via ssh"
    # per asset, keyed by BARE username (domain-stripped, case-insensitive), and subtract that
    # footprint before flagging reuse.
    scan_hosts_by_user, scan_via_by_user = {}, {}
    _scan_re = re.compile(r"credentialed checks\s*:\s*yes,\s*as\s+'([^']+)'\s+via\s+(\w+)", re.I)
    for i, r in enumerate(db.query("SELECT asset_uuid, output FROM vulns WHERE plugin_id='19506' "
                                   "AND lower(output) LIKE '%credentialed checks : yes, as%'", path=db_path)):
        if not i % _CHECK_EVERY:
            db.checkpoint("identity: 19506 parse")
        m = _scan_re.search(r.get("output") or "")
        if not m:
            continue
        key = m.group(1).split("\\")[-1].strip().lower()
        au = r.get("asset_uuid")
        if key:
            if au:
                scan_hosts_by_user.setdefault(key, set()).add(au)
            scan_via_by_user.setdefault(key, set()).add(m.group(2).strip().lower())

    # account reuse across many hosts (lateral-movement risk), minus the scan-credential footprint.
    # The same account NAME on many hosts is all navi.db can show — it never says the password
    # is the same, so nothing here infers password reuse.
    def _no_login(a):   # nologin / false shells can't be used to log in, so they are not a lateral path
        sh = (a.get("shell") or "").strip().lower()
        return bool(sh) and ("nologin" in sh or sh.endswith("/false"))
    for a in acct.values():
        if a["klass"] == "machine":
            continue
        key = a["user"].split("\\")[-1].strip().lower()
        sset = scan_hosts_by_user.get(key)
        if sset:
            effu = [u for u in a["asset_uuids"] if u not in sset]   # hosts NOT explained by scanning
            eff = len(effu)
            a["scan_credential"] = {"hosts": len(sset & set(a["asset_uuids"])),
                                    "via": sorted(scan_via_by_user.get(key, []))}
            if "scan credential" not in a["flags"]:
                _flag(a, "scan credential")
        else:
            effu = list(a["asset_uuids"])
            eff = len(effu)
        if eff >= 5 and not _no_login(a) and not any(x.startswith("account reuse") for x in a["flags"]):
            _flag(a, "account reuse ×" + str(eff))
            a["reuse_uuids"] = effu

    scan_creds = sorted(
        ({"user": next((x["user"] for x in acct.values()
                        if x["user"].split("\\")[-1].strip().lower() == k), k),
          "hosts": len(v), "via": sorted(scan_via_by_user.get(k, []))}
         for k, v in scan_hosts_by_user.items()),
        key=lambda x: -x["hosts"])

    # correlate identities to exploitable hosts (KEV / critical = crown jewels)
    def _corr(sql, flag):
        s = sql if isinstance(sql, set) else _uset(sql, db_path)
        host_sets[flag] = sorted(s)
        if s:
            for a in acct.values():
                if a["klass"] != "machine" and any(u in s for u in a["asset_uuids"]):
                    _flag(a, flag)
        return len(s)

    if hx:
        # KEV (any state) = hx_asset.kev_any; critical (any state) stays a per-finding severity
        # test on the covering index, limited to critical plugins; the name arms of the two
        # sweeps resolve on hx_plugin.lname and their output arms come from the shared pass
        if out_pass is None:
            out_pass = _output_pass(db_path)
        kev_q = "SELECT asset_uuid FROM hx_asset WHERE kev_any"
        crit_q = (hx_summary.assets_with("sevn = 4", path=db_path)
                  + " AND (lower(severity)='critical' OR severity='4')")
        dc_q = _uset(hx_summary.assets_with(_lname_any(_DC_NAME), path=db_path), db_path) | out_pass[1]
        ad_q = _uset(hx_summary.assets_with(_lname_any(_AD_NAME), path=db_path), db_path) | out_pass[2]
    else:
        kev_q = "SELECT DISTINCT asset_uuid FROM vulns WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%'"
        crit_q = "SELECT DISTINCT asset_uuid FROM vulns WHERE lower(severity)='critical' OR severity='4'"
        dc_q = ("SELECT DISTINCT asset_uuid FROM vulns WHERE lower(plugin_name) LIKE '%default cred%' "
                "OR lower(plugin_name) LIKE '%default password%' OR lower(plugin_name) LIKE '%blank password%' "
                "OR lower(plugin_name) LIKE '%anonymous%' OR lower(output) LIKE '%default credentials%' "
                "OR lower(output) LIKE '%blank password%'")
        ad_q = ("SELECT DISTINCT asset_uuid FROM vulns WHERE lower(plugin_name) LIKE '%kerberoast%' "
                "OR lower(plugin_name) LIKE '%as-rep%' OR lower(plugin_name) LIKE '%asrep%' "
                "OR lower(plugin_name) LIKE '%delegation%' OR lower(output) LIKE '%krbtgt%'")
    kevHostN = _corr(kev_q, "on KEV host")
    critHostN = _corr(crit_q, "on critical host")
    dcHosts = _host_flag(dc_q, "default/blank cred", ("human", "service", "nhi"))
    adHosts = _host_flag(ad_q, "AD attack path", ("human", "service", "nhi", "machine"))
    # SNMP write community (private) is worse than read (public)
    if _scalar0("SELECT COUNT(*) FROM vulns WHERE plugin_id='41028' AND lower(output) LIKE '%private%'",
                db_path) and "__41028" in acct:
        _flag(acct["__41028"], "write (private)")

    # coverage gap — reachable hosts scanned WITHOUT credentials
    blind_set = _uset("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id IN ('110723','104410')", db_path)
    blind = len(blind_set)
    cred_set = _uset("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='19506' "
                     "AND lower(output) LIKE '%credentialed checks : yes%'", db_path)
    host_sets["uncredentialed"] = sorted(blind_set)

    order = {"machine": 0, "nhi": 1, "human": 2, "service": 3}
    accounts = sorted(acct.values(), key=lambda x: (order.get(x["klass"], 9), x["user"]))
    def _risky(a):   # flags that actually indicate risk — a bare scan credential is expected
        return [f for f in a["flags"] if f != "scan credential"]

    def _is_reused(a):   # account reuse across ≥5 hosts (scanner footprint subtracted)
        return any(f.startswith("account reuse") for f in a["flags"])
    reused_hosts = {u for a in accounts for u in (a.get("reuse_uuids") or [])}
    counts = {"total": len(accounts),
              "nhi": sum(1 for a in accounts if a["klass"] == "nhi"),
              "human": sum(1 for a in accounts if a["klass"] == "human"),
              "service": sum(1 for a in accounts if a["klass"] == "service"),
              "machine": sum(1 for a in accounts if a["klass"] == "machine"),
              "flagged": sum(1 for a in accounts if _risky(a)),
              "scan_creds": sum(1 for a in accounts if a.get("scan_credential")),
              "reused": sum(1 for a in accounts if _is_reused(a)),
              "reused_hosts": len(reused_hosts)}
    return {"accounts": accounts, "counts": counts, "blind": blind, "fresh": fresh,
            "sshHosts": sshHosts, "weakHosts": weakHosts, "kevHostN": kevHostN,
            "critHostN": critHostN, "dcHosts": dcHosts, "adHosts": adHosts,
            "scan_creds": scan_creds, "host_sets": host_sets,
            "credentialed": len(cred_set - blind_set),
            "identity_hosts": len({u for a in accounts for u in a["asset_uuids"]})}


_HI_USER = re.compile(r"^\s*User(?:name)?\s*[:=]\s*([A-Za-z_][A-Za-z0-9_.\-\$]{1,31})", re.I)
_HI_DASH = re.compile(r"^\s*-\s*([A-Za-z_][A-Za-z0-9_.\-\$]{1,31})\b")
_HI_UID = re.compile(r"^\s*(?:UID|Uid)\s*[:=]\s*(\d+)")


def _klass_for(user, section=""):
    """Best-effort class for ONE enumerated account (Argos per-host view). External
    authority (well-known SID/RID, AD `$`, UID convention) wins; otherwise fall back to the
    guess lists and the system-account convention."""
    k, auth = authority_class(user)
    if k:
        return k, auth
    lu = (user or "").strip().lower()
    if lu in HUM:
        return "human", ""
    if lu in NHI:
        return "nhi", ""
    if lu in SVC:
        return "service", ""
    if _is_system(lu) or section == "system":
        return "service", "system / pseudo account"
    return "human", ""


def host_identities(uuid, db_path=None):
    """Identities enumerated ON one asset — for the Argos deep-dive. Parses the local-user
    enumeration plugins for this asset_uuid and classifies each account the same way Janus
    does (external authority first). Scoped to one host, so it's cheap. Returns a list of
    ``{user, klass, authority, plugins}`` ordered machine → NHI → service → human → system."""
    if not uuid:
        return []
    try:
        rows = db.query("SELECT plugin_id, output FROM vulns WHERE asset_uuid=? "
                        "AND plugin_id IN ('95928','10860','10785','83303','10914','10915') "
                        "AND output IS NOT NULL AND output<>''", (uuid,), path=db_path)
    except Exception:
        return []
    found = {}
    for r in rows:
        pid = str(r.get("plugin_id") or "")
        section, last = "", None
        for raw in (r.get("output") or "").splitlines():
            line = raw.strip()
            low = line.lower()
            if "[" in line and "user accounts" in low:
                section = "user"; last = None; continue
            if "[" in line and "system accounts" in low:
                section = "system"; last = None; continue
            m = _HI_USER.match(line)
            # dash-list plugins: 10860/10785 (SMB enum) AND 10914/10915 (Windows
            # local users: never-changed-password / never-logged-in) — all emit
            # "  - <account>" lines, no User:/Username: prefix.
            if not m and pid in ("10860", "10785", "10914", "10915"):
                m = _HI_DASH.match(line)
            if m:
                u = m.group(1)
                if not _valid_account(u):
                    last = None; continue
                k = u.lower()
                if k not in found:
                    kl, auth = _klass_for(u, section)
                    found[k] = {"user": u, "klass": kl, "authority": auth or "", "plugins": [pid]}
                elif pid not in found[k]["plugins"]:
                    found[k]["plugins"].append(pid)
                last = k
                continue
            um = _HI_UID.match(line)
            if um and last and last in found:
                try:
                    kl, auth = authority_class(found[last]["user"], uid=int(um.group(1)))
                    if kl:
                        found[last]["klass"] = kl
                        found[last]["authority"] = auth
                except ValueError:
                    pass
    order = {"machine": 0, "nhi": 1, "service": 2, "human": 3, "system": 4}
    return sorted(found.values(), key=lambda x: (order.get(x["klass"], 9), x["user"].lower()))


def selector_for(asset_uuids):
    """navi tag-by-query SQL selecting the given assets (the identity's hosts). One query —
    for a set that may be large, tag with core.navi_cli.tag_uuids_batched (agents/identity/api)."""
    ids = [u for u in (asset_uuids or []) if u]
    if not ids:
        return ""
    from core import navi_cli
    return navi_cli.uuids_query(ids)
