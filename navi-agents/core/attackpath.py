"""Fenrir — attack-path engine (defensive exposure analysis over navi.db).

Purpose: show how weaknesses Tenable already found CHAIN together to reach the assets
that matter, and which fixes break the most of those chains. Read-only; nothing here
touches a host — it reasons over findings already in navi.db.

Threat model: assumed internal breach. An adversary already has a network position
(phished workstation, VPN, flat network) and can reach services navi saw open on a
port. Public IPs are additionally flagged as internet-exposed. There is NO flow or
firewall data in navi.db, so reachability is INFERRED and every edge says how.

GRAPH
  Nodes (states)
    ATTACKER                 the starting position
    <asset>:user / :admin    footholds on a host at user vs admin/root/SYSTEM level
    cred:<account>           an account present on several hosts (ACCOUNT reuse: navi.db never shows that
                             the password is shared, so it is never treated as password reuse)
    seg:<segment>            "on the same segment" hub — used by exploits that need an account
    relay:<segment>          NTLM capture position inside a segment
    domuser / domain         a domain-account context / domain-admin control
  Edges (each carries likelihood p, evidence, ATT&CK id, and the fixes that remove it)
    exploit   ATTACKER → host        network exploit, found on a port, no credentials needed
    defcred   ATTACKER → host        default / blank credentials on a network service
    unauth    ATTACKER → host        service open without authentication (Redis, Docker API, VNC…)
    authrce   seg → host             network exploit that needs any valid account
    privesc   host:user → host:admin LOCAL privilege escalation (vuln found locally, or failed control)
    harvest   host:admin → cred      account present here and on other hosts
    login     cred → host            that account on another host with a login service open
    capture   host → relay:<seg>     LLMNR/NBT-NS poisoning possible (control FAILED)
    relay     relay → host:admin     SMB server signing not required on the target
    dc        → DC host:admin        domain-controller takeover flaw (Zerologon unauth, noPac needs an account)
    owned     DC host:admin → domain owning a domain controller = domain admin
    kerb      domuser → domain       Kerberoast / AS-REP / delegation / AD CS weakness (offline cracking etc.)
    da        domain → host:admin    domain admin controls domain-joined Windows hosts (membership inferred)

CLASSIFICATION (once per plugin, from name + description + family, and the PORT it was found on)
  * A remote exploit needs explicit code/command-execution wording, a non-zero port, severity
    high/critical or KEV, and no client-side wording (opening a file, ssh-agent, user interaction).
  * Privilege escalation counts only when local (found on port 0 or "local user/attacker").
  * Domain-controller flaws match the PLUGIN NAME only — Windows cumulative updates list every CVE
    they fix in the description, so description text would mark workstations as DCs.
  * A DC is a host with Kerberos (88) + LDAP (389/636/3268) open, a "domain controller" plugin
    name, or a DC-only takeover finding.
  * Same account NAME on several hosts is ACCOUNT reuse, shown with a low likelihood — never
    password reuse; local Administrator becomes a likely shared credential only where the LAPS
    control FAILED.

SCORING
  Path likelihood = Π p over the best (max-product) route (Dijkstra on −ln p). Risk = likelihood ×
  ACR/10. Likelihoods RANK routes; they are not breach probabilities. Fix ranking = how much
  crown-jewel exposure (Σ likelihood × ACR) disappears when that one fix is applied, recomputed over
  the whole graph; the bundle picks fixes greedily on the residual exposure.
"""
import heapq
import ipaddress
import math
import re

from core import db

CROWN_ACR = 7
MAX_FIX_CANDIDATES = 60
MAX_ENTRIES = 60          # entry states searched individually (strongest first)
PATHS_PER_TARGET = 5      # diverse routes per crown jewel
SERVICE_PORTS = {"ssh": {"22"}, "smb": {"445", "139"}, "rdp": {"3389"}, "winrm": {"5985", "5986"},
                 "web": {"80", "443", "8080", "8443", "8000", "8888"}}
WIN_SVC_PORTS = {"135", "139", "445", "3389", "5985", "5986"}
DC_PORTS_KRB, DC_PORTS_LDAP = {"88"}, {"389", "636", "3268", "3269"}
BUILTIN = {"root", "administrator", "guest", "krbtgt", "defaultaccount", "wdagutilityaccount",
           "daemon", "bin", "sys", "nobody", "admin", "user", "test", "postgres", "mysql", "oracle",
           "ec2-user", "ubuntu", "centos", "debian", "fedora", "vagrant", "pi", "opc", "azureuser",
           "git", "www-data", "apache", "nginx", "tomcat", "redis", "mongodb", "elasticsearch",
           "jenkins", "nagios", "zabbix", "splunk", "ftp", "operator", "games", "lp", "mail", "news",
           "sshd", "systemd-network", "systemd-resolve", "messagebus", "syslog", "polkitd", "chrony"}

# ---- finding classification ----
_RCE = re.compile(r"remote code execution|execute arbitrary (code|commands|groovy|os commands|shell)|arbitrary code "
                  r"execution|command injection|os command|ognl injection|script console|code injection|\brce\b", re.I)
_CLIENT = re.compile(r"ssh-agent|client[- ]side|opens? a (specially crafted|malicious)|malicious (file|document|"
                     r"web ?page|link|email)|convinc\w* (a|the) user|user interaction|visits? a|"
                     r"\b(adobe (reader|acrobat)|microsoft (office|word|excel|outlook)|google chrome|firefox|"
                     r"thunderbird|safari|flash player|vlc|zoom client|java se|jre|internet explorer|"
                     r"scripting engine|browser)\b", re.I)
# Windows cumulative / monthly rollups list every CVE they fix — never treat one as a single network exploit
_ROLLUP = re.compile(r"^kb\d+|cumulative update|monthly rollup|security only|servicing stack", re.I)
_UNAUTH = re.compile(r"unauthenticated|without authentication|no authentication|uncredentialed|pre-auth|"
                     r"network access to a domain controller", re.I)
_AUTHREQ = re.compile(r"\bauthenticated(,)? (remote )?(attacker|user)|requires? (valid )?(credentials|authentication)|"
                      r"valid (account|credentials)|domain user|low-privileged user", re.I)
_LOCAL = re.compile(r"\blocal (user|attacker|privilege|elevation)|unprivileged local|locally authenticated", re.I)
_PRIVESC = re.compile(r"privilege escalation|elevation of privilege|elevate privileges|gain root|root privileges|"
                      r"system privileges|escalate privileges", re.I)
_WEBAPP = re.compile(r"wordpress|drupal|joomla|plugin for|\bcms\b|subscriber|application administrator", re.I)
_CREDDUMP = re.compile(r"password hashes|dump (credentials|hashes)|\bsam database|lsass|cleartext password", re.I)
_DEFCRED = re.compile(r"default (password|credentials|account|login)|blank password|'sa' account|empty password|"
                      r"no password|known credentials", re.I)
_DEFCRED_ADMIN = re.compile(r"administrat|'sa'|\broot\b|admin account|full (administrative )?(access|privileges)|"
                            r"execute commands", re.I)
_UNAUTH_SVC = re.compile(r"(redis|mongodb|elasticsearch|memcached|couchdb|docker|kubernetes|kubelet|etcd|vnc|x11|"
                         r"rsync|nfs|jupyter|ray dashboard|jenkins)\b.*(unauthenticated|no authentication|"
                         r"without authentication|open access|not password protected|unprotected|anonymous)|"
                         r"(unauthenticated|anonymous) (access|login|bind) (to|on)|writable (share|nfs export)", re.I)
_UNAUTH_SVC_ADMIN = re.compile(r"docker|kubernetes|kubelet|etcd|x11|vnc", re.I)
_DC_NAME = re.compile(r"zerologon|netlogon elevation|samaccountname spoofing|\bnopac\b|ms14-068|"
                      r"kerberos checksum|certifried|domain controller", re.I)
_DC_UNAUTH = re.compile(r"zerologon|netlogon elevation", re.I)
_AD_WEAK = re.compile(r"kerberoast|as-rep|asrep|unconstrained delegation|resource-based constrained|"
                      r"\bad cs\b|adcs|\besc[1-8]\b|vulnerable certificate template", re.I)
_RELAY = re.compile(r"smb signing not required|signing is not required on the remote smb", re.I)
_SYSTEM = re.compile(r"\b(with|as) (system|root) privileges\b|\bas root\b|\bsystem-level\b|"
                     r"\bnt authority\\system\b|full administrative", re.I)
_UNCRED = re.compile(r"no credentials provided|credentialed checks : no|authentication failure|"
                     r"credential status.*fail|insufficient privilege", re.I)

# ---- compliance enablers (FAILED checks only), matched on check_name.
#      effect "step" = builds / strengthens graph steps; "context" = shown, but no step relies on it
ENABLERS = [
    ("smb_sign", r"(network server|smb server|lanmanserver).{0,40}digitally sign|requiresecuritysignature|"
                 r"smb server signing", "SMB server signing not required", "lateral",
     "NTLM authentication can be relayed to this host's SMB service", "step"),
    ("llmnr", r"multicast name resolution|\bllmnr\b|netbios over tcp|nbt-?ns|netbios node type",
     "LLMNR / NetBIOS name resolution enabled", "capture",
     "credentials can be captured by name poisoning on the segment", "step"),
    ("wdigest", r"wdigest", "WDigest enabled", "harvest", "cleartext passwords kept in memory", "step"),
    ("lsa", r"\blsass\b|lsa protection|run as a protected process|credential guard", "LSASS not protected",
     "harvest", "credential dumping from memory is easier", "step"),
    ("laps", r"\blaps\b|admpwd|local administrator password solution", "LAPS not deployed", "harvest",
     "local Administrator password likely identical across hosts", "step"),
    ("emptyacct", r"password fields are not empty|accounts? (have|with) (an )?(empty|blank) password|"
                  r"no accounts? (have|with) (empty|blank) password", "Accounts with empty passwords", "entry",
     "an account on this host has no password", "step"),
    ("sudo", r"password for privilege escalation|\bnopasswd\b|!authenticate|sudo.{0,40}(require|authenticat)",
     "Privilege escalation without password", "privesc", "sudo / escalation does not ask for a password", "step"),
    ("uac", r"user account control|alwaysinstallelevated", "UAC / installer elevation weak", "privesc",
     "local elevation to admin is easier", "step"),
    ("firewall", r"firewall.{0,30}(state|enabled|is active|default (deny|zone)|inbound connections)|"
                 r"firewall rules exist|firewall (is )?installed",
     "Host firewall off / incomplete", "reach", "services reachable from other segments", "step"),
    ("nla", r"network level authentication", "RDP without NLA", "login", "RDP exposes the login screen pre-auth", "step"),
    ("permitempty", r"permitemptypasswords", "SSH allows empty passwords", "login",
     "SSH would accept an account with an empty password", "context"),
    ("rootlogin", r"permitrootlogin|root login", "SSH root login allowed", "login", "root can log in over SSH", "context"),
    ("smbv1", r"smbv1|smb v1|smb 1\.0", "SMBv1 enabled", "lateral", "legacy SMB exposes known remote exploits", "context"),
    ("audit", r"\baudit (policy|logon|credential|account|process)|auditd|audit logs?|logging is configured",
     "Audit logging gaps", "evasion", "activity on these paths may not be logged", "context"),
    ("av", r"antivirus|windows defender|endpoint protection|real-?time protection", "Antivirus missing / off",
     "evasion", "malware is less likely to be blocked", "context"),
]
_ENABLER_RX = [(k, re.compile(rx, re.I), lbl, kind, why, eff) for k, rx, lbl, kind, why, eff in ENABLERS]
_ENABLER_NOT = re.compile(r"network client|nonamereleaseondemand|firewall.{0,30}log|\bsudo is installed", re.I)

TECH = {"exploit": "T1210", "defcred": "T1078.001", "unauth": "T1190", "authrce": "T1210", "privesc": "T1068",
        "harvest": "T1003", "login": "T1021", "capture": "T1557.001", "relay": "T1557.001", "dc": "T1210",
        "owned": "T1078.002", "kerb": "T1558", "da": "T1078.002", "domuser": "T1078.002", "seg": ""}
TECH_NAME = {"T1190": "Exploit Public-Facing Application", "T1210": "Exploitation of Remote Services",
             "T1078.001": "Default Accounts", "T1068": "Exploitation for Privilege Escalation",
             "T1003": "OS Credential Dumping", "T1021": "Remote Services",
             "T1557.001": "LLMNR/NBT-NS Poisoning and SMB Relay", "T1078.002": "Domain Accounts",
             "T1558": "Steal or Forge Kerberos Tickets"}


def _q(sql, params=(), path=None):
    try:
        return db.query(sql, params, path=path)
    except Exception:
        return []


def _cols(table, path=None):
    return {r["name"] for r in _q(f'PRAGMA table_info("{table}");', path=path)}


def _sev(v):
    s = str(v or "").strip().lower()
    return {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info"}.get(s, s)


def _segment(ip, network=""):
    """Network segment key: IPv4 /24, IPv6 /64, prefixed by navi's network name when it isn't Default."""
    s = str(ip or "").strip()
    net = (network or "").strip()
    pre = (net + " · ") if net and net.lower() != "default" else ""
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return ""
    if a.version == 6 and a.ipv4_mapped:
        a, s = a.ipv4_mapped, str(a.ipv4_mapped)
    if a.version == 4:
        return pre + ".".join(s.split(".")[:3]) + ".0/24"
    return pre + str(ipaddress.ip_network(s + "/64", strict=False))


def _public(ip):
    try:
        a = ipaddress.ip_address(str(ip or "").strip())
        return a.is_global
    except ValueError:
        return False


def _windows(os_, ports):
    s = (os_ or "").lower()
    if "windows" in s:
        return True
    if s:
        return False
    return bool(ports & (SERVICE_PORTS["smb"] | SERVICE_PORTS["rdp"]))


def classify(name, desc, family=""):
    """Static per-plugin capabilities (port/severity checks are applied per finding)."""
    t = (name or "") + " " + (desc or "")
    rce = bool(_RCE.search(t)) and not _CLIENT.search(t) and not _ROLLUP.search((name or "").strip())
    return {"rce": rce, "unauth": bool(_UNAUTH.search(t)), "authreq": bool(_AUTHREQ.search(t)) and not _UNAUTH.search(t),
            "local": bool(_LOCAL.search(t)), "privesc": bool(_PRIVESC.search(t)),
            "webapp": bool(_WEBAPP.search(t)) or (family or "").lower().startswith("cgi"),
            "creddump": bool(_CREDDUMP.search(t)), "defcred": bool(_DEFCRED.search(t)),
            "defcred_admin": bool(_DEFCRED_ADMIN.search(t)),
            "unauth_svc": bool(_UNAUTH_SVC.search(t)), "unauth_svc_admin": bool(_UNAUTH_SVC_ADMIN.search(name or "")),
            "dc": bool(_DC_NAME.search(name or "")), "dc_unauth": bool(_DC_UNAUTH.search(name or "")),
            "ad_weak": bool(_AD_WEAK.search(name or "")), "relay": bool(_RELAY.search(t)),
            "system": bool(_SYSTEM.search(t))}


def _likelihood(f):
    """Base likelihood that a finding is usable, from exploit intelligence."""
    if f["kev"]:
        return 0.9
    if f["epss"] >= 0.5 or f["vpr"] >= 9:
        return 0.8
    if f["sev"] == "critical":
        return 0.65
    if f["sev"] == "high":
        return 0.5
    return 0.35


# =========================================================================== load
def _load(path=None, crown_acr=CROWN_ACR):
    acols = _cols("assets", path)
    sel = [c if c in acols else f"NULL AS {c}" for c in ("uuid", "hostname", "ip_address", "acr")] + \
        [c for c in ("operating_system", "fqdn", "url", "network") if c in acols]
    assets = {}
    for a in _q("SELECT " + ",".join(sel) + " FROM assets", path=path):
        u = a.get("uuid")
        if not u:
            continue
        try:
            acr = float(str(a.get("acr") or "").strip() or 0)
        except ValueError:
            acr = 0.0
        ip = a.get("ip_address") or ""
        assets[u] = {"uuid": u, "host": (a.get("hostname") or a.get("fqdn") or ip or "").strip() or u[:8],
                     "ip": ip, "os": a.get("operating_system") or "", "acr": acr, "url": a.get("url") or "",
                     "subnet": _segment(ip, a.get("network")), "public": _public(ip), "ports": set(),
                     "findings": [], "controls": {}, "accounts": set(), "dc": False, "sshpw": False}

    vcols = _cols("vulns", path)
    pcols = _cols("plugins", path)
    state_sql = " AND COALESCE(lower(state),'open') <> 'fixed'" if "state" in vcols else ""
    # ports: every row that carries one (service detections are Info, so this is separate)
    if "port" in vcols:
        for r in _q("SELECT DISTINCT asset_uuid, port FROM vulns WHERE port IS NOT NULL AND port NOT IN ('', '0')"
                    + state_sql, path=path):
            a = assets.get(r.get("asset_uuid"))
            if a:
                a["ports"].add(str(r.get("port")).strip())
    for r in _q("SELECT DISTINCT asset_uuid FROM vulns WHERE plugin_id='149334'" + state_sql, path=path):
        a = assets.get(r.get("asset_uuid"))
        if a:
            a["sshpw"] = True

    # plugin metadata once
    desc, fam = {}, {}
    if "description" in pcols:
        for r in _q("SELECT plugin_id, description" + (", plugin_family" if "plugin_family" in pcols else "")
                    + " FROM plugins", path=path):
            desc[str(r.get("plugin_id"))] = r.get("description") or ""
            fam[str(r.get("plugin_id"))] = r.get("plugin_family") or ""
    epss = {}
    for r in _q("SELECT cve, epss_value FROM epss", path=path):
        try:
            epss[str(r["cve"]).upper()] = float(r.get("epss_value") or 0)
        except (TypeError, ValueError):
            pass

    # findings: medium+ only, plus the low/info plugins that matter (relay, default creds, open services)
    sev_in = "('critical','high','medium','4','3','2')"
    extra = ("lower(plugin_name) LIKE '%signing%' OR lower(plugin_name) LIKE '%default%' OR "
             "lower(plugin_name) LIKE '%unauthenticated%' OR lower(plugin_name) LIKE '%anonymous%' OR "
             "lower(plugin_name) LIKE '%domain controller%' OR lower(plugin_name) LIKE '%kerberoast%' OR "
             "lower(plugin_name) LIKE '%as-rep%' OR lower(plugin_name) LIKE '%delegation%'")
    opt = lambda c: c if c in vcols else f"NULL AS {c}"
    has_port = "port" in vcols
    sql = ("SELECT asset_uuid, plugin_id, plugin_name, " + ", ".join(opt(c) for c in ("severity", "cves", "xrefs"))
           + (", port" if "port" in vcols else "") + (", plugin_family" if "plugin_family" in vcols else "")
           + (", score" if "score" in vcols else "")
           + " FROM vulns WHERE (" + (f"lower(COALESCE(severity,'')) IN {sev_in} OR " if "severity" in vcols else "1=1 OR ")
           + f"{extra})" + state_sql)
    cls_cache = {}
    for r in _q(sql, path=path):
        a = assets.get(r.get("asset_uuid"))
        if not a:
            continue
        pid = str(r.get("plugin_id") or "")
        name = r.get("plugin_name") or ""
        key = pid or name
        if key not in cls_cache:
            cls_cache[key] = classify(name, desc.get(pid, ""), fam.get(pid) or r.get("plugin_family") or "")
        c = cls_cache[key]
        if has_port:
            port = str(r.get("port") or "").strip()
            port = "" if port == "0" else port
        else:
            port = "?"          # navi.db has no port column: network reachability unknown, assumed
        cves = [x.upper() for x in re.findall(r"CVE-\d{4}-\d{3,}", r.get("cves") or "", re.I)]
        try:
            vpr = float(r.get("score") or 0)
        except (TypeError, ValueError):
            vpr = 0.0
        f = {"pid": pid, "name": name, "sev": _sev(r.get("severity")), "port": port, "cves": cves,
             "kev": "CISA-KNOWN-EXPLOITED" in (r.get("xrefs") or "").upper(),
             "epss": max([epss.get(x, 0) for x in cves] or [0]), "vpr": vpr, "c": c}
        if c["dc"] or "domain controller" in name.lower():
            a["dc"] = True
        if not any(c[k] for k in ("rce", "privesc", "creddump", "defcred", "unauth_svc", "dc", "ad_weak", "relay")):
            continue
        a["findings"].append(f)

    # compliance — FAILED controls become enablers (or context)
    if "check_name" in _cols("compliance", path):
        for r in _q("SELECT asset_uuid, check_name, audit_file FROM compliance WHERE upper(status)='FAILED'", path=path):
            a = assets.get(r.get("asset_uuid"))
            if not a:
                continue
            nm = r.get("check_name") or ""
            if _ENABLER_NOT.search(nm):
                continue
            for k, rx, lbl, kind, why, eff in _ENABLER_RX:
                if rx.search(nm):
                    a["controls"].setdefault(k, {"key": k, "label": lbl, "kind": kind, "why": why, "effect": eff,
                                                 "check": nm, "audit": r.get("audit_file") or ""})
                    break
    for a in assets.values():
        a["win"] = _windows(a["os"], a["ports"])
        if a["ports"] & DC_PORTS_KRB and a["ports"] & DC_PORTS_LDAP:
            a["dc"] = True
    return assets, desc


def _accounts(assets, path=None):
    """Accounts that MAY act as shared credentials. Same name ≠ same password, so custom accounts
    on several hosts are 'possible reuse' (low likelihood); local Administrator counts only where
    the LAPS control FAILED; well-known built-in / distro / service names never count."""
    try:
        from core import identity
        acc = identity.scan(db_path=path).get("accounts") or []
    except Exception:
        acc = []
    shared = {}
    for x in acc:
        if x.get("klass") == "machine":
            continue
        name = (x.get("user") or "").strip()
        ln = name.lower().split("\\")[-1]
        uu = [u for u in (x.get("asset_uuids") or []) if u in assets]
        shell = (x.get("shell") or "").lower()
        if "nologin" in shell or shell.endswith("false"):
            continue
        for u in uu:
            assets[u]["accounts"].add(name)
        # local Administrator first: a scan credential that works everywhere confirms reuse, it doesn't rule it out
        if ln != "administrator" and x.get("scan_credential"):
            continue
        if ln == "administrator":
            uu = [u for u in uu if "laps" in assets[u]["controls"] and assets[u]["win"]]
            if len(uu) >= 2:
                shared["Local Administrator (no LAPS)"] = {"name": "Administrator", "uuids": set(uu), "admin": True,
                                                         "builtin": True}
            continue
        if ln in BUILTIN or ln.startswith(("systemd-", "_")) or len(uu) < 2:
            continue
        shared[name] = {"name": name, "uuids": set(uu), "admin": False, "builtin": False, "verified": False}
    return shared


# =========================================================================== graph
class _G:
    def __init__(self):
        self.edges = []
        self.out = {}

    def add(self, frm, to, kind, p, label, evidence, fixes, tech=None):
        p = 1.0 if kind in ("same", "seg") else max(0.01, min(0.99, p))
        e = {"id": len(self.edges), "frm": frm, "to": to, "kind": kind, "p": round(p, 3),
             "label": label, "evidence": evidence, "fixes": sorted(set(fixes)), "tech": tech or TECH.get(kind, "")}
        self.edges.append(e)
        self.out.setdefault(frm, []).append(e)
        return e


def _node_asset(u, lvl):
    return f"{u}:{lvl}"


def _fev(f):
    return {"type": "finding", "pid": f["pid"], "name": f["name"], "sev": f["sev"], "kev": f["kev"],
            "epss": f["epss"], "port": f["port"], "cves": f["cves"][:4]}


def _cev(c):
    return {"type": "control", "key": c["key"], "label": c["label"], "check": c["check"], "audit": c["audit"]}


def build_graph(assets, shared, crown=frozenset()):
    G = _G()
    noport = {"type": "note", "text": "No open ports recorded for this host in navi.db — service reachability assumed."}
    for u, a in assets.items():
        U, AD = _node_asset(u, "user"), _node_asset(u, "admin")
        G.add(AD, U, "same", 1.0, "admin includes user", [], [])
        if a["subnet"]:
            G.add(U, "seg:" + a["subnet"], "seg", 1.0, "On segment " + a["subnet"], [], [])
        for f in a["findings"]:
            c = f["c"]
            fix = ["plugin:" + f["pid"]]
            ev = [_fev(f)]
            base = _likelihood(f)
            serious = f["kev"] or f["sev"] in ("critical", "high")
            unk = f["port"] == "?"
            if unk:
                ev = ev + [{"type": "note", "text": "navi.db has no port data — network reachability assumed."}]
            netp = 0.8 if unk else 1.0
            # domain-controller takeover (name-matched; lands on the DC host first)
            if c["dc"] and a["dc"]:
                if c["dc_unauth"] and not c["authreq"]:
                    G.add("ATTACKER", AD, "dc", base, f["name"], ev, fix)
                else:
                    G.add("domuser", AD, "dc", base * 0.85, f["name"] + " (needs a domain account)", ev, fix)
                continue
            if c["ad_weak"]:
                G.add("domuser", "domain", "kerb", 0.4, f["name"] + " (offline cracking / abuse of a privileged account)",
                      ev, fix)
                continue
            # network exploit: execution wording + found on a port + serious + not client-side
            if c["rce"] and f["port"] and serious and not (c["local"] and not c["unauth"] and not c["authreq"]):
                lvl = "admin" if c["system"] or (a["win"] and f["port"] in WIN_SVC_PORTS) else "user"
                if c["authreq"]:
                    if a["subnet"]:
                        G.add("seg:" + a["subnet"], _node_asset(u, lvl), "authrce", base * 0.7 * netp,
                              f["name"] + " (needs a valid account, same segment)", ev, fix)
                else:
                    G.add("ATTACKER", _node_asset(u, lvl), "exploit", base * netp, f["name"], ev, fix,
                          tech="T1190" if (a["public"] or f["port"] in SERVICE_PORTS["web"]) else "T1210")
            # local privilege escalation: local wording or a local (port 0) check, not a web-app role change
            if c["privesc"] and (c["local"] or not f["port"]) and not c["webapp"]:
                G.add(U, AD, "privesc", min(0.95, base + 0.1), f["name"], ev, fix)
            if c["creddump"] and (c["local"] or not f["port"]):
                G.add(U, AD, "privesc", base, f["name"] + " (reads password hashes)", ev, fix)
            if c["defcred"] and f["port"]:
                adm = c["defcred_admin"]
                G.add("ATTACKER", _node_asset(u, "admin" if adm else "user"), "defcred", (0.8 if adm else 0.55) * netp,
                      f["name"], ev, fix)
            if c["unauth_svc"] and f["port"] and not c["defcred"]:
                adm = c["unauth_svc_admin"]
                G.add("ATTACKER", _node_asset(u, "admin" if adm else "user"), "unauth", (0.7 if adm else 0.5) * netp,
                      f["name"], ev, fix)
        # compliance-only steps
        for k in ("sudo", "uac"):
            ctl = a["controls"].get(k)
            if ctl:
                G.add(U, AD, "privesc", 0.45, ctl["label"], [_cev(ctl)], ["check:" + k])
        ctl = a["controls"].get("emptyacct")
        if ctl and (a["sshpw"] or a["ports"] & (SERVICE_PORTS["ssh"] | SERVICE_PORTS["rdp"])):
            G.add("ATTACKER", U, "defcred", 0.5, ctl["label"], [_cev(ctl)], ["check:emptyacct"])
        if "llmnr" in a["controls"] and a["win"] and a["subnet"]:
            G.add(U, "relay:" + a["subnet"], "capture", 0.8, "Capture hashes by LLMNR / NBT-NS poisoning",
                  [_cev(a["controls"]["llmnr"])], ["check:llmnr"])

    # relay targets: SMB server signing not required (finding or failed SERVER control)
    relay_hubs = {e["to"] for e in G.edges if e["kind"] == "capture"}
    for u, a in assets.items():
        if not a["win"]:
            continue
        sig_f = [f for f in a["findings"] if f["c"]["relay"]]
        sig_c = a["controls"].get("smb_sign")
        if not (sig_f or sig_c):
            continue
        if a["ports"] and not (a["ports"] & SERVICE_PORTS["smb"]):
            continue
        ev, fixes = [], []
        if sig_f:
            ev.append(_fev(sig_f[0]))
            fixes.append("plugin:" + sig_f[0]["pid"])
        if sig_c:
            ev.append(_cev(sig_c))
            fixes.append("check:smb_sign")
        if not a["ports"]:
            ev.append(noport)
        same_hub = "relay:" + a["subnet"]
        if same_hub in relay_hubs:
            G.add(same_hub, _node_asset(u, "admin"), "relay", 0.4 * (1 if a["ports"] else 0.7),
                  "Relay captured NTLM authentication to SMB", ev, fixes)
        if u in crown or a["dc"]:     # cross-segment relay only toward crown jewels / DCs, via one hub
            p = (0.3 if "firewall" in a["controls"] else 0.2) * (1 if a["ports"] else 0.7)
            G.add("relay:*", _node_asset(u, "admin"), "relay", p,
                  "Relay captured NTLM authentication to SMB (cross-segment, inferred)", ev, fixes)
    if any(e["to"] == "relay:*" or e["frm"] == "relay:*" for e in G.edges):
        for hub in relay_hubs:
            G.add(hub, "relay:*", "seg", 1.0, "Captured hash used from another segment", [], [])

    # shared credentials (possible reuse): harvest from admin footholds, log in elsewhere
    for name, s in shared.items():
        cn = "cred:" + name
        fixes = ["check:laps"] if s["builtin"] else ["cred:" + name]
        for u in s["uuids"]:
            a = assets[u]
            if s["builtin"]:
                p = 0.75 + (0.1 if ("wdigest" in a["controls"] or "lsa" in a["controls"]) else 0)
                lbl = "Harvest local Administrator hash (LAPS not deployed)"
            else:
                p = 0.6 + (0.1 if ("wdigest" in a["controls"] or "lsa" in a["controls"]) else 0)
                lbl = f"Harvest {s['name']} credential (account reuse — password on other hosts not verified)"
            ev = [{"type": "credential", "account": s["name"], "hosts": len(s["uuids"]),
                   "verified": None if s["builtin"] else False}]
            ev += [_cev(a["controls"][k]) for k in ("wdigest", "lsa", "laps") if k in a["controls"]]
            G.add(_node_asset(u, "admin"), cn, "harvest", p, lbl, ev, fixes)
        for u in s["uuids"]:
            a = assets[u]
            svc = (SERVICE_PORTS["smb"] | SERVICE_PORTS["rdp"] | SERVICE_PORTS["winrm"]) if a["win"] else SERVICE_PORTS["ssh"]
            if a["ports"] and not (a["ports"] & svc):
                continue
            lvl = "admin" if s["admin"] else "user"
            if s["builtin"]:
                p = 0.7
            else:
                p = 0.55 if (a["sshpw"] and not a["win"]) else 0.45
            ev = [{"type": "credential", "account": s["name"],
                   "service": ",".join(sorted(a["ports"] & svc)) or "login"}]
            if "nla" in a["controls"]:
                ev.append(_cev(a["controls"]["nla"]))
            if not a["ports"]:
                ev.append(noport)
                p *= 0.7
            G.add(cn, _node_asset(u, lvl), "login", p,
                  f"Log in as {s['name']}" + ("" if s["builtin"] else " (account reuse — only if the password/key is also reused)"), ev, fixes)

    # domain: Windows footholds act as a domain user; owning a DC = domain admin
    has_dom = any(e["kind"] in ("dc", "kerb") for e in G.edges)
    if has_dom:
        for u, a in assets.items():
            if a["win"]:
                G.add(_node_asset(u, "user"), "domuser", "domuser", 0.9, "Use the host's domain account context",
                      [{"type": "note", "text": "A foothold on a domain-joined Windows host can act as a domain user "
                                                "(membership inferred from OS)."}], [])
        for u, a in assets.items():
            if a["dc"]:
                G.add(_node_asset(u, "admin"), "domain", "owned", 0.95, "Domain controller owned → domain admin",
                      [{"type": "note", "text": "Admin on a domain controller controls the domain."}], [])
        if any(e["to"] == "domain" for e in G.edges):
            for u, a in assets.items():
                if a["dc"]:
                    G.add("domain", _node_asset(u, "admin"), "da", 0.95, "Domain admin controls every domain controller",
                          [{"type": "note", "text": "Domain admin has administrative rights on all domain controllers."}], [])
                elif a["win"]:
                    G.add("domain", _node_asset(u, "admin"), "da", 0.85, "Domain admin rights (domain membership inferred)",
                          [{"type": "note", "text": "Assumed domain-joined because it runs Windows — navi.db has no "
                                                    "domain-membership data. Verify before acting."}], [])
    return G


# =========================================================================== search
def _dijkstra(G, banned=frozenset(), start="ATTACKER", d0=0.0, banned_kinds=frozenset()):
    dist, prev = {start: d0}, {}
    pq = [(d0, start)]
    while pq:
        d, n = heapq.heappop(pq)
        if d > dist.get(n, 1e18):
            continue
        for e in G.out.get(n, []):
            if banned and any(f in banned for f in e["fixes"]):
                continue
            if banned_kinds and e["kind"] in banned_kinds:
                continue
            nd = d - math.log(e["p"])
            if nd < dist.get(e["to"], 1e18) - 1e-12:
                dist[e["to"]] = nd
                prev[e["to"]] = e
                heapq.heappush(pq, (nd, e["to"]))
    return dist, prev


def _best(dist, u):
    """Best state reached on asset u: prefer admin when nearly as likely."""
    da, du = dist.get(f"{u}:admin"), dist.get(f"{u}:user")
    if da is None and du is None:
        return None
    if da is not None and (du is None or da <= du + 0.2):
        return f"{u}:admin", da
    return f"{u}:user", du


def _reach_d(dist, u):
    """Distance of the MOST LIKELY state on asset u (for exposure math), or None."""
    v = [d for d in (dist.get(f"{u}:admin"), dist.get(f"{u}:user")) if d is not None]
    return min(v) if v else None


def _path(prev, node, stop=None):
    out = []
    while node in prev and node != stop:
        e = prev[node]
        if e["kind"] not in ("same", "seg"):
            out.append(e)
        node = e["frm"]
    return list(reversed(out))


# =========================================================================== analyze
def analyze(db_path=None, crown_acr=CROWN_ACR, max_paths=200):
    assets, _ = _load(db_path, crown_acr)
    shared = _accounts(assets, db_path)
    crown = [u for u, a in assets.items() if a["acr"] >= crown_acr]
    fallback = False
    if not crown:   # uncalibrated ACR: fall back to the most exposed servers
        fallback = True
        crown = [u for u, a in assets.items() if a["dc"]] or \
            [u for u, a in assets.items() if any(f["kev"] for f in a["findings"]) and a["ports"] & WIN_SVC_PORTS
             and len(a["findings"]) >= 3]
    G = build_graph(assets, shared, frozenset(crown))
    dist, prev = _dijkstra(G)
    # search budget scales with graph size so big estates stay responsive
    E = max(1, len(G.edges))
    n_entries = max(8, min(MAX_ENTRIES, int(3_000_000 / E)))
    n_fix = max(10, min(MAX_FIX_CANDIDATES, int(1_500_000 / E)))

    def host(n):
        if n in ("ATTACKER", "domain", "domuser") or n.startswith(("cred:", "relay:", "seg:")):
            return None
        return assets.get(n.split(":")[0])

    def step(e):
        fa, ta = host(e["frm"]), host(e["to"])
        return {"kind": e["kind"], "frm": e["frm"], "to": e["to"], "p": e["p"], "label": e["label"],
                "tech": e["tech"], "tech_name": TECH_NAME.get(e["tech"], ""), "evidence": e["evidence"],
                "fixes": e["fixes"], "from_host": fa["host"] if fa else _label(e["frm"]),
                "to_host": ta["host"] if ta else _label(e["to"])}

    # ---- per-entry search: the best chain from EACH way in, so redundant routes show ----
    entry_edges = [e for e in G.edges if e["frm"] == "ATTACKER"]
    best_in = {}
    for e in entry_edges:                       # strongest edge per entry state
        if e["to"] not in best_in or e["p"] > best_in[e["to"]]["p"]:
            best_in[e["to"]] = e
    ent_states = sorted(best_in.values(), key=lambda e: -e["p"])[:n_entries]
    crown_set = set(crown)
    cand = {u: [] for u in crown}               # target -> [(likelihood, node, steps, entry_host)]
    blast = {}
    # also look for routes that avoid the domain, and ones that avoid domain + shared credentials
    variants = [frozenset(), frozenset({"dc", "da", "owned", "kerb"}),
                frozenset({"dc", "da", "owned", "kerb", "harvest", "login"})]
    for e, bk in ((e, bk) for e in ent_states for bk in variants):
        if bk and e["to"] == "domain":
            continue
        d2, p2 = _dijkstra(G, start=e["to"], d0=-math.log(e["p"]), banned_kinds=bk)
        eh = host(e["to"])
        ekey = eh["uuid"] if eh else e["to"]
        for u in crown:
            b = _best(d2, u)
            if not b:
                continue
            node, d = b
            chain = [e] + _path(p2, node, stop=e["to"])
            blast.setdefault(ekey, set()).add(u)
            cand[u].append((math.exp(-d), node, chain, ekey))
    def _mk(u, like, node, chain):
        a = assets[u]
        steps, last = [], "ATTACKER"
        for x in chain:
            if x["kind"] in ("same", "seg"):
                continue
            st = step(x)
            if st["frm"].startswith("seg:") or st["frm"] == "relay:*":
                st["via"] = _label(st["frm"])
                st["frm"] = last
                h0 = host(last)
                st["from_host"] = h0["host"] if h0 else _label(last)
            steps.append(st)
            last = st["to"]
        kinds = {x["kind"] for x in steps}
        return {
            "target": _pub(a), "level": node.split(":")[1], "likelihood": round(like, 3),
            "risk": round(100 * like * max(a["acr"], 1) / 10), "hops": len(steps),
            "entry": _pub(host(chain[0]["to"])) if host(chain[0]["to"]) else {"host": _label(chain[0]["to"])},
            "steps": steps, "primary": False,
            "direct": len(steps) == 1 or (len(steps) == 2 and steps[1]["kind"] == "privesc"),
            "uses": {"kev": any(ev.get("kev") for x in steps for ev in x["evidence"]),
                     "cred": bool(kinds & {"harvest", "login"}), "relay": "relay" in kinds,
                     "domain": bool(kinds & {"da", "dc", "owned", "kerb"}), "privesc": "privesc" in kinds,
                     "defcred": bool(kinds & {"defcred", "unauth"}),
                     "control": any(ev.get("type") == "control" for x in steps for ev in x["evidence"])}}

    # per target, pick a DIVERSE set: best overall, then the best route that avoids the domain,
    # uses a shared credential, uses NTLM relay, uses a failed control — then the next most likely
    picks_by = [lambda p: True, lambda p: not p["uses"]["domain"], lambda p: p["uses"]["cred"],
                lambda p: p["uses"]["relay"], lambda p: p["uses"]["control"]]
    paths = []
    for u in crown:
        b = _best(dist, u)
        if b:   # the global best route always leads, even if its entry wasn't searched individually
            chain = _path(prev, b[0])
            if chain:
                eh = host(chain[0]["to"])
                cand[u].append((math.exp(-b[1]), b[0], chain, eh["uuid"] if eh else chain[0]["to"]))
        cs = sorted(cand[u], key=lambda c: (-c[0], len(c[2])))
        built = [(c[3], _mk(u, c[0], c[1], c[2])) for c in cs]
        chosen, sigs = [], set()

        def take(ek, p):
            sig = (ek, tuple(x["kind"] for x in p["steps"]), tuple(x["to"] for x in p["steps"]))
            if sig in sigs:
                return False
            sigs.add(sig)
            chosen.append(p)
            return True
        for want in picks_by:
            for ek, p in built:
                if want(p) and take(ek, p):
                    break
            if len(chosen) >= PATHS_PER_TARGET:
                break
        used_entries = {p["entry"].get("uuid") for p in chosen}
        for ek, p in built:
            if len(chosen) >= PATHS_PER_TARGET:
                break
            if p["entry"].get("uuid") not in used_entries:
                if take(ek, p):
                    used_entries.add(p["entry"].get("uuid"))
        if chosen:
            chosen.sort(key=lambda p: -p["likelihood"])
            chosen[0]["primary"] = True
            paths.extend(chosen)
    reach = {p["target"]["uuid"] for p in paths}
    primaries = [p for p in paths if p["primary"]]
    paths_total = len(paths)
    uses_all = {k: sum(1 for p in paths if p["uses"][k]) for k in ("kev", "cred", "relay", "privesc", "control", "domain", "defcred")}
    uses_best = {k: sum(1 for p in paths if p["primary"] and p["uses"][k]) for k in uses_all}
    chains_all = sum(1 for p in paths if p["hops"] >= 3)
    # display set: every crown jewel's best route first, then alternatives, capped
    paths.sort(key=lambda p: (not p["primary"], -p["risk"], p["hops"]))
    paths = paths[:max(max_paths, 1)]
    paths.sort(key=lambda p: (-p["risk"], p["hops"]))
    for i, p in enumerate(paths):
        p["id"] = i

    # ---- entries and their blast radius ----
    rev = {}
    for e in G.edges:
        rev.setdefault(e["to"], []).append(e["frm"])
    can_reach, stack = set(), [f"{u}:{l}" for u in reach for l in ("user", "admin")]
    while stack:
        n = stack.pop()
        if n in can_reach:
            continue
        can_reach.add(n)
        stack.extend(rev.get(n, []))
    searched = {(host(e["to"]) or {}).get("uuid", e["to"]) for e in ent_states}
    entries = {}
    for e in entry_edges:
        h = host(e["to"])
        if not h:
            continue
        x = entries.setdefault(h["uuid"], {**_pub(h), "how": [], "kev": False, "p": 0})
        x["how"].append(e["label"])
        x["kev"] = x["kev"] or any(ev.get("kev") for ev in e["evidence"])
        x["p"] = max(x["p"], e["p"])
    for e in entry_edges:
        h = host(e["to"])
        if h and e["to"] in can_reach:
            entries[h["uuid"]]["reaches_any"] = True
    ent_list = sorted(({**v, "how": sorted(set(v["how"]))[:4], "crown_reached": len(blast.get(k, ())),
                        "reaches_any": bool(v.get("reaches_any")), "searched": k in searched,
                        "crown_hosts": sorted(assets[t]["host"] for t in blast.get(k, ()))[:12]}
                       for k, v in entries.items()),
                      key=lambda v: (-v["crown_reached"], -int(v["reaches_any"]), -v["p"]))

    # ---- choke points: which fix breaks the most mapped paths ----
    path_fixes = [set(f for x in p["steps"] for f in x["fixes"]) for p in paths]
    on_path = {}
    for i, fs in enumerate(path_fixes):
        for f in fs:
            on_path.setdefault(f, set()).add(i)
    def _exp_of(d2):
        tot, alive = 0.0, 0
        for u in reach:
            d = _reach_d(d2, u)
            if d is not None:
                alive += 1
                tot += math.exp(-d) * max(assets[u]["acr"], 1) / 10
        return tot, alive
    base_total, _ = _exp_of(dist)
    # candidates: every fix on a mapped path, plus every fix on each crown jewel's current best route
    best_fixes = set()
    for u in reach:
        b = _best(dist, u)
        if b:
            for e in _path(prev, b[0]):
                best_fixes.update(e["fixes"])
    cands = list(dict.fromkeys(sorted(best_fixes, key=lambda f: (-len(on_path.get(f, ())), f))
                               + sorted(on_path, key=lambda f: (-len(on_path[f]), f))))[:n_fix]
    def _fix_entry(f):
        d2, _ = _dijkstra(G, banned=frozenset([f]))
        ex, alive = _exp_of(d2)
        tg = {paths[i]["target"]["uuid"] for i in on_path.get(f, ())}
        return {"fix": f, **_fix_label(f, G, assets, shared), "paths": len(on_path.get(f, ())),
                "path_ids": sorted(on_path.get(f, ())), "targets": len(tg), "cuts": len(reach) - alive,
                "exposure_cut_pct": max(0.0, round(100 * (base_total - ex) / base_total, 1)) if base_total else 0}
    fixes = [_fix_entry(f) for f in cands]
    fixes.sort(key=lambda x: (-x["exposure_cut_pct"], -x["cuts"], -x["paths"], x["fix"]))
    # ---- remediation bundle: greedy on REAL residual exposure (whole graph, not just mapped paths) ----
    def exposure(banned):
        d2, p2 = _dijkstra(G, banned=frozenset(banned))
        tot, alive = _exp_of(d2)
        return tot, alive, d2, p2
    base_exp, _, d0, p0 = exposure(set())
    bundle, banned = [], set()
    fixmeta = {fx["fix"]: fx for fx in fixes}
    for _ in range(6):
        if not base_exp:
            break
        cur = set()
        for u in sorted(reach):               # fixes on the CURRENT best route to each crown jewel
            b = _best(d0, u)
            if b:
                for e in _path(p0, b[0]):
                    cur.update(e["fixes"])
        cur -= banned
        if not cur:
            break
        best = None
        single = {fx["fix"]: fx["exposure_cut_pct"] for fx in fixes}
        for fx in sorted(cur, key=lambda f: (-single.get(f, 0), f))[:max(6, n_fix // 2)]:
            ex, alive, d2, p2 = exposure(banned | {fx})
            if best is None or ex < best[1] - 1e-9:
                best = (fx, ex, alive, d2, p2)
        prev_exp = exposure(banned)[0]
        if best is None or best[1] >= prev_exp - 1e-9:
            break
        banned.add(best[0])
        d0, p0 = best[3], best[4]
        meta = fixmeta.get(best[0])
        if meta is None:      # picked on the residual graph but not a first-pass candidate: add it to the list too
            meta = _fix_entry(best[0])
            fixmeta[best[0]] = meta
            fixes.append(meta)
        bundle.append({**meta, "exposure_left_pct": round(100 * best[1] / base_exp, 1), "still_reachable": best[2]})
    fixes.sort(key=lambda x: (-x["exposure_cut_pct"], -x["cuts"], -x["paths"], x["fix"]))

    # ---- compliance controls as attack enablers ----
    ctl = {}
    for k, _, lbl, kind, why, eff in ENABLERS:
        uu = [u for u, a in assets.items() if k in a["controls"]]
        if not uu:
            continue
        on = set(on_path.get("check:" + k, set())) | {
            i for i, p in enumerate(paths) for st in p["steps"] for ev in st["evidence"] if ev.get("key") == k}
        ex = assets[uu[0]]["controls"][k]
        ctl[k] = {"key": k, "label": lbl, "kind": kind, "why": why, "effect": eff, "assets": len(uu), "uuids": uu,
                  "check": ex["check"], "audit": ex["audit"], "paths": len(on),
                  "crown_on": sum(1 for u in uu if u in reach)}
    controls = sorted(ctl.values(), key=lambda c: (c["effect"] != "step", -c["paths"], -c["assets"]))

    # ---- map: union of the shown paths ----
    graph = _map(paths, assets, G, cap=len(paths))

    # ---- metrics ----
    n_crown = len(crown)
    dom = dist.get("domain")
    hops = sorted(p["hops"] for p in primaries)
    comp_paths = sum(1 for p in primaries if p["uses"]["control"])
    m = {
        "assets": len(assets), "crown": n_crown, "crown_reachable": len(reach),
        "crown_pct": round(100 * len(reach) / n_crown, 1) if n_crown else None,
        "paths": paths_total, "paths_shown": len(paths),
        "direct": sum(1 for p in primaries if p["direct"]),
        "chains": sum(1 for p in primaries if p["hops"] >= 3),
        "entries": len(entries), "entries_to_crown": sum(1 for v in ent_list if v["reaches_any"]),
        "public_entries": sum(1 for v in ent_list if v.get("public")),
        "median_hops": hops[len(hops) // 2] if hops else None, "max_hops": hops[-1] if hops else None,
        "domain_reachable": dom is not None, "domain_likelihood": round(math.exp(-dom), 3) if dom is not None else None,
        "domain_steps": len(_path(prev, "domain")) if dom is not None else None,
        "kev_paths": sum(1 for p in primaries if p["uses"]["kev"]),
        "cred_paths": sum(1 for p in primaries if p["uses"]["cred"]),
        "relay_paths": sum(1 for p in primaries if p["uses"]["relay"]),
        "privesc_paths": sum(1 for p in primaries if p["uses"]["privesc"]),
        "control_paths": comp_paths,
        "shared_creds": len({v["name"] for v in shared.values()}),
        "uses_all": uses_all, "uses_best": uses_best, "chains_all": chains_all,
        "controls_failed_assets": sum(1 for a in assets.values() if a["controls"]),
        "controls_on_paths": sum(1 for c in controls if c["paths"]),
        "top_fix_paths": fixes[0]["paths"] if fixes else 0,
        "top_fix_label": fixes[0]["label"] if fixes else "",
        "top_fix_cut_pct": fixes[0]["exposure_cut_pct"] if fixes else 0,
        "bundle_exposure_cut_pct": round(100 - bundle[-1]["exposure_left_pct"], 1) if bundle else 0,
        "bundle_size": len(bundle),
        "bundle_still_reachable": bundle[-1].get("still_reachable") if bundle else None,
        "avg_likelihood": round(sum(p["likelihood"] for p in primaries) / max(1, len(primaries)), 3) if primaries else None,
        "fallback_targets": fallback, "graph_edges": E,
        "entries_searched": len(ent_states), "entry_states": len(best_in),
    }
    blind = _q("SELECT COUNT(DISTINCT asset_uuid) n FROM vulns WHERE plugin_id IN ('110723','104410','21745','110385')",
               path=db_path)
    m["uncredentialed"] = (blind[0].get("n") if blind else 0) or 0
    m["n_controls_step"] = sum(1 for c in controls if c["effect"] == "step")
    note = ""
    if fallback:
        note = ("No assets have ACR ≥ %d, so targets fall back to domain controllers / the most exposed servers. "
                "Calibrate ACR (Anubis) so paths end at your real crown jewels." % crown_acr)
    return {"ok": True, "paths": paths, "entries": ent_list, "fixes": fixes, "bundle": bundle, "graph": graph,
            "controls": controls,
            "metrics": m, "note": note, "crown_acr": crown_acr,
            "unreached": [_pub(assets[u]) for u in crown if u not in reach][:200],
            "reachable": sorted(reach),
            "edge_kinds": _kind_counts(G)}


def _kind_counts(G):
    out = {}
    for e in G.edges:
        if e["kind"] not in ("same", "seg"):
            out[e["kind"]] = out.get(e["kind"], 0) + 1
    return out


def _label(n):
    if n == "ATTACKER":
        return "Attacker (network position)"
    if n == "domain":
        return "Domain admin"
    if n == "domuser":
        return "Domain user context"
    if n.startswith("cred:"):
        return n[5:]
    if n == "relay:*":
        return "NTLM relay (any segment)"
    if n.startswith("relay:"):
        return "NTLM relay · " + n[6:]
    if n.startswith("seg:"):
        return "Segment " + n[4:]
    return n


def _pub(a):
    if not a:
        return {}
    return {"uuid": a["uuid"], "host": a["host"], "ip": a["ip"], "acr": a["acr"], "os": a["os"],
            "subnet": a["subnet"], "public": a["public"], "dc": a["dc"], "url": a["url"]}


def _fix_label(f, G, assets, shared):
    kind, key = f.split(":", 1)
    if kind == "plugin":
        ex = next((ev for e in G.edges if f in e["fixes"] for ev in e["evidence"] if ev.get("pid") == key), {})
        hosts = {u for u, a in assets.items() if any(x["pid"] == key for x in a["findings"])}
        return {"type": "Patch", "label": ex.get("name") or ("Plugin " + key), "detail": f"plugin {key}",
                "kev": bool(ex.get("kev")), "assets": len({h for h in hosts if h in assets}),
                "uuids": sorted(h for h in hosts if h in assets)}
    if kind == "check":
        lbl = next((e[2] for e in ENABLERS if e[0] == key), key)
        uu = sorted(u for u, a in assets.items() if key in a["controls"])
        ex = next((assets[u]["controls"][key]["check"] for u in uu), "")
        return {"type": "Fix control", "label": lbl, "detail": ex, "kev": False, "assets": len(uu), "uuids": uu}
    if kind == "cred":
        s = shared.get(key, {})
        det = "account on %d hosts — confirm the passwords differ" % len(s.get("uuids", ()))
        return {"type": "Rotate / make unique", "label": key, "detail": det,
                "kev": False, "assets": len(s.get("uuids", ())), "uuids": sorted(s.get("uuids", ()))}
    return {"type": "Fix", "label": f, "detail": "", "kev": False, "assets": 0, "uuids": []}


def _map(paths, assets, G, cap=40):
    """Nodes/edges for the interactive map: union of the top `cap` paths, with each node's
    column = its earliest step index (attacker 0 … crown jewel last)."""
    nodes, edges, col = {}, {}, {}

    def nid(n):
        if ":" in n and not n.startswith(("cred:", "relay:")):
            return n.split(":")[0]
        return n

    for i, p in enumerate(paths[:cap]):
        seq = ["ATTACKER"] + [s["to"] for s in p["steps"]]
        for k, n in enumerate(seq):
            v = nid(n)
            col[v] = min(col.get(v, k), k) if v != nid(p["target"]["uuid"]) else max(col.get(v, k), k)
            if v not in nodes:
                a = assets.get(v)
                kind = ("attacker" if v == "ATTACKER" else "domain" if v in ("domain", "domuser") else
                        "cred" if v.startswith("cred:") else "relay" if v.startswith("relay:") else "asset")
                nodes[v] = {"id": v, "kind": kind, "label": a["host"] if a else _label(v),
                            "acr": a["acr"] if a else None, "ip": a["ip"] if a else "", "os": a["os"] if a else "",
                            "subnet": a["subnet"] if a else "", "dc": a["dc"] if a else False,
                            "public": a["public"] if a else False, "paths": [], "crown": False, "entry": False,
                            "findings": [], "controls": []}
                if a:
                    nodes[v]["findings"] = [{"pid": f["pid"], "name": f["name"], "sev": f["sev"], "kev": f["kev"],
                                             "port": f["port"]} for f in a["findings"]
                                            if f["sev"] in ("critical", "high") or f["kev"] or f["c"]["relay"]][:12]
                    nodes[v]["controls"] = [{"label": c["label"], "check": c["check"], "why": c["why"]}
                                            for c in a["controls"].values()]
            nodes[v]["paths"].append(i)
        nodes[nid(p["target"]["uuid"])]["crown"] = True
        if p["steps"]:
            nodes[nid(p["steps"][0]["to"])]["entry"] = True
        for s in p["steps"]:
            k = (nid(s["frm"]), nid(s["to"]), s["kind"])
            if k[0] == k[1]:
                # in-host step (privesc): show on the node, not as an edge
                nodes[k[0]].setdefault("privesc", []).append(s["label"])
                continue
            e = edges.setdefault(k, {"frm": k[0], "to": k[1], "kind": s["kind"], "label": s["label"], "p": s["p"],
                                     "tech": s["tech"], "paths": []})
            e["paths"].append(i)
    for v, n in nodes.items():
        n["col"] = col.get(v, 0)
        n["paths"] = sorted(set(n["paths"]))
        if n.get("privesc"):
            n["privesc"] = sorted(set(n["privesc"]))
    return {"nodes": list(nodes.values()), "edges": list(edges.values()),
            "cols": max(col.values()) + 1 if col else 0, "shown": min(cap, len(paths))}
