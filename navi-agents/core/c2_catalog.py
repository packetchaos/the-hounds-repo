"""Built-in, READ-ONLY troubleshooting catalog for the Command & Control hound (Amarok).

Every entry is a FIXED POSIX-sh string. The only operator input is an optional parameter
(a path or a package name), validated by a regex / rule and passed through shlex.quote, so
``/tmp/x; rm -rf /`` stays ONE quoted argument. Entries never change the host: no package
installs, no service restarts, no file writes. A few use ``sudo -n`` (non-interactive — it
never prompts, so navi never sends the stored sudo password) and degrade gracefully when
sudo needs a password.

A run packs one or more checks into ONE `navi action push --command` per host (one SSH
login), each check wrapped as

    printf … "C2""_BEGIN=<id>"; ${C2T:+timeout <s>} sh -c '<check>' 2>&1; printf '\\nC2''_END=<id> rc=%s\\n' "$?"

The markers are spelled with split quotes so the shell's echo of the command line can never
be mistaken for real output; ``timeout`` bounds each check on the remote side (124 = timed
out) and is skipped on a host without coreutils' timeout. Bundles longer than ~3000 bytes are
split into several pushes (a remote tty line holds ~4095 bytes).

Public IP (``pubip``) contacts a third party (api.ipify.org, then a fallback) and reveals the
host's egress IP — the owner wants it in the default Quick-health bundle, so it is there and
labelled as such everywhere it shows (page, confirm, this note).
"""
import re
import shlex

DEFAULT_TIMEOUT = 20          # seconds per check on the remote side
MAX_TIMEOUT = 120
MAX_BUNDLE = 3000             # bytes per pushed command line (remote tty line limit ~4095)
PUBIP_NOTE = "contacts api.ipify.org (or a fallback) — reveals the host's egress IP"

# param validators -----------------------------------------------------------------------
_PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_:@-]{0,127}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def check_path(p):
    """(ok, value_or_reason). An absolute path (or ~/…), no control characters, <= 1024 chars.
    Shell characters are allowed — the value is shell-quoted, never interpreted."""
    p = str(p if p is not None else "")
    if not p:
        return False, "path required"
    if len(p) > 1024:
        return False, "path too long (max 1024)"
    if _CTRL.search(p):
        return False, "control characters / newlines are not allowed in a path"
    if not (p.startswith("/") or p.startswith("~/")):
        return False, "use an absolute path (/…) or ~/…"
    return True, p


def check_pkg(n):
    n = str(n if n is not None else "").strip()
    if not _PKG_RE.match(n):
        return False, "package name must match " + _PKG_RE.pattern
    return True, n


def qword(v):
    """Single-quote `v` as ONE shell word that navi cannot misread. navi's build_remote_command
    rewrites the first `\bsudo\b` anywhere in the command line (to inject its sudo prompt) and
    drops every output line containing NAVI_EXIT — so a value like /usr/bin/sudo or the package
    `sudo` is emitted quote-split ('/usr/bin/su''do'): the shell joins it back, navi's regex never
    matches it. Always quoted (never bare), so nothing in it is ever interpreted."""
    s = str(v).replace("sudo", "su\0do").replace("NAVI_", "NAV\0I_")
    return "".join("'" + piece.replace("'", "'\"'\"'") + "'" for piece in s.split("\0"))


def q_path(p):
    """Shell-quote a validated path; ~/x becomes "$HOME"/'x' so the tilde still expands."""
    if p.startswith("~/"):
        return '"$HOME"/' + qword(p[2:]) if p[2:] else '"$HOME"'
    return qword(p)


# the catalog ------------------------------------------------------------------------------
# cmd placeholders: {P} = shell-quoted path, {N} = shell-quoted package name
CATALOG = [
    {"id": "ident", "label": "Identity & sudo rights", "group": "Access", "needs_sudo": False,
     "cmd": "id; whoami; (hostname -f 2>/dev/null || hostname); sudo -n -l 2>&1 | head -40; true"},
    {"id": "cred", "label": "Credential test (login + sudo -n)", "group": "Access", "needs_sudo": False,
     "timeout": 15, "hidden": True,
     "cmd": "id -un; id; if sudo -n true 2>/dev/null; then printf '%s\\n' \"C2\"\"_SUDO=ok\"; "
            "else printf '%s\\n' \"C2\"\"_SUDO=needs_password\"; fi"},
    {"id": "os", "label": "OS & kernel", "group": "System", "needs_sudo": False,
     "cmd": "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null; uname -a"},
    {"id": "uptime", "label": "Uptime & load", "group": "System", "needs_sudo": False,
     "cmd": "uptime; cat /proc/loadavg 2>/dev/null; true"},
    {"id": "reboot", "label": "Last reboot", "group": "System", "needs_sudo": False,
     "cmd": "who -b 2>/dev/null; last -x reboot 2>/dev/null | head -5; uptime -s 2>/dev/null; true"},
    {"id": "disk", "label": "Disk usage", "group": "Resources", "needs_sudo": False,
     "cmd": "df -hP -x tmpfs -x devtmpfs 2>/dev/null || df -hP"},
    {"id": "inode", "label": "Inode usage", "group": "Resources", "needs_sudo": False,
     "cmd": "df -iP -x tmpfs -x devtmpfs 2>/dev/null || df -iP"},
    {"id": "mem", "label": "Memory", "group": "Resources", "needs_sudo": False,
     "cmd": "free -m 2>/dev/null || head -5 /proc/meminfo"},
    {"id": "top", "label": "Top processes (CPU)", "group": "Resources", "needs_sudo": False,
     "cmd": "ps -eo pid,user,%cpu,%mem,etime,comm --sort=-%cpu 2>/dev/null | head -15 || ps aux | head -15"},
    {"id": "ports", "label": "Listening ports", "group": "Network", "needs_sudo": True,
     "cmd": "(sudo -n ss -tulpn 2>/dev/null || ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null) | head -60"},
    {"id": "routes", "label": "Interfaces & routes", "group": "Network", "needs_sudo": False,
     "cmd": "ip -br addr 2>/dev/null; ip route 2>/dev/null || route -n 2>/dev/null; true"},
    {"id": "dns", "label": "DNS configuration", "group": "Network", "needs_sudo": False,
     "cmd": "cat /etc/resolv.conf 2>/dev/null; resolvectl status 2>/dev/null | head -30; true"},
    {"id": "pubip", "label": "Public egress IP", "group": "Network", "needs_sudo": False, "timeout": 15,
     "note": PUBIP_NOTE,
     "cmd": "curl -s -m 5 https://api.ipify.org 2>/dev/null || wget -qO- -T 5 https://api.ipify.org 2>/dev/null "
            "|| dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null"},
    {"id": "tconn", "label": "Tenable cloud reachability", "group": "Network", "needs_sudo": False,
     "note": "contacts sensor.cloud.tenable.com:443",
     "cmd": "curl -sS -o /dev/null -m 10 -w '%{http_code} %{time_total}s\\n' https://sensor.cloud.tenable.com/ 2>&1 "
            "|| (bash -c 'echo > /dev/tcp/sensor.cloud.tenable.com/443' 2>/dev/null && echo tcp_ok) "
            "|| printf '%s\\n' \"C2\"\"_TCONN=unreachable\""},
    {"id": "time", "label": "Time sync", "group": "System", "needs_sudo": False,
     "cmd": "timedatectl 2>/dev/null | grep -Ei 'synchron|NTP|zone'; (chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null) "
            "| head -12; date -u"},
    {"id": "failed", "label": "Failed services", "group": "System", "needs_sudo": False,
     "cmd": "systemctl --failed --no-pager --plain 2>/dev/null || service --status-all 2>/dev/null | head -60"},
    {"id": "authfail", "label": "Recent auth failures (24 h)", "group": "Security", "needs_sudo": True,
     "cmd": "(journalctl -q -u ssh -u sshd --since -24h --no-pager 2>/dev/null; sudo -n journalctl -q -u ssh -u sshd "
            "--since -24h --no-pager 2>/dev/null) | grep -Ei 'fail|invalid' | tail -20; "
            "(grep -hEi 'fail|invalid' /var/log/auth.log /var/log/secure 2>/dev/null) | tail -20; "
            "lastb -n 10 2>/dev/null; true"},
    {"id": "pkgmgr", "label": "Package manager", "group": "Packages", "needs_sudo": False,
     "cmd": "for p in apt-get dnf yum zypper apk; do command -v $p >/dev/null 2>&1 && echo $p; done; true"},
    {"id": "updates", "label": "Pending updates (read-only)", "group": "Packages", "needs_sudo": False,
     "timeout": 60, "ok_exits": [0, 100],
     "note": "apt reads its cached lists (no apt update); dnf/yum may refresh metadata — no packages change",
     "cmd": "if command -v apt >/dev/null 2>&1; then o=$(apt list --upgradable 2>/dev/null | grep -v '^Listing'); "
            "elif command -v dnf >/dev/null 2>&1; then o=$(dnf -q check-update 2>/dev/null); r=$?; "
            "elif command -v yum >/dev/null 2>&1; then o=$(yum -q check-update 2>/dev/null); r=$?; "
            "elif command -v zypper >/dev/null 2>&1; then o=$(zypper -q --non-interactive list-updates 2>/dev/null); "
            "fi; printf '%s\\n' \"$o\" | head -60; "
            "if [ -n \"$(printf '%s' \"$o\" | tr -d '[:space:]')\" ] || [ \"${r:-0}\" = 100 ]; "
            "then printf '%s\\n' \"C2\"\"_UPDATES=available\"; else printf '%s\\n' \"C2\"\"_UPDATES=none\"; fi"},
    {"id": "pkgver", "label": "Installed package version", "group": "Packages", "needs_sudo": False,
     "params": {"name": {"label": "package name", "kind": "pkg"}},
     "cmd": "dpkg-query -W -f='${{Package}} ${{Version}}\\n' {N} 2>/dev/null || rpm -q {N} 2>/dev/null "
            "|| apk info -v {N} 2>/dev/null || printf '%s\\n' \"C2\"\"_PKG=not_installed\""},
    {"id": "pathx", "label": "Path exists? (stat + sha256)", "group": "Files", "needs_sudo": False,
     "params": {"path": {"label": "path", "kind": "path"}},
     "note": "sha256 only for regular files up to 50 MB; falls back to sudo -n when the path is unreadable",
     "cmd": "P={P}; S=''; if [ ! -e \"$P\" ] && [ ! -L \"$P\" ] && sudo -n test -e \"$P\" 2>/dev/null; then S='sudo -n'; fi; "
            "if [ -e \"$P\" ] || [ -L \"$P\" ] || [ -n \"$S\" ]; then printf '%s\\n' \"C2\"\"_PATH=exists\"; "
            "$S stat -c 'C2''_STAT=%F|%s|%U|%G|%a|%Y' -- \"$P\" 2>/dev/null || $S ls -ld -- \"$P\"; "
            "if $S test -f \"$P\"; then z=$($S stat -c %s -- \"$P\" 2>/dev/null || echo 0); "
            "if [ \"$z\" -le 52428800 ]; then printf 'C2''_SHA=%s\\n' \"$($S sha256sum -- \"$P\" 2>/dev/null | cut -d' ' -f1)\"; "
            "else printf '%s\\n' \"C2\"\"_SHA=skipped_size\"; fi; fi; "
            "elif [ -d \"$(dirname -- \"$P\")\" ] && [ ! -x \"$(dirname -- \"$P\")\" ]; then printf '%s\\n' \"C2\"\"_PATH=denied\"; "
            "else printf '%s\\n' \"C2\"\"_PATH=missing\"; fi"},
    {"id": "certexp", "label": "Certificate expiry (file)", "group": "Files", "needs_sudo": False,
     "params": {"path": {"label": "certificate file", "kind": "path"}},
     "cmd": "P={P}; S=''; [ -r \"$P\" ] || S='sudo -n'; $S openssl x509 -noout -subject -issuer -enddate -in \"$P\" && "
            "{{ if $S openssl x509 -checkend 2592000 -noout -in \"$P\" >/dev/null; then printf '%s\\n' \"C2\"\"_CERT=ok_30d\"; "
            "else printf '%s\\n' \"C2\"\"_CERT=expires_within_30d\"; fi; }}"},
    {"id": "agent", "label": "Nessus / Tenable agent status", "group": "Tenable", "needs_sudo": True,
     "cmd": "(sudo -n /opt/nessus_agent/sbin/nessuscli agent status 2>&1 || /opt/nessus_agent/sbin/nessuscli agent status 2>&1) "
            "| head -30; for u in nessusagent nessusd; do printf '%s: ' $u; systemctl is-active $u 2>/dev/null || echo n/a; done; true"},
    {"id": "mac", "label": "SELinux / AppArmor", "group": "Security", "needs_sudo": False,
     "cmd": "getenforce 2>/dev/null; sestatus 2>/dev/null | head -5; cat /sys/module/apparmor/parameters/enabled 2>/dev/null; "
            "aa-status --enabled 2>/dev/null && echo apparmor_enabled; true"},
    {"id": "fw", "label": "Firewall status", "group": "Security", "needs_sudo": True,
     "cmd": "firewall-cmd --state 2>/dev/null; sudo -n ufw status 2>/dev/null || ufw status 2>/dev/null; "
            "sudo -n nft list ruleset 2>/dev/null | head -40; sudo -n iptables -S 2>/dev/null | head -40; true"},
]
BY_ID = {c["id"]: c for c in CATALOG}

BUNDLES = [
    {"id": "quick", "label": "Quick health", "default": True,
     "checks": ["ident", "os", "uptime", "disk", "mem", "failed", "time", "pubip"]},
    {"id": "network", "label": "Network", "checks": ["routes", "dns", "ports", "pubip", "tconn"]},
    {"id": "security", "label": "Security posture", "checks": ["ident", "authfail", "mac", "fw", "updates"]},
    {"id": "tenable", "label": "Tenable agent", "checks": ["agent", "tconn", "os", "time"]},
    {"id": "resources", "label": "Resources", "checks": ["uptime", "disk", "inode", "mem", "top", "reboot"]},
]


def public():
    """The catalog as the page shows it (commands included, so the operator sees exactly what runs)."""
    return {"checks": [{k: v for k, v in c.items() if k != "cmd"} | {"command": c["cmd"],
                        "timeout": c.get("timeout", DEFAULT_TIMEOUT), "read_only": True}
                       for c in CATALOG],
            "bundles": BUNDLES, "default_timeout": DEFAULT_TIMEOUT, "pubip_note": PUBIP_NOTE}


def render(cid, params=None):
    """(command, error) — the fixed catalog command with validated, shell-quoted params."""
    c = BY_ID.get(cid)
    if not c:
        return None, f"unknown check '{cid}'"
    params = params or {}
    sub = {}
    for name, spec in (c.get("params") or {}).items():
        v = params.get(name)
        if isinstance(v, dict):
            v = v.get(cid)
        ok, val = (check_path(v) if spec["kind"] == "path" else check_pkg(v))
        if not ok:
            return None, f"{c['label']}: {val}"
        if spec["kind"] == "path":
            sub["P"] = q_path(val)
        else:
            sub["N"] = qword(val)
    cmd = c["cmd"].format(**sub) if (c.get("params") or "{{" in c["cmd"]) else c["cmd"]
    return cmd, ""


def _wrap(cid, cmd, timeout):
    t = int(timeout)
    return ("printf '%s\\n' \"C2\"\"_BEGIN=" + cid + "\"; ${C2T:+timeout " + str(t) + "} sh -c "
            + shlex.quote(cmd) + " 2>&1; printf '\\nC2''_END=" + cid + " rc=%s\\n' \"$?\"")


_PRE = "C2T=''; command -v timeout >/dev/null 2>&1 && C2T=1; "


def build(ids, params=None, timeout=None):
    """Validated ids → {"chunks":[{"command","ids","timeout"}], "errors":[…], "checks":[…]}.
    Each chunk is ONE pushed command line (<= MAX_BUNDLE bytes when possible)."""
    errors, parts = [], []
    seen = set()
    for cid in ids or []:
        cid = str(cid)
        if cid in seen:
            continue
        seen.add(cid)
        cmd, err = render(cid, params)
        if err:
            errors.append(err)
            continue
        c = BY_ID[cid]
        try:
            t = int(timeout) if timeout else int(c.get("timeout", DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            t = DEFAULT_TIMEOUT
        t = max(3, min(MAX_TIMEOUT, t))
        parts.append((cid, _wrap(cid, cmd, t), t))
    chunks, cur, cur_ids, cur_t = [], "", [], 0
    for cid, w, t in parts:
        if cur and len(_PRE) + len(cur) + len(w) + 2 > MAX_BUNDLE:
            chunks.append({"command": _PRE + cur, "ids": cur_ids, "timeout": cur_t})
            cur, cur_ids, cur_t = "", [], 0
        cur = (cur + "; " + w) if cur else w
        cur_ids.append(cid)
        cur_t += t
    if cur:
        chunks.append({"command": _PRE + cur, "ids": cur_ids, "timeout": cur_t})
    return {"chunks": chunks, "errors": errors, "checks": [p[0] for p in parts]}


_BEGIN = re.compile(r"^C2_BEGIN=([a-z0-9_]+)\s*$")
_END = re.compile(r"^C2_END=([a-z0-9_]+) rc=(\d+)\s*$")
OUT_CAP = 8000


def parse(text):
    """{check_id: {"rc": int|None, "output": str, "status": …}} from a bundle's remote output."""
    res, cur, buf = {}, None, []
    for raw in (text or "").splitlines():
        line = raw.rstrip("\r")
        m = _BEGIN.match(line.strip())
        if m:
            cur, buf = m.group(1), []
            continue
        m = _END.match(line.strip())
        if m and cur == m.group(1):
            res[cur] = {"rc": int(m.group(2)), "output": "\n".join(buf).strip("\n")}
            cur, buf = None, []
            continue
        if cur:
            buf.append(line)
    if cur:                                   # started, never finished (session cut / navi timeout)
        res[cur] = {"rc": None, "output": "\n".join(buf).strip("\n")}
    for cid, r in res.items():
        c = BY_ID.get(cid) or {}
        rc = r["rc"]
        out = r["output"]
        if len(out) > OUT_CAP:
            out = out[:OUT_CAP] + "\n… (output truncated for display)"
            r["truncated"] = True
        r["output"] = out
        if rc is None or rc == 124:
            r["status"] = "timeout"
        elif rc in (c.get("ok_exits") or [0]):
            r["status"] = "ok"
        elif rc == 127:
            r["status"] = "not_applicable"
        else:
            r["status"] = "failed"
        r["facts"] = facts(cid, r["output"])
    return res


_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_IPV6 = re.compile(r"\b([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})\b")


def facts(cid, out):
    """Small structured summary pulled from a check's output (shown in the results table)."""
    o = out or ""
    f = {}
    for line in o.splitlines():
        m = re.match(r"^C2_([A-Z]+)=(.*)$", line.strip())
        if m:
            f[m.group(1).lower()] = m.group(2).strip()
    if cid == "pubip":
        m = _IPV4.search(o) or _IPV6.search(o)
        f["public_ip"] = m.group(1) if m else ""
    if cid == "pathx":
        st = f.get("stat")
        if st and "|" in st:
            p = st.split("|")
            if len(p) >= 6:
                f.update({"type": p[0], "size": p[1], "owner": p[2], "group": p[3], "mode": p[4], "mtime": p[5]})
        f["exists"] = f.get("path") == "exists"
    if cid == "os":
        m = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', o, re.M)
        if m:
            f["pretty"] = m.group(1)
    if cid == "cred":
        lines = [ln.strip() for ln in o.splitlines() if ln.strip() and not ln.startswith("C2_")]
        f["user"] = lines[0] if lines else ""
    return f
