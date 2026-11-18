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


MAX_PKGS = 12
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,7}$")         # sec H1b: ASCII digits only (Python \d takes ٢٠٢٤)


def check_pkgs(v):
    """(ok, [names] | reason) — several package names (a list, or a comma / space separated string), each one
    validated like check_pkg; at most MAX_PKGS."""
    if isinstance(v, (list, tuple)):
        items = [str(x).strip() for x in v]
    else:
        items = [x for x in re.split(r"[\s,]+", str(v if v is not None else "").strip())]
    items = [x for x in dict.fromkeys(items) if x]
    if not items:
        return False, "at least one package name"
    if len(items) > MAX_PKGS:
        return False, f"at most {MAX_PKGS} package names"
    for x in items:
        ok, r = check_pkg(x)
        if not ok:
            return False, f"'{x[:40]}': {r}"
    return True, items


def check_cve(v):
    """linux C10: the changelog check's CVE param — exactly CVE-YYYY-NNNN(…), passed through qword."""
    v = str(v if v is not None else "").strip().upper()
    if not _CVE_RE.match(v):
        return False, "CVE must match " + _CVE_RE.pattern
    return True, v


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
     "cmd": "who -b 2>/dev/null; last -x reboot 2>/dev/null | head -5; uptime -s 2>/dev/null; "
            "journalctl --list-boots -q --no-pager 2>/dev/null | tail -3; true"},
    {"id": "disk", "label": "Disk usage", "group": "Resources", "needs_sudo": False,
     "cmd": "df -hP -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -hP"},
    {"id": "inode", "label": "Inode usage", "group": "Resources", "needs_sudo": False,
     "cmd": "df -iP -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -iP"},
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
            "| head -12; date -u; s=$(timedatectl show -p NTPSynchronized --value 2>/dev/null); "
            "[ -n \"$s\" ] && printf 'C2''_SYNCED=%s\\n' \"$s\"; true"},
    {"id": "failed", "label": "Failed services", "group": "System", "needs_sudo": False,
     "cmd": "systemctl --failed --no-pager --plain 2>/dev/null || service --status-all 2>/dev/null | head -60"},
    # build 486 (linux P1-10): the root path first, the unprivileged one only as a fallback (no duplicates), and a
    # PARTIAL marker when nothing root-only was readable — an empty result must never read as "no failures"
    {"id": "authfail", "label": "Recent auth failures (24 h)", "group": "Security", "needs_sudo": True,
     "cmd": "R=''; sudo -n true 2>/dev/null && R='sudo -n'; "
            "$R journalctl -q -u ssh -u sshd --since -24h --no-pager 2>/dev/null | grep -Ei 'fail|invalid' | tail -20; "
            "$R grep -hEi 'fail|invalid' /var/log/auth.log /var/log/secure 2>/dev/null | tail -20; "
            "$R lastb -n 10 2>/dev/null; [ -z \"$R\" ] && printf 'C2''_READ=partial\\n'; true"},
    {"id": "pkgmgr", "label": "Package manager", "group": "Packages", "needs_sudo": False,
     "cmd": "for p in apt-get dnf yum zypper apk; do command -v $p >/dev/null 2>&1 && echo $p; done; true"},
    {"id": "updates", "label": "Pending updates (read-only)", "group": "Packages", "needs_sudo": False,
     "timeout": 60, "ok_exits": [0, 100],
     "note": "apt reads its cached lists (no apt update); dnf/yum may refresh metadata — no packages change",
     "cmd": "if command -v apt >/dev/null 2>&1; then o=$(apt list --upgradable 2>/dev/null | grep -v '^Listing'); "
            "elif command -v dnf >/dev/null 2>&1; then o=$(dnf -q check-update 2>/dev/null); r=$?; "
            "elif command -v yum >/dev/null 2>&1; then o=$(yum -q check-update 2>/dev/null); r=$?; "
            "elif command -v zypper >/dev/null 2>&1; then o=$(zypper -q --non-interactive list-updates 2>/dev/null); z=$?; "
            "case $z in 0|10[0-6]) ;; *) r=1;; esac; "
            "fi; printf '%s\\n' \"$o\" | head -60; "
            "if [ \"${r:-0}\" = 1 ]; then printf '%s\\n' \"C2\"\"_UPDATES=error\"; "
            "elif [ -n \"$(printf '%s' \"$o\" | tr -d '[:space:]')\" ] || [ \"${r:-0}\" = 100 ]; "
            "then printf '%s\\n' \"C2\"\"_UPDATES=available\"; else printf '%s\\n' \"C2\"\"_UPDATES=none\"; fi; "
            # build 486 (linux P1-10): apt reads its CACHED lists — say how old they are ("none" from 3-week-old lists
            # means nothing)
            "a=$(stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || "
            "stat -c %Y /var/lib/apt/lists/partial 2>/dev/null); "
            "[ -n \"$a\" ] && printf 'C2''_LISTAGE=%s\\n' $(( $(date +%s) - a )); true"},
    {"id": "pkgver", "label": "Installed package version", "group": "Packages", "needs_sudo": False,
     "params": {"name": {"label": "package name", "kind": "pkg"}},
     "note": "status-aware on dpkg hosts: only an installed package (ii, or hi = held) counts — rc / un are not installed",
     "cmd": "if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${{db:Status-Abbrev}} ${{Package}} ${{Version}}\\n' {N} "
            "2>/dev/null | awk 'substr($1,2,1)==\"i\" {{print $2\" \"$3 (substr($1,1,1)==\"h\" ? \" (held)\" : \"\"); f=1}} END {{if (!f) print \"C2\" \"_PKG=not_installed\"}}'; "
            "else rpm -q {N} 2>/dev/null || apk info -v {N} 2>/dev/null || printf '%s\\n' \"C2\"\"_PKG=not_installed\"; fi"},
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
    # build 486 (linux P1-10): nessuscli is root-only — say so (no_sudo) instead of a green "ok" over "permission
    # denied"; extract linked-to / link status / last scan / last connection
    {"id": "agent", "label": "Nessus / Tenable agent status", "group": "Tenable", "needs_sudo": True,
     "cmd": "B=/opt/nessus_agent/sbin/nessuscli; if [ ! -e $B ]; then printf 'C2''_AGENT=not_installed\\n'; "
            "elif o=$(sudo -n $B agent status 2>&1); then printf '%s\\n' \"$o\" | head -30; "
            "if printf '%s' \"$o\" | grep -Eqi 'Linked to: *(None|$)|not linked'; then printf 'C2''_AGENT=unlinked\\n'; "
            "else printf 'C2''_AGENT=linked\\n'; fi; printf 'C2''_AGENTVER=%s\\n' \"$(sudo -n $B -v 2>/dev/null | head -1)\"; "
            "else printf '%s\\n' \"$o\" | head -3; printf 'C2''_AGENT=no_sudo\\n'; fi; "
            "for u in nessusagent nessusd; do printf '%s: ' $u; systemctl is-active $u 2>/dev/null || echo n/a; done; true"},
    {"id": "mac", "label": "SELinux / AppArmor", "group": "Security", "needs_sudo": False,
     "cmd": "getenforce 2>/dev/null; sestatus 2>/dev/null | head -5; cat /sys/module/apparmor/parameters/enabled 2>/dev/null; "
            "aa-status --enabled 2>/dev/null && echo apparmor_enabled; true"},
    {"id": "fw", "label": "Firewall status", "group": "Security", "needs_sudo": True,
     "cmd": "firewall-cmd --state 2>/dev/null; sudo -n ufw status 2>/dev/null || ufw status 2>/dev/null; "
            "sudo -n nft list ruleset 2>/dev/null | head -40; sudo -n iptables -S 2>/dev/null | head -40; true"},

    # ---------------- build 486 — Phase 2 pre-flight probes (linux P1-1/5/6/8, C4/C9/C10). All read-only. ----------
    {"id": "osrel", "label": "Live OS family (os-release, kernel, arch)", "group": "Packages", "needs_sudo": False,
     "note": "ID / ID_LIKE / VERSION_ID → the plan group (family · distro · major); immutable OSes are flagged",
     "cmd": "r=/etc/os-release; [ -r $r ] || r=/usr/lib/os-release; g(){ sed -n \"s/^$1=//p\" $r 2>/dev/null | head -1 "
            "| tr -d \"\\\"'\"; }; printf 'C2''_ID=%s\\nC2''_IDLIKE=%s\\nC2''_VER=%s\\nC2''_PRETTY=%s\\n' \"$(g ID)\" "
            "\"$(g ID_LIKE)\" \"$(g VERSION_ID)\" \"$(g PRETTY_NAME)\"; [ -r /etc/redhat-release ] && printf "
            "'C2''_RHREL=%s\\n' \"$(head -1 /etc/redhat-release)\"; printf 'C2''_KREL=%s\\nC2''_ARCH=%s\\n' \"$(uname -r)\" "
            "\"$(uname -m)\"; im=no; [ -e /run/ostree-booted ] && im=rpm-ostree; command -v transactional-update "
            ">/dev/null 2>&1 && im=transactional-update; [ \"$(g ID)\" = ubuntu-core ] && im=ubuntu-core; "
            "printf 'C2''_IMMUTABLE=%s\\n' $im"},
    {"id": "pkgstate", "label": "Installed versions of the plan's packages (status-aware)", "group": "Packages",
     "needs_sudo": False, "params": {"names": {"label": "package names", "kind": "pkgs"}},
     "note": "dpkg: only ii / hi count as installed (rc / un are not); rpm: one line per installed build (kernels)",
     "cmd": "if command -v dpkg-query >/dev/null 2>&1; then for p in {NS}; do o=$(dpkg-query -W "
            "-f='${{db:Status-Abbrev}} ${{Package}} ${{Version}}\\n' \"$p\" 2>/dev/null); if [ -n \"$o\" ]; then "
            "printf '%s\\n' \"$o\" | sed \"s/^/C2\"\"_PKGLINE=/\"; else printf 'C2''_PKGLINE=un %s -\\n' \"$p\"; fi; done; "
            "elif command -v rpm >/dev/null 2>&1; then for p in {NS}; do if rpm -q \"$p\" >/dev/null 2>&1; then rpm -q "
            "--qf '%{{NAME}} %{{EPOCH}}:%{{VERSION}}-%{{RELEASE}}\\n' \"$p\" | sed \"s/^/C2\"\"_PKGLINE=ii /\"; else "
            "printf 'C2''_PKGLINE=un %s -\\n' \"$p\"; fi; done; fi; printf 'C2''_KRUN=%s\\n' \"$(uname -r)\""},
    {"id": "pkgcand", "label": "Candidate versions from the repos", "group": "Packages", "needs_sudo": False,
     "params": {"names": {"label": "package names", "kind": "pkgs"}}, "timeout": 120,
     "note": "apt-cache policy reads cached lists; dnf / yum list --upgrades may refresh metadata (non-root, cold cache: "
             "120 s) — no package changes; a repo error or timeout is 'repo check failed', never 'nothing newer'",
     "cmd": "if command -v apt-cache >/dev/null 2>&1; then apt-cache policy {NS} 2>/dev/null; "
            "elif command -v dnf >/dev/null 2>&1; then dnf -q list --upgrades {NS} 2>&1; printf 'C2''_PMRC=%s\\n' $?; "
            "elif command -v yum >/dev/null 2>&1; then yum --setopt=exit_on_lock=1 -q list updates {NS} 2>&1; printf 'C2''_PMRC=%s\\n' $?; "
            "elif command -v zypper >/dev/null 2>&1; then zypper -q info {NS} 2>/dev/null; fi; true"},
    {"id": "pkglock", "label": "Package-manager lock / auto-updater / half-configured", "group": "Packages",
     "needs_sudo": True,
     "note": "busy + a bounded lock wait (apt ≥ 1.9.11, zypper) → warn; busy elsewhere, half-configured, or an "
             "unfinished yum transaction → excluded",
     # linux F7 (verify round): also the auto-updaters — yum-cron (python … /usr/sbin/yum-cron), dnf-automatic,
     # unattended-upgrades — and packagekitd (reported as PRESENT, not busy)
     "cmd": "pgrep -a -f '[a]pt-get |/usr/bin/[a]pt |[d]pkg |[u]nattended-upgrade|/usr/bin/[d]nf |/usr/bin/[y]um |"
            "[y]um-cron|[d]nf-automatic|[p]ackagekitd|[z]ypper |[r]pm -[iUe]' 2>/dev/null | grep -v -e unattended-upgrade-shut''down -e _BEGIN= | head -5 | "
            "sed \"s/^/C2\"\"_HOLDER=/\"; printf 'C2''_LOCKPIDS=%s\\n' \"$(sudo -n fuser /var/lib/dpkg/lock-frontend "
            "/var/lib/dpkg/lock /var/lib/apt/lists/lock 2>/dev/null | tr -s ' ')\"; for u in apt-daily.service "
            "apt-daily-upgrade.service dnf-automatic.service dnf-automatic-install.service; do s=$(systemctl is-active "
            "$u 2>/dev/null); case $s in active|activating) printf 'C2''_UNIT=%s\\n' $u;; esac; done; "
            "if command -v dpkg >/dev/null 2>&1; then a=$(dpkg --audit 2>/dev/null | head -3); if [ -n \"$a\" ]; then "
            "printf 'C2''_AUDIT=broken\\n%s\\n' \"$a\"; else printf 'C2''_AUDIT=ok\\n'; fi; printf 'C2''_APTVER=%s\\n' "
            "\"$(apt-get --version 2>/dev/null | head -1 | cut -d' ' -f2)\"; fi; ls /var/lib/yum/transaction-all* "
            ">/dev/null 2>&1 && printf 'C2''_YUMTX=unfinished\\n'; true"},
    {"id": "holds", "label": "Held / version-locked / excluded packages", "group": "Packages", "needs_sudo": False,
     "note": "apt-mark showhold · dnf / yum versionlock list (absent plugin → n/a) · exclude= · zypper locks",
     "cmd": "command -v apt-mark >/dev/null 2>&1 && apt-mark showhold 2>/dev/null | sed \"s/^/C2\"\"_HOLD=/\"; "
            "for m in dnf yum; do if command -v $m >/dev/null 2>&1; then if [ $m = yum ]; then o=$(yum --setopt=exit_on_lock=1 "
            "-q versionlock list 2>/dev/null); else o=$(dnf -q versionlock list 2>/dev/null); fi; "
            "if [ $? = 0 ]; then printf '%s\\n' \"$o\" | sed \"s/^/C2\"\"_VLOCK=/\"; else printf 'C2''_VLOCKRC=na\\n'; fi; "
            "break; fi; done; grep -hi '^exclude' /etc/dnf/dnf.conf /etc/yum.conf 2>/dev/null | sed \"s/^/C2\"\"_EXCL=/\"; "
            "command -v zypper >/dev/null 2>&1 && zypper -q locks 2>/dev/null | sed \"s/^/C2\"\"_ZLOCK=/\"; true"},
    {"id": "rebootreq", "label": "Reboot required? (running vs newest kernel)", "group": "System", "needs_sudo": False,
     "note": "/var/run/reboot-required · needs-restarting -r · zypper needs-rebooting · else running vs newest kernel",
     # (the path is quote-split — /var/run/re''boot-required — so no literal "reboot" word appears in a read-only check)
     "cmd": "r=unknown; if [ -f /var/run/re''boot-required ]; then r=yes; sed \"s/^/C2\"\"_RRPKG=/\" "
            "/var/run/re''boot-required.pkgs 2>/dev/null; elif command -v needs-restarting >/dev/null 2>&1; then "
            "needs-restarting -r >/dev/null 2>&1; case $? in 0) r=no;; 1) r=yes;; esac; printf 'C2''_RTOOL=needs-restarting\\n'; "
            # build 487 (owner decision 7a): dnf's own plugin when the standalone tool is absent — "No such command"
            # (dnf-plugins-core missing) stays unknown
            # fix round 487 (linux M-1): decided on dnf's TEXT, never on rc 1 alone (rc 1 is also "No such command" or
            # an rpmdb error) — "Reboot is required" → yes; "No core libraries or services have been updated" /
            # "Reboot should not be necessary" → no; anything else → unknown (the fallback below)
            "elif command -v dnf >/dev/null 2>&1 && {{ o=$(dnf needs-restarting -r 2>&1); printf '%s' \"$o\" | grep -qi "
            "-e 'Re''boot is required' -e 'No core libraries or services have been updated' -e 'Re''boot should not be "
            "necessary'; }}; then if printf '%s' \"$o\" | grep -qi 'Re''boot is required'; then r=yes; else r=no; fi; "
            "printf 'C2''_RTOOL=dnf needs-restarting\\n'; elif command -v zypper "
            ">/dev/null 2>&1; then zypper needs-rebooting >/dev/null 2>&1; case $? in 0) r=no;; 102) r=yes;; esac; "
            "elif [ -d /var/lib/update-notifier ]; then r=no; fi; printf 'C2''_REBOOT=%s\\nC2''_KRUN=%s\\n' $r "
            "\"$(uname -r)\"; "
            # linux F5 (verify round): no `sort -V` guess over /boot — the installed kernels are listed from the package
            # database and the NEWEST is picked server-side with the rpm / dpkg comparator
            "if command -v dpkg-query >/dev/null 2>&1; then printf 'C2''_KFMT=deb\\n'; dpkg-query -W "
            "-f='${{db:Status-Abbrev}} ${{Package}}\\n' 'linux-image-[0-9]*' 2>/dev/null | grep '^ii' | sed "
            "\"s/^ii *linux-image-/C2\"\"_KLIST=/\"; elif command -v rpm >/dev/null 2>&1; then printf 'C2''_KFMT=rpm\\n'; "
            "rpm -q --qf '%{{VERSION}}-%{{RELEASE}}.%{{ARCH}}\\n' kernel kernel-core kernel-default kernel-uek kernel-ml "
            "kernel-lt kernel-rt kernel-rt-core 2>/dev/null | "
            "grep -v 'not installed' | sed \"s/^/C2\"\"_KLIST=/\"; fi"},
    {"id": "needrestart", "label": "Services still using old libraries", "group": "System", "needs_sudo": True,
     "note": "needrestart -b -r l (list only) · needs-restarting -s · zypper ps -s — needs passwordless sudo",
     "cmd": "if command -v needrestart >/dev/null 2>&1; then o=$(sudo -n needrestart -b -r l 2>/dev/null); "
            "if [ -n \"$o\" ]; then printf '%s\\n' \"$o\"; printf 'C2''_SVCREAD=ok\\n'; else printf 'C2''_SVCREAD=no_sudo\\n'; fi; "
            "elif command -v needs-restarting >/dev/null 2>&1; then if o=$(sudo -n needs-restarting -s 2>/dev/null); then "
            "printf '%s\\n' \"$o\" | sed \"s/^/C2\"\"_SVC=/\"; printf 'C2''_SVCREAD=ok\\n'; else printf 'C2''_SVCREAD=no_sudo\\n'; fi; "
            "elif command -v zypper >/dev/null 2>&1; then if o=$(sudo -n zypper ps -s 2>/dev/null); then printf '%s\\n' "
            "\"$o\"; printf 'C2''_SVCREAD=ok\\n'; else printf 'C2''_SVCREAD=no_sudo\\n'; fi; else printf 'C2''_SVCREAD=absent\\n'; fi"},
    {"id": "chlog", "label": "Changelog names the CVE? (backport evidence)", "group": "Packages", "needs_sudo": False,
     "params": {"names": {"label": "package names", "kind": "pkgs"}, "cve": {"label": "CVE", "kind": "cve"}},
     "note": "a miss is 'no evidence', never 'not fixed' — minimal / container images strip /usr/share/doc",
     "cmd": "C={CVE}; for p in {NS}; do if [ -z \"$C\" ]; then printf 'C2''_CL=%s no_cve\\n' \"$p\"; continue; fi; "
            "if command -v dpkg >/dev/null 2>&1; then h=$(zcat -f /usr/share/doc/\"$p\"/changelog.Debian.gz "
            "2>/dev/null | grep -m5 -F \"$C\"); else h=$(rpm -q --changelog \"$p\" 2>/dev/null | grep -m5 -F \"$C\"); fi; "
            "if [ -n \"$h\" ]; then printf 'C2''_CL=%s found\\n' \"$p\"; printf '%s\\n' \"$h\" | head -3; "
            "else printf 'C2''_CL=%s no_evidence\\n' \"$p\"; fi; done"},
    {"id": "pkgsim", "label": "Package-manager simulation (what the upgrade would do)", "group": "Packages",
     "needs_sudo": True, "params": {"names": {"label": "package names", "kind": "pkgs"}}, "timeout": 90,
     "note": "apt-get -s (no root) · dnf / yum --assumeno · zypper --dry-run — read-only (dnf briefly takes the rpm lock)",
     "cmd": "if command -v apt-get >/dev/null 2>&1; then apt-get -s install --only-upgrade {NS} 2>&1 | grep -E "
            "'^(Inst|Remv|Conf) |^E: ' | head -60; elif command -v dnf >/dev/null 2>&1; then sudo -n dnf --assumeno upgrade "
            "{NS} 2>&1 | head -80; elif command -v yum >/dev/null 2>&1; then sudo -n yum --setopt=exit_on_lock=1 --assumeno update {NS} 2>&1 | "
            "head -80; elif command -v zypper >/dev/null 2>&1; then sudo -n zypper --non-interactive update --dry-run {NS} "
            "2>&1 | head -80; fi; true"},
    {"id": "entitle", "label": "Entitlement (Ubuntu Pro / RHEL subscription)", "group": "Packages", "needs_sudo": True,
     "note": "optional, off by default — shown on the page only (the C2 log never stores output)",
     "cmd": "command -v pro >/dev/null 2>&1 && pro status 2>/dev/null | head -20; command -v subscription-manager "
            ">/dev/null 2>&1 && sudo -n subscription-manager status 2>&1 | head -8; true"},
    {"id": "rbavail", "label": "Downgrade availability (repos + cache)", "group": "Packages", "needs_sudo": False,
     "params": {"names": {"label": "package names", "kind": "pkgs"}}, "timeout": 120,
     "note": "probed BEFORE the change: apt-cache madison + /var/cache/apt/archives · dnf / yum --showduplicates · "
             "zypper search -s --match-exact",
     "cmd": "if command -v apt-cache >/dev/null 2>&1; then for p in {NS}; do apt-cache madison \"$p\" 2>/dev/null | "
            "sed \"s/^/C2\"\"_RV=/\"; for f in /var/cache/apt/archives/\"$p\"_*.deb; do [ -e \"$f\" ] && printf "
            "'C2''_RC=%s\\n' \"${{f##*/}}\"; done; done; elif command -v dnf >/dev/null 2>&1; then dnf -q list "
            "--showduplicates {NS} 2>/dev/null | sed \"s/^/C2\"\"_RV=/\"; elif command -v yum >/dev/null 2>&1; then yum --setopt=exit_on_lock=1 -q "
            "list --showduplicates {NS} 2>/dev/null | sed \"s/^/C2\"\"_RV=/\"; elif command -v zypper >/dev/null 2>&1; then "
            "for p in {NS}; do zypper -q search -s --match-exact \"$p\" 2>/dev/null | sed \"s/^/C2\"\"_RV=/\"; done; fi; true"},
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
        kind = spec["kind"]
        if kind == "pkgs" and v in (None, "", []):
            v = params.get("name")                  # one package (the Inspect field) is a list of one
        if kind == "cve" and v in (None, ""):
            sub["CVE"] = "''"                       # no CVE given: the check says so (no_cve) — never grep for ''
            continue
        ok, val = (check_path(v) if kind == "path" else check_pkgs(v) if kind == "pkgs" else
                   check_cve(v) if kind == "cve" else check_pkg(v))
        if not ok:
            return None, f"{c['label']}: {val}"
        if kind == "path":
            sub["P"] = q_path(val)
        elif kind == "pkgs":
            sub["NS"] = " ".join(qword(x) for x in val)     # every name ONE single-quoted word
        elif kind == "cve":
            sub["CVE"] = qword(val)
        else:
            sub["N"] = qword(val)
    cmd = c["cmd"].format(**sub) if (c.get("params") or "{{" in c["cmd"]) else c["cmd"]
    return cmd, ""


def _wrap(cid, cmd, timeout):
    # build 486 (linux §3/§5): `timeout -k 5` also kills a child (curl, journalctl) that ignores TERM — only where the
    # host's timeout supports -k (C2K, probed once in _PRE; busybox may not)
    t = int(timeout)
    return ("printf '%s\\n' \"C2\"\"_BEGIN=" + cid + "\"; ${C2T:+timeout ${C2K:+-k 5 }" + str(t) + "} sh -c "
            + shlex.quote(cmd) + " 2>&1; printf '\\nC2''_END=" + cid + " rc=%s\\n' \"$?\"")


# LC_ALL=C: facts are parsed from English output (timedatectl, df headers, apt-cache policy) — a de_DE / fr_FR
# host must not change what a check reports (linux §3)
_PRE = ("LC_ALL=C; export LC_ALL; C2T=''; C2K=''; command -v timeout >/dev/null 2>&1 && C2T=1 && "
        "timeout -k 1 5 true >/dev/null 2>&1 && C2K=1; ")


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
        # build 486 (linux P1-9): the HEALTH verdict is separate from the execution status — `df` exits 0 at 99 %,
        # `systemctl --failed` exits 0 with failed units. Green is for a proven healthy verdict only.
        r["health"] = health(cid, r["facts"], r["status"]) if r["status"] == "ok" else None
    return res


def os_family(os_id, id_like="", version_id="", raw=""):
    """The package-manager family from /etc/os-release (ID, ID_LIKE, VERSION_ID): apt | dnf | yum |
    zypper | apk | unknown. A host whose os-release could not be read is 'unknown' — never guessed."""
    ids = [x for x in ((os_id or "").lower().split() + (id_like or "").lower().split()) if x]
    try:
        major = int(str(version_id or "").split(".")[0])
    except ValueError:
        major = None
    if not ids:
        if re.search(r"(?i)\b(red hat|centos)\b.*release 7", raw or ""):
            return "yum"
        return "unknown"
    if any(i in ("debian", "ubuntu", "raspbian", "linuxmint", "kali") for i in ids):
        return "apt"
    if any(i in ("sles", "suse", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sled") for i in ids):
        return "zypper"
    if "alpine" in ids:
        return "apk"
    if "amzn" in ids:
        return "dnf" if (major or 0) >= 2022 else "yum"     # AL1 (2018.03) and AL2 are yum; AL2023 is dnf
    if any(i in ("rhel", "centos", "fedora", "rocky", "almalinux", "ol") for i in ids):
        return "yum" if (major is not None and major <= 7 and "fedora" not in ids[:1]) else "dnf"
    return "unknown"


_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_IPV6 = re.compile(r"\b([0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})\b")


_LBL = {"ubuntu": "Ubuntu", "debian": "Debian", "rhel": "RHEL", "rocky": "Rocky", "almalinux": "Alma", "centos": "CentOS",
        "amzn": "Amazon Linux", "sles": "SLES", "sled": "SLED", "opensuse-leap": "openSUSE Leap", "ol": "Oracle Linux",
        "fedora": "Fedora", "alpine": "Alpine", "raspbian": "Raspbian", "linuxmint": "Mint", "kali": "Kali"}


def group_of(os_id, version_id, family):
    """linux P1-1: one plan per (family, ID, major VERSION_ID) — {key, label, family, os_id, major}."""
    oid = (os_id or "").lower()
    ver = str(version_id or "")
    major = ver.split(".")[0] if ver else ""
    if oid == "ubuntu" and ver:
        major = ".".join(ver.split(".")[:2])          # Ubuntu's major release is YY.MM (20.04 ≠ 20.10)
    if oid == "opensuse-tumbleweed":
        major, ver = "", ""                            # linux M5: rolling — VERSION_ID is a snapshot date, one group
    lab = (_LBL.get(oid, oid or "unknown") + (" " + (ver if oid in ("ubuntu", "amzn") else major) if ver else "")).strip()
    return {"key": f"{family}|{oid}|{major}", "label": lab + " · " + (family or "unknown"), "family": family or "unknown",
            "os_id": oid, "major": major}


def _num_ver(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:4])


def _pkglines(lines):
    """pkgstate → {name: {state, versions[], held}}; dpkg status letters: 2nd = installed (i) / config-files (c) /
    not-installed (n) / half (U F H W t); 1st 'h' = hold. rpm lines are 'ii name epoch:ver-rel'."""
    out = {}
    for ln in lines:
        p = ln.split()
        if len(p) < 2:
            continue
        st, name = p[0], p[1].split(":", 1)[0].lower()
        ver = p[2] if len(p) > 2 else ""
        ver = re.sub(r"^\(none\):", "", ver)
        d = out.setdefault(name, {"state": "not_installed", "versions": [], "held": False})
        s2 = st[1:2]
        if s2 == "i" and ver and ver != "-":
            d["state"] = "installed"
            d["versions"].append(ver)
            d["held"] = d["held"] or st[:1] == "h"
        elif s2 in ("U", "F", "H", "W", "t") and d["state"] != "installed":
            d["state"] = "half_configured"
        elif s2 == "c" and d["state"] == "not_installed":
            d["state"] = "config_files_only"
    return out


def _apt_policy(o):
    out, cur, in_tab = {}, None, False
    for ln in o.splitlines():
        m = re.match(r"^(\S+):\s*$", ln)
        if m:
            cur = out.setdefault(m.group(1).split(":", 1)[0].lower(), {"installed": "", "candidate": "", "table": []})
            in_tab = False
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+Installed:\s*(\S+)", ln)
        if m:
            cur["installed"] = "" if m.group(1) == "(none)" else m.group(1)
            continue
        m = re.match(r"^\s+Candidate:\s*(\S+)", ln)
        if m:
            cur["candidate"] = "" if m.group(1) == "(none)" else m.group(1)
            continue
        if re.match(r"^\s+Version table:", ln):
            in_tab = True
            continue
        m = re.match(r"^\s+(?:\*\*\*\s+)?(\S+)\s+(-?\d+)\s*$", ln)
        if in_tab and m:
            cur["table"].append(m.group(1))
    return out


def facts(cid, out):
    """Small structured summary pulled from a check's output (shown in the results table)."""
    o = out or ""
    f = {}
    multi = {}
    for line in o.splitlines():
        m = re.match(r"^C2_([A-Z]+)=(.*)$", line.strip())
        if m:
            f[m.group(1).lower()] = m.group(2).strip()
            multi.setdefault(m.group(1), []).append(m.group(2).strip())
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
    if cid == "os":
        kv = dict(re.findall(r'^(ID|ID_LIKE|VERSION_ID)="?([^"\n]*)"?\s*$', o, re.M))
        f["os_id"], f["id_like"], f["version_id"] = kv.get("ID", ""), kv.get("ID_LIKE", ""), kv.get("VERSION_ID", "")
        f["family"] = os_family(f["os_id"], f["id_like"], f["version_id"], o)
        m = re.search(r"^Linux \S+ (\S+)", o, re.M)
        if m:
            f["kernel"] = m.group(1)
    if cid == "pkgver" and f.get("pkg") != "not_installed":
        first = next((ln.strip() for ln in o.splitlines() if ln.strip() and not ln.startswith("C2_")), "")
        parts = first.split()
        if len(parts) >= 2 and re.match(r"^\d", parts[1]):  # dpkg: "name version" (version starts with a digit / epoch)
            f["installed"] = parts[1]
            f["held"] = "(held)" in first
        elif len(parts) == 1 and re.match(r"^[A-Za-z0-9][\w.+-]*-\d", parts[0]):
            f["installed"] = parts[0]                       # rpm -q / apk: name-version-release
    if cid == "ident":
        # fix round (linux F2): what matters is the COMMAND list after "(runas)", not the run-as user —
        # "(root) NOPASSWD: ALL" is all commands; "(ALL) /usr/bin/apt-get" is limited
        rules = re.findall(r"^\s*\([^)]*\)\s*(.*)$", o, re.M)
        def _cmds(r):
            r = re.sub(r"\b(NOPASSWD|PASSWD|SETENV|NOSETENV|EXEC|NOEXEC|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT):", " ", r)
            return [c.strip() for c in r.split(",") if c.strip()]
        f["sudo_rules"] = "all" if any("ALL" in _cmds(r) for r in rules) else ("narrow" if rules else "")
    if cid == "disk":
        for ln in o.splitlines():
            m = re.match(r"^\S+\s+\S+\s+\S+\s+\S+\s+(\d+)%\s+(/\S*)\s*$", ln.strip())
            if m and m.group(2) in ("/", "/var", "/boot"):
                f["use_" + (m.group(2).strip("/") or "root")] = int(m.group(1))
    if cid == "cred":
        lines = [ln.strip() for ln in o.splitlines() if ln.strip() and not ln.startswith("C2_")]
        f["user"] = lines[0] if lines else ""
    # ---------------- build 486: Phase 2 facts ----------------
    if cid == "os" and f.get("os_id") is not None:
        f["group"] = group_of(f["os_id"], f["version_id"], f["family"])
    if cid == "osrel":
        oid = (f.get("id") or "").lower()
        f = {"os_id": oid, "id_like": (f.get("idlike") or "").lower(), "version_id": f.get("ver") or "",
             "pretty": f.get("pretty") or "", "kernel": f.get("krel") or "", "arch": f.get("arch") or "",
             "immutable": (f.get("immutable") or "no") not in ("no", ""), "immutable_kind": f.get("immutable") or "no"}
        f["family"] = os_family(oid, f["id_like"], f["version_id"], o)
        f["group"] = group_of(oid, f["version_id"], f["family"])
    if cid == "disk" or cid == "inode":
        for ln in o.splitlines():
            m = re.match(r"^\S+\s+\S+\s+\S+\s+\S+\s+(\d+)%\s+(/\S*)\s*$", ln.strip())
            if m and m.group(2) in ("/", "/var", "/boot", "/tmp"):
                f[("use_" if cid == "disk" else "iuse_") + (m.group(2).strip("/") or "root")] = int(m.group(1))
    if cid == "failed":
        m = re.search(r"(\d+) loaded units? listed", o)
        if m:
            f["failed_units"] = int(m.group(1))
            f["failed_names"] = [ln.split()[0] for ln in o.splitlines() if re.match(r"^\S+\.(service|socket|mount|timer)\s", ln)][:10]
    if cid == "time":
        s = (f.get("synced") or "").lower()
        if not s:
            m = re.search(r"(?:System clock synchronized|NTP synchronized):\s*(yes|no)", o, re.I)
            s = m.group(1).lower() if m else ""
        f["synced"] = s
    if cid == "agent":
        for k, lab in (("linked_to", "Linked to"), ("link_status", "Link status"), ("last_scanned", "Last scanned"),
                       ("last_connect", "Last connection")):
            m = re.search(r"^\s*" + lab + r":\s*(.+)$", o, re.M | re.I)
            if m:
                f[k] = m.group(1).strip()[:120]
    if cid == "pkgstate":
        f = {"pkgs": _pkglines(multi.get("PKGLINE", [])), "krun": f.get("krun", "")}
    if cid == "pkgcand":
        cand = {}
        if re.search(r"^\s+Candidate:", o, re.M):
            cand = {n: {"candidate": d["candidate"], "installed": d["installed"], "table": d["table"]}
                    for n, d in _apt_policy(o).items()}
            f["source"] = "apt-cache policy"
        elif re.search(r"^Information for package", o, re.M):
            for blk in re.split(r"^Information for package ", o, flags=re.M)[1:]:
                n = re.search(r"^Name\s*:\s*(\S+)", blk, re.M)
                v = re.search(r"^Version\s*:\s*(\S+)", blk, re.M)
                s = re.search(r"^Status\s*:\s*(.+)$", blk, re.M)
                if n and v:
                    iv = re.search(r"version (\S+) installed", s.group(1)) if s else None
                    cand[n.group(1).lower()] = {"candidate": v.group(1),
                                                "installed": iv.group(1) if iv else (v.group(1) if s and "up-to-date" in s.group(1) else "")}
            f["source"] = "zypper info"
        else:
            for ln in o.splitlines():
                m = re.match(r"^([A-Za-z0-9._+-]+)\.(x86_64|i686|noarch|aarch64|ppc64le|s390x|src)\s+(\S+)\s+(\S+)\s*$", ln.strip())
                if m:
                    cand[m.group(1).lower()] = {"candidate": m.group(3), "installed": "", "repo": m.group(4)}
            f["source"] = "dnf / yum list --upgrades"
            # linux F4 (verify round): classify the repo check — a dead mirror / metadata failure / non-zero exit is
            # "repo check failed", NEVER "nothing newer than installed"
            em = next((m_ for m_ in (re.search(p_, o, re.I) for p_ in _REPO_ERR_FIRST) if m_), None) or _REPO_ERR.search(o)
            lk = re.search(r"Existing lock [^\n]*", o)
            if lk:
                # build 487 (owner decision 7b): yum --setopt=exit_on_lock=1 exited on a held lock — busy, not a repo error
                f["status"], f["error_text"] = "locked", lk.group(0).strip()[:160]
            elif em:
                f["status"], f["error_text"] = "repo_error", em.group(0).strip()[:160]
            elif re.search(r"No matching Packages", o):
                f["status"] = "none"
            elif (f.get("pmrc") or "0") == "0":
                f["status"] = "ok"
            else:
                first = next((ln.strip() for ln in o.splitlines() if ln.strip() and not ln.startswith("C2_")), "")
                f["status"], f["error_text"] = "repo_error", (f"exit {f.get('pmrc')}" + (": " + first[:120] if first else ""))
            f["error"] = f["status"] == "repo_error"
        if f.get("source") != "dnf / yum list --upgrades":
            f["status"] = "ok"
        f["cand"] = cand
    if cid == "pkglock":
        holders = [h for h in multi.get("HOLDER", []) if h]
        pids = (f.get("lockpids") or "").strip()
        units = multi.get("UNIT", [])
        present = [h for h in holders if "packagekitd" in h]          # idle on desktops: present, not busy
        holders = [h for h in holders if "packagekitd" not in h]
        f = {"holders": holders[:5], "lock_pids": pids, "units": units, "audit": f.get("audit", ""),
             "apt_version": f.get("aptver", ""), "yum_unfinished": f.get("yumtx") == "unfinished",
             "present": ["packagekitd"] if present else []}
        f["busy"] = bool(holders or pids or units)
        def _who(h):
            m = re.search(r"(yum-cron|dnf-automatic|unattended-upgrade|apt-get|apt|dpkg|dnf|yum|zypper|rpm)", h)
            return (m.group(1) if m else h.split()[1:2][0] if len(h.split()) > 1 else "?") + " pid " + h.split()[0]
        f["holder_text"] = (", ".join(_who(h) for h in holders[:2]) or (", ".join(units))
                            or (("lock held by pid " + pids) if pids else ""))
        av = f["apt_version"]
        f["apt_bounded"] = bool(av) and _num_ver(av) >= (1, 9, 11)
        f["half_configured"] = f["audit"] == "broken"
    if cid == "holds":
        held = set(x.split()[0].lower() for x in multi.get("HOLD", []) if x.strip())
        for x in multi.get("VLOCK", []):
            m = re.match(r"^(?:\d+:)?([A-Za-z0-9._+-]+?)-(?:\d+:)?\d", x.strip())
            if m:
                held.add(m.group(1).lower())
        for x in multi.get("ZLOCK", []):
            cols = [c.strip() for c in x.split("|")]
            if len(cols) >= 3 and cols[0].isdigit():
                held.add(cols[1].lower())
        pats = []
        for x in multi.get("EXCL", []):
            pats += [p for p in re.split(r"[\s,]+", x.split("=", 1)[-1]) if p]
        f = {"held": sorted(held), "exclude": pats[:20], "versionlock": "n/a" if f.get("vlockrc") == "na" else "ok"}
    if cid == "rebootreq":
        # linux F5 (verify round): the authoritative tools decide (reboot-required file, needs-restarting -r, zypper
        # needs-rebooting). Only when NONE of them answered is the running kernel compared with the NEWEST installed
        # kernel — picked with the rpm / dpkg comparator, never `sort -V`, and "newer than running", never "≠".
        # If that cannot decide either: reboot state unknown. (`dnf needs-restarting -r` is NOT used: the owner
        # approved the C10 allow-list exactly — pending owner decision.)
        r = f.get("reboot") or "unknown"
        kr = f.get("krun") or ""
        kfmt = f.get("kfmt") or ""
        klist = [k for k in multi.get("KLIST", []) if re.match(r"^[0-9][0-9A-Za-z.+_~-]*$", k or "")]
        kn, newer = _newest_kernel(klist, kfmt), None
        # verify round 2 (linux R2): the kernel list decides only when the RUNNING kernel is in it — a flavour the
        # query does not cover (UEK, kernel-ml / -lt, -rt …) is "reboot state unknown", never "decided"
        listed = bool(kr) and any(_kstrip(k) == _kstrip(kr) for k in klist)
        if kr and kn and listed:
            newer = _kcmp(kn, kr, kfmt) > 0
        tool = ("needs-restarting (yum-utils / dnf-utils)" if kfmt == "rpm" else
                "update-notifier-common (/var/run/reboot-required)" if kfmt == "deb" else "a reboot-required tool")
        f = {"reboot": r, "krun": kr, "knew": kn, "kernels": klist[:10], "pkgs": multi.get("RRPKG", [])[:10],
             "kernel_newer": bool(newer) if r == "unknown" else False,
             # linux R1: where the state came from — the authoritative tool, or the kernel-only fallback
             "via": "tool" if r in ("yes", "no") else ("kernel_list" if newer is not None else "none"),
             "missing_tool": tool if r not in ("yes", "no") else "", "kernel_listed": listed,
             "rtool": f.get("rtool") or ""}        # build 487: which tool answered (needs-restarting / dnf needs-restarting)
        f["pending"] = r == "yes" or (r == "unknown" and newer is True)
        f["decided"] = r in ("yes", "no") or newer is not None
    if cid == "needrestart":
        svcs = []
        ksta = ""
        for ln in o.splitlines():
            m = re.match(r"^NEEDRESTART-SVC:\s*(\S+)", ln.strip())
            if m:
                svcs.append(m.group(1))
            m = re.match(r"^NEEDRESTART-KSTA:\s*(\d)", ln.strip())
            if m:
                ksta = m.group(1)
            cols = [c.strip() for c in ln.split("|")]
            if len(cols) >= 6 and cols[0].isdigit() and cols[-1]:
                svcs.append(cols[-1])
        svcs += [x for x in multi.get("SVC", []) if x]
        f = {"services": sorted(set(s.replace(".service", "") for s in svcs))[:20], "ksta": ksta,
             "read": f.get("svcread") or ""}
        f["kernel_pending"] = ksta in ("2", "3")
    if cid == "pkgsim":
        up, rm, new_, err = [], [], [], ""
        for ln in o.splitlines():
            m = re.match(r"^Inst (\S+) \[([^\]]+)\] \((\S+)", ln)
            if m:
                up.append({"name": m.group(1).split(":")[0], "from": m.group(2), "to": m.group(3)})
                continue
            m = re.match(r"^Inst (\S+) \((\S+)", ln)
            if m:
                new_.append(m.group(1).split(":")[0])
                continue
            m = re.match(r"^Remv (\S+)", ln)
            if m:
                rm.append(m.group(1).split(":")[0])
            if ln.startswith("E: "):
                err = ln[3:].strip()[:160]
        sec, cur, removed = {}, None, []
        for ln in o.splitlines():                       # dnf / yum transaction summary sections
            t = ln.strip()
            # linux F3 (verify round): EVERY section header — yum EL7 "Installing for dependencies:", "Updating for
            # dependencies:", "Removing for dependencies:", dnf "Installing weak dependencies:", "Removing dependent
            # packages:", "Obsoleting …" — and any other "…:" line ends the section (never misfiled as an upgrade)
            m = re.match(r"^(Installing|Upgrading|Updating|Removing|Erasing|Downgrading|Reinstalling|Obsoleting)\b.*:$", t)
            if m:
                cur = {"Installing": "install", "Upgrading": "upgrade", "Updating": "upgrade", "Removing": "remove",
                       "Erasing": "remove", "Downgrading": "downgrade", "Reinstalling": "reinstall",
                       "Obsoleting": "obsolete"}[m.group(1)]
                continue
            if t.endswith(":") or t.startswith(("Transaction Summary", "Package", "=")):
                cur = None
                continue
            m = re.match(r"^\s+(\S+)\s+\S+\s+(\S+)\s+\S+", ln)
            if cur and m:
                sec.setdefault(cur, []).append(m.group(1))
                if cur == "remove":
                    removed.append({"name": m.group(1), "version": m.group(2)})
            elif not t:
                cur = None
        up += [{"name": n, "from": "", "to": ""} for n in sec.get("upgrade", [])]
        new_ += sec.get("install", [])
        rm += sec.get("remove", [])
        # zypper: "The following N packages are going to be REMOVED:" / "… upgraded:"
        zr = re.search(r"going to be REMOVED:\s*\n\s*(.+)", o)
        if zr:
            rm += zr.group(1).split()
        zu = re.search(r"going to be upgraded:\s*\n\s*(.+)", o)
        if zu:
            up += [{"name": n, "from": "", "to": ""} for n in zu.group(1).split()]
        for ln in o.splitlines():
            m = re.match(r"^Remv (\S+) \[([^\]]+)\]", ln)
            if m:
                removed.append({"name": m.group(1).split(":")[0], "version": m.group(2)})
        f = {"upgrade": up[:40], "install": sorted(set(new_))[:40], "remove": sorted(set(rm))[:40], "error": err,
             "removed": removed[:40], "downgrade": sec.get("downgrade", [])[:20],
             # linux M6: sudo refused → the simulation was NOT read (never "no removals")
             "read": "no_sudo" if re.search(r"a password is required|sudo: a terminal is required|"
                                            r"may not run sudo", o) else ("ok" if o.strip() else "empty")}
    if cid == "chlog":
        f = {"changelog": {x.split()[0].lower(): x.split()[1] for x in multi.get("CL", []) if len(x.split()) >= 2}}
    if cid == "entitle":
        esm = re.findall(r"^(esm-\w+)\s+yes\s+(\w+)", o, re.M)
        rh = re.search(r"Overall Status:\s*(.+)$", o, re.M)
        f = {"esm": {k: v for k, v in esm}, "rhsm": rh.group(1).strip() if rh else "",
             "pro_attached": bool(re.search(r"^(esm-\w+)\s+yes\s+enabled", o, re.M))}
    if cid == "rbavail":
        repo, cache = {}, {}
        for x in multi.get("RV", []):
            cols = [c.strip() for c in x.split("|")]
            if len(cols) >= 6 and cols[0] in ("i", "v", "i+", "", "v+") and cols[1].lower() != "name":
                if cols[5] != "(System Packages)":                              # zypper: installed-only row
                    repo.setdefault(cols[1].lower(), []).append(cols[3])        # zypper search -s
            elif len(cols) >= 3 and not cols[0].isdigit() and cols[0] not in ("S", "") and re.match(r"^[\w.+-]+$", cols[0]):
                repo.setdefault(cols[0].lower(), []).append(cols[1])            # apt-cache madison
            else:
                m = re.match(r"^([A-Za-z0-9._+-]+)\.(?:x86_64|i686|noarch|aarch64|ppc64le|s390x)\s+(\S+)\s+(\S+)", x)
                # linux F2 (verify round): an INSTALLED row (repo @anaconda / @base / installed) is not downloadable —
                # "available" means the old build is in an enabled remote repo
                if m and not m.group(3).startswith("@") and m.group(3) != "installed":    # dnf / yum --showduplicates
                    repo.setdefault(m.group(1).lower(), []).append(m.group(2))
        for x in multi.get("RC", []):
            m = re.match(r"^([^_]+)_([^_]+)_[^_]+\.deb$", x)
            if m:
                cache.setdefault(m.group(1).lower(), []).append(m.group(2).replace("%3a", ":"))
        f = {"repo": repo, "cache": cache}
    return f


_REPO_ERR = re.compile(r"Cannot find a valid baseurl[^\n]*|Failed to download metadata[^\n]*|Cannot retrieve repository "
                       r"metadata[^\n]*|Could not resolve host[^\n]*|Curl error[^\n]*|Could not retrieve mirrorlist[^\n]*|"
                       r"Errors during downloading metadata[^\n]*|Cannot download repomd[^\n]*|"
                       r"This system is not registered[^\n]*", re.I)


_REPO_ERR_FIRST = (r"Cannot find a valid baseurl[^\n]*", r"Failed to download metadata[^\n]*",
                   r"Cannot retrieve repository metadata[^\n]*")      # the definitive line wins over a mirrorlist line


def _kstrip(v):
    return re.sub(r"\.(x86_64|i[3-6]86|aarch64|ppc64le|s390x|noarch)$", "", str(v or "").strip())


def _kcmp(a, b, kfmt):
    from core import c2_remediate as R
    a, b = _kstrip(a), _kstrip(b)
    if kfmt == "deb":
        # Debian/Ubuntu kernel ABI names '5.15.0-91-generic': compare the numeric part with dpkg's comparator
        a, b = re.sub(r"-[a-z][a-z0-9-]*$", "", a), re.sub(r"-[a-z][a-z0-9-]*$", "", b)
        return R.dpkg_cmp(a, b)
    return R.rpm_cmp(a, b)


def _newest_kernel(klist, kfmt):
    best = ""
    for k in klist:
        if not best or _kcmp(k, best, kfmt) > 0:
            best = k
    return best


def health(cid, f, status="ok"):
    """{level: ok | warn | crit | info | unknown, text} from parsed facts, or None (no verdict for this check).
    Thresholds (linux P1-9): disk / inode ≥ 90 % warn, ≥ 97 % crit; a separate /boot ≥ 80 % warn."""
    f = f or {}
    if cid in ("disk", "inode"):
        pre = "use_" if cid == "disk" else "iuse_"
        vals = {k[len(pre):]: v for k, v in f.items() if k.startswith(pre)}
        if not vals:
            return {"level": "unknown", "text": "no mount parsed"}
        worst = max((v for k, v in vals.items() if k != "boot"), default=0)
        boot = vals.get("boot")
        txt = " · ".join(("/" if k == "root" else "/" + k) + f" {v} %" for k, v in vals.items())
        lvl = "crit" if worst >= 97 else ("warn" if worst >= 90 or (boot is not None and boot >= 80) else "ok")
        return {"level": lvl, "text": txt + (" ⚠" if lvl != "ok" else "")}
    if cid == "failed" and "failed_units" in f:
        n = f["failed_units"]
        return {"level": "warn" if n else "ok", "text": f"{n} failed unit{'s' if n != 1 else ''}"
                + (": " + ", ".join(f.get("failed_names") or []) if n and f.get("failed_names") else "")}
    if cid == "time" and f.get("synced"):
        return {"level": "ok" if f["synced"] == "yes" else "warn",
                "text": "clock synced" if f["synced"] == "yes" else "clock not synced ⚠"}
    if cid == "authfail" and f.get("read") == "partial":
        return {"level": "unknown", "text": "auth logs unreadable without root ◌ — an empty result proves nothing"}
    if cid == "updates" and f.get("updates"):
        age = f.get("listage")
        old = age and str(age).isdigit() and int(age) > 7 * 86400
        if f["updates"] == "error":
            return {"level": "warn", "text": "package-manager query failed (repo / subscription?)"}
        lvl = "warn" if old else ("info" if f["updates"] == "available" else "ok")
        return {"level": lvl, "text": ("updates available" if f["updates"] == "available" else "no updates pending")
                + (f" — apt lists are {int(age) // 86400} d old" if old else "")}
    if cid == "pubip":
        return {"level": "info", "text": "egress IP " + f["public_ip"] if f.get("public_ip") else "no direct egress"}
    if cid == "agent" and f.get("agent"):
        a = f["agent"]
        return {"level": {"linked": "ok", "unlinked": "warn", "no_sudo": "unknown", "not_installed": "info"}.get(a, "unknown"),
                "text": {"linked": "agent linked" + (" to " + f["linked_to"] if f.get("linked_to") else ""),
                         "unlinked": "agent installed but NOT linked", "no_sudo": "agent status needs root ◌",
                         "not_installed": "no Tenable agent"}.get(a, a)}
    if cid == "pkglock":
        if f.get("half_configured") or f.get("yum_unfinished"):
            return {"level": "crit", "text": "half-configured packages (dpkg --audit)" if f.get("half_configured")
                    else "unfinished yum transaction"}
        return {"level": "warn" if f.get("busy") else "ok",
                "text": ("busy: " + f.get("holder_text", "")) if f.get("busy") else "package manager idle"}
    if cid == "rebootreq":
        if f.get("pending"):
            return {"level": "warn", "text": "reboot pending" + (f" — running {f['krun']}, newest installed {f['knew']}"
                                                                if f.get("kernel_newer") else "")}
        if not f.get("decided"):
            why = (f"running kernel {f.get('krun')} is not in the package list (UEK / kernel-ml / -rt?)"
                   if f.get("krun") and f.get("kernels") and not f.get("kernel_listed") else "no kernel list")
            return {"level": "unknown", "text": f"reboot state unknown — this host lacks {f.get('missing_tool') or 'a reboot tool'}"
                                                f"; {why}"}
        if f.get("via") == "kernel_list":
            # linux R1: the kernel-only fallback never says "no reboot pending" — library triggers were not checked
            return {"level": "unknown", "text": "running the newest installed kernel — library reboot triggers not checked "
                                                f"(this host lacks {f.get('missing_tool')})"}
        return {"level": "ok", "text": "no reboot pending"}
    if cid == "needrestart":
        if f.get("read") in ("no_sudo", "absent"):
            return {"level": "unknown", "text": "needs passwordless sudo ◌" if f["read"] == "no_sudo" else "no needrestart tool"}
        s = f.get("services") or []
        return {"level": "warn" if s else "ok", "text": ("restart needed: " + ", ".join(s[:6])) if s else "no service uses an old library"}
    if cid == "ident" and f.get("sudo_rules"):
        return {"level": "ok" if f["sudo_rules"] == "all" else "warn",
                "text": "sudo: all commands" if f["sudo_rules"] == "all" else "sudo: limited commands"}
    if cid == "osrel" and f.get("group"):
        return {"level": "crit" if f.get("immutable") else ("info" if f["family"] != "unknown" else "warn"),
                "text": f["group"]["label"] + (" · immutable (" + f["immutable_kind"] + ")" if f.get("immutable") else "")}
    return None
