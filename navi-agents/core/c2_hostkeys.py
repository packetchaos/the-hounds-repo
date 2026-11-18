"""navi's known_hosts, read LOCALLY on the console (build 486 — sec L-1 / C7, design spec §3.4).

navi opens every SSH session through OpenSSH with `StrictHostKeyChecking=accept-new` (default) or `yes`
(--strict-host-keys) and no UserKnownHostsFile of its own, so the keys it trusts live in the console user's OpenSSH
known_hosts — ~/.ssh/known_hosts unless ~/.ssh/config says otherwise. `ssh -G <host>` prints the effective
`userknownhostsfile`; NAVI_SSH_KNOWN_HOSTS overrides it (an unusual setup, and the tests).

What this gives the page:
  * located / not located — when navi's known_hosts can NOT be located, Health / Path / Login switch to strict host
    keys by default and new keys are recorded only via 🔑 Record new host keys (sec C7b);
  * a host's recorded key fingerprints (SHA256, like `ssh-keygen -l`), plain and hashed (|1|salt|hmac) entries;
  * "key NEW · recorded": a host with no entry before an accept-new contact and one after it.
Nothing here contacts a host; nothing is written.
"""
import base64
import hashlib
import hmac
import os
import re
import shutil
import subprocess
import threading
import time

_LOCK = threading.Lock()
_LOC = {"ts": 0.0, "v": None}
_CACHE = {}


def _ssh_g(host="localhost"):
    exe = shutil.which("ssh")
    if not exe:
        return None
    try:
        p = subprocess.run([exe, "-G", "--", host], capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    if p.returncode != 0:
        return None
    for ln in p.stdout.splitlines():
        if ln.lower().startswith("userknownhostsfile "):
            first = ln.split()[1]
            return os.path.expanduser(first)
    return None


def locate():
    """{located, file, how} — cached for 60 s."""
    env = os.environ.get("NAVI_SSH_KNOWN_HOSTS")
    if env:
        return {"located": True, "file": env, "how": "NAVI_SSH_KNOWN_HOSTS"}
    with _LOCK:
        if _LOC["v"] is not None and time.time() - _LOC["ts"] < 60:
            return dict(_LOC["v"])
    f = _ssh_g()
    v = ({"located": True, "file": f, "how": "ssh -G (OpenSSH's effective UserKnownHostsFile)"} if f else
         {"located": False, "file": "", "how": "no OpenSSH client on the console (ssh -G failed) — strict host keys "
                                              "by default; record new keys only with 🔑 Record new host keys"})
    with _LOCK:
        _LOC.update(ts=time.time(), v=v)
    return dict(v)


def _entries(path):
    try:
        st = os.stat(path)
    except OSError:
        return []
    key = (path, st.st_mtime_ns, st.st_size)
    with _LOCK:
        if key in _CACHE:
            return _CACHE[key]
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                parts = ln.split()
                if parts[0].startswith("@"):        # @cert-authority / @revoked: not a host's own key
                    continue
                if len(parts) < 3:
                    continue
                out.append((parts[0], parts[1], parts[2]))
    except OSError:
        return []
    with _LOCK:
        _CACHE.clear()
        _CACHE[key] = out
    return out


def _match(hosts_field, host, port=22):
    name = host if port == 22 else f"[{host}]:{port}"
    if hosts_field.startswith("|1|"):
        try:
            _, _, salt, mac = hosts_field.split("|", 3)
            calc = hmac.new(base64.b64decode(salt), name.encode(), hashlib.sha1).digest()
            return hmac.compare_digest(calc, base64.b64decode(mac))
        except Exception:
            return False
    neg = hit = False
    for pat in hosts_field.split(","):
        n = pat.startswith("!")
        if _pat(pat[1:] if n else pat).fullmatch(name.lower()):
            if n:
                neg = True
            else:
                hit = True
    return hit and not neg


def _pat(p):
    """known_hosts patterns: only `*` and `?` are wildcards ('[host]:port' is literal, not a glob class)."""
    return re.compile("".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in p.lower()))


def fingerprint(b64key):
    try:
        return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(b64key)).digest()).decode().rstrip("=")
    except Exception:
        return ""


def lookup(host, port=22):
    """[{keytype, fingerprint}] recorded for `host` in navi's known_hosts ([] when none / not located)."""
    loc = locate()
    if not loc["located"]:
        return []
    return [{"keytype": kt, "fingerprint": fingerprint(k)} for h, kt, k in _entries(loc["file"]) if _match(h, host, port)]
