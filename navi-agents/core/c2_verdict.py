"""Amarok (C2) Phase 2 — per-host pre-flight ELIGIBILITY and per-host remediation VERDICTS, computed from the facts
the read-only catalog checks parsed (core/c2_catalog.py). Pure functions: no I/O, no SSH, no navi.db.

Words must be provable (design spec U6 / linux P1-1…P1-8, C4, C6, C7):
  * a version compare is made only against a DISTRO build (rpm release / Debian revision); an upstream-only fixed
    version is backport-unaware, so it never yields "Fixed" or "not fixed" — the changelog check is evidence, and a
    miss is "no evidence", never "not fixed";
  * across several packages, Fixed = EVERY package ≥ its own fixed build; the host verdict is the WORST package
    verdict; Not installed = NONE of the plan's packages is installed (C7);
  * "Upgraded, still vulnerable" = after > before but after < an authoritative fixed build — proven NOT fixed (C6);
  * busy package manager: excluded unless the wait is bounded (apt ≥ 1.9.11 with DPkg::Lock::Timeout, zypper with
    ZYPP_LOCK_TIMEOUT); crown jewels are never changed while it is busy (C4).
"""
import re

from . import c2_remediate as R

LOCK_WAIT = R.LOCK_WAIT


def _ck(pf, cid):
    return (((pf or {}).get("checks") or {}).get("checks") or {}).get(cid) or {}


def _f(pf, cid):
    return _ck(pf, cid).get("facts") or {}


def live_os(pf):
    """The live os facts (osrel, else the Phase 1 os check) — {family, group, kernel, immutable, …} or {}."""
    f = _f(pf, "osrel") or _f(pf, "os")
    return f if f.get("family") else {}


def _cmp(a, b, compare):
    try:
        return R.vcmp(a, b, compare)
    except Exception:
        return None


def _vf(host_v, fixed_v, compare):
    """A host-read version vs Tenable's fixed build — the epoch rule of c2_remediate.vs_fixed (linux F1)."""
    try:
        return R.vs_fixed(host_v, fixed_v, compare)
    except Exception:
        return None


def _strip_arch(v):
    return re.sub(r"\.(x86_64|i[3-6]86|noarch|aarch64|ppc64le|s390x|amd64|arm64)$", "", str(v or ""))


def installed_of(pkg_facts, name, compare):
    """(state, newest installed version or '', all versions, held) for one package from pkgstate facts."""
    if not R.ci_has(pkg_facts, name):
        return "unread", "", [], False            # this read did not include the package — never "not installed"
    d = R.ci_get(pkg_facts, name) or {}
    vs = [_strip_arch(v) for v in d.get("versions") or []]
    return d.get("state") or "", R.max_version(vs, compare) if vs else "", vs, bool(d.get("held"))


def candidate_of(cand_facts, name, installed):
    c = R.ci_get((cand_facts or {}).get("cand") or {}, name)
    if c is None:
        # dnf / yum list only what HAS an upgrade: not listed = nothing newer than the installed build — but ONLY when
        # the repo check itself worked (linux F4: a dead mirror / timeout is "repo check failed", never "nothing newer")
        src = (cand_facts or {}).get("source") or ""
        st = (cand_facts or {}).get("status")
        return installed if (src.startswith("dnf") and st in ("ok", "none")) else ""
    return _strip_arch(c.get("candidate") or "")


def eol_hint(os_):
    """End-of-life / entitlement wording per release (linux F4 + M1)."""
    oid, maj, ver = os_.get("os_id") or "", _maj(os_.get("version_id")), str(os_.get("version_id") or "")
    if oid == "centos" and maj == 7:
        return (" — CentOS Linux 7 is end-of-life (2024-06-30); mirrorlist.centos.org is gone — point the repos at "
                "vault.centos.org/7.9.2009 or your mirror")
    if oid == "centos" and maj >= 8 and "stream" not in (os_.get("pretty") or "").lower():
        return " — CentOS Linux 8 is end-of-life: its repos moved to vault.centos.org and no new fixes ship"
    if oid == "ubuntu" and ver.startswith(("18.04", "16.04", "14.04")):
        return (f" — Ubuntu {ver} standard support has ended; fixes ship only via ESM (Ubuntu Pro): check `pro status`")
    if oid == "ubuntu" and maj <= 20:
        return " — on this release new fixes may ship only via ESM: check `pro status`"
    if oid == "debian":
        return (" — check that the release's -security suite is in sources.list (Debian LTS / ELTS after EOL)")
    if oid == "rhel":
        return " — check the RHEL subscription (subscription-manager status) and repo sync"
    return ""


def rollback_available(rb_facts, name, version, compare):
    """True / False / None (not probed). The old build must still be in the repos or the local cache."""
    if not rb_facts or not version:
        return None
    if R.is_kernel_pkg(name):
        return False
    # linux F2: installed rows ('@anaconda') are never recorded by the catalog parser; a stray '@' still never counts.
    # Epochs: the host read carries one, a --showduplicates row may too — compare without a 0: epoch.
    norm = lambda v: re.sub(r"^(0|\(none\)):", "", _strip_arch(str(v)))       # noqa: E731
    v = norm(version)
    repo = [norm(x) for x in R.ci_get(rb_facts.get("repo") or {}, name, []) if not str(x).endswith("@")]
    cache = [norm(x) for x in R.ci_get(rb_facts.get("cache") or {}, name, [])]
    if v in cache:
        return "cache"
    if v in repo:
        return "repos"
    return False


def eligibility(pf, ctx=None):
    """Per-host eligibility for a change. pf = {cred:{status,sudo}, checks:{status, checks:{cid:{facts}}}};
    ctx = {family, group_key, group_label, packages[], fixed:{pkg:{version, source}}, compare, kernel, crown,
    include_sudo}. → {ok, optional, none, reason, notes[], will_fix, packages[], group}"""
    ctx = ctx or {}
    c = (pf or {}).get("cred") or {}
    out = {"ok": False, "optional": False, "none": False, "reason": "", "code": "", "notes": [], "will_fix": False,
           "packages": [], "group": None}

    def no(code, reason, **kw):
        # verify round 2 (sec M7): a STABLE code beside the words — the server's not_eligible check and the one
        # override (include_sudo) match on the code, never on reason text
        out.update(code=code, reason=reason, **kw)
        return out
    st = c.get("status")
    if st == "hostkey_mismatch":
        return no(code='hostkey', reason="host key CHANGED")
    if st == "hostkey_unknown":
        return no(code='hostkey', reason="host key not yet known — 🔑 Record new host keys (Inspect › Login test)")
    if st == "auth_failed":
        return no(code='creds', reason="login failed (one attempt, not retried)")
    if st and st != "ok":
        return no(code='unreachable', reason="Not reached: " + str(st).replace("_", " "))
    chk = (pf or {}).get("checks") or {}
    if chk.get("status") != "ok":
        return no(code='checks_incomplete', reason="the read-only checks did not complete (" + str(chk.get("status") or "not run").replace("_", " ") + ")")
    if _f(pf, "ident").get("sudo_rules") == "narrow":
        return no(code='sudo_narrow', reason="sudoers too narrow for this plan (sudo: limited commands)")
    os_ = live_os(pf)
    fam = os_.get("family") or "unknown"
    grp = os_.get("group") or {}
    out["group"] = grp or None
    if fam == "unknown":
        return no(code='family_unknown', reason="OS family unknown (os-release unreadable)")
    if os_.get("immutable"):
        return no(code='immutable', reason=f"immutable OS ({os_.get('immutable_kind') or 'image-based'}) — package upgrades are not "
                  "supported by this plan")
    pfam = ctx.get("family")
    if pfam and pfam != "unknown" and fam != pfam:
        return no(code='family', reason=f"family {fam} ≠ plan {pfam}")
    if ctx.get("group_key") and grp.get("key") and grp["key"] != ctx["group_key"]:
        return no(code='group', reason=f"{grp.get('label', grp['key'])} ≠ plan group {ctx.get('group_label') or ctx['group_key']} "
                  "(one plan per OS family + release)")
    d = _f(pf, "disk")
    if (d.get("use_root") or 0) >= 97 or (d.get("use_var") or 0) >= 97:
        return no(code='disk', reason="disk ≥ 97 % full")
    if ctx.get("kernel") and d.get("use_boot") is not None and d["use_boot"] >= 80:
        return no(code='disk', reason=f"/boot {d['use_boot']} % full — a kernel plan needs room for a new kernel")
    lk = _f(pf, "pkglock")
    if lk.get("half_configured"):
        return no(code='half_configured', reason="half-configured packages (dpkg --audit) — finish them (dpkg --configure -a) first")
    if lk.get("yum_unfinished"):
        return no(code='half_configured', reason="unfinished yum transaction — complete it (yum-complete-transaction / dnf history) first")
    if lk.get("busy"):
        who = lk.get("holder_text") or "another package-manager process"
        bounded = (fam == "apt" and lk.get("apt_bounded")) or fam == "zypper"
        if ctx.get("crown"):
            return no(code='pm_busy_crown', reason=f"package manager busy ({who}) — crown jewel, excluded")
        if not bounded:
            why = ("apt " + lk["apt_version"] + " < 1.9.11 ignores DPkg::Lock::Timeout") if fam == "apt" and lk.get("apt_version") \
                else ("dnf / yum wait for the lock without a limit" if fam in ("dnf", "yum") else "no bounded lock wait")
            return no(code='pm_busy_unbounded', reason=f"package manager busy ({who}) — no bounded lock wait on this host ({why}); retry later")
        out["notes"].append(f"package manager busy ({who}) — the plan waits up to {LOCK_WAIT} s for the lock")
    pkgs = ctx.get("packages") or []
    cmpk = ctx.get("compare") or ("dpkg" if fam == "apt" else "rpm")
    pst = _f(pf, "pkgstate").get("pkgs") or {}
    cand = _f(pf, "pkgcand")
    held = set(str(x).lower() for x in _f(pf, "holds").get("held") or [])
    excl = _f(pf, "holds").get("exclude") or []
    rbf = _f(pf, "rbavail")
    cl = _f(pf, "chlog").get("changelog") or {}
    fixed = ctx.get("fixed") or {}
    rows = []
    for n in pkgs:
        state, inst, allv, hld = installed_of(pst, n, cmpk)
        fx = (fixed.get(n) or {})
        fv, fsrc = fx.get("version") or "", fx.get("source") or ""
        cv = candidate_of(cand, n, inst) if state == "installed" else ""
        row = {"name": n, "state": state or "unread", "installed": inst,
               "installed_all": allv, "candidate": cv, "fixed": fv, "fixed_source": fsrc,
               "held": hld or n.lower() in held or any(__import__("fnmatch").fnmatch(n, p) for p in excl),
               "vs_fixed": "", "cand_vs_fixed": "", "changelog": R.ci_get(cl, n, ""),
               "rollback": rollback_available(rbf, n, inst, cmpk)}
        if inst and fv and fsrc == "distro":
            k = _vf(inst, fv, cmpk)                 # linux F1: Tenable's rpm fixed build has no epoch
            row["vs_fixed"] = "" if k is None else ("at_least" if k >= 0 else "older")
            if cv:
                k2 = _vf(cv, fv, cmpk)
                row["cand_vs_fixed"] = "" if k2 is None else ("at_least" if k2 >= 0 else "older")
        rows.append(row)
    rows.sort(key=lambda r: (0 if r["vs_fixed"] == "older" else 1, r["name"]))   # the worst row first (C12)
    out["packages"] = rows
    if pkgs and not pst:
        # sec M7: the plan's packages were never read on this host — a hard exclusion, never "eligible"
        return no(code="not_read", reason="this pre-flight did not read the plan's packages (" + ", ".join(pkgs)
                  + ") — run pre-flight again with the plan in place")
    if pkgs and pst:
        inst_rows = [r for r in rows if r["state"] == "installed"]
        unread = [r["name"] for r in rows if r["state"] == "unread"]
        if unread:
            # spec §5: the installed version of EVERY affected package is mandatory
            return no(code='not_read', reason="this pre-flight did not read the plan's packages (" + ", ".join(unread) + ") — run pre-flight again "
                      "with the plan in place")
        if any(r["state"] == "half_configured" for r in rows):
            return no(code='half_configured', reason="a plan package is half-configured — finish it (dpkg --configure -a) first")
        if not inst_rows:
            return no(code='not_installed', reason="Not installed — none of " + ", ".join(pkgs) + " is installed; nothing to do", none=True)
        h = [r["name"] for r in inst_rows if r["held"]]
        if h:
            return no(code='held', reason="Held (apt-mark hold / versionlock / exclude) — " + ", ".join(h) + " — skipped; un-holding is your "
                      "decision")
        sim = _f(pf, "pkgsim")
        if sim.get("remove"):
            # linux F3: an install-only kernel's OLDEST build removed at installonly_limit is normal — a note, not an
            # exclusion (never the running kernel). Any other removal still excludes.
            krun = _strip_arch(os_.get("kernel") or _f(pf, "pkgstate").get("krun") or "")
            rem = sim.get("removed") or [{"name": n, "version": ""} for n in sim["remove"]]
            io = [x for x in rem if R.is_kernel_pkg(x["name"]) and x.get("version")
                  and _strip_arch(re.sub(r"^\d+:", "", x["version"])) not in (krun, "")]
            other = sorted({x["name"] for x in rem if x not in io})
            if other:
                return no(code='sim_removes', reason="the package manager's simulation would REMOVE " + ", ".join(other[:6])
                          + " — this plan never removes packages; resolve it by hand")
            for x in io:
                out["notes"].append(f"removes old kernel {x['name']} {x['version']} (install-only limit)")
        if sim and sim.get("read") == "no_sudo":
            out["notes"].append("simulation not read (sudo needs a password) — removals unknown")
        if len(sim.get("install") or []) > 10:
            out["notes"].append(f"the simulation would also install {len(sim['install'])} new packages")
        auth = [r for r in inst_rows if r["fixed"] and r["fixed_source"] == "distro" and r["vs_fixed"]]
        if auth and all(r["vs_fixed"] == "at_least" for r in auth) and len(auth) == len(inst_rows):
            fod = fixed_on_disk(auth, os_.get("kernel") or _f(pf, "pkgstate").get("krun") or "", cmpk)
            if fod:
                # linux F6: the fixed kernel is installed but not booted — still vulnerable, never "Already fixed"
                return no(code='fixed_on_disk', reason=fod, none=True, fixed_on_disk=True)
            return no(code='already_fixed', reason="Already fixed — " + ", ".join(f"{r['name']} {r['installed']}" for r in auth) + " ≥ fixed "
                      + ", ".join(sorted({r['fixed'] for r in auth})), none=True)
        up = [r for r in inst_rows if r["fixed"] and r["fixed_source"] == "upstream"]
        if up and ctx.get("cve") and all(r["changelog"] == "found" for r in up) and len(up) == len(inst_rows):
            return no(code='already_fixed', reason=f"Already fixed — fix present by backport (the changelog of {', '.join(r['name'] for r in up)} "
                      f"names {ctx['cve']})", none=True)
        if up:
            ev = [r["name"] for r in up if r["changelog"] == "found"]
            out["notes"].append(("changelog names the CVE for " + ", ".join(ev)) if ev else
                                "upstream fixed version only — no changelog evidence (a miss is not proof)")
        if cand.get("status") == "locked":
            return no(code="pm_busy_unbounded", reason="package manager busy during pre-flight (" + (cand.get("error_text") or "yum lock")
                      + ") — retry pre-flight")
        if cand.get("status") == "repo_error" or (_ck(pf, "pkgcand").get("status") == "timeout"
                                                  and fam in ("dnf", "yum")):
            # linux F4: never "repos offer the installed build" when the repo check itself failed
            why = cand.get("error_text") or "the repo check timed out"
            return no(code='repo_error', reason=f"repo check failed: {why}" + eol_hint(os_))
        short = [r for r in inst_rows if r["vs_fixed"] == "older" and r["cand_vs_fixed"] == "older"]
        if short:
            hint = eol_hint(os_)
            r0 = short[0]
            return no(code='cand_lt_fixed', reason=f"repos offer {r0['name']} {r0['candidate']} < fixed {r0['fixed']} — this plan cannot fix it"
                      + hint)
        out["will_fix"] = any(r["vs_fixed"] == "older" for r in inst_rows)
        nr = [r["name"] for r in inst_rows if r["rollback"] is False and not R.is_kernel_pkg(r["name"])]
        if nr:
            out["notes"].append("downgrade not possible here (old build not in repos / cache): " + ", ".join(nr))
    rb = _f(pf, "rebootreq")
    if rb.get("pending"):
        out["notes"].append("reboot already pending")
    if (d.get("use_root") or 0) >= 90 or (d.get("use_var") or 0) >= 90:
        out["notes"].append("disk ≥ 90 %")
    if d.get("use_boot") is not None and d["use_boot"] >= 80 and not ctx.get("kernel"):
        out["notes"].append(f"/boot {d['use_boot']} %")
    if c.get("sudo") == "sudo_needs_password" and not ctx.get("include_sudo"):
        return no(code='sudo_password', reason="sudo needs a password (not included)", optional=True)
    if c.get("sudo") == "sudo_needs_password":
        out["notes"].append("navi types the stored sudo password")
    out["ok"], out["code"] = True, "ok"
    return out


def fixed_on_disk(rows, krun, compare):
    """linux F6: a kernel row whose newest INSTALLED build is ≥ fixed while the RUNNING kernel is older than fixed →
    'Fixed on disk — reboot required to take effect' (the host stays vulnerable), else ''."""
    run = _strip_arch(krun or "")
    if not run:
        return ""
    for r in rows:
        if not R.is_kernel_pkg(r.get("name")) or not r.get("fixed"):
            continue
        k = _vf(run, r["fixed"], compare)
        if k is not None and k < 0:
            return (f"Fixed on disk — reboot required to take effect: {r['name']} {r.get('installed') or r.get('after')} "
                    f"≥ fixed {r['fixed']} is installed, but the host still runs {run} (vulnerable until it boots the "
                    "new kernel; Amarok never reboots)")
    return ""


def _maj(v):
    try:
        return int(str(v or "0").split(".")[0])
    except ValueError:
        return 0


# --------------------------------------------------------------------------------------------- #
#  Verdicts (design spec §4.3 + linux C6 / C7)
# --------------------------------------------------------------------------------------------- #
_RANK = {"fixed_on_disk": 0, "still_vulnerable": 0, "no_change": 1, "changed_unexpectedly": 1, "unproven": 2, "fixed": 3,
         "already": 4, "not_installed": 5}


def pkg_verdict(name, before, after, fixed, source, compare):
    b, a = _strip_arch(before), _strip_arch(after)
    row = {"name": name, "before": b, "after": a, "fixed": fixed or "", "fixed_source": source or ""}
    if not b and not a:
        return dict(row, verdict="not_installed")
    auth = bool(fixed) and source == "distro"
    ge = lambda v: (lambda k: k is not None and k >= 0)(_vf(v, fixed, compare))      # noqa: E731 — None ≠ fixed
    if auth and b and ge(b):
        # already at / above the fixed build before the change: "already" only if nothing changed — an upgrade that
        # still ran is a change, never "Nothing changed"
        return dict(row, verdict="already") if (not a or a == b) else dict(row, verdict="fixed", was_already=True)
    if auth and a and ge(a):
        return dict(row, verdict="fixed")
    if a == b:
        return dict(row, verdict="no_change")
    k = _cmp(a, b, compare) if a and b else None
    if auth:
        return dict(row, verdict="still_vulnerable" if (k is not None and k > 0) else "changed_unexpectedly")
    return dict(row, verdict="unproven" if (k is not None and k > 0) else "changed_unexpectedly")


def _short(v, ref):
    """'1.1.1f-1ubuntu2.20' next to '1.1.1f-1ubuntu2.16' stays whole (the spec shows full builds)."""
    return v or "?"


def host_verdict(meta, before_pk, after_pk, reboot=None, services=None, krun=""):
    """→ {verdict, status, message, before, after, fixed, packages[], reboot_required, restart_services[]} from the
    pkgstate facts read before and after the change. None when the package state could not be read (the caller
    falls back to the plan's own checks)."""
    meta = meta or {}
    pkgs = meta.get("packages") or []
    if not pkgs or before_pk is None or after_pk is None:
        return None
    cmpk = meta.get("compare") or "dpkg"
    rows = []
    for n in pkgs:
        _s1, b, _ab, _h1 = installed_of(before_pk, n, cmpk)
        _s2, a, _aa, _h2 = installed_of(after_pk, n, cmpk)
        fx = (meta.get("fixed") or {}).get(n) or {}
        rows.append(pkg_verdict(n, b, a, fx.get("version"), fx.get("source"), cmpk))
    live = [r for r in rows if r["verdict"] != "not_installed"]
    if not live:
        v = "not_installed"
    else:
        worst = min(live, key=lambda r: _RANK[r["verdict"]])["verdict"]
        v = "already_fixed" if all(r["verdict"] == "already" for r in live) else worst
        if v == "already":                 # some already, some fixed → the host is fixed
            v = "fixed"
    live.sort(key=lambda r: _RANK[r["verdict"]])
    pairs = " · ".join(f"{r['name']} {_short(r['before'], r['after'])} → {_short(r['after'], r['before'])}" for r in live
                       if r["verdict"] != "already") or " · ".join(f"{r['name']} {r['before']}" for r in live)
    fxs = sorted({r["fixed"] for r in live if r["fixed"]})
    srcs = {r["fixed_source"] for r in live if r["fixed"]}
    src_lbl = "distro package check" if srcs == {"distro"} else ("upstream version" if srcs == {"upstream"} else "")
    kern = bool(meta.get("kernel"))
    rb = reboot or {}
    run_k = _strip_arch(krun or rb.get("krun") or "")
    newest = ""
    if kern:
        kp = [r for r in live if R.is_kernel_pkg(r["name"])]
        newest = (kp[0]["after"] if kp else "") or ""
    reboot_req = bool(rb.get("pending")) or (kern and bool(newest) and bool(run_k) and newest not in run_k
                                              and v in ("fixed", "unproven"))
    fod = ""
    if kern and v in ("fixed", "already_fixed"):
        fod = fixed_on_disk([dict(r, installed=r["after"]) for r in live], run_k, cmpk)
    svc = [s for s in (services or []) if s]
    res = {"verdict": v, "packages": rows, "before": live[0]["before"] if live else "",
           "after": live[0]["after"] if live else "", "fixed": ", ".join(fxs), "fixed_source": src_lbl,
           "reboot_required": reboot_req, "restart_services": svc[:20], "running_kernel": run_k}
    if fod:
        # linux F6: installed ≥ fixed, still RUNNING the old kernel → still vulnerable until it boots
        changed = any(r["verdict"] != "already" for r in live)
        res.update(verdict="fixed_on_disk", status="changed" if changed else "not_applicable", reboot_required=True,
                   message=("⟳ Fixed on disk — reboot required to take effect — " + pairs + f" (≥ fixed {', '.join(fxs)}); "
                            f"the host still runs {run_k}, so it stays vulnerable until it boots the new kernel. "
                            "Amarok never reboots; reboot in your change window, then re-run pre-flight."))
        return res
    if v == "fixed":
        msg = f"✓ Fixed — {pairs} (≥ fixed {', '.join(fxs)}, {src_lbl or 'distro package check'} · version compare)."
        if all(r.get("was_already") or r["verdict"] == "already" for r in live):
            msg += " It was already at or above the fixed build before this run."
        status = "changed"
    elif v == "unproven":
        msg = (f"◐ Upgraded, fix not proven — {pairs} (fixed version "
               + (f"{', '.join(fxs)} is upstream-only — backport-unaware" if fxs else "not stated") + "; rescan).")
        status = "changed"
    elif v == "still_vulnerable":
        bad = [r for r in live if r["verdict"] == "still_vulnerable"]
        msg = (f"✗ Upgraded, still vulnerable — {pairs} < fixed {', '.join(sorted({r['fixed'] for r in bad}))} "
               "(the repos don't carry the fix yet: check ESM / subscription / mirror sync).")
        status = "failed"
    elif v == "no_change":
        msg = (f"✗ No change — still {', '.join(r['name'] + ' ' + (r['before'] or '?') for r in live if r['verdict'] == 'no_change')}. "
               "The repos offered nothing newer (check: repo sync / ESM / subscription / version lock).")
        status = "failed"
    elif v == "already_fixed":
        # host_verdict runs only AFTER the steps ran: they executed, but no package version moved
        msg = (f"— Already fixed — installed {', '.join(r['name'] + ' ' + r['before'] for r in live)} ≥ fixed "
               f"{', '.join(fxs)}. The steps ran; no package version changed.")
        status = "changed"
    elif v == "not_installed":
        msg = "— Not installed — none of " + ", ".join(pkgs) + " is installed on this host. Nothing changed."
        status = "not_applicable"
    else:
        msg = f"✗ Changed unexpectedly — {pairs}. Check the host before anything else."
        status = "failed"
        v = "changed_unexpectedly"
    # verify round 2 (linux R1): the reboot state came from the kernel-only fallback (no needs-restarting /
    # reboot-required / zypper needs-rebooting on this host) — a library that usually needs a reboot was upgraded,
    # so never a bare "✓ Fixed": say the reboot state is unknown, and why
    lib = [r["name"] for r in live if R.needs_reboot_pkg(r["name"]) and not R.is_kernel_pkg(r["name"])
           and r["verdict"] != "already"]
    if (lib and not reboot_req and status == "changed" and rb and rb.get("via") in ("kernel_list", "none")):
        msg += (f" ⟳ Reboot state unknown — {', '.join(lib[:4])} usually need a reboot; this host lacks "
                f"{rb.get('missing_tool') or 'a reboot-required tool'} — check it in your change window.")
        res["reboot_state"] = "unknown"
    if reboot_req and status == "changed":
        msg += (f" ⟳ Not effective until reboot — installed {newest or 'a new build'}; still running {run_k or '?'}. "
                "Amarok never reboots; reboot in your change window, then re-run pre-flight.")
    if svc and status == "changed":
        msg += " ↻ Services still using the old library: " + ", ".join(svc[:8]) + " (restart needed)."
    res.update(verdict=v, status=status, message=msg)
    return res


def before_state(meta, before_pk, krun=""):
    """The decision BEFORE any change, from the multi-package pkgstate read (linux M2 / F1 / F6, verify round) →
    a not_applicable result {status, verdict, message, before} or None (go ahead and change the host)."""
    meta = meta or {}
    pkgs = meta.get("packages") or []
    if not pkgs or before_pk is None:
        return None
    cmpk = meta.get("compare") or "dpkg"
    rows = []
    for n in pkgs:
        st, inst, _all, held = installed_of(before_pk, n, cmpk)
        fx = (meta.get("fixed") or {}).get(n) or {}
        rows.append({"name": n, "state": st, "installed": inst, "held": held, "fixed": fx.get("version") or "",
                     "source": fx.get("source") or ""})
    live = [r for r in rows if r["state"] == "installed"]
    if not live:
        # C7: Not installed = NONE of the plan's packages is installed (dpkg-query's rc says "any missing")
        return {"status": "not_applicable", "verdict": "not_installed",
                "message": "— Not installed — none of " + ", ".join(pkgs) + " is installed on this host. Nothing changed."}
    hld = [r["name"] for r in live if r["held"]]
    if hld:
        return {"status": "not_applicable", "verdict": "held",
                "message": "— Held (apt-mark hold) — " + ", ".join(hld) + " skipped. Un-holding is an operator decision "
                                                                         "outside Amarok."}
    auth = [r for r in live if r["fixed"] and r["source"] == "distro"]
    if auth and len(auth) == len(live) and all((lambda k: k is not None and k >= 0)(_vf(r["installed"], r["fixed"], cmpk)) for r in auth):
        if meta.get("kernel"):
            fod = fixed_on_disk(auth, krun, cmpk)
            if fod:
                return {"status": "not_applicable", "verdict": "fixed_on_disk", "reboot_required": True,
                        "before": auth[0]["installed"], "message": "⟳ " + fod + ". Nothing to install."}
        return {"status": "not_applicable", "verdict": "already_fixed", "before": auth[0]["installed"],
                "message": "— Already fixed — installed " + ", ".join(f"{r['name']} {r['installed']}" for r in auth)
                           + " ≥ fixed " + ", ".join(sorted({r['fixed'] for r in auth})) + " (version compare). Nothing changed."}
    return None


_PROGRESS = re.compile(r"^\s*(Unpacking |Setting up |Preparing to unpack |Removing |Running transaction|Updating\s+:|"
                       r"Upgrading\s*:|Installing\s*:|Downgrading\s*:|Cleanup\s*:|Verifying\s*:|Erasing\s*:|"
                       r"dpkg: error processing|Retrieving |\(\d+/\d+\): )|Error in \S+ scriptlet|error: unpacking of archive",
                       re.M | re.I)
_WAIT = re.compile(r"Waiting for cache lock|waiting for process with pid|Another app is currently holding the yum lock;\s*"
                   r"waiting|Could not get lock[^\n]*\.\.\.\s*\d+s", re.I)


def classify_step_failure(output, exit_code, command=""):
    """A failed change step, in words (fix round 487 — sec / linux V3-F1). "Package manager busy — nothing changed" is
    claimed ONLY for a TERMINAL lock refusal before any transaction started:
      * yum: exit 200 on a step that carries --setopt=exit_on_lock=1 (stderr may not be merged), or the
        "exiting as configured by exit_on_lock" line;
      * apt: a final `E: Could not get lock` / `E: Unable to acquire the dpkg frontend lock` line with no Unpacking /
        Setting up / Preparing / Removing line;
      * zypper: exit 7 (ZYPPER_EXIT_ZYPP_LOCKED, raised before anything runs).
    dnf is NEVER busy — it waits for its lock without a limit (that ends in the timeout → Unknown state path).
    A lock WAIT followed by progress or another error is "lock_wait": the step failed after waiting for the package
    lock and the host may be partly changed. → (kind: pm_busy | lock_wait | held | "", words). The caller re-reads the
    package versions before it says "nothing changed"."""
    o = output or ""
    c = command or ""
    progress = bool(_PROGRESS.search(o))
    m = re.search(r"(?:held by process|process|pid)\s+(\d+)(?:\s*\(([^)]+)\))?", o)
    who = (m.group(2) + " pid " + m.group(1)) if m and m.group(2) else (("pid " + m.group(1)) if m else "")
    busy_words = f"✗ Package manager busy{(' (' + who + ')') if who else ''} — nothing changed (retry)."
    yum_step = bool(re.match(r"^\s*(sudo\s+(-n\s+)?)?yum\s", c)) or (not c and "yum" in o.lower())
    tok = R.YUM_LOCK_OPT in c
    if not progress:
        if re.search(r"exiting as configured by exit_on_lock", o, re.I) or (exit_code == 200 and tok and yum_step):
            return "pm_busy", busy_words
        if re.search(r"^E: (Could not get lock|Unable to acquire the dpkg frontend lock)", o, re.M):
            return "pm_busy", busy_words
        if exit_code == 7 and ("zypper" in c or "zypp" in o.lower() or "System management is locked" in o):
            return "pm_busy", busy_words
    if _WAIT.search(o) or (re.search(r"Existing lock /var/run/yum\.pid", o) and progress):
        return "lock_wait", ("✗ The step failed after waiting for the package lock; the host may be partly changed. "
                             "Run pre-flight before retrying.")
    if re.search(r"Held packages were changed|have been kept back|is held|versionlock", o, re.I):
        return "held", "— Held (apt-mark hold / versionlock) — skipped. Un-holding is an operator decision outside Amarok."
    return "", ""
