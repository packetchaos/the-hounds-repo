"""Gabriel / Email & Reports — self-contained HTTP actions (the loop-closer).

Read-only composition, double-gated send:

`run`        — readiness + gate status.
`status`     — the email gate (writes + email opt-in) so the UI shows the right fix.
`recipients` — the OWNER ROUTING table: reads Atlas `Owner:` tags, groups assets by
               owner, guesses an email, counts assets + KEV/critical exposure. This is
               what wires the Ownership (Atlas) agent to Gabriel.
`preview`    — compose one or more emails WITHOUT sending. Reports:
                 owner_remediation | vuln_detail | kev_alarm | cert_countdown |
                 briefing | contract_plan | contract_result.
               Templates: board (summary) vs technical (per-asset + per-vuln deep-links).
               Every asset carries its Tenable platform URL (assets.url) and every
               finding its plugin deep-link (vulns.url) + the tag filter to view it
               in-platform.
`send`        — DOUBLE-gated: confirm=True AND NAVI_ALLOW_WRITES=1 AND NAVI_EMAIL=1.
               Sends the exact previewed messages (what you saw is what goes out) via
               `navi action mail`, recording each send in the Tagging log (the
               accountability ledger — who was notified, when).
"""
import datetime
import re

from core import db, tagname
from core.gates import confirmed

AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import GabrielAgent
        AGENT = GabrielAgent()
    return AGENT


def _cols(table):
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}");')}
    except Exception:
        return set()


_SEV_NUM = {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info"}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {k: i for i, k in enumerate(_SEV_ORDER)}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _sev_name(raw):
    if raw is None:
        return None
    s = str(raw).strip().lower()
    if s in _SEV_ORDER:
        return s
    if s in _SEV_NUM:
        return _SEV_NUM[s]
    return {"informational": "info"}.get(s, s or None)


# --------------------------------------------------------------------------- #
#  Tenable platform deep-links. Real navi.db carries assets.url / vulns.url; we
#  derive the console base from one of them (fallback: cloud.tenable.com).
# --------------------------------------------------------------------------- #
_DEFAULT_BASE = "https://cloud.tenable.com/tio/app.html"


def _console_base():
    try:
        r = db.query("SELECT url FROM assets WHERE url IS NOT NULL AND url!='' LIMIT 1;")
        if r:
            u = r[0].get("url") or ""
            m = re.match(r"(https?://[^/]+/tio/app\.html)", u)
            if m:
                return m.group(1)
    except Exception:
        pass
    return _DEFAULT_BASE


def _tag_filter_url(category, value):
    """A best-effort platform link that filters the asset list by a tag. Lets the
    recipient see the exact tagged set in-platform (the 'tag in the platform')."""
    base = _console_base()
    from urllib.parse import quote
    return (f"{base}#/exposure-management/tenable-inventory/assets"
            f"?tag={quote(str(category))}:{quote(str(value))}")


# --------------------------------------------------------------------------- #
#  Owner routing — reads Atlas `Owner:` tags. Value scheme is "<app>: <owner>".
# --------------------------------------------------------------------------- #
def _owner_index():
    """owner -> {assets:set(uuid), apps:set, tag_values:set}. Owner is the part after
    the last ': ' in the tag value (Atlas writes `Owner : <app>: <owner>`)."""
    tc = _cols("tags")
    if not tc or "asset_uuid" not in tc:
        return {}
    key_col = "tag_key" if "tag_key" in tc else ("category" if "category" in tc else None)
    val_col = "tag_value" if "tag_value" in tc else ("value" if "value" in tc else None)
    if not key_col or not val_col:
        return {}
    try:
        # Owner and its Settings → Test run name (Hounds-Owner) — core.tagname
        rows = db.query(f"SELECT asset_uuid, {val_col} AS v, {key_col} AS k FROM tags "
                        f"WHERE lower({tagname.sql_base(key_col)})='owner' AND {val_col} IS NOT NULL;")
    except Exception:
        return {}
    idx = {}
    for r in rows:
        v = (r.get("v") or "").strip()
        if not v:
            continue
        if ":" in v:
            app, owner = v.rsplit(":", 1)
            app, owner = app.strip(), owner.strip()
        else:
            app, owner = "", v
        owner = owner or "(unassigned)"
        e = idx.setdefault(owner, {"assets": set(), "apps": set(), "tag_values": set(), "tag_key": r.get("k") or "Owner"})
        if r.get("asset_uuid"):
            e["assets"].add(r["asset_uuid"])
        if app:
            e["apps"].add(app)
        e["tag_values"].add(v)
    return idx


def _guess_email(owner, domain=""):
    if _EMAIL_RE.search(owner or ""):
        return _EMAIL_RE.search(owner).group(0)
    if domain:
        handle = re.sub(r"[^a-z0-9._-]+", ".", (owner or "").strip().lower()).strip(".")
        if handle:
            return f"{handle}@{domain.lstrip('@')}"
    return ""


def _asset_meta(uuids):
    if not uuids:
        return {}
    ac = _cols("assets")
    if not ac:
        return {}
    sel = ["uuid"]
    for c in ("hostname", "ip_address", "operating_system", "acr", "network", "url"):
        if c in ac:
            sel.append(c)
    inl = ",".join("'" + str(u).replace("'", "''") + "'" for u in uuids)
    try:
        rows = db.query(f"SELECT {', '.join(sel)} FROM assets WHERE uuid IN ({inl});")
    except Exception:
        return {}
    return {r.get("uuid"): r for r in rows}


def _kev_uuids():
    vc = _cols("vulns")
    if not vc or "asset_uuid" not in vc or "xrefs" not in vc:
        return set()
    try:
        rows = db.query("SELECT DISTINCT asset_uuid FROM vulns "
                        "WHERE xrefs LIKE '%CISA-KNOWN-EXPLOITED%';")
        return {r.get("asset_uuid") for r in rows if r.get("asset_uuid")}
    except Exception:
        return set()


def _vulns_for(uuids, min_rank=1, limit_per_asset=8):
    """Top findings per asset (severity>=min_rank where 0=critical..4=info), with the
    Tenable plugin deep-link (vulns.url) when present."""
    if not uuids:
        return {}
    vc = _cols("vulns")
    if not vc or "asset_uuid" not in vc:
        return {}
    sel = ["asset_uuid", "plugin_id", "plugin_name"]
    for c in ("severity", "vpr", "cves", "plugin_family", "xrefs", "url", "finding_id"):
        if c in vc:
            sel.append(c)
    inl = ",".join("'" + str(u).replace("'", "''") + "'" for u in uuids)
    try:
        rows = db.query(f"SELECT {', '.join(sel)} FROM vulns WHERE asset_uuid IN ({inl});")
    except Exception:
        return {}
    by = {}
    for v in rows:
        sn = _sev_name(v.get("severity"))
        rank = _SEV_RANK.get(sn, 9)
        if rank > min_rank:  # keep only sev at/above the floor (critical/high by default)
            continue
        rec = {"plugin_id": v.get("plugin_id"), "plugin_name": v.get("plugin_name"),
               "finding_id": v.get("finding_id") or "",
               "severity": sn, "vpr": v.get("vpr"), "family": v.get("plugin_family"),
               "kev": "CISA-KNOWN-EXPLOITED" in str(v.get("xrefs") or ""),
               "url": v.get("url") or ""}
        by.setdefault(v.get("asset_uuid"), []).append(rec)
    for u, lst in by.items():
        lst.sort(key=lambda r: (_SEV_RANK.get(r["severity"], 9), -_flt(r.get("vpr"))))
        by[u] = lst[:limit_per_asset]
    return by


def _flt(x):
    try:
        return float(x)
    except Exception:
        return 0.0


def _briefing_numbers():
    """On the Scent headline numbers for the morning briefing."""
    def scalar(sql, default=0):
        try:
            r = db.query(sql)
            if r:
                return list(r[0].values())[0]
        except Exception:
            pass
        return default
    total = scalar("SELECT COUNT(DISTINCT uuid) FROM assets;")
    kev = len(_kev_uuids())
    crit = scalar("SELECT COUNT(DISTINCT asset_uuid) FROM vulns WHERE "
                  "severity IN ('4','critical','Critical');")
    certs = _cert_rows(30)
    return {"assets": total, "kev_assets": kev, "critical_assets": crit,
            "certs_expiring_30d": len(certs)}


def _cert_rows(days):
    cc = _cols("certs")
    if not cc or "not_valid_after" not in cc:
        return []
    try:
        from core.certdates import parse_cert_date
    except Exception:
        parse_cert_date = lambda s: None
    sel = [c for c in ("asset_uuid", "common_name", "not_valid_after", "organization") if c in cc]
    try:
        rows = db.query(f"SELECT {', '.join(sel)} FROM certs;")
    except Exception:
        return []
    now = datetime.date.today()
    horizon = now + datetime.timedelta(days=int(days))
    out = []
    for c in rows:
        d = parse_cert_date(c.get("not_valid_after")) if c.get("not_valid_after") else None
        dd = getattr(d, "date", lambda: d)() if hasattr(d, "date") else d
        if isinstance(dd, datetime.datetime):
            dd = dd.date()
        if isinstance(dd, datetime.date) and dd <= horizon:
            c["expiry"] = dd.isoformat()
            c["days_left"] = (dd - now).days
            out.append(c)
    out.sort(key=lambda x: x.get("days_left", 9999))
    return out


# --------------------------------------------------------------------------- #
#  Report composition. Each report returns a list of "messages":
#    {to, owner, subject, body_text, body_html, asset_count, meta}
#  body_text is what actually gets emailed; body_html is the UI preview.
# --------------------------------------------------------------------------- #
_SIGN = "\n— The Hounds · automated by navi (reply to reach the security team)"
_HOUND_FOR = [("kev", "Laelaps (CISA KEV)"), ("cert", "Certania (certificates)"),
              ("eol", "Charon (end-of-life)"), ("lifecycle", "Charon (end-of-life)"),
              ("post-quantum", "Heimdall (post-quantum)"), ("mitre", "Orthrus (ATT&CK)"),
              ("iot", "Cerberus (IoT/OT)"), ("ai", "Pythia (AI)")]


def _sev_tag(s):
    return {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MED]",
            "low": "[LOW]", "info": "[INFO]"}.get(s, "[-]")


def _owner_message(owner, entry, template, domain, min_rank):
    uuids = list(entry["assets"])
    meta = _asset_meta(uuids)
    kev = _kev_uuids()
    vulns = _vulns_for(uuids, min_rank=min_rank) if template == "technical" else {}
    # rank assets: KEV first, then ACR desc
    def akey(u):
        m = meta.get(u, {})
        return (0 if u in kev else 1, -_flt(m.get("acr")))
    ordered = sorted(uuids, key=akey)
    n = len(uuids)
    kev_n = sum(1 for u in uuids if u in kev)
    apps = ", ".join(sorted(entry["apps"])) or "your systems"

    lines = [f"Hi {owner},", "",
             f"The security team is tracking {n} asset{'s' if n != 1 else ''} you own"
             f" ({apps}).",
             (f"{kev_n} carr{'y' if kev_n != 1 else 'ies'} a CISA Known-Exploited "
              f"vulnerability — please prioritize those." if kev_n else ""),
             ""]
    hintro = (f"<p>Hi <b>{_esc(owner)}</b>,</p>"
              f"<p>The security team is tracking <b>{n}</b> asset{'s' if n!=1 else ''} you "
              f"own ({_esc(apps)})."
              + (f" <b>{kev_n}</b> carry a CISA Known-Exploited vulnerability — please "
                 "prioritize those." if kev_n else "") + "</p>")
    hitems = []

    cap = 25 if template == "technical" else 12
    for u in ordered[:cap]:
        m = meta.get(u, {})
        host = m.get("hostname") or m.get("ip_address") or u
        url = m.get("url") or ""
        acr = m.get("acr")
        head = f"• {host} ({m.get('ip_address') or '—'})" + (f" · ACR {acr}" if acr else "")
        if u in kev:
            head += " · 🔥 CISA KEV"
        lines.append(head)
        if url:
            lines.append(f"    Open in Tenable: {url}")
        hrow = (f"<b>{_esc(host)}</b> <span style='color:#8a99ad'>({_esc(m.get('ip_address') or '—')}"
                f"{' · ACR '+_esc(acr) if acr else ''})</span>"
                + (" <span style='color:#c81e3f'>🔥 CISA KEV</span>" if u in kev else "")
                + (f" — <a href='{_esc(url)}'>open in Tenable ↗</a>" if url else ""))
        if template == "technical":
            vs = vulns.get(u, [])
            for v in vs:
                tag = _sev_tag(v["severity"])
                vu = f"  →  {v['url']}" if v.get("url") else ""
                _fid = v.get("finding_id")
                _pn = v.get("plugin_name")
                lines.append(f"    {tag} plugin id {v.get('plugin_id')}"
                             + (f" — finding id: {_fid}" if _fid else "")
                             + (f" ({_pn})" if _pn else "") + vu)
            if vs:
                hrow += "<ul>" + "".join(
                    f"<li>{_sev_tag(v['severity'])} <span style='font-family:monospace'>plugin id "
                    f"<b>{_esc(str(v.get('plugin_id') or ''))}</b>"
                    + (f" — finding id: <b>{_esc(str(v.get('finding_id')))}</b>" if v.get('finding_id') else "")
                    + "</span>"
                    + (f" {_esc(v.get('plugin_name'))}" if v.get('plugin_name') else "")
                    + (f" — <a href='{_esc(v['url'])}'>open finding ↗</a>" if v.get('url') else "") + "</li>"
                    for v in vs) + "</ul>"
        hitems.append("<li>" + hrow + "</li>")
        lines.append("")
    if n > cap:
        lines.append(f"… and {n - cap} more asset{'s' if n-cap != 1 else ''}.")
        hitems.append(f"<li style='color:#8a99ad'>… and {n-cap} more</li>")
    hlines = [hintro, "<ul>"] + hitems + ["</ul>"]
    # graphic: this owner's findings by severity
    sev = _sev_counts(uuids)
    sev_pairs = [(k.capitalize(), sev[k]) for k in _SEV_ORDER if sev[k]]
    sct, sch = _chart_block(sev_pairs, "Your findings by severity")
    if sct:
        lines += ["", sct]
    if sch:
        hlines.insert(1, f"<div style='margin:10px 0'>{sch}</div>")
    # tag filter deep-link so they can see the whole set in-platform
    tv = sorted(entry["tag_values"])[0] if entry["tag_values"] else ""
    if tv:
        furl = _tag_filter_url(entry.get("tag_key") or "Owner", tv)
        lines += ["", f"See all your tagged assets in Tenable: {furl}"]
    lines.append(_SIGN)

    subject = (f"[Tenable] {n} asset{'s' if n!=1 else ''} need your attention"
               + (f" — {kev_n} actively exploited" if kev_n else "") + f" ({owner})")
    body_text = "\n".join([l for l in lines if l is not None])
    body_html = _html_wrap(subject, "\n".join(hlines) + _sign_html())
    to = _guess_email(owner, domain)
    return {"to": to, "owner": owner, "subject": subject, "body_text": body_text,
            "body_html": body_html, "asset_count": n, "kev_count": kev_n,
            "needs_address": not bool(to)}


def _kev_message(domain, to):
    kev = _kev_uuids()
    meta = _asset_meta(list(kev))
    n = len(kev)
    ordered = sorted(kev, key=lambda u: -_flt(meta.get(u, {}).get("acr")))
    lines = ["🔥 CISA KEV fire-alarm — assets with an actively-exploited vulnerability", "",
             f"{n} asset{'s' if n!=1 else ''} in the estate currently carry a CISA "
             f"Known-Exploited vulnerability. These are being used by attackers in the wild "
             f"— patch first.", ""]
    hrows = []
    for u in ordered[:60]:
        m = meta.get(u, {})
        host = m.get("hostname") or m.get("ip_address") or u
        url = m.get("url") or ""
        acr = m.get("acr")
        lines.append(f"• {host} ({m.get('ip_address') or '—'})" + (f" · ACR {acr}" if acr else "")
                     + (f"\n    {url}" if url else ""))
        hrows.append(f"<li><b>{_esc(host)}</b> ({_esc(m.get('ip_address') or '—')})"
                     + (f" · ACR {_esc(acr)}" if acr else "")
                     + (f" — <a href='{_esc(url)}'>open ↗</a>" if url else "") + "</li>")
    if n > 60:
        lines.append(f"… and {n-60} more.")
    # graphic: KEV assets by ACR band
    band = {"Crown-jewel (9-10)": 0, "High (7-8)": 0, "Medium (4-6)": 0, "Low (1-3)": 0}
    for u in kev:
        a = _flt(meta.get(u, {}).get("acr"))
        band["Crown-jewel (9-10)" if a >= 9 else "High (7-8)" if a >= 7 else "Medium (4-6)" if a >= 4 else "Low (1-3)"] += 1
    kpairs = [(k, v) for k, v in band.items() if v]
    kct, kch = _chart_block(kpairs, "KEV assets by criticality (ACR)")
    if kct:
        lines += ["", kct]
    lines.append(_SIGN)
    subject = f"🔥 [Tenable] {n} asset{'s' if n!=1 else ''} with actively-exploited (CISA KEV) vulns"
    body_html = _html_wrap(subject, f"<p>{n} assets carry a CISA Known-Exploited vulnerability "
                           "— attackers are using these in the wild. Patch first.</p>"
                           + (f"<div style='margin:10px 0'>{kch}</div>" if kch else "") + "<ul>"
                           + "".join(hrows) + "</ul>" + _sign_html())
    return {"to": to, "owner": "Security team", "subject": subject,
            "body_text": "\n".join(lines), "body_html": body_html,
            "asset_count": n, "kev_count": n, "needs_address": not bool(to)}


def _cert_message(days, to):
    rows = _cert_rows(days)
    n = len(rows)
    lines = [f"⏳ Certificate countdown — expiring within {days} days", "",
             f"{n} certificate{'s' if n!=1 else ''} will expire in the next {days} days. "
             f"Renew before they break a service.", ""]
    hrows = []
    for c in rows[:80]:
        cn = c.get("common_name") or "(no CN)"
        dl = c.get("days_left")
        when = f"{dl}d" if dl is not None else c.get("expiry", "?")
        lines.append(f"• {cn} — {when} left (expires {c.get('expiry','?')})")
        hrows.append(f"<li><b>{_esc(cn)}</b> — <span style='color:#d9772b'>{_esc(when)} left</span>"
                     f" (expires {_esc(c.get('expiry','?'))})</li>")
    # graphic: certs bucketed by urgency
    buck = {"≤7 days": 0, "8–30 days": 0, "31–90 days": 0, "91+ days": 0}
    for c in rows:
        dl = c.get("days_left")
        dl = dl if dl is not None else 999
        buck["≤7 days" if dl <= 7 else "8–30 days" if dl <= 30 else "31–90 days" if dl <= 90 else "91+ days"] += 1
    cpairs = [(k, v) for k, v in buck.items() if v]
    cct, cch = _chart_block(cpairs, "Certificates by urgency")
    if cct:
        lines += ["", cct]
    lines.append(_SIGN)
    subject = f"⏳ [Tenable] {n} certificate{'s' if n!=1 else ''} expiring within {days} days"
    body_html = _html_wrap(subject, f"<p>{n} certificates expire within {days} days. Renew before "
                           "they break a service.</p>"
                           + (f"<div style='margin:10px 0'>{cch}</div>" if cch else "") + "<ul>"
                           + "".join(hrows) + "</ul>" + _sign_html())
    return {"to": to, "owner": "Cert owners", "subject": subject,
            "body_text": "\n".join(lines), "body_html": body_html,
            "asset_count": n, "needs_address": not bool(to)}


def _briefing_message(to):
    b = _briefing_numbers()
    pairs = [("CISA KEV", b['kev_assets']), ("Critical", b['critical_assets']),
             ("Certs ≤30d", b['certs_expiring_30d'])]
    ct, ch = _chart_block(pairs, "Pressing exposure")
    lines = ["🌅 Morning briefing — exposure at a glance", "",
             f"Assets in scope:        {b['assets']}",
             f"Assets with CISA KEV:   {b['kev_assets']}",
             f"Assets with a critical: {b['critical_assets']}",
             f"Certs expiring ≤30d:    {b['certs_expiring_30d']}",
             ct, "",
             "Full detail is in the Hounds console.", _SIGN]
    subject = (f"🌅 [Tenable] Morning briefing — {b['kev_assets']} KEV · "
               f"{b['critical_assets']} critical · {b['certs_expiring_30d']} certs due")
    cards = "".join(f"<div style='display:inline-block;min-width:120px;margin:6px 10px 6px 0;"
                    f"padding:10px 14px;border:1px solid #e2e8f0;border-radius:10px;background:#fbfcfe'>"
                    f"<div style='font-size:26px;font-weight:800;color:#0f172a'>{v}</div>"
                    f"<div style='color:#64748b;font-size:12px'>{_esc(k)}</div></div>"
                    for k, v in [("assets in scope", b['assets']),
                                 ("with CISA KEV", b['kev_assets']),
                                 ("with a critical", b['critical_assets']),
                                 ("certs ≤30d", b['certs_expiring_30d'])])
    body_html = _html_wrap(subject, "<p>Exposure at a glance:</p>" + cards
                           + (f"<div style='margin:12px 0'>{ch}</div>" if ch else "") + _sign_html())
    return {"to": to, "owner": "Leadership", "subject": subject,
            "body_text": "\n".join(lines), "body_html": body_html,
            "asset_count": b['assets'], "needs_address": not bool(to)}


def _contract_message(kind, to, payload):
    title = "the plan" if kind == "contract_plan" else "the result"
    body = (payload or {}).get("text") or ""
    when = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [f"🤝 AI Contract — {title} ({when})", "", body or "(no detail supplied)", _SIGN]
    subject = f"🤝 [Tenable] AI Contract {('plan' if kind=='contract_plan' else 'result')} — {when}"
    body_html = _html_wrap(subject, f"<p><b>AI Contract — {title}</b> ({_esc(when)})</p>"
                           f"<pre style='white-space:pre-wrap'>{_esc(body)}</pre>" + _sign_html())
    return {"to": to, "owner": "Contract watchers", "subject": subject,
            "body_text": "\n".join(lines), "body_html": body_html,
            "asset_count": 0, "needs_address": not bool(to)}


# Known per-agent detection signals (the finding IDs that make up each Hound's asset
# search). Used when the hand-off doesn't carry explicit finding_ids. Agents whose
# detection is name/xref/signal-based (not a fixed plugin set) fall back to deriving the
# top plugins from the tagged assets.
_AGENT_SIGNALS = {
    "scan_eval": ["104410", "21745", "19506"],
    "postquantum": ["277650", "277654", "70657", "153588", "56984", "277652", "277653"],
    "identity": ["83303", "10860", "41028", "10859", "149334", "17651", "104410", "110723"],
    "iot_squad": [],
}
_AGENT_HOUND = {
    "cisakev": "Laelaps", "certificate": "Certania", "postquantum": "Heimdall",
    "attackpath": "Fenrir", "iot_squad": "Cerberus", "ai": "Pythia", "exproute": "Atlas",
    "software": "Mimir", "eol": "Charon", "acr": "Anubis", "scan_eval": "Chronos",
    "agentgroup": "Sirius", "tagremoval": "Garmr", "mitre": "Orthrus", "customapp": "Cavall",
    "identity": "Janus", "insights": "Sphinx",
}


def _uuids_for_tag(category, value):
    tc = _cols("tags")
    if not tc or "asset_uuid" not in tc:
        return []
    kc = "tag_key" if "tag_key" in tc else ("category" if "category" in tc else None)
    vc = "tag_value" if "tag_value" in tc else ("value" if "value" in tc else None)
    if not kc or not vc:
        return []
    try:
        rows = db.query(f"SELECT DISTINCT asset_uuid FROM tags WHERE {kc}=? AND {vc}=?;",
                        (category, value))
        return [r.get("asset_uuid") for r in rows if r.get("asset_uuid")]
    except Exception:
        return []


def _derive_plugins(uuids, limit=25):
    """Top plugin_ids across an asset set, worst severity first — the findings that make
    up the set when the agent didn't hand us an explicit signal list."""
    if not uuids:
        return []
    vc = _cols("vulns")
    if not vc or "plugin_id" not in vc or "asset_uuid" not in vc:
        return []
    inl = ",".join("'" + str(u).replace("'", "''") + "'" for u in list(uuids)[:2000])
    sevexpr = "severity" if "severity" in vc else "'3'"
    try:
        rows = db.query(f"SELECT plugin_id, COUNT(DISTINCT asset_uuid) n, MIN({sevexpr}) sev "
                        f"FROM vulns WHERE asset_uuid IN ({inl}) AND plugin_id IS NOT NULL "
                        f"GROUP BY plugin_id ORDER BY n DESC LIMIT {int(limit)};")
        return [str(r.get("plugin_id")) for r in rows if r.get("plugin_id")]
    except Exception:
        return []


def _assets_per_category():
    """COUNT(DISTINCT asset_uuid) grouped by tag category — 'against how many assets'."""
    tc = _cols("tags")
    if not tc or "asset_uuid" not in tc:
        return {}
    kc = "tag_key" if "tag_key" in tc else ("category" if "category" in tc else None)
    if not kc:
        return {}
    try:
        rows = db.query(f"SELECT {kc} k, COUNT(DISTINCT asset_uuid) n FROM tags "
                        f"WHERE {kc} IS NOT NULL GROUP BY {kc};")
        return {r.get("k"): int(r.get("n") or 0) for r in rows}
    except Exception:
        return {}


def _contract_summary_message(payload, to):
    """The AI Contract's post-run report: how many tags were deployed in each category and
    against how many assets, plus errors and which agents didn't run / weren't enabled.
    Reads the live tag log (tagq) + navi.db; merges an optional plan payload from the
    Contract page for the enabled/disabled/selected picture."""
    payload = payload or {}
    # 1) deployed tags + errors — from the live tag log (this process shares tagq)
    jobs = payload.get("tag_jobs")
    if jobs is None:
        try:
            from core import tagq
            jobs = tagq.list_jobs()
        except Exception:
            jobs = []
    by_cat, errors = {}, []
    for j in jobs:
        cat = j.get("category") or "(uncategorized)"
        st = (j.get("status") or ("done" if j.get("ok") else "")).lower()
        ok = (st == "done") or bool(j.get("ok"))
        e = by_cat.setdefault(cat, {"deployed": 0, "errors": 0, "values": set()})
        if ok:
            e["deployed"] += 1
            if j.get("value"):
                e["values"].add(j.get("value"))
        elif st == "error" or j.get("ok") is False:
            e["errors"] += 1
            errors.append({"category": cat, "value": j.get("value"),
                           "agent": j.get("agent"), "message": (j.get("message") or "")[:160]})
    # 2) assets per category — from navi.db
    apc = _assets_per_category()

    # 3) which agents didn't run / weren't enabled — from the plan payload
    plan_agents = payload.get("plan_agents") or []   # [{agent,selected,error,enabled}]
    disabled = [a.get("agent") for a in plan_agents if a.get("enabled") is False]
    zero = [a.get("agent") for a in plan_agents if a.get("enabled") is not False
            and not a.get("error") and (a.get("selected") or 0) == 0]
    errored_agents = [(a.get("agent"), a.get("error")) for a in plan_agents if a.get("error")]
    armed = payload.get("armed")

    cats = sorted(by_cat.items(), key=lambda kv: -kv[1]["deployed"])
    total_tags = sum(v["deployed"] for _, v in cats)
    total_err = sum(v["errors"] for _, v in cats)
    total_assets = sum(apc.get(c, 0) for c, _ in cats) if cats else sum(apc.values())

    # charts
    tag_pairs = [(c, v["deployed"]) for c, v in cats if v["deployed"]]
    asset_pairs = [(c, apc.get(c, 0)) for c, _ in cats if apc.get(c, 0)]
    tct, tch = _chart_block(tag_pairs, "Tags deployed by category")
    act, ach = _chart_block(asset_pairs, "Assets tagged by category", unit="")

    # text body
    L = [f"📜 AI Contract — run summary ({'ARMED · executed' if armed else 'PLAN · preview'})", "",
         f"Tags deployed: {total_tags} across {len(tag_pairs)} categor{'y' if len(tag_pairs)==1 else 'ies'}"
         + (f", touching ~{total_assets} assets" if total_assets else "") + ".",
         (f"Errors: {total_err + len(errored_agents)}." if (total_err or errored_agents) else "No errors."), ""]
    if tag_pairs:
        L += [tct, ""]
    if asset_pairs:
        L += [act, ""]
    L.append("By category:")
    for c, v in cats:
        L.append(f"  • {c}: {v['deployed']} tag{'s' if v['deployed']!=1 else ''}"
                 + (f" · ~{apc.get(c,0)} assets" if apc.get(c) else "")
                 + (f" · {v['errors']} error(s)" if v["errors"] else ""))
    if not cats:
        L.append("  (no tags deployed this run)")
    if disabled:
        L += ["", "Not enabled (skipped in the contract): " + ", ".join(str(x) for x in disabled)]
    if zero:
        L += ["Ran but matched nothing: " + ", ".join(str(x) for x in zero)]
    if errored_agents:
        L += ["", "Agents that errored:"] + [f"  • {a}: {e}" for a, e in errored_agents]
    if errors:
        L += ["", "Tag write errors:"] + [f"  • {x['category']} : {x['value']} — {x['message']}" for x in errors[:20]]
    L.append(_SIGN)

    # html body (charts first)
    hstat = "".join(
        f"<div style='display:inline-block;min-width:120px;margin:6px 10px 6px 0;padding:10px 14px;"
        f"border:1px solid #e2e8f0;border-radius:10px;background:#fbfcfe'><div style='font-size:26px;font-weight:800;color:{col}'>{val}</div>"
        f"<div style='color:#64748b;font-size:12px'>{_esc(lab)}</div></div>"
        for lab, val, col in [("tags deployed", total_tags, "#0b6b47"),
                              ("categories", len(tag_pairs), "#3559b3"),
                              ("~assets tagged", total_assets, "#0b6b47"),
                              ("errors", total_err + len(errored_agents), "#c81e3f" if (total_err or errored_agents) else "#64748b")])
    hcat = "".join(f"<li><b>{_esc(c)}</b> — {v['deployed']} tag{'s' if v['deployed']!=1 else ''}"
                   + (f" · ~{apc.get(c,0)} assets" if apc.get(c) else "")
                   + (f" · <span style='color:#e11d48'>{v['errors']} error(s)</span>" if v['errors'] else "") + "</li>"
                   for c, v in cats) or "<li style='color:#64748b'>no tags deployed this run</li>"
    skip_html = ""
    if disabled:
        skip_html += f"<p style='color:#8a99ad'><b>Not enabled</b> (skipped): {_esc(', '.join(str(x) for x in disabled))}</p>"
    if zero:
        skip_html += f"<p style='color:#8a99ad'><b>Ran, matched nothing:</b> {_esc(', '.join(str(x) for x in zero))}</p>"
    err_html = ""
    if errored_agents or errors:
        items = "".join(f"<li>{_esc(a)}: {_esc(e)}</li>" for a, e in errored_agents) + \
                "".join(f"<li>{_esc(x['category'])} : {_esc(x['value'])} — {_esc(x['message'])}</li>" for x in errors[:20])
        err_html = f"<p style='color:#c81e3f;margin-bottom:4px'><b>Errors</b></p><ul>{items}</ul>"
    inner = (f"<p><b>AI Contract — run summary</b> · {'ARMED · executed' if armed else 'PLAN · preview'}</p>"
             + hstat
             + (f"<div style='margin:12px 0'>{tch}</div>" if tch else "")
             + (f"<div style='margin:12px 0'>{ach}</div>" if ach else "")
             + f"<p style='margin-bottom:4px'><b>By category</b></p><ul>{hcat}</ul>"
             + skip_html + err_html + _sign_html())
    subject = (f"📜 [Tenable] AI Contract summary — {total_tags} tags / {len(tag_pairs)} categories"
               + (f" · {total_err+len(errored_agents)} errors" if (total_err or errored_agents) else ""))
    return {"to": to or payload.get("to") or "", "owner": "Contract watchers", "subject": subject,
            "body_text": "\n".join(L), "body_html": _html_wrap(subject, inner),
            "asset_count": total_assets, "needs_address": not bool(to or payload.get("to"))}


def _plugin_names(finding_ids):
    """Resolve plugin_id -> plugin_name for the finding IDs that drove an agent's search
    (so the email names the detection signals, not just bare numbers)."""
    ids = [str(x).strip() for x in (finding_ids or []) if str(x).strip()]
    if not ids:
        return {}
    vc = _cols("vulns")
    if not vc or "plugin_id" not in vc:
        return {}
    inl = ",".join("'" + i.replace("'", "''") + "'" for i in ids[:400])
    try:
        rows = db.query(f"SELECT DISTINCT plugin_id, plugin_name FROM vulns "
                        f"WHERE plugin_id IN ({inl});")
        return {str(r.get("plugin_id")): r.get("plugin_name") for r in rows}
    except Exception:
        return {}


def _findings_message(payload, template, domain, to):
    """Generic HAND-OFF from ANY hound to Gabriel. The agent passes the finding IDs
    (plugins) that made up its asset search + the matched assets + the tag it applied;
    Gabriel emails a high-level overview, the detection signals, the tagged assets with
    Tenable deep-links, and says which Hound produced the detail."""
    payload = payload or {}
    agent = (payload.get("source_agent") or "").strip()
    hound = (payload.get("source_hound") or payload.get("hound")
             or _AGENT_HOUND.get(agent) or "a Hound").strip()
    headline = (payload.get("headline") or f"{hound} findings").strip()
    fids = [str(x).strip() for x in (payload.get("finding_ids") or []) if str(x).strip()]
    uuids = [str(x).strip() for x in (payload.get("asset_uuids") or []) if str(x).strip()]
    tag = payload.get("tag") or {}
    tcat, tval = tag.get("category", ""), tag.get("value", "")
    to = to or payload.get("to") or ""

    # Resolve the asset set + detection signals SERVER-SIDE when the hand-off didn't carry
    # them — so an agent only has to pass {source_agent, tag} and Gabriel does the rest.
    if not uuids and tcat and tval:
        uuids = _uuids_for_tag(tcat, tval)
    if not fids:
        fids = _AGENT_SIGNALS.get(agent) if agent in _AGENT_SIGNALS else None
        if not fids:
            fids = _derive_plugins(uuids)

    pnames = _plugin_names(fids)
    meta = _asset_meta(uuids)
    kev = _kev_uuids()
    vulns = _vulns_for(uuids, min_rank=1) if template == "technical" else {}
    n = len(uuids)
    kev_n = sum(1 for u in uuids if u in kev)

    # high-level overview
    lines = [f"🐾 {headline}", "",
             f"{hound} identified {n} asset{'s' if n!=1 else ''}"
             + (f" using {len(fids)} detection signal{'s' if len(fids)!=1 else ''}." if fids else ".")]
    if kev_n:
        lines.append(f"{kev_n} of them carry a CISA Known-Exploited vulnerability.")
    if tcat and tval:
        lines.append(f"Tag applied in Tenable: {tcat} : {tval}")
    lines.append("")

    if fids:
        lines.append("Detection signals (the finding IDs that made up this search):")
        for i in fids[:60]:
            nm = pnames.get(i)
            lines.append(f"  • plugin {i}" + (f" — {nm}" if nm else ""))
        if len(fids) > 60:
            lines.append(f"  … and {len(fids)-60} more")
        lines.append("")

    lines.append("Assets:")
    ordered = sorted(uuids, key=lambda u: (0 if u in kev else 1, -_flt(meta.get(u, {}).get("acr"))))
    for u in ordered[:40]:
        m = meta.get(u, {})
        host = m.get("hostname") or m.get("ip_address") or u
        url = m.get("url") or ""
        lines.append(f"  • {host} ({m.get('ip_address') or '—'})"
                     + (" · 🔥 KEV" if u in kev else "") + (f"\n      {url}" if url else ""))
        if template == "technical":
            for v in vulns.get(u, []):
                vu = f"  →  {v['url']}" if v.get("url") else ""
                lines.append(f"      {_sev_tag(v['severity'])} "
                             f"{v.get('plugin_name') or v.get('plugin_id')}{vu}")
    if n > 40:
        lines.append(f"  … and {n-40} more asset{'s' if n-40!=1 else ''}.")
    # graphic: severity mix of the matched set
    sev = _sev_counts(uuids)
    sev_pairs = [(k.capitalize(), sev[k]) for k in _SEV_ORDER if sev[k]]
    fct, fch = _chart_block(sev_pairs, "Findings by severity")
    if fct:
        lines += ["", fct]
    if tcat and tval:
        lines += ["", f"View this set in Tenable (filtered by tag): {_tag_filter_url(tcat, tval)}"]
    lines += ["", f"Details produced by: {hound}" + (f" ({agent})" if agent else ""), _SIGN]

    # html preview
    sig_rows = "".join(f"<li>plugin <b>{_esc(i)}</b>" + (f" — {_esc(pnames.get(i))}" if pnames.get(i) else "") + "</li>"
                       for i in fids[:60])
    asset_rows = "".join(
        f"<li><b>{_esc((meta.get(u,{}) or {}).get('hostname') or (meta.get(u,{}) or {}).get('ip_address') or u)}</b>"
        f" <span style='color:#8a99ad'>({_esc((meta.get(u,{}) or {}).get('ip_address') or '—')})</span>"
        + (" <span style='color:#c81e3f'>🔥 KEV</span>" if u in kev else "")
        + (f" — <a href='{_esc((meta.get(u,{}) or {}).get('url'))}'>open ↗</a>" if (meta.get(u,{}) or {}).get('url') else "")
        + "</li>" for u in ordered[:40])
    inner = (f"<p><b>{_esc(hound)}</b> identified <b>{n}</b> asset{'s' if n!=1 else ''}"
             + (f" using <b>{len(fids)}</b> detection signal{'s' if len(fids)!=1 else ''}." if fids else ".")
             + (f" <b>{kev_n}</b> carry a CISA KEV vuln." if kev_n else "") + "</p>"
             + (f"<p style='color:#8a99ad'>Tag applied: <b>{_esc(tcat)} : {_esc(tval)}</b></p>" if tcat and tval else "")
             + (f"<div style='margin:10px 0'>{fch}</div>" if fch else "")
             + (f"<p style='margin-bottom:4px'><b>Detection signals</b> (finding IDs that made up the search):</p><ul>{sig_rows}</ul>" if fids else "")
             + f"<p style='margin-bottom:4px'><b>Assets</b></p><ul>{asset_rows}</ul>"
             + (f"<p><a href='{_esc(_tag_filter_url(tcat, tval))}'>View this tagged set in Tenable ↗</a></p>" if tcat and tval else "")
             + f"<p style='color:#8a99ad;font-size:12px'>Details produced by {_esc(hound)}"
             + (f" ({_esc(agent)})" if agent else "") + "</p>")
    subject = f"🐾 [Tenable] {headline} — {n} asset{'s' if n!=1 else ''}" + (f", {kev_n} KEV" if kev_n else "")
    return {"to": to, "owner": hound, "subject": subject, "body_text": "\n".join(lines),
            "body_html": _html_wrap(subject, inner + _sign_html()),
            "asset_count": n, "kev_count": kev_n, "needs_address": not bool(to)}


# --------------------------------------------------------------------------- #
#  Chart graphics — EVERY email carries a visual. Two renderings from one dataset:
#   • text: Unicode block bars (render in ANY mail client, even plain-text)
#   • html: a self-contained inline SVG bar chart (renders in the console preview
#     and HTML-capable mail clients). No external libraries, no images to attach.
# --------------------------------------------------------------------------- #
_BLK = "█"
_SVG_PALETTE = ["#3559b3", "#c05a25", "#0d9488", "#b7791f", "#b23a72", "#0b6b47", "#6a5bc4", "#c81e3f"]


def _bars_text(pairs, width=22):
    """pairs = [(label, value), …] → aligned Unicode bar chart lines."""
    pairs = [(str(l), float(v or 0)) for l, v in pairs]
    if not pairs:
        return "(no data)"
    mx = max((v for _, v in pairs), default=0) or 1
    lw = min(24, max((len(l) for l, _ in pairs), default=4))
    out = []
    for l, v in pairs:
        n = int(round(v / mx * width))
        out.append(f"  {l[:lw].ljust(lw)} {_BLK * max(n, 1 if v else 0)} {int(v) if v == int(v) else round(v,1)}")
    return "\n".join(out)


# Light, email-client-safe palette (SVG isn't rendered by Gmail/Outlook, so charts are
# built from plain <div>/<table> with inline styles instead).
_HTML_PALETTE = ["#3559b3", "#c05a25", "#0d9488", "#b7791f", "#b23a72", "#0b6b47", "#6a5bc4", "#c81e3f"]

# Hounds Signature severity — semantic colors so severity charts read red→slate, not by index.
_SEV_HTML = {"critical": "#c81e3f", "high": "#d9772b", "medium": "#b7791f", "low": "#2f6fb0", "info": "#5b6580"}


def _bars_svg(pairs, title="", unit=""):
    """pairs = [(label, value), …] → an EMAIL-SAFE horizontal bar chart built from
    <div> rows (no SVG — Gmail/Outlook strip <svg>, which is why charts didn't show).
    Light theme so it reads on a white email background."""
    pairs = [(str(l), float(v or 0)) for l, v in pairs]
    if not pairs:
        return ""
    mx = max((v for _, v in pairs), default=0) or 1
    rows = []
    if title:
        rows.append(f"<div style='font-size:13px;font-weight:700;color:#0f172a;margin:2px 0 8px'>{_esc(title)}</div>")
    for i, (l, v) in enumerate(pairs):
        pct = int(round(v / mx * 100)) if v else 0
        c = _SEV_HTML.get(l.strip().lower().split()[0] if l.strip() else "", _HTML_PALETTE[i % len(_HTML_PALETTE)])
        val = int(v) if v == int(v) else round(v, 1)
        rows.append(
            f"<div style='margin:6px 0'>"
            f"<div style='font-size:12px;color:#334155;margin-bottom:2px'>{_esc(l[:44])} — "
            f"<b style='color:#0f172a'>{val}{_esc(unit)}</b></div>"
            f"<div style='height:13px;background:#eef2f7;border-radius:6px;overflow:hidden'>"
            f"<div style='width:{max(pct, 2) if v else 0}%;height:100%;background:{c};border-radius:6px'></div>"
            f"</div></div>")
    return ("<div style='border:1px solid #e2e8f0;border-left:3px solid #8b8fe6;border-radius:10px;"
            "padding:10px 12px;margin:6px 0;background:#fbfcfe'>" + "".join(rows) + "</div>")


def _sev_counts(uuids):
    """Severity histogram across an asset set — {critical,high,medium,low,info}."""
    out = {k: 0 for k in _SEV_ORDER}
    if not uuids:
        return out
    vc = _cols("vulns")
    if not vc or "asset_uuid" not in vc or "severity" not in vc:
        return out
    inl = ",".join("'" + str(u).replace("'", "''") + "'" for u in list(uuids)[:2000])
    try:
        rows = db.query(f"SELECT severity, COUNT(*) n FROM vulns WHERE asset_uuid IN ({inl}) GROUP BY severity;")
        for r in rows:
            sn = _sev_name(r.get("severity"))
            if sn in out:
                out[sn] += int(r.get("n") or 0)
    except Exception:
        pass
    return out


def _chart_block(pairs, title, unit=""):
    """Return (text_chart, html_chart) for a dataset — used by every report."""
    return ("\n" + title + ":\n" + _bars_text(pairs) if pairs else "",
            _bars_svg(pairs, title, unit) if pairs else "")


# ---- HTML helpers (preview only) ---------------------------------------------
def _esc(s):
    return (str(s if s is not None else "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _sign_html():
    return ("<p style='color:#8a99ad;font-size:12px;margin-top:16px'>— The Hounds · "
            "automated by navi (reply to reach the security team)</p>")


def _html_wrap(subject, inner):
    # Light theme — reads well in an email client (dark background looked bad in mail).
    return (f"<div style='font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:640px;"
            f"color:#0f172a;background:#ffffff;border:1px solid #e2e8f0;border-top:4px solid #8b8fe6;"
            f"border-radius:12px;padding:18px 20px'>"
            f"<div style='font-family:ui-monospace,Menlo,monospace;font-size:10px;letter-spacing:.14em;"
            f"text-transform:uppercase;color:#5457cc;font-weight:700;margin-bottom:6px'>\U0001F43E The Hounds</div>"
            f"<div style='font-weight:800;font-size:16px;margin-bottom:8px;"
            f"color:#0f172a'>{_esc(subject)}</div>{inner}</div>")


# --------------------------------------------------------------------------- #
#  Actions
# --------------------------------------------------------------------------- #
def _gate():
    from core import navi_cli
    return {"email_enabled": navi_cli.email_enabled(),
            "allow_writes": navi_cli.allow_writes(),
            "navi_available": navi_cli.navi_available(),
            "reason": navi_cli.email_gate_reason()}


def status(p):
    return {"ok": True, **_gate()}, 200


def recipients(p):
    """The owner-routing table — wires Atlas Owner: tags to Gabriel."""
    domain = (p.get("domain") or "").strip()
    idx = _owner_index()
    kev = _kev_uuids()
    out = []
    for owner, e in sorted(idx.items(), key=lambda kv: -len(kv[1]["assets"])):
        uuids = e["assets"]
        out.append({"owner": owner, "apps": sorted(e["apps"]),
                    "assets": len(uuids), "kev": len(uuids & kev),
                    "email": _guess_email(owner, domain),
                    "tag_value": sorted(e["tag_values"])[0] if e["tag_values"] else ""})
    return {"ok": True, "owners": out, "count": len(out),
            "total_owned_assets": sum(o["assets"] for o in out),
            "domain": domain, **_gate()}, 200


def _sphinx_message(to):
    """On the Scent daily digest — the Sphinx visualization data as an HTML email."""
    from core import insights
    r = insights.compute()
    S = r.get("stories", {}) or {}
    total = r.get("asset_total", 0) or 0
    kev, owned, inv = S.get("kev", 0), S.get("owned", 0), S.get("inventory", 0)
    cloud, shadow, certN = r.get("cloud_assets", 0), r.get("shadow_assets", 0), r.get("certs_failing", 0)
    ownerless = max(0, total - owned)
    pq, funnel, champ = (S.get("pq") or {}), (S.get("funnel") or {}), (S.get("champion") or {})
    date = datetime.date.today().isoformat()

    def pct(a, b):
        return (int(a) * 1000 // int(b)) / 10 if b else 0

    SEV = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}
    sev_pairs = [(SEV[x["sev"]], x.get("count", 0)) for x in (S.get("severity") or []) if x.get("sev") in SEV]
    order = ["Critical", "High", "Medium", "Low", "Info"]
    sev_pairs.sort(key=lambda p: order.index(p[0]) if p[0] in order else 9)
    top_pairs = [(t.get("app") or "—", t.get("vulns", 0)) for t in (S.get("top_routes") or []) if t.get("vulns")]

    def kpi(v, l, c="#0f172a"):
        return (f"<td style='padding:5px'><div style='border:1px solid #e2e8f0;border-radius:10px;"
                f"padding:10px 8px;text-align:center'><div style='font-size:21px;font-weight:800;"
                f"color:{c}'>{v:,}</div><div style='font-size:11px;color:#64748b'>{l}</div></div></td>")
    kpis = ("<table style='width:100%;border-collapse:collapse'><tr>"
            + kpi(total, "assets") + kpi(kev, "🔥 KEV assets", "#e11d48") + kpi(ownerless, "Ownerless Risk", "#e11d48")
            + "</tr><tr>" + kpi(certN, "certs ≤12mo", "#f59e0b") + kpi(shadow, "shadow software", "#f59e0b")
            + kpi(cloud, "cloud assets", "#2563eb") + "</tr></table>")

    def bar(l, pv, c):
        return (f"<div style='margin:6px 0'><div style='font-size:12px;color:#334155;margin-bottom:2px'>{l} — "
                f"<b>{pv}%</b></div><div style='height:12px;background:#eef2f7;border-radius:6px;overflow:hidden'>"
                f"<div style='width:{min(100, pv)}%;height:100%;background:{c}'></div></div></div>")
    cov = (bar("Ownership coverage", pct(owned, total), "#16a34a")
           + bar("Software-inventory coverage", pct(inv, total), "#16a34a")
           + bar("KEV exposure", pct(kev, total), "#e11d48")
           + bar("Post-quantum at-risk certs", pct(pq.get("vuln", 0), pq.get("vuln", 0) + pq.get("safe", 0)), "#e11d48"))
    _, sev_svg = _chart_block(sev_pairs, "Findings by severity")
    _, top_svg = _chart_block(top_pairs, "Top apps / routes by exposure")
    redu = ""
    if funnel.get("cves"):
        redu = (f"<p style='margin:12px 0;font-size:13px'>📉 <b>The reduction:</b> {funnel['cves']:,} CVEs → "
                f"{funnel.get('routes', 0):,} apps — <b>{pct(funnel['cves'] - funnel.get('routes', 0), funnel['cves'])}% "
                f"fewer</b> things to track if you own at the app level.</p>")
    champ_html = ""
    if champ.get("cve_count"):
        champ_html = (f"<div style='border-left:3px solid #a3b81a;background:#f7fbe0;padding:8px 12px;"
                      f"border-radius:6px;margin:8px 0;font-size:13px'><b>🏆 One fix, {champ['cve_count']:,} CVEs</b> — "
                      f"patch <b>{_esc(champ.get('name') or '')}</b> to clear {champ['cve_count']:,} CVEs on "
                      f"{champ.get('assets', 0)} asset{'s' if champ.get('assets', 0) != 1 else ''}.</div>")
    inner = (f"<p style='color:#64748b;margin:0 0 10px'>🐾 On the Scent · daily unknown-unknowns digest · {date}</p>"
             + kpis + "<h3 style='margin:14px 0 6px;font-size:14px'>Coverage &amp; blind spots</h3>" + cov + redu + champ_html
             + (f"<div style='margin:12px 0 4px'>{sev_svg}</div>" if sev_svg else "")
             + (f"<div style='margin:12px 0 4px'>{top_svg}</div>" if top_svg else ""))
    subject = f"[Tenable] On the Scent digest — {kev} KEV · {ownerless} Ownerless · {date}"
    lines = [f"On the Scent — daily digest ({date})", "",
             f"Assets: {total}", f"KEV assets: {kev}", f"Ownerless Risk: {ownerless}",
             f"Certs failing <=12mo: {certN}", f"Shadow software: {shadow}", f"Cloud assets: {cloud}", "",
             f"Ownership coverage: {pct(owned, total)}%", f"Inventory coverage: {pct(inv, total)}%",
             f"KEV exposure: {pct(kev, total)}%",
             f"PQ at-risk certs: {pct(pq.get('vuln', 0), pq.get('vuln', 0) + pq.get('safe', 0))}%", ""]
    if funnel.get("cves"):
        lines.append(f"Reduction: {funnel['cves']} CVEs -> {funnel.get('routes', 0)} apps "
                     f"({pct(funnel['cves'] - funnel.get('routes', 0), funnel['cves'])}% fewer).")
    if champ.get("cve_count"):
        lines.append(f"Champion fix: {champ.get('name')} clears {champ['cve_count']} CVEs.")
    lines.append(_SIGN)
    return {"to": to, "owner": "On the Scent", "subject": subject,
            "body_text": "\n".join(lines), "body_html": _html_wrap(subject, inner + _sign_html()),
            "asset_count": total, "kev_count": kev, "needs_address": not bool(to)}


def preview(p):
    report = (p.get("report") or "owner_remediation").strip()
    template = (p.get("template") or "technical").strip()
    domain = (p.get("domain") or "").strip()
    to = (p.get("to") or "").strip()
    days = int(p.get("days") or 30)
    # severity floor: technical → high+critical (rank<=1), board → critical only handled per report
    min_rank = 1 if (p.get("severity") or "high") == "high" else 0

    msgs = []
    if report in ("owner_remediation", "vuln_detail"):
        idx = _owner_index()
        only = (p.get("owner") or "").strip()
        items = idx.items()
        if only:
            items = [(o, e) for o, e in idx.items() if o == only]
        for owner, e in sorted(items, key=lambda kv: -len(kv[1]["assets"])):
            if not e["assets"]:
                continue
            msgs.append(_owner_message(owner, e, template, domain, min_rank))
        if not msgs:
            return {"ok": True, "messages": [], "report": report,
                    "note": "No Owner: tags found in navi.db yet. Run the Ownership (Atlas) "
                            "agent first to assign owners, then Gabriel can route to them.",
                    **_gate()}, 200
    elif report == "kev_alarm":
        msgs = [_kev_message(domain, to)]
    elif report == "cert_countdown":
        msgs = [_cert_message(days, to)]
    elif report == "briefing":
        msgs = [_briefing_message(to)]
    elif report in ("contract_plan", "contract_result"):
        msgs = [_contract_message(report, to, p.get("payload"))]
    elif report == "contract_summary":
        msgs = [_contract_summary_message(p.get("payload") or p, to)]
    elif report == "agent_findings":
        msgs = [_findings_message(p.get("payload") or p, template, domain, to)]
    elif report == "sphinx_digest":
        msgs = [_sphinx_message(to)]
    else:
        return {"ok": False, "error": f"unknown report '{report}'"}, 400

    return {"ok": True, "report": report, "template": template, "messages": msgs,
            "count": len(msgs),
            "addressable": sum(1 for m in msgs if not m.get("needs_address")),
            **_gate()}, 200


def send(p):
    """DOUBLE-gated send. Requires confirm=True (UI approval) AND the server email gate
    (NAVI_ALLOW_WRITES=1 + NAVI_EMAIL=1). Sends the exact messages previewed."""
    from core import navi_cli
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to send email"}, 400
    if not navi_cli.email_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.email_gate_reason(),
                **_gate()}, 200
    msgs = p.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return {"ok": False, "error": "messages[] required (preview first)"}, 400
    import tempfile, os
    results, sent, failed, skipped = [], 0, 0, 0
    for m in msgs:
        to = (m.get("to") or "").strip()
        if not to:
            skipped += 1
            results.append({"owner": m.get("owner"), "to": "", "ok": False,
                            "skipped": True, "message": "no recipient address"})
            continue
        # Render the rich HTML body via navi's --html (a file path); body_text is the
        # plaintext fallback. Write to a temp file, send synchronously, then clean up.
        html_path, body_html = "", (m.get("body_html") or "")
        if body_html.strip():
            try:
                fd, html_path = tempfile.mkstemp(prefix="gabriel_", suffix=".html")
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(body_html)
            except Exception:
                html_path = ""
        r = navi_cli.mail(to=to, subject=m.get("subject") or "Tenable report",
                          message=m.get("body_text") or "", html=html_path, agent="email")
        if html_path:
            try:
                os.unlink(html_path)
            except Exception:
                pass
        ok = bool(r.get("ok"))
        sent += 1 if ok else 0
        failed += 0 if ok else 1
        results.append({"owner": m.get("owner"), "to": to, "ok": ok, "html": bool(html_path),
                        "message": r.get("message"), "cmd": r.get("cmd")})
    return {"ok": failed == 0, "sent": sent, "failed": failed, "skipped": skipped,
            "results": results, "email_enabled": navi_cli.email_enabled()}, 200


def graph(p):
    """DOUBLE-gated send of a rendered graph (Sankey / threads).

    An inline base64 image (``<img src="data:image/png;base64,…">``) does NOT render in
    Gmail or most webmail — they strip ``data:`` URIs. navi's mailer (SMTP + Resend) also
    has no ``multipart/related`` / Content-ID support, so a true CID inline image isn't
    available either. The reliable path that renders/previews in every client is to decode
    the PNG and send it as a real image ATTACHMENT via ``navi --file``; the body carries a
    short light-theme note pointing at it."""
    from core import navi_cli
    import tempfile, os, base64, re as _re
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to send email"}, 400
    if not navi_cli.email_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.email_gate_reason(), **_gate()}, 200
    to = (p.get("to") or "").strip()
    if not to:
        return {"ok": False, "error": "recipient (to) required"}, 400
    png = (p.get("png") or "").strip()          # data:image/png;base64,…
    if not png:
        return {"ok": False, "error": "no graph image"}, 400
    m = _re.match(r"^data:image/(png|jpeg|jpg);base64,(.+)$", png, _re.S)
    if not m:
        return {"ok": False, "error": "graph image must be a base64 PNG/JPEG data-URI"}, 400
    ext = "png" if m.group(1) == "png" else "jpg"
    try:
        raw = base64.b64decode(m.group(2))
    except Exception:
        return {"ok": False, "error": "could not decode graph image"}, 400
    title = p.get("title") or "Ownership graph"
    subject = p.get("subject") or f"[Tenable] {title}"
    safe = _re.sub(r"[^A-Za-z0-9]+", "-", title).strip("-") or "ownership-graph"
    tmpdir = tempfile.mkdtemp(prefix="hounds_graph_")
    ipath = os.path.join(tmpdir, f"{safe}.{ext}")
    bpath = ""
    try:
        with open(ipath, "wb") as fh:
            fh.write(raw)
        # Body is a short note; the graph rides as an attachment (renders/previews inline in
        # Gmail's attachment strip, Outlook, and Apple Mail — unlike a stripped data-URI img).
        inner = (f"<p style='margin:0 0 10px'><b>{_esc(title)}</b> — from the Hounds Ownership Map.</p>"
                 f"<p style='margin:0 0 10px;color:#475569'>The graph is attached as "
                 f"<b>{_esc(safe)}.{ext}</b>. (Mail clients strip embedded images, so it rides "
                 f"as an attachment — open it to view the {_esc(title.lower())}.)</p>"
                 + _sign_html())
        body = _html_wrap(subject, inner)
        bfd, bpath = tempfile.mkstemp(prefix="hounds_gbody_", suffix=".html")
        with os.fdopen(bfd, "w", encoding="utf-8") as fh:
            fh.write(body)
        r = navi_cli.mail(to=to, subject=subject,
                          message=f"{title} — see the attached image ({safe}.{ext}).",
                          html=bpath, file=ipath, agent="email")
    finally:
        for pth in (bpath, ipath):
            if pth:
                try:
                    os.unlink(pth)
                except Exception:
                    pass
        try:
            os.rmdir(tmpdir)
        except Exception:
            pass
    return {"ok": bool(r.get("ok")), "message": r.get("message"), "to": to,
            "cmd": r.get("cmd"), "attached": f"{safe}.{ext}", **_gate()}, 200


# --------------------------------------------------------------------------- #
#  Custom Dashboard → email-safe HTML
# --------------------------------------------------------------------------- #
_DPAL = ["#4f52c8", "#3f78c2", "#2a8f8f", "#2f9d6b", "#7d60cb", "#3f8fb0",
         "#4a6fd0", "#3aa088", "#6b6ee0", "#2f88a8", "#5a7fc0", "#7f5fc0"]


def _dnum(v):
    try:
        f = float(v)
        return f if f == f else None
    except (TypeError, ValueError):
        return None


def _dash_table(cols, rows, cap=60):
    head = "".join(f"<th style='text-align:left;border-bottom:1px solid #cbd5e1;padding:6px 8px;"
                   f"font-size:12px;color:#475569'>{_esc(c)}</th>" for c in cols)
    body = ""
    for r in rows[:cap]:
        body += "<tr>" + "".join(f"<td style='border-bottom:1px solid #eef2f7;padding:6px 8px;"
                                 f"font-size:12.5px;color:#0f172a'>{_esc(r.get(c))}</td>" for c in cols) + "</tr>"
    more = (f"<div style='font-size:11.5px;color:#64748b;margin-top:4px'>… and {len(rows)-cap} more row(s)</div>"
            if len(rows) > cap else "")
    return f"<table style='border-collapse:collapse;width:100%'><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{more}"


def _dash_kpi(cols, row):
    return "".join(
        f"<div style='display:inline-block;min-width:120px;margin:6px 10px 6px 0;padding:10px 14px;"
        f"border:1px solid #e2e8f0;border-radius:10px;background:#f8fafc'>"
        f"<div style='font-size:22px;font-weight:800;color:#0f172a'>{_esc(row.get(c))}</div>"
        f"<div style='font-size:12px;color:#64748b'>{_esc(c)}</div></div>" for c in cols)


def _dash_bars(rows, lc, vc, cap=20):
    mx = max([(_dnum(r.get(vc)) or 0) for r in rows[:cap]] + [1])
    out = ""
    for i, r in enumerate(rows[:cap]):
        v = _dnum(r.get(vc)) or 0
        w = max(3, round(v / mx * 100))
        c = _DPAL[i % len(_DPAL)]
        out += (f"<div style='margin:6px 0'><div style='font-size:12px;color:#334155;margin-bottom:2px'>"
                f"{_esc(r.get(lc))} — <b>{_esc(r.get(vc))}</b></div>"
                f"<div style='background:#eef2f7;border-radius:5px;overflow:hidden'>"
                f"<div style='width:{w}%;background:{c};height:16px;border-radius:5px'></div></div></div>")
    more = (f"<div style='font-size:11.5px;color:#64748b;margin-top:4px'>… and {len(rows)-cap} more</div>"
            if len(rows) > cap else "")
    return out + more


def _dash_component(comp):
    title = comp.get("title") or "Component"
    note = comp.get("note") or ""
    cols = comp.get("columns") or []
    rows = comp.get("rows") or []
    viz = (comp.get("viz") or "").lower()

    def _isnum_col(c):
        vals = [r.get(c) for r in rows[:30] if r.get(c) not in (None, "")]
        return bool(vals) and all(_dnum(v) is not None for v in vals)
    numcols = [c for c in cols if _isnum_col(c)]
    lc = comp.get("label_col") if comp.get("label_col") in cols else \
        next((c for c in cols if c not in numcols), (cols[0] if cols else None))
    vc = comp.get("value_col") if comp.get("value_col") in numcols else \
        next((c for c in numcols if c != lc), (numcols[0] if numcols else None))

    if not rows:
        inner = "<div style='font-size:12.5px;color:#64748b'>No rows in the current navi.db snapshot.</div>"
    elif viz == "kpi" or (not viz and len(rows) == 1 and numcols):
        inner = _dash_kpi(cols, rows[0]) + (_dash_table(cols, rows) if len(rows) > 1 else "")
    elif viz in ("bar", "pie", "line") and lc and vc:
        inner = _dash_bars(rows, lc, vc)
    else:
        inner = _dash_table(cols, rows)

    head = (f"<div style='font-weight:700;font-size:14px;color:#0f172a;margin:0 0 2px'>{_esc(title)}</div>"
            + (f"<div style='font-size:12px;color:#64748b;margin:0 0 8px'>{_esc(note)}</div>" if note
               else "<div style='margin-bottom:6px'></div>"))
    return (f"<div style='border:1px solid #e2e8f0;border-radius:10px;padding:12px 14px;margin:0 0 14px'>"
            f"{head}{inner}</div>")


def dashboard(p):
    """DOUBLE-gated send of a Custom Dashboard as an email-safe HTML body. Each component is
    rendered with INLINE styles only — KPI boxes, div bar charts, tables — since mail clients
    strip <style>, inline <svg>, and data-URI images. The page hands over its pinned
    components (title / note / viz / columns / rows)."""
    from core import navi_cli
    import tempfile, os
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to send email"}, 400
    if not navi_cli.email_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.email_gate_reason(), **_gate()}, 200
    to = (p.get("to") or "").strip()
    if not to:
        return {"ok": False, "error": "recipient (to) required"}, 400
    comps = p.get("components") or []
    if not comps:
        return {"ok": False, "error": "no dashboard components to send"}, 400
    title = p.get("title") or "Custom Dashboard"
    subject = p.get("subject") or f"[Tenable] {title}"
    intro = (f"<p style='margin:0 0 12px;color:#475569'>{len(comps)} component(s) from the Hounds "
             f"Custom Dashboard — a point-in-time navi.db snapshot.</p>")
    body_inner = intro + "".join(_dash_component(c) for c in comps[:30]) + _sign_html()
    body = _html_wrap(subject, body_inner)
    bpath = ""
    try:
        bfd, bpath = tempfile.mkstemp(prefix="hounds_dash_", suffix=".html")
        with os.fdopen(bfd, "w", encoding="utf-8") as fh:
            fh.write(body)
        r = navi_cli.mail(to=to, subject=subject,
                          message=f"{title} — {len(comps)} component(s). Open in an HTML mail client.",
                          html=bpath, agent="email")
    finally:
        if bpath:
            try:
                os.unlink(bpath)
            except Exception:
                pass
    return {"ok": bool(r.get("ok")), "message": r.get("message"), "to": to,
            "components": len(comps), "cmd": r.get("cmd"), **_gate()}, 200


def widget(p):
    """DOUBLE-gated send of ONE chart widget — its PICTURE and its LIST (build 462).

    The picture is rendered in the browser (console.js hSnapshot): a PNG data-URI, or — where the
    browser can't rasterise HTML (Safari) — a self-contained HTML snapshot. Mail clients strip
    inline images and <svg>, so the picture rides as the ATTACHMENT (navi mail takes one file).
    The list goes INLINE in the HTML body (up to WIDGET_INLINE rows); a longer list is cut there
    and the attachment becomes a .zip holding the picture + the full list as CSV."""
    from core import navi_cli
    import tempfile, os, csv, base64, zipfile, io, re as _re
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to send email"}, 400
    if not navi_cli.email_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.email_gate_reason(), **_gate()}, 200
    to = (p.get("to") or "").strip()
    if not to:
        return {"ok": False, "error": "recipient (to) required"}, 400
    rows = [r for r in (p.get("rows") or []) if isinstance(r, dict)]
    cols = [str(c) for c in (p.get("columns") or [])] or (list(rows[0].keys()) if rows else [])
    title = str(p.get("title") or "Widget")[:160]
    note = str(p.get("note") or "")[:600]
    subject = str(p.get("subject") or f"[Tenable] {title}")[:200]
    safe = _re.sub(r"[^A-Za-z0-9]+", "-", title).strip("-")[:60] or "widget"
    pic, pic_name = None, ""
    png = (p.get("png") or "").strip()
    if png:
        m = _re.match(r"^data:image/png;base64,(.+)$", png, _re.S)
        if not m:
            return {"ok": False, "error": "picture must be a base64 PNG data-URI"}, 400
        try:
            pic, pic_name = base64.b64decode(m.group(1), validate=False), safe + ".png"
        except Exception:
            return {"ok": False, "error": "could not decode the picture"}, 400
    elif (p.get("html") or "").strip():
        pic, pic_name = str(p["html"]).encode("utf-8"), safe + ".html"
    if not rows and pic is None:
        return {"ok": False, "error": "nothing to send — run the widget first"}, 400
    n = len(rows)
    inline = rows[:WIDGET_INLINE]
    long_list = n > WIDGET_INLINE
    att_name = (safe + ".zip") if (long_list and pic is not None) else (safe + ".csv") if long_list else pic_name
    pic_line = ""
    if pic is not None:
        pic_line = (f"<p style='margin:0 0 10px;color:#475569'>The widget as it looks on the page is attached as "
                    f"<b>{_esc(pic_name)}</b>{' inside <b>' + _esc(att_name) + '</b>' if long_list else ''} "
                    f"(mail clients strip embedded images, so it rides as an attachment"
                    f"{' — open the HTML file in a browser' if pic_name.endswith('.html') else ''}).</p>")
    list_line = (f"<p style='margin:0 0 8px;color:#475569'>{n} row(s)"
                 + (f" — the first {WIDGET_INLINE} below; the full list is attached as CSV" if long_list else "")
                 + ".</p>") if n else ""
    inner = (f"<p style='margin:0 0 6px'><b>{_esc(title)}</b></p>"
             + (f"<p style='margin:0 0 10px;color:#475569'>{_esc(note)}</p>" if note else "")
             + pic_line + list_line + (_dash_table(cols, inline, cap=WIDGET_INLINE) if n else "") + _sign_html())
    tmpdir = tempfile.mkdtemp(prefix="hounds_widget_")
    bpath = os.path.join(tmpdir, "body.html")
    apath = os.path.join(tmpdir, att_name) if att_name else ""
    try:
        with open(bpath, "w", encoding="utf-8") as fh:
            fh.write(_html_wrap(subject, inner))
        if long_list:
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(cols)
            for r in rows:
                w.writerow([r.get(c, "") for c in cols])
            data_csv = buf.getvalue().encode("utf-8-sig")
            if pic is not None:
                with zipfile.ZipFile(apath, "w", zipfile.ZIP_DEFLATED) as z:
                    z.writestr(pic_name, pic)
                    z.writestr(safe + ".csv", data_csv)
            else:
                with open(apath, "wb") as fh:
                    fh.write(data_csv)
        elif pic is not None:
            with open(apath, "wb") as fh:
                fh.write(pic)
        r = navi_cli.mail(to=to, subject=subject,
                          message=f"{title} — {n} row(s); the picture is attached ({att_name or 'none'}).",
                          html=bpath, file=apath, agent="email")
    finally:
        for pth in (bpath, apath):
            if pth:
                try:
                    os.unlink(pth)
                except Exception:
                    pass
        try:
            os.rmdir(tmpdir)
        except Exception:
            pass
    return {"ok": bool(r.get("ok")), "message": r.get("message"), "to": to, "cmd": r.get("cmd"),
            "attached": att_name, "rows": n, "rows_inline": len(inline), **_gate()}, 200


WIDGET_INLINE = 200


def data(p):
    """DOUBLE-gated send of ONE widget's query result. Threshold rule (per the operator):
    a small result — UNDER 100 rows — is rendered inline in the HTML email body as a table;
    100 rows or more ride along as a generated CSV attachment with a short body note. Same
    gate as the other sends (confirm=True AND NAVI_ALLOW_WRITES=1 + NAVI_EMAIL=1)."""
    from core import navi_cli
    import tempfile, os, csv, re as _re
    if not confirmed(p):
        return {"ok": False, "error": "confirm=true required to send email"}, 400
    if not navi_cli.email_enabled():
        return {"ok": False, "blocked": True, "reason": navi_cli.email_gate_reason(), **_gate()}, 200
    to = (p.get("to") or "").strip()
    if not to:
        return {"ok": False, "error": "recipient (to) required"}, 400
    rows = p.get("rows") or []
    if not rows:
        return {"ok": False, "error": "no rows to send"}, 400
    cols = p.get("columns") or []
    if not cols:                                    # derive from the first row if not supplied
        cols = list(rows[0].keys()) if isinstance(rows[0], dict) else []
    title = p.get("title") or "Query data"
    note = p.get("note") or ""
    sql = p.get("sql") or ""
    subject = p.get("subject") or f"[Tenable] {title}"
    n = len(rows)
    INLINE_MAX = 100                                # under 100 → inline body; 100+ → CSV attachment

    intro = (f"<p style='margin:0 0 6px'><b>{_esc(title)}</b></p>"
             + (f"<p style='margin:0 0 10px;color:#475569'>{_esc(note)}</p>" if note else "")
             + f"<p style='margin:0 0 12px;color:#475569'>{n} row(s) · {len(cols)} column(s) — "
               f"a point-in-time navi.db snapshot.</p>")
    sql_block = (f"<div style='font-family:ui-monospace,Menlo,monospace;font-size:11.5px;white-space:pre-wrap;"
                 f"color:#334155;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px;"
                 f"margin:0 0 14px'>{_esc(sql)}</div>" if sql else "")

    bpath, cpath, tmpdir, attached, mode = "", "", "", None, "body"
    try:
        if n < INLINE_MAX:
            body_inner = intro + sql_block + _dash_table(cols, rows, cap=INLINE_MAX) + _sign_html()
            body = _html_wrap(subject, body_inner)
            bfd, bpath = tempfile.mkstemp(prefix="hounds_data_", suffix=".html")
            with os.fdopen(bfd, "w", encoding="utf-8") as fh:
                fh.write(body)
            r = navi_cli.mail(to=to, subject=subject,
                              message=f"{title} — {n} row(s). Open in an HTML mail client.",
                              html=bpath, agent="email")
        else:
            mode = "attachment"
            safe = _re.sub(r"[^A-Za-z0-9]+", "-", title).strip("-") or "query-data"
            attached = f"{safe}.csv"
            tmpdir = tempfile.mkdtemp(prefix="hounds_data_")
            cpath = os.path.join(tmpdir, attached)
            with open(cpath, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(cols)
                for row in rows:
                    w.writerow([(row.get(c, "") if isinstance(row, dict) else "") for c in cols])
            body_inner = (intro + sql_block
                          + f"<p style='margin:0 0 10px;color:#475569'>The full result — <b>{n} rows</b> — is "
                            f"attached as <b>{_esc(attached)}</b> (too large to render inline).</p>"
                          + _sign_html())
            body = _html_wrap(subject, body_inner)
            bfd, bpath = tempfile.mkstemp(prefix="hounds_data_", suffix=".html")
            with os.fdopen(bfd, "w", encoding="utf-8") as fh:
                fh.write(body)
            r = navi_cli.mail(to=to, subject=subject,
                              message=f"{title} — {n} row(s), attached as {attached}.",
                              html=bpath, file=cpath, agent="email")
    finally:
        for pth in (bpath, cpath):
            if pth:
                try:
                    os.unlink(pth)
                except Exception:
                    pass
        if tmpdir:
            try:
                os.rmdir(tmpdir)
            except Exception:
                pass
    return {"ok": bool(r.get("ok")), "message": r.get("message"), "to": to, "rows": n,
            "mode": mode, "attached": attached, "cmd": r.get("cmd"), **_gate()}, 200


def run(p):
    return {"ok": True, "agent": _agent().meta(), "result": _agent().run(), **_gate()}, 200


ACTIONS = {"run": run, "status": status, "recipients": recipients,
           "preview": preview, "send": send, "graph": graph, "dashboard": dashboard, "data": data,
           "widget": widget}
