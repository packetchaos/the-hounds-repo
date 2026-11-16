"""Zero-day lookup for the Software Explorer (Harrier): turn "the new Ivanti bug" or a CVE id
into the affected PRODUCTS and VERSION RANGES, so the explorer can search the software
inventory for them.

  plan(prompt)          → the sources Harrier proposes to read (NVD, CVE.org, OSV for each CVE;
                          an NVD keyword search when there is no CVE id; any URL the user pasted).
                          Nothing is fetched here.
  fetch(urls, prompt)   → reads ONLY the URLs the user approved, one by one, and parses them:
                          NVD / CVE.org / OSV JSON deterministically; any other page (a vendor
                          advisory, a blog) through the configured model, if one is set up.

Every site needs the user's approval on the page, every time — the Settings switch that
auto-approves the catalog downloads does not apply here. The fetcher only speaks http(s) on
ports 80 / 443 to PUBLIC addresses (no loopback / private / link-local / metadata ranges),
follows a redirect only within the same site, and reads at most 2 MB per page.

A model never decides what is affected in YOUR estate: it only reads a page into the same
{product, ranges} shape the JSON parsers produce, the ranges are validated by the same parser
the search uses, and the inventory match itself is plain SQL + version comparison.
"""
import datetime as _dt
import html
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request

from core import downloads, swsearch

SOURCE_ID = "zeroday_lookup"
downloads.register(SOURCE_ID, "Zero-day lookup (Software Explorer)",
                   ["https://services.nvd.nist.gov/rest/json/cves/2.0", "https://cveawg.mitre.org/api/cve/",
                    "https://api.osv.dev/v1/vulns/", "any advisory URL you paste"],
                   agent="ex_software",
                   purpose="Harrier's ✨ zero-day lookup — reads a CVE's affected products and versions so "
                           "the Software Explorer can search your inventory for them.",
                   fallback="none — you approve each site on the page, every time (not covered by "
                            "auto-approve)", approval=False)

MAX_URLS = 10
MAX_BYTES = 2_000_000
TIMEOUT = 20
UA = "TheHounds-Harrier/1.0 (zero-day lookup; navi-agents)"
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
_STOP = set("""a an and any are affected affecting about against all bug bugs by critical cve cves day
days exploit exploited exploits find for from have hit hits how i in into is it its latest look lookup
me my new newly of on or our recent released show the this to vuln vulns vulnerability vulnerabilities
vulnerable we what which with zero zeroday zero-day 0day 0-day""".split())

NVD_CVE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s"
CVEORG = "https://cveawg.mitre.org/api/cve/%s"
OSV = "https://api.osv.dev/v1/vulns/%s"


# ── 1. plan: what Harrier proposes to read ────────────────────────────────────
def _keywords(prompt):
    words = [w for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9._+-]*", _URL.sub(" ", _CVE.sub(" ", prompt or "")))
             if w.lower() not in _STOP and len(w) > 1]
    return words[:4]


def _nvd_keyword_url(words, days=119, today=None):
    """NVD's keyword search, newest disclosures only (NVD caps a published-date window at
    120 days)."""
    end = today or _dt.datetime.now(_dt.timezone.utc)
    start = end - _dt.timedelta(days=days)
    f = "%Y-%m-%dT%H:%M:%S.000"
    q = urllib.parse.urlencode({"keywordSearch": " ".join(words), "pubStartDate": start.strftime(f),
                                "pubEndDate": end.strftime(f), "resultsPerPage": "20"})
    return "https://services.nvd.nist.gov/rest/json/cves/2.0?" + q


def plan(prompt, interpret=None):
    """{cves, keywords, sources:[{url, domain, kind, why}], interpreted_by}. `interpret` is an
    optional callable(prompt) → {cves, keywords} (the model); it can only add CVE ids and
    search words — the URLs are always built here, from fixed templates."""
    prompt = str(prompt or "").strip()
    cves = sorted({c.upper() for c in _CVE.findall(prompt)})
    words = _keywords(prompt)
    by = "rules"
    if interpret and not cves:
        try:
            got = interpret(prompt) or {}
            mc = sorted({c.upper() for c in (got.get("cves") or []) if _CVE.fullmatch(str(c).strip())})
            mk = [str(k).strip() for k in (got.get("keywords") or []) if str(k).strip()][:4]
            if mc or mk:
                cves, words, by = mc or cves, mk or words, "model"
        except Exception:
            pass
    src = []
    for c in cves[:5]:
        src.append({"url": NVD_CVE % c, "kind": "nvd", "why": "NVD — %s: description, CVSS, affected CPEs and "
                                                              "version ranges" % c})
        src.append({"url": CVEORG % c, "kind": "cveorg", "why": "CVE.org — %s: the vendor's (CNA's) own list of "
                                                                "affected products and versions" % c})
        src.append({"url": OSV % c, "kind": "osv", "why": "OSV — %s: affected open-source packages and fixed "
                                                          "versions" % c})
    if not cves and words:
        src.append({"url": _nvd_keyword_url(words), "kind": "nvd_search",
                    "why": "NVD search — CVEs published in the last 120 days matching “%s”" % " ".join(words)})
    for u in _URL.findall(prompt):
        u = u.rstrip(".,;")
        if not any(s["url"] == u for s in src):
            src.append({"url": u, "kind": "page", "why": "the page you pasted"})
    for s in src:
        s["domain"] = urllib.parse.urlsplit(s["url"]).hostname or ""
    return {"cves": cves, "keywords": words, "sources": src, "interpreted_by": by}


# ── 2. the guarded fetcher ────────────────────────────────────────────────────
class Blocked(Exception):
    pass


def check_url(url):
    """Raise Blocked unless the URL is http(s) on 80/443 to a host whose EVERY address is public."""
    try:
        u = urllib.parse.urlsplit(str(url or "").strip())
    except ValueError:
        raise Blocked("not a URL")
    if u.scheme not in ("http", "https") or not u.hostname:
        raise Blocked("only http(s) URLs")
    if u.username or u.password:
        raise Blocked("URLs with a user name or password are not fetched")
    try:
        port = u.port
    except ValueError:
        raise Blocked("bad port")
    if port not in (None, 80, 443):
        raise Blocked("only ports 80 / 443")
    try:
        infos = socket.getaddrinfo(u.hostname, port or (443 if u.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise Blocked("can't resolve %s" % u.hostname)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global or ip.is_multicast:
            raise Blocked("%s resolves to a non-public address (%s) — not fetched" % (u.hostname, ip))
    return u


def _same_site(a, b):
    strip = lambda h: (h or "").lower()[4:] if (h or "").lower().startswith("www.") else (h or "").lower()
    return strip(a) == strip(b)


class _Redirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3

    def __init__(self, host):
        super().__init__()
        self.host = host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        nu = urllib.parse.urlsplit(newurl)
        if not _same_site(nu.hostname, self.host):
            raise Blocked("redirected to another site (%s) — approve that site to read it" % nu.hostname)
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _ctx():
    try:
        from core import llm
        return llm._SSL_CTX
    except Exception:
        return None


def _peer_guard(conn_cls, host):
    """conn_cls whose connect() re-checks the address it ACTUALLY connected to. check_url()
    resolves the name once; the HTTP client resolves it again, so a TTL-0 DNS answer could
    swap a public address for 127.0.0.1 / 169.254.169.254 in between (DNS rebinding). A
    connection to a configured proxy (its host is not the target site) is left to the proxy."""
    class _Guarded(conn_cls):
        def connect(self):
            super().connect()
            if getattr(self, "_tunnel_host", None) or not _same_site(self.host, host):
                return
            try:
                ip = ipaddress.ip_address(str(self.sock.getpeername()[0]).split("%")[0])
                ip = getattr(ip, "ipv4_mapped", None) or ip          # ::ffff:a.b.c.d → a.b.c.d
            except (OSError, ValueError, AttributeError, IndexError):
                ip = None
            if ip is None or not ip.is_global or ip.is_multicast:
                self.close()
                raise Blocked("%s connected to a non-public address (%s) — not fetched" % (self.host, ip))
    return _Guarded


def _handlers(host):
    import http.client

    class _H(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(_peer_guard(http.client.HTTPConnection, host), req)

    class _S(urllib.request.HTTPSHandler):
        def https_open(self, req):
            kw = {"context": self._context}
            if hasattr(self, "_check_hostname"):
                kw["check_hostname"] = self._check_hostname
            return self.do_open(_peer_guard(http.client.HTTPSConnection, host), req, **kw)
    return _H(), _S(context=_ctx())


def get(url, timeout=TIMEOUT):
    """(text, content_type, truncated) — raises Blocked / urllib errors."""
    u = check_url(url)
    op = urllib.request.build_opener(_Redirect(u.hostname), *_handlers(u.hostname))
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json, text/html;q=0.9, */*;q=0.5"})
    with op.open(req, timeout=timeout) as r:
        body = r.read(MAX_BYTES + 1)
        ctype = (r.headers.get("Content-Type") or "").lower()
        cs = r.headers.get_content_charset() or "utf-8"
    return body[:MAX_BYTES].decode(cs, "replace"), ctype, len(body) > MAX_BYTES


# ── 3. parsers → one shape ────────────────────────────────────────────────────
#   advisory = {cve, title, summary, published, cvss, severity, kev, source, products:[product]}
#   product  = {vendor, product, ranges (text, swsearch syntax), fixed, terms[], note}
def _v(x):
    x = str(x or "").strip()
    return x if (x and x not in ("*", "-", "n/a", "N/A", "unspecified", "0") and re.search(r"\d", x)) else ""


def _clause(start="", start_incl=True, end="", end_incl=False, exact=""):
    if exact:
        return [("=", exact)]
    c = []
    if start:
        c.append((">=" if start_incl else ">", start))
    if end:
        c.append(("<=" if end_incl else "<", end))
    return c or [(">=", "0")]                      # every version


def _terms(vendor, product):
    """Inventory search words for a product name (the model can add aliases later)."""
    out = []
    p = str(product or "").strip()
    vw = {w.lower() for w in re.split(r"[\s_:/-]+", str(vendor or "")) if w}
    rest = " ".join(w for w in re.split(r"\s+", p) if w.lower() not in vw)   # "Apache Log4j2" → "Log4j2"
    for t in (p, p.replace("_", " "), p.replace("_", "-"), p.split(":")[-1], p.split("/")[-1], rest):
        t = t.strip()
        if len(t) >= 2 and t.lower() not in (x.lower() for x in out):
            out.append(t)
    return out[:5]


def _prod(vendor, product, clauses, fixed=""):
    clauses = [c for c in clauses if c]
    return {"vendor": vendor or "", "product": product or "", "ranges": swsearch.ranges_text(clauses),
            "fixed": fixed or "", "terms": _terms(vendor, product), "note": ""}


def _merge(prods):
    """One row per vendor/product, clauses OR'd together."""
    out = {}
    for p in prods:
        k = (p["vendor"].lower(), p["product"].lower())
        if k in out:
            a = out[k]
            if p["ranges"] and p["ranges"] not in a["ranges"].split("; "):
                a["ranges"] = "; ".join(x for x in (a["ranges"], p["ranges"]) if x)
            a["fixed"] = _fixes(a["fixed"], p["fixed"])
        else:
            out[k] = dict(p)
            out[k]["fixed"] = _fixes(p["fixed"])
    return list(out.values())


def _fixes(*vals):
    """Every distinct fixed version, oldest first — a CVE can be fixed on several lines
    (Log4Shell: 2.3.1, 2.12.2, 2.15.0)."""
    import functools
    vs = []
    for v in vals:
        for x in str(v or "").split(","):
            x = x.strip()
            if x and x not in vs:
                vs.append(x)
    return ", ".join(sorted(vs, key=functools.cmp_to_key(swsearch.vcmp)))


def parse_nvd(doc):
    advs = []
    for item in (doc.get("vulnerabilities") or [])[:20]:
        c = item.get("cve") or {}
        desc = next((d.get("value") for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")
        score = sev = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            m = (c.get("metrics") or {}).get(key) or []
            if m:
                d = m[0].get("cvssData") or {}
                score, sev = d.get("baseScore"), d.get("baseSeverity") or m[0].get("baseSeverity")
                break
        prods = []
        for cfg in c.get("configurations") or []:
            for node in cfg.get("nodes") or []:
                for m in node.get("cpeMatch") or []:
                    if not m.get("vulnerable"):
                        continue                    # "running on" platform rows
                    parts = str(m.get("criteria") or "").split(":")
                    if len(parts) < 6:
                        continue
                    vendor, product, ver = parts[3], parts[4], parts[5]
                    upd = parts[6] if len(parts) > 6 else ""
                    if _v(ver) and upd not in ("", "*", "-"):
                        ver = "%s-%s" % (ver, upd)      # cpe:…:log4j:2.0:beta9 → 2.0-beta9
                    st = _v(m.get("versionStartIncluding")) or _v(m.get("versionStartExcluding"))
                    en = _v(m.get("versionEndExcluding")) or _v(m.get("versionEndIncluding"))
                    if st or en:
                        cl = _clause(st, bool(_v(m.get("versionStartIncluding"))), en,
                                     bool(_v(m.get("versionEndIncluding"))))
                    else:
                        cl = _clause(exact=_v(ver))
                    p = _prod(vendor, product, [cl], fixed=_v(m.get("versionEndExcluding")))
                    p["part"] = {"a": "application", "o": "operating system", "h": "hardware"}.get(parts[2], "")
                    prods.append(p)
        advs.append({"cve": c.get("id") or "", "title": "", "summary": desc, "published": c.get("published") or "",
                     "cvss": score, "severity": sev, "kev": bool(c.get("cisaExploitAdd")),
                     "kev_due": c.get("cisaActionDue") or "", "source": "nvd", "products": _merge(prods)})
    return advs


def parse_cveorg(doc):
    meta = doc.get("cveMetadata") or {}
    cna = (doc.get("containers") or {}).get("cna") or {}
    desc = next((d.get("value") for d in cna.get("descriptions") or [] if str(d.get("lang", "")).startswith("en")), "")
    prods = []
    for a in cna.get("affected") or []:
        vendor, product = a.get("vendor") or "", a.get("product") or a.get("packageName") or ""
        cls = []
        fixed = ""
        for v in a.get("versions") or []:
            if str(v.get("status") or "").lower() != "affected":
                continue
            ver = _v(v.get("version"))
            if v.get("lessThan"):
                lt = _v(v.get("lessThan"))
                cls.append(_clause(ver, True, lt, False))
                fixed = _fixes(fixed, lt)
            elif v.get("lessThanOrEqual"):
                cls.append(_clause(ver, True, _v(v.get("lessThanOrEqual")), True))
            elif ver:
                cls.append(_clause(exact=ver))
        if not cls and str(a.get("defaultStatus") or "").lower() == "affected":
            cls.append(_clause())
        if cls:
            prods.append(_prod(vendor, product, cls, fixed))
    score = sev = None
    for m in cna.get("metrics") or []:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            if m.get(key):
                score, sev = m[key].get("baseScore"), m[key].get("baseSeverity")
                break
        if score is not None:
            break
    return [{"cve": meta.get("cveId") or "", "title": cna.get("title") or "", "summary": desc,
             "published": meta.get("datePublished") or "", "cvss": score, "severity": sev, "kev": False,
             "source": "cveorg", "products": _merge(prods)}]


def parse_osv(doc):
    prods = []
    for a in doc.get("affected") or []:
        pkg = a.get("package") or {}
        name, eco = pkg.get("name") or "", pkg.get("ecosystem") or ""
        cls, fixed = [], ""
        for r in a.get("ranges") or []:
            if str(r.get("type") or "").upper() == "GIT":
                continue                            # commit hashes — not comparable to an installed version
            cur = None                              # None: no open interval · "": open from the start
            for e in r.get("events") or []:
                if "introduced" in e:
                    cur = _v(e["introduced"])
                elif "fixed" in e and cur is not None:
                    cls.append(_clause(cur, True, _v(e["fixed"]), False))
                    fixed = _fixes(fixed, _v(e["fixed"]))
                    cur = None
                elif "last_affected" in e and cur is not None:
                    cls.append(_clause(cur, True, _v(e["last_affected"]), True))
                    cur = None
            if cur is not None:
                cls.append(_clause(cur, True))      # introduced, never fixed
        if not cls and a.get("versions"):
            cls = [_clause(exact=_v(v)) for v in a["versions"][:40] if _v(v)]
        if name and cls:
            p = _prod(eco, name, cls, fixed)
            p["ecosystem"] = eco
            prods.append(p)
    cve = next((x for x in [doc.get("id")] + list(doc.get("aliases") or []) if _CVE.fullmatch(str(x or ""))),
               doc.get("id") or "")
    return [{"cve": cve, "title": doc.get("summary") or "", "summary": doc.get("details") or doc.get("summary") or "",
             "published": doc.get("published") or "", "cvss": None, "severity": None, "kev": False,
             "source": "osv", "products": _merge(prods)}]


def page_text(body, ctype=""):
    """Readable text from an HTML page (scripts, styles and markup removed)."""
    if "html" not in ctype and not re.search(r"<\s*(html|body|div|p)\b", body[:2000], re.I):
        return re.sub(r"[ \t]+", " ", body).strip()
    t = re.sub(r"(?is)<(script|style|noscript|svg|head)[^>]*>.*?</\1>", " ", body)
    t = re.sub(r"(?i)<br\s*/?>|</(p|div|li|tr|h\d)>", "\n", t)
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    t = html.unescape(t)
    t = re.sub(r"[ \t\r\f\v]+", " ", t)
    return re.sub(r"\n\s*\n+", "\n\n", t).strip()


def clean_model_products(items):
    """Validate what a model read from a page: ranges must parse (else kept as a note)."""
    out = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        prod = str(it.get("product") or "").strip()[:120]
        if not prod:
            continue
        rng = str(it.get("ranges") or it.get("affected") or "").strip()[:300]
        note = ""
        try:
            rng = swsearch.ranges_text(swsearch.parse_ranges(rng)) if rng else ""
        except ValueError:
            note, rng = "the page's version wording could not be read as a range: %s" % rng, ""
        terms = [str(t).strip()[:60] for t in (it.get("terms") or it.get("search_terms") or []) if str(t).strip()]
        p = {"vendor": str(it.get("vendor") or "").strip()[:80], "product": prod, "ranges": rng,
             "fixed": str(it.get("fixed") or "").strip()[:60], "note": note}
        p["terms"] = []
        for t in terms + _terms(p["vendor"], prod):
            if len(t) >= 2 and t.lower() not in (x.lower() for x in p["terms"]):
                p["terms"].append(t)
        p["terms"] = p["terms"][:6]
        out.append(p)
    return out[:25]


def parse(url, body, ctype, read_page=None):
    """→ (advisories, how). JSON from NVD / CVE.org / OSV is parsed by rules; anything else goes
    to read_page(text, url) (the model) when one is given."""
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    doc = None
    if "json" in ctype or body.lstrip()[:1] in ("{", "["):
        try:
            doc = json.loads(body)
        except ValueError:
            doc = None
    if isinstance(doc, dict):
        if "vulnerabilities" in doc and host.endswith("nvd.nist.gov"):
            return parse_nvd(doc), "rules"
        if "cveMetadata" in doc:
            return parse_cveorg(doc), "rules"
        if "affected" in doc and ("id" in doc or "aliases" in doc):
            return parse_osv(doc), "rules"
    if read_page is None:
        return [], "none"
    text = page_text(body, ctype)
    if len(text) < 40:
        return [], "empty"
    got = read_page(text[:24000], url) or {}
    cves = sorted({c.upper() for c in _CVE.findall(" ".join(str(x) for x in got.get("cves") or []))})
    prods = clean_model_products(got.get("products"))
    adv = {"cve": ", ".join(cves[:5]) or "(no CVE id on the page)", "title": str(got.get("title") or "")[:200],
           "summary": str(got.get("summary") or "")[:1200], "published": "", "cvss": None, "severity": None,
           "kev": False, "source": "page", "products": prods}
    return ([adv] if (prods or adv["summary"]) else []), "model"


def combine(advs):
    """Merge the same CVE read from several sources: one card per CVE, products merged, the
    sources listed."""
    out = {}
    for a in advs:
        k = a["cve"] or ("#%d" % len(out))
        c = out.get(k)
        if c is None:
            c = out[k] = dict(a, sources=[a["source"]], products=list(a["products"]))
            continue
        if a["source"] not in c["sources"]:
            c["sources"].append(a["source"])
        for f in ("title", "summary", "published", "severity", "kev_due"):
            if not c.get(f) and a.get(f):
                c[f] = a[f]
        if c.get("cvss") is None and a.get("cvss") is not None:
            c["cvss"] = a["cvss"]
        c["kev"] = c["kev"] or a["kev"]
        c["products"] = _merge(c["products"] + a["products"])
    return list(out.values())


def kev_flags(advs):
    """Mark CVEs in the CISA KEV catalog — the snapshot already on disk, no network."""
    try:
        from core import kev
        cat, src = kev.fetch_catalog(allow_live=False)
        ids = {str(v.get("cveID") or "").upper(): v for v in cat.get("vulnerabilities") or []}
    except Exception:
        return
    for a in advs:
        for c in _CVE.findall(a.get("cve") or ""):
            v = ids.get(c.upper())
            if v:
                a["kev"] = True
                a["kev_due"] = a.get("kev_due") or v.get("dueDate") or ""
