"""Synthetic navi.db for the SLA agent (Sköll) — sized for profiling and equivalence tests.

    python3 tests/sla_fixture.py out.db [assets] [findings] [seed] [--no-fixed] [--no-acr]
                                        [--no-routes] [--no-owner] [--no-sla]

Writes the tables core/sla.py reads, shaped like navi's:
  sla    (critical, high, medium, low)                           — day thresholds
  vulns  (asset_uuid, plugin_id, plugin_name, severity, state, first_found, last_found, …)
         open / reopened / fixed rows across ~2 years; ISO 'YYYY-MM-DDTHH:MM:SS.sssZ'
  fixed  (asset_uuid, plugin_id, plugin_name, severity, state, first_found, last_found,
          last_fixed, delta, pass_fail) — every non-info finding with navi's Pass/Fail
  assets (uuid, hostname, ip_address, acr)
  tags   Owner:<team> (+ duplicate rows on a few assets, as navi can hold), Env:<x>,
         and Owner dispositions '<route|path>: Ignored/Accepted/Mitigated'
  vuln_route / vuln_paths — so the disposition exclusion has real work to do
"""
import datetime as _dt
import os
import random
import sqlite3
import sys
import uuid

TEAMS = ["VM Team", "Linux Team", "Web Team", "DBA Team", "Platform Team", "App Team",
         "Network Team", "Desktop Team"]
SEV_W = [("critical", 6), ("high", 24), ("medium", 40), ("low", 20), ("info", 10)]
THR = {"critical": 15, "high": 30, "medium": 90, "low": 180}


def _iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (d.microsecond // 1000)


def build(out, n_assets=10000, n_findings=600000, seed=7, fixed=True, acr=True, routes=True,
          owner=True, sla=True, now=None):
    rnd = random.Random(seed)
    now = now or _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)
    if os.path.exists(out):
        os.remove(out)
    c = sqlite3.connect(out)
    c.executescript("""
    CREATE TABLE vulns (asset_ip TEXT, asset_uuid TEXT, asset_hostname TEXT, first_found TEXT,
      last_found TEXT, output TEXT, plugin_id TEXT, plugin_name TEXT, plugin_family TEXT,
      port TEXT, protocol TEXT, severity TEXT, scan_completed TEXT, scan_started TEXT,
      scan_uuid TEXT, schedule_id TEXT, state TEXT, cves TEXT, score TEXT, exploit TEXT,
      xrefs TEXT, synopsis TEXT, see_also TEXT, solution TEXT, version TEXT, description TEXT,
      cvss3_base_score TEXT, cvss3_temporal_score TEXT, cvss_base_score TEXT,
      cvss_temporal_score TEXT, OSes TEXT, url TEXT);
    CREATE TABLE tags (tag_id INTEGER PRIMARY KEY, asset_uuid TEXT, asset_ip TEXT, tag_key TEXT,
      tag_uuid TEXT, tag_value TEXT, tag_added_date TEXT);
    CREATE TABLE plugins (plugin_id TEXT, vpr_score REAL, cvss3_base_score REAL);
    """)
    c.execute("CREATE TABLE assets (uuid TEXT, hostname TEXT, ip_address TEXT%s, aes INTEGER, url TEXT)"
              % (", acr TEXT" if acr else ""))
    if sla:
        c.execute("CREATE TABLE sla (critical TEXT, high TEXT, medium TEXT, low TEXT)")
        c.execute("INSERT INTO sla VALUES (?,?,?,?)", tuple(str(THR[s]) for s in ("critical", "high", "medium", "low")))
    A = [str(uuid.UUID(int=rnd.getrandbits(128))) for _ in range(n_assets)]
    arows = []
    for i, u in enumerate(A):
        ip = "10.%d.%d.%d" % (i // 65536 % 256, i // 256 % 256, i % 256)
        row = [u, "host-%05d.corp" % i, ip]
        if acr:
            row.append(str(rnd.choice([2, 3, 5, 6, 7, 8, 9, 10, 5, 6])))
        row += [rnd.randint(100, 900), ""]
        arows.append(tuple(row))
    c.executemany("INSERT INTO assets VALUES (%s)" % ",".join("?" * len(arows[0])), arows)

    n_pl = max(500, n_findings // 200)
    pids = [str(100000 + i) for i in range(n_pl)]
    psev = {p: rnd.choices([s for s, _ in SEV_W], [w for _, w in SEV_W])[0] for p in pids}
    c.executemany("INSERT INTO plugins VALUES (?,?,?)",
                  [(p, round(rnd.uniform(1, 10), 1), round(rnd.uniform(2, 10), 1)) for p in pids])

    span = 730  # ~2 years of history
    vrows, frows = [], []
    for k in range(n_findings):
        u = A[rnd.randrange(n_assets)]
        p = pids[min(n_pl - 1, int(rnd.paretovariate(1.2)) - 1 + rnd.randrange(n_pl) // 7)]
        sev = psev[p]
        # findings arrive with a mild upward trend over the period
        age = span * (1 - rnd.random() ** 0.8)
        ff = now - _dt.timedelta(days=age, seconds=rnd.randrange(86400))
        r = rnd.random()
        fix_days = None
        if r < 0.38 and age > 1:      # fixed (unless the drawn fix date is still in the future)
            thr = THR.get(sev, 60)
            fd = rnd.expovariate(1.0 / (thr * rnd.choice([0.4, 0.8, 1.3, 2.5])))
            if fd < age:
                fix_days = fd
        if fix_days is not None:
            lf = ff + _dt.timedelta(days=fix_days)
            st = "fixed"
        else:
            st = "reopened" if r > 0.95 else "open"
            lf = now - _dt.timedelta(days=rnd.random() * min(age, 20))
        sffx = _iso(ff)
        if k % 997 == 0:              # navi sometimes stores a bare date
            sffx = ff.strftime("%Y-%m-%d")
        sev_out = sev.upper() if k % 1013 == 0 else sev   # odd casing must still count
        vrows.append(("", u, "", sffx, _iso(lf), "", p, "Plugin %s" % p, "General", "443", "tcp",
                      sev_out, "", "", "", "", st, "", "", "", "", "", "", "", "", "", "", "",
                      "", "", "", ""))
        if fixed and sev != "info":
            thr = THR[sev]
            if st == "fixed":
                pf = "Pass" if fix_days <= thr else "Fail"
                last_fixed = _iso(lf)
            else:
                pf = "Pass" if age <= thr else "Fail"
                last_fixed = None
            frows.append((u, p, "Plugin %s" % p, sev_out, st, sffx, _iso(lf), last_fixed,
                          str(round(fix_days if fix_days is not None else age, 2)), pf))
    c.executemany("INSERT INTO vulns VALUES (%s)" % ",".join("?" * 32), vrows)
    if fixed:
        c.execute("CREATE TABLE fixed (asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, severity TEXT,"
                  " state TEXT, first_found TEXT, last_found TEXT, last_fixed TEXT, delta TEXT, pass_fail TEXT)")
        c.executemany("INSERT INTO fixed VALUES (?,?,?,?,?,?,?,?,?,?)", frows)

    trows = []
    if owner:
        for u in A:
            if rnd.random() < 0.85:
                t = rnd.choice(TEAMS)
                trows.append((u, "", "Owner", "t", t, ""))
                if rnd.random() < 0.01:                 # duplicate tag row (navi can hold these)
                    trows.append((u, "", "Owner", "t", t, ""))
                if rnd.random() < 0.05:                 # a second owner on the same asset
                    trows.append((u, "", "Owner", "t", rnd.choice(TEAMS), ""))
    for u in A:
        trows.append((u, "", "Env", "t", rnd.choice(["prod", "dev", "test"]), ""))
    if routes:
        c.executescript("""
        CREATE TABLE vuln_route (route_id INTEGER PRIMARY KEY, app_name TEXT, plugin_list TEXT,
          total_vulns INTEGER, vuln_type TEXT);
        CREATE TABLE vuln_paths (path_id INTEGER PRIMARY KEY, plugin_id TEXT, path TEXT,
          asset_uuid TEXT, finding_id TEXT);""")
        rts = []
        for r in range(max(20, n_pl // 10)):
            pl = rnd.sample(pids, rnd.randint(2, 10))
            rts.append((r + 1, "APP %d SERVER" % r, str(pl), 0, "Application"))
        c.executemany("INSERT INTO vuln_route VALUES (?,?,?,?,?)", rts)
        paths = ["/opt/app%d/lib/component-%d.jar" % (i, i) for i in range(max(10, n_findings // 2000))]
        prow = []
        for i in range(max(50, n_findings // 50)):
            v = vrows[rnd.randrange(len(vrows))]
            prow.append((v[6], rnd.choice(paths), v[1], "f%d" % i))
        c.executemany("INSERT INTO vuln_paths(plugin_id,path,asset_uuid,finding_id) VALUES (?,?,?,?)", prow)
        # dispositions: Owner tags '<route|path>: Ignored/Accepted/Mitigated' on assets of that route/path
        by_pid = {}
        for v in vrows:
            by_pid.setdefault(v[6], set()).add(v[1])
        for rt in rnd.sample(rts, max(1, len(rts) // 12)):
            d = rnd.choice(["Ignored", "Accepted", "Mitigated"])
            aus = set().union(*[by_pid.get(p, set()) for p in eval(rt[2])])
            for u in aus:
                if rnd.random() < 0.6:
                    trows.append((u, "", "Owner", "t", "%s: %s" % (rt[1], d), ""))
        for pth in rnd.sample(paths, max(1, len(paths) // 6)):
            d = rnd.choice(["Ignored", "Accepted", "Mitigated"])
            for pr in prow:
                if pr[1] == pth and rnd.random() < 0.7:
                    trows.append((pr[2], "", "Owner", "t", "%s: %s" % (pth, d), ""))
    c.executemany("INSERT INTO tags(asset_uuid,asset_ip,tag_key,tag_uuid,tag_value,tag_added_date) "
                  "VALUES (?,?,?,?,?,?)", trows)
    c.commit()
    c.close()
    return out


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a[5:] for a in sys.argv[1:] if a.startswith("--no-")}
    out = args[0] if args else "sla_fixture.db"
    na = int(args[1]) if len(args) > 1 else 10000
    nf = int(args[2]) if len(args) > 2 else 600000
    sd = int(args[3]) if len(args) > 3 else 7
    build(out, na, nf, sd, fixed="fixed" not in flags, acr="acr" not in flags,
          routes="routes" not in flags, owner="owner" not in flags, sla="sla" not in flags)
    print(out, na, nf, sd, sorted(flags))
