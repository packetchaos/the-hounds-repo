# Tests

Regression tests for The Hounds that run against a generated fixture navi.db. They need no
real Tenable data and no network, you don't start a server for them (a few start their own on
loopback), and they clean up after themselves. Every `test_*.py` is a **plain script**: run it
with `python3` from `navi-agents/`; exit code 0 = pass.

```
python3 tests/test_attackpath.py      # PASS/FAIL per check, non-zero exit on failure
python3 tests/test_agents.py          # the other agents' regression checks
python3 tests/test_exproute.py        # Exposure Routes: ownership math, parser, re-tag, snapshot cache
python3 tests/test_sla.py             # SLA: one-pass engine == old SQL, cache, trends, history
python3 tests/test_downloads.py       # Settings → Auto-approve downloads, the download gate
python3 tests/test_ai_atlas.py        # AI Inventory ATLAS drill-down + server-side tag_atlas
python3 tests/test_fused_score.py     # Exposure Score: open-only findings, SLA aging, account-reuse tier, server-side tag set, cache
python3 tests/test_release.py        # Release the Hounds: recipes in sidebar order, reads only, page cache, cancel
python3 tests/test_contract.py        # AI Contract: every tagging agent orchestrated, per-agent tag specs, old contracts load, no removals, query size
python3 tests/test_argos.py           # Argos at-a-glance: past-SLA = SLA page, weak-cert rule, EPSS cap
python3 tests/test_tagprefix.py       # Settings → Test run: prefixed writes, exact removals/ACR, readers match both names, off = build 440
python3 tests/test_insights.py        # On the Scent: built from the Release cache only, states, links, no navi.db reads
python3 tests/test_iot_squad.py       # IoT Discovery: glance metrics vs SQL, missing tables, no double tagging
python3 tests/test_asset_ownership.py # Asset Ownership: coverage metrics, bare Owner tags, confirm gate
python3 tests/test_classify.py        # Asset Classification: glance numbers vs SQL, run keys kept, write gate
python3 tests/test_write_confirms.py  # every browser write asks first (one confirm, cancel sends nothing)
python3 tests/test_glance.py         # shared 📊 At a glance template: escaping, safeHref, no inline handlers, zero dimming, filter clicks; migrated pages
python3 tests/test_acr_protect.py     # ACR protection: preview == navi's selection, NO : UPDATE exact, ACR log rows, business case, contract option
python3 tests/test_c2.py              # Command & Control: targets, read-only catalog + quoting, gates, cred-test statuses, C2 log (no output, masked, hash chain), hand-offs, AI-plan validator, canary/threshold/abort (fake navi: tests/c2_fakenavi.py; navi's real command handling: tests/c2_realnavi.py)
```

The `test_*_4NN.py` files are the per-build regression suites (e.g. `test_ex_compliance_471.py`
Compliance Explorer, `test_explorer_nl_472.py` the explorers' ✨ Ask, `test_classify_473.py` device
types + cloud, `test_ex_software_475.py` Software Explorer + zero-day lookup,
`test_release_pipeline_477.py` AI Contract ▸ Release the Hounds, `test_software_shape_478.py`
navi's one-row-per-software-string shape); `test_review_*.py`, `test_security_*.py`, `test_hx_*.py`
and the rest cover the review fixes, the server security model and the ⚡ Optimize summary tables.

Run everything:

```
for t in tests/test_*.py; do python3 "$t" > /dev/null 2>&1 || echo "FAILED $t"; done
```

## Attack paths (Fenrir)

- `attackpath_fixture.py` builds a realistic navi.db with five network segments:
  - **DMZ:** Log4Shell / Confluence.
  - **Workstations:** PrintNightmare, EternalBlue, BlueKeep, SMB signing off, LLMNR, no LAPS.
  - **Servers:** a Zerologon / noPac domain controller and SQL with a blank `sa` password.
  - **Linux app tier:** shared service accounts, PwnKit / Dirty Pipe.
  - **Isolated lab:** must reach no crown jewel.
  - **Plus:** an internet-facing host and failed CIS/STIG controls.
- `test_attackpath.py` checks the engine (`core/attackpath.py`) against that fixture:
  - **False positives that must stay out:**
    - Windows cumulative rollups that mention Netlogon;
    - client-side bugs (Adobe Reader, ssh-agent) and denial-of-service-only flaws;
    - domain-SID enumeration listing `krbtgt`;
    - web-app role escalation;
    - loose compliance keywords ("sudo is installed", SMB *client* signing, firewall logging, NoNameReleaseOnDemand);
    - built-in account names treated as shared passwords.
  - **Signals that must be present:**
    - KEV chains;
    - unauthenticated Redis;
    - accounts with empty passwords;
    - Kerberoast;
    - PrintNightmare as a lateral exploit;
    - local Administrator reuse where LAPS failed;
    - internet exposure;
    - domain admin reaching every domain controller.
  - **Edge cases:**
    - missing `acr` / `cves` / `xrefs` / `port` columns;
    - an empty database;
    - no compliance table;
    - scanning as Administrator;
    - IPv4-mapped IPv6 addresses;
    - a remediation bundle that's the same on every run.
  - **Account reuse only — password reuse is never inferred:**
    - the same account name on many hosts is *account* reuse, never *password* reuse;
    - even identical `/etc/shadow`-format lines on several hosts don't create password reuse or a
      "confirmed" credential step, and no hash-like value appears in identity or attack-path output;
    - a `nologin` account is not flagged as reuse.

## Other agents

`test_agents.py` holds the regression checks from the agent reviews, on tiny in-memory fixtures:
EOL dates tagged per asset (undated and fixed findings excluded), OS vs application from the
plugin name, MITRE ICS technique ids, the cross-site POST guard, per-agent tag-category
whitelists, the identity tag selector, and the Certificate agent on Feb 29.
Scan Evaluations (Chronos): worst credential state wins, a 110723 for one protocol doesn't override a
credentialed scan, fixed findings don't count, freshness buckets, agent grouping, old plugin feeds,
crown-jewel blind spots, and the tag action refusing keys or scanners it doesn't know.

Generate the fixture on its own to explore it in the app:

```
python3 tests/attackpath_fixture.py /tmp/ap_full.db
NAVI_DB_PATH=/tmp/ap_full.db python3 run.py
```

When you fix a bug, add the row that reproduces it to the fixture and a `check(...)` for it.
