# MITRE ATT&CK Tagging Agent

Tags assets by the **MITRE ATT&CK framework**, following the navi-enrich skill
recipe (`tag-by-cve-external-csv`): it downloads the live
[Center for Threat-Informed Defense ATT&CK→CVE mapping](https://github.com/center-for-threat-informed-defense/attack_to_cve)
and, for each CVE, writes three `Mitre` tags — **Primary Impact**, **Secondary
Impact**, and **Exploit Technique** — using navi's own **tag-by-CVE** function
(`navi enrich tag --cve`). The navi tagging is **not reimplemented or bundled**;
this agent only fetches the live CSV and orchestrates navi's write path.

## Actions

- `run` — fetch the live mapping and build the per-CVE plan. Default scope is the
  CVEs actually present in your navi.db (`vulns.cves`); `scope="all"` returns the
  full mapping (thousands of CVEs — a CLI bulk job per the skill).
- `apply` — gated; tags each approved CVE via `navi enrich tag --cve` (needs
  `NAVI_ALLOW_WRITES=1` and `navi` on PATH).

Reads use the read-only navi.db; writes go through navi's gated CLI. In the
hosted artifact the same recipe runs through the navi-mcp `navi_enrich_tag(cve=…)`
tool.
