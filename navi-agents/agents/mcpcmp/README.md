# MCP Compare — Tenable MCP vs navi MCP

A practical reference for using the two surfaces as one toolkit:

- **Capability & routing matrix** — where each job (asset/finding lookup, tagging,
  ACR/AES, scans, agents, policies, WAS, dashboards, raw API) naturally lives.
- **Limits & handoffs** — the rule-based tag cap (~1024 IPs / 1999 UUIDs),
  OS/app/device detection handoff to navi, ACR/AES being navi-only, dashboards
  being Tenable-MCP-only, and same-account safety.
- **navi-side snapshot** — tag categories, asset count, and navi's own identity,
  so you can sanity-check what navi is pointed at.

The full live "same account" cross-check (navi.db ⇄ Tenable categories) runs in the
desktop console, which has the Tenable MCP available. A standalone repo only has
navi, so this page shows the navi side and the static guidance.

Action: `run` / `snapshot`.
