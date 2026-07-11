# Argos — Asset Deep-Dive (`argos`)

*Odysseus's faithful hound — the one who recognized his master's identity after twenty years.*

Give Argos a single asset **UUID or IP** and it recognizes it across every table in
`navi.db`, assembling one dossier:

- **Identity** — hostname, IP, OS, network, ACR/AES, UUID, Tenable link.
- **Risk** — a 0–100 score + band from the severity mix, KEV / exploitable findings,
  and the pack's tag intelligence, with a severity breakdown.
- **What the pack knows** — every tag on the asset **deciphered**: what it means and
  which Hound raised it (Laelaps → CISA KEV, Certania → cert failure, Charon → EOL, …).
- **CVEs**, **top findings**, **software**, and **certificates** (weak-crypto flagged).

Reads `navi.db` read-only. The **Live · navi explore uuid** panel runs the flag-driven
per-asset views (`-software`, `-patches`, `-details`, `-cves`, base) through the navi
CLI on demand — needs `navi` on the server (`NAVI_BIN`).

## Actions
| action | payload | returns |
|--------|---------|---------|
| `run` | — | readiness stub (hub Execute) |
| `lookup` | `{target}` (UUID or IP) | the full dossier |
| `live` | `{target, view}` | `navi explore uuid <target> [view]` output |

Deep-link: `page.html?target=<uuid|ip>` auto-runs the lookup.
