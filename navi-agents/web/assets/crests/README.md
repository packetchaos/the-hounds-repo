# Agent crest images

One square PNG per agent, named by the agent id (served as `/static/crests/<id>.png`). The
codename banner on each agent page and its hub card show the crest automatically; if a file
is missing the banner falls back to the 🐾 glyph (the hub card to the agent's icon).
Recommended: 256×256 (or larger square), transparent or charcoal background to match the app.

| File | Agent / codename |
|---|---|
| `certificate.png` | Certificate — Certania |
| `iot_squad.png` | IoT Discovery Squad — Cerberus Hound |
| `acr.png` | ACR Calibration — Anubis |
| `customapp.png` | Custom App — Cavall Hound |
| `mitre.png` | MITRE ATT&CK — Orthrus Hound |
| `eol.png` | EOL / Unsupported — Charon |
| `dashboard.png` | Dashboard Builder — Daedalus |
| `ai.png` | AI Inventory — Pythia |
| `identity.png` | Identity Inventory — Janus |
| `scan_eval.png` | Scan Evaluations — Chronos |
| `insights.png` | On the Scent — Sphinx |
| `exproute.png` | Exposure Routes — Atlas |
| `software.png` | Software Analyzer — Mimir |
| `ex_assets.png` | Asset Explorer — Bloodhound |
| `ex_vulns.png` | Vulnerability Explorer — Hellhound |
| `ex_plugins.png` | Plugin Explorer — Foxhound |
| `ex_routes.png` | Route Explorer — Wolfhound |
| `ex_paths.png` | Path Explorer — Greyhound |
| `asset_ownership.png` | Asset Ownership — Terminus |
| `c2.png` | Command & Control — Amarok |
| `compliance.png` | Compliance — Minos |
| `compliance_asset.png` | Compliance Deep-Dive — Tiresias |
| `custom_audit.png` | Custom Audit — Draco |
| `ex_apps.png` | WAS Apps Explorer — Vizsla |
| `ex_compliance.png` | Compliance Explorer — Saluki |
| `ex_fixed.png` | Fixed Explorer — Plott |
| `ex_tags.png` | Tag Explorer — Basset |
| `ex_software.png` | Software Explorer — Harrier |
| `fused_score.png` | Exposure Score — Nemesis |
| `mcpcmp.png` | MCP Compare — Pointer |
| `sla.png` | SLA Adherence — Sköll |
| `was.png` | WAS · Web Apps — Arachne |
| `was_asset.png` | Web App Recon — Beagle |
| `agentgroup.png` | Agent Group Tagging — Sirius Hound |
| `alert.png` | Alerting — Alert Raven |
| `argos.png` | Asset Deep-Dive — Argos Hound |
| `attackpath.png` | Attack Path Analysis — Fenrir Hound |
| `cisakev.png` | CISA KEV Tagging — Laelaps Hound |
| `classify.png` | Asset Classification — Linnaeus |
| `contract.png` | AI Navi Contract — Covenant |
| `email.png` | Email & Reports — Gabriel |
| `postquantum.png` | Post-Quantum Cipher Analysis — Heimdall |
| `tagremoval.png` | Tag Removal — Garmr Hound |

`hounds.png` is the pack's own crest — the app logo and the Release the Hounds heading
(`.hcrest` in `console.css`). The same crests are embedded in the "Meet the Hound" one-pagers
(`tools/hound_pages.py`).
