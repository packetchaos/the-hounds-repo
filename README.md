# The Hounds — navi-agents

The executable harness for **The Hounds**: a pack of exposure-management agents that run
over [Tenable **navi**](https://github.com/packetchaos/navi) (`navi.db` + the Tenable API)
and surface the results in a local console. Each "hound" is a specialist that hunts one
kind of exposure and then tags it, calibrates its risk, or answers a question — grounded
in real navi queries, with every write gated and confirmed by a human.

Version `1.43.484` — the scheme is `MAJOR.<hounds>.<build>`, where the middle number is
the count of hounds the server discovers (43 in this release; `navi-agents/core/version.py`).

## Quick start

```bash
cd navi-agents
python3 run.py            # auto: FastAPI if installed, else Flask, else the built-in server
python3 run.py stdlib     # force the zero-dependency server (no pip required)
python3 run.py fastapi    # FastAPI (auto-installs if missing)
python3 run.py flask      # Flask  (auto-installs if missing)
```

Run it from `navi-agents/` (the folder that contains `run.py`, `core/` and `app_*.py`), then
open the URL it prints (`http://localhost:8000` by default). On first run it builds a bundled
sample database (`sample_navi.db`) so you can try it with no setup. For production, point
`NAVI_DB_PATH` at navi's real database:

```bash
export NAVI_DB_PATH=/path/to/navi.db
export NAVI_ALLOW_WRITES=0   # keep writes disabled until you're ready
python3 run.py
```

Full setup is in [navi-agents/INSTALL.md](navi-agents/INSTALL.md); the console, every hound
and the configuration are described in [navi-agents/README.md](navi-agents/README.md).

## Layout

```
navi-agents/
  run.py            one-command launcher (stdlib / FastAPI / Flask)
  app_stdlib.py     zero-dependency HTTP server
  hounds_mcp.py     optional read-only MCP server (see HOUNDS-MCP.md)
  core/             engine: db, signals, discovery, security, gates, llm, release pipeline, …
  agents/           one folder per hound (manifest.json · api.py · page.html · agent.py)
  web/              the hub, shared dashboards, and the "Meet the Hound" one-pagers (web/hounds/)
  tests/            regression tests — plain scripts: python3 tests/test_<name>.py
```

## The pack

Laelaps (CISA KEV), Certania (certificates), Heimdall (post-quantum), Fenrir (attack
paths), Cerberus (IoT/OT), Pythia (AI inventory), Janus (identities), Linnaeus (asset
classification), Atlas (route ownership), Terminus (asset ownership), Mimir (software),
Charon (EOL/unsupported), Anubis (ACR), Chronos (scan health), Sirius (agent groups),
Garmr (tag removal), Orthrus (MITRE ATT&CK), Cavall (custom apps), Arachne (web apps),
Minos (compliance), Tiresias (compliance deep-dive), Beagle (web-app recon), Sköll (SLA),
Nemesis (exposure score), Argos (asset deep-dive), Sphinx (On the Scent), Covenant (the AI
Contract) — plus Gabriel (email), Alert Raven, Amarok (command & control), Draco (custom
audits), Daedalus (dashboards), MCP Compare, and the Search
Hounds: explorers for assets, vulns, plugins, tags, routes, paths, WAS apps, fixed
findings, compliance results (Saluki) and software (Harrier, with a zero-day lookup).

## Prerequisites

- Python 3.10 or newer (a stock install works — the built-in server needs no third-party packages).
- [Tenable **navi**](https://github.com/packetchaos/navi) with a synced `navi.db` for
  production use (a sample DB is generated automatically for evaluation).
- A Tenable Vulnerability Management / Tenable One account with API keys configured in navi.
- Optional: a model (Anthropic, OpenAI-compatible, Ollama or Bedrock) for the plain-English
  features — see [navi-agents/BYO_MODEL.md](navi-agents/BYO_MODEL.md).

## Outputs

- A local web console listing detected exposures per hound, with the triggering signals.
- Proposed navi tag / ACR writes, shown for confirmation. Nothing is applied unless writes
  are enabled and you confirm — or you arm the AI Contract, which then applies its
  previewed plan on a schedule behind the same gate.

## Known limitations

- Detection is signal-based inference; confirm findings before tagging.
- Writes are disabled by default (`NAVI_ALLOW_WRITES=0`) and every write is gated behind
  explicit confirmation; email and remote execution each need a further opt-in.
- Results are only as current as the `navi.db` you point it at.

## License

MIT — see [LICENSE](LICENSE).
