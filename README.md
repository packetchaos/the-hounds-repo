# The Hounds — navi-agents

The executable harness for **The Hounds**: a pack of exposure-management agents that run
over [Tenable **navi**](https://github.com/packetchaos/navi) (`navi.db` + the Tenable API)
and surface the results in a local console. Each "hound" is a specialist that hunts one
kind of exposure and then tags it, calibrates its risk, or answers a question — grounded
in real navi queries, with every write proposed for human approval.

## Quick start

```bash
python3 run.py            # auto: built-in zero-dependency server (no pip required)
python3 run.py fastapi    # FastAPI (auto-installs if missing)
python3 run.py flask      # Flask  (auto-installs if missing)
python3 run.py stdlib     # force the zero-dependency server
```

Run from the repo root (the folder that contains `run.py`, `core/` and `app_*.py`). On
first run it builds a bundled sample database (`sample_navi.db`) so you can try it with no
setup. For production, point `NAVI_DB_PATH` at navi's real database:

```bash
export NAVI_DB_PATH=/path/to/navi.db
export NAVI_ALLOW_WRITES=0   # keep writes disabled until you're ready
python3 run.py
```

## Layout

```
run.py            one-command launcher (stdlib / FastAPI / Flask)
app_stdlib.py     zero-dependency HTTP server
core/             engine: db, signals, discovery, health, scan_eval, mitre, eol, …
core/agents/      the hound implementations (ACR, certificate, custom-app, IoT, …)
```

## The pack

Laelaps (CISA KEV), Certania (certificates), Heimdall (post-quantum), Fenrir (attack
paths), Cerberus (IoT/OT), Pythia (AI inventory), Atlas (ownership), Mimir (software),
Charon (EOL/unsupported), Anubis (ACR), Chronos (scan health), Sirius (agent groups),
Garmr (tag removal), Orthrus (MITRE ATT&CK), Argus (custom apps), Argos (asset deep-dive),
Sphinx (overview), Covenant (the AI Contract).

## Prerequisites

- Python 3 (a stock install works — the default server needs no third-party packages).
- [Tenable **navi**](https://github.com/packetchaos/navi) with a synced `navi.db` for
  production use (a sample DB is generated automatically for evaluation).
- A Tenable Vulnerability Management / Tenable One account with API keys configured for navi.

## Outputs

- A local web console listing detected exposures per hound, with the triggering signals.
- Proposed navi tag / ACR writes (shown for confirmation; never applied automatically).

## Known limitations

- Detection is signal-based inference; confirm findings before tagging.
- Writes are disabled by default (`NAVI_ALLOW_WRITES=0`) and every write is gated behind
  explicit confirmation.
- Results are only as current as the `navi.db` you point it at.

## License

MIT — see [LICENSE](LICENSE).
