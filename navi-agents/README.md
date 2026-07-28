# The Hounds — Navi Agent Command Center

A modular suite of **exposure-management agents** for Tenable Vulnerability
Management / Tenable One, built on top of the open-source **navi** CLI. Each
agent is a drop-in module (Python + one HTML page) that discovers something in
your environment and **tags it**, calibrates risk, or answers a plain-English
question — all over a local `navi.db` snapshot, with every write gated behind an
explicit confirmation.

> **Read-only by default. Writes are on purpose.** Nothing is written to your
> tenant unless writes are enabled *and* a confirm is supplied.

---

## Requirements

- **Python 3.10 or newer** (the code uses `X | None` type hints). Check with
  `python3 --version`. On 3.9 or older it will fail to import — this is the most
  common "it won't run" cause.
- No third-party packages required for the default server.

## Quick start

```bash
# from the repo root (the folder with run.py):
python3 run.py
```

Then **open the URL it prints in your browser:**

> ### → http://localhost:8000

⚠️ **Open that URL — do not double-click `web/index.html`.** The app is served by
a small local web server; opening the HTML file directly (a `file://…` path)
gives you a **blank page**, because the browser can't load the app's `/static`
assets or reach the `/api` backend. Always use `http://localhost:8000`.

`run.py` needs nothing but Python 3.10+. It builds a sample dataset on first run,
uses FastAPI/uvicorn if they're installed, and otherwise falls back to a
zero-dependency stdlib server.

**No navi.db yet?** Seed a sample so the UI works with fixture data:

```bash
python3 make_sample_db.py     # writes ./sample_navi.db
python3 run.py
```

**Point at your real tenant** (live data + tagging):

```bash
export NAVI_ALLOW_WRITES=1        # required for any tag/ACR write
export ANTHROPIC_API_KEY=sk-...   # optional: enables the NL→SQL features
python3 run.py
```

The app reads whatever `navi.db` navi maintains locally. Keep it fresh with
`navi update assets` / `navi update vulns` (the UI has a one-click **Refresh
navi.db**). navi.db is a point-in-time snapshot, so freshness matters.

---

## What's inside

| Agent | Codename | What it does |
|---|---|---|
| **AI Navi Contract** | Covenant Hound | Orchestrator — capture a policy once; it plans, then tags / sets-ACR on a loop when armed |
| **Certificate Agent** | Certania Hound | Tags 12-month certificate failures; cert-issue × asset heat maps |
| **IoT Discovery Squad** | Cerberus Hound | Detect → expand → cross-reference → QA; tags IoT / embedded devices |
| **ACR Calibration** | Anubis Hound | Adjust Asset Criticality Rating per tag (set / +N / −N), bulk or by NL rules |
| **Custom App Tagging** | Argus Hound | Finds custom apps via routes / paths; tag from plain English |
| **MITRE ATT&CK Tagging** | Orthrus Hound | Maps CVEs to ATT&CK techniques and tags the affected assets |
| **EOL / Unsupported** | Charon Hound | Tags end-of-life / unsupported software by plugin lifecycle text |
| **AI Inventory** | Pythia Hound | Finds assets running AI / ML software and tags them |
| **Identity Inventory** | Janus Hound | Human + non-human identities; tags the hosting assets |
| **Scan Evaluations** | Chronos Hound | Scan-time analysis + credential-failure coverage |
| **Exposure Routes** | Atlas Hound | Maps routes / paths to owners (`Owner: <app>: <user>`), with coverage analytics |
| **Software Analyzer** | Mimir Hound | Version sprawl, most-deployed, and rare single-install software |
| **Tag Removal** | Garmr Hound | Lists every tag and removes the chosen ones; feeds the contract's removal phase |
| **Agent Group Tagging** | Sirius Hound | Tags assets by Tenable agent group (NL list / widget / all) |
| **CISA KEV Tagging** | Laelaps Hound | Tags Known-Exploited vulns off the CISA-KNOWN-EXPLOITED xref, all or by catalog date |
| **Post-Quantum Cipher Analysis** | Heimdall Hound | Tags assets in Tenable's PQ-cipher plugins (277650 / 277652 / 277653) |
| **Dashboard Builder** | Daedalus Hound | NL → read-only SQL → KPI / bar / line / pie; pin + promote to a Custom Dashboard |
| **On the Scent (Insights)** | Sphinx Hound | Surfaces the unknown-unknowns as one exposure overview |
| **Explorers** | Bloodhound / Hellhound / Foxhound / Wolfhound / Greyhound | Read-only drill-downs over assets, vulns, plugins, routes, paths |

---

## Layout

```
.
├── run.py                  cross-platform launcher (stdlib, or FastAPI/Flask if installed)
├── app_stdlib.py           zero-dependency server
├── app_fastapi.py          uvicorn server         (optional)
├── app_flask.py            flask server           (optional)
├── make_sample_db.py       seed a fixture navi.db
├── core/                   shared infrastructure
│   ├── db.py               read-only sqlite3 access to navi.db
│   ├── navi_cli.py         gated navi writes (tag by plugin/CVE/xref/group/query, ACR)
│   ├── tagq.py             background tag queue (the Tagging log)
│   ├── contract.py         autonomous policy engine (plan → arm → loop)
│   ├── llm.py              optional NL→SQL / NL→rules (Anthropic API)
│   ├── discovery.py        scans agents/*/manifest.json → registry
│   └── launcher.py         generic /api/<id>/<action> dispatch
├── agents/                 ONE folder per agent (manifest.json · agent.py · api.py · page.html)
│   └── _template/          copy this to add your own agent
└── web/                    hub (index.html), shared console.css / console.js, agent crests
```

## Add your own agent

Copy `agents/_template/` to `agents/<your-id>/`, fill in `manifest.json`,
`agent.py`, `api.py`, and `page.html`. The hub discovers it automatically on the
next start. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security notes

- **Writes are gated** by `NAVI_ALLOW_WRITES=1` *and* a per-action `confirm`.
- **Never commit `navi.db`** — it's a snapshot of your tenant. It's already in
  `.gitignore` along with sqlite journals and `.env`.
- Set secrets (`ANTHROPIC_API_KEY`, navi API keys) via environment variables,
  never in code.

## Troubleshooting

**Blank / white page.** You almost certainly opened `web/index.html` directly.
Close it and open **http://localhost:8000** (the URL `run.py` printed) instead.
Still blank on that URL? Hard-refresh (Ctrl/Cmd-Shift-R) and check the browser
console (F12) — and confirm the terminal still shows the server running.

**`TypeError: unsupported operand type(s) for |` on startup / it won't import.**
Your Python is older than 3.10. Run `python3 --version`; install 3.10+ (pyenv,
Homebrew `python@3.12`, or your package manager) and re-run.

**`ModuleNotFoundError: No module named 'fastapi'`.** You launched a server that
needs deps. Just use `python3 run.py` (it falls back to the built-in server), or
force it: `python3 run.py stdlib`.

**Port 8000 already in use.** `PORT=8010 python3 run.py`, then open
`http://localhost:8010`.

**"No agents / discovering agents…" forever.** You're not on the served URL, or
you started `run.py` from the wrong folder. Run it from the repo root (the folder
that contains `run.py`, `agents/`, and `web/`).

**Everything reads "SAMPLE data".** That's expected until you point at a real
navi.db — set `NAVI_DB_PATH=/path/to/navi.db` (or run from navi's working dir).

**"⚠ Claude: no API key" chip / natural-language features greyed out.** The
Anthropic key is **optional** — the whole app works without it. It only powers the
NL extras (ask-which-Hound, NL→SQL, NL ACR rules, cert reasoning). To enable them,
get a key at <https://console.anthropic.com> → API Keys and
`export ANTHROPIC_API_KEY=sk-ant-...` before `python3 run.py`. Run
`python3 check_llm.py` to verify it's picked up.

---

## Credits & license

Built on **navi** by Casey Reid. Released under the [MIT License](LICENSE).
