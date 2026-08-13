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

## Configuration

All configuration is environment variables (put them in a `.env` in the repo root —
`run.py` loads it; real shell env always wins). Nothing here is required to boot the
demo; the defaults run the bundled sample read-only.

| Variable | Default | Purpose |
|---|---|---|
| `NAVI_DB_PATH` | bundled `sample_navi.db` | Path to navi's SQLite database — point this at your real `navi.db`. |
| `NAVI_ALLOW_WRITES` | `0` | Master gate for **all** writes (tag / ACR / remove / email / push). Must be `1` **and** each action passes `confirm`. (Or drop an empty `ALLOW_WRITES` file in the repo root.) |
| `NAVI_REMOTE_CODE_EXECUTION` | `0` | **Separate** opt-in required by Command & Control (Amarok) on top of writes — enables `navi action push` (SSH RCE) to a single Linux host. (Or an empty `ALLOW_REMOTE_EXEC` file.) The highest-risk gate in the pack. |
| `NAVI_BIN` | `navi` on `PATH` | Full path to the navi CLI if it isn't on `PATH`. |
| `ANTHROPIC_API_KEY` | — | Enables the model features: NL→SQL, NL audit authoring, ownership/OS/tagging plans, correlation narration. Agents degrade gracefully without it. |
| `ANTHROPIC_MODEL` | app default | Override the Claude model (set one your key can access). |
| `ANTHROPIC_MAX_TOKENS` | app default | Hard ceiling on output tokens for every agent call. |
| `NAVI_TAG_WORKERS` | `4` | Parallel tag writes (1–32). Adjustable live from the Tagging log; persisted in the sidecar. |
| `NAVI_TAG_GAP_MS` | `1500` | Pacing gap between tag writes (rate-limit safety). |
| `NAVI_TAGLOG_DB` | `tag_jobs.db` (repo root) | Durable, shared **Tagging log** sidecar — survives restarts and is visible across processes. |
| `NAVI_UUID_CAP` | `1999` | Tenable per-call asset-UUID cap; navi loops past it (the app prefers server-side selectors over the cap). |
| `NAVI_ALERT_EMAIL` | — | Recipient for Alert Raven / the contract's per-cycle change email. |
| `NAVI_EMAIL` / SMTP | — | Enables Gabriel email sends (`NAVI_EMAIL=1` + `navi config smtp` set out-of-band). |
| `PORT` | `8000` (FastAPI) / `8001` (Flask) | Server port. |

Writes are always double-gated (`NAVI_ALLOW_WRITES=1` **and** a per-action `confirm`);
remote execution (Command & Control) is **triple-gated** — it additionally requires
`NAVI_REMOTE_CODE_EXECUTION=1` and a per-host confirm. Read-only exploration is safe by
default.

---

## What's inside

Naming: the **detection hounds are literal dogs/wolves** (Cerberus, Laelaps, Fenrir,
Sköll, Garmr, Orthrus, Argos, Cavall, Amarok) and the **explorers are dog breeds**; the
**higher-order agents are domain-matched figures** whose myth maps to the job (Charon
ferries EOL to retirement, Anubis weighs criticality, Atlas bears the routes, Gabriel
carries the mail, Daedalus builds, Terminus marks boundaries). Only actual canines keep
the “Hound” suffix.

**Signal & analysis**

| Agent | Codename | What it does |
|---|---|---|
| **MITRE ATT&CK Tagging** | Orthrus Hound | Maps CVEs to ATT&CK techniques and tags the affected assets |
| **CISA KEV Tagging** | Laelaps Hound | Tags Known-Exploited vulns off the CISA-KNOWN-EXPLOITED xref, all or by catalog date |
| **EOL / Unsupported** | Charon | Tags end-of-life / unsupported software by plugin lifecycle text |
| **Certificate Agent** | Certania | Tags 12-month certificate failures; cert-issue × asset heat maps |
| **IoT Discovery Squad** | Cerberus Hound | Detect → expand → cross-reference → QA; tags IoT / embedded / OT devices |
| **Post-Quantum Cipher Analysis** | Heimdall | Tags assets in Tenable's PQ-cipher plugins (277650 / 277652 / 277653) |
| **AI Inventory** | Pythia | Finds AI / ML software; labels EOL + ATT&CK exposure; tags |
| **Identity Inventory** | Janus | Human + non-human identities; tags the hosting assets |
| **Software Analyzer** | Mimir | Version sprawl, most-deployed, and a risk leaderboard (package × its vulns) |
| **Custom App Tagging** | Cavall Hound | Finds custom / in-house apps via routes & paths; tag from plain English |
| **WAS · Web Apps** | Arachne | Consolidated Tenable WAS — severity, OWASP profile, tech inventory, scan coverage; tag web apps |
| **Attack Path Analysis** | Fenrir Hound | Surfaces attack paths and choke points across the estate |
| **Scan Evaluations** | Chronos | Scan-time analysis + credential-failure coverage |
| **Asset Classification** | Linnaeus | Classifies assets (class / subnet / OS) and tags by OS from plain English |
| **Compliance** | Minos | Consolidated audit compliance — pass/fail/warn, top failing controls, framework rollup, per-asset scorecards; assign an Audit Owner |

**Organize**

| Agent | Codename | What it does |
|---|---|---|
| **Agent Group Tagging** | Sirius Hound | Tags assets by Tenable agent group (NL list / widget / all) |
| **Exposure Routes** | Atlas | Maps routes / paths to owners (`Owner: <app>: <user>`), with coverage analytics |
| **Asset Ownership** | Terminus | Multi-layer ownership (business owners; technology owners over routes & paths), % owned, unclaimed / blind, crown jewels |
| **ACR Calibration** | Anubis | Adjust Asset Criticality Rating per tag (set / +N / −N), bulk or by NL rules |
| **Custom Audit** | Draco | Author a Tenable `.audit` from plain English or a guided builder; upload & edit existing files; validate; auto-map framework refs |

**Operationalize**

| Agent | Codename | What it does |
|---|---|---|
| **SLA Adherence** | Sköll | Findings against their remediation clock — what's overdue, by how long, for whom |
| **Email & Reports** | Gabriel | Emails a dashboard or report as an email-safe HTML digest (gated) |
| **Alerting** | Alert Raven | Baseline + threshold alerts; crafts and emails the change |
| **Tag Removal** | Garmr Hound | Lists every tag and removes the chosen ones; feeds the contract's removal phase |
| **Command & Control** | Amarok Hound | Remediation executor — `navi action push` (SSH RCE) to **one** Linux host: run a command, ship a file, or apply a vuln-derived patch. Triple-gated (writes + RCE opt-in + per-host confirm), canary-first campaigns with stop-on-failure + abort, Route→Tag→Push→Verify |
| **AI Navi Contract** | Covenant | Orchestrator — capture a policy once; it plans, then tags / sets-ACR on a loop when armed |

**Views & deep-dives**

| Agent | Codename | What it does |
|---|---|---|
| **Exposure Score** | Nemesis | Fuses every Hound's signal into one exposure score per asset; worst-from-each, convergence, projected reduction |
| **On the Scent** | Sphinx | The estate brain — posture across every Hound, blind spots, and cross-Hound surprises |
| **Dashboard Builder** | Daedalus | NL → read-only SQL → KPI / bar / line / pie; pin + promote to a Custom Dashboard |
| **Compliance Deep-Dive** | Tiresias | One asset *or* one audit file in full — checks (actual vs expected), framework maps, and inferred audit↔vuln links |
| **Asset Deep-Dive** | Argos Hound | Recognizes one asset across every table — the full dossier |
| **Web App Recon** | Beagle | Per-web-app recon — sitemap, target, screenshot, plugin output |

**Explorers** — read-only drill-downs over the estate: Bloodhound (assets) · Hellhound (vulns) · Foxhound (plugins) · Wolfhound (routes) · Greyhound (paths) · Vizsla (WAS apps) · Plott (fixed).

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
