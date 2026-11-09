# The Hounds — Navi Agent Command Center

A modular suite of **41 exposure-management agents** for Tenable Vulnerability
Management / Tenable One, built on top of the open-source **navi** CLI. Each
agent is a drop-in module (Python + one HTML page) that discovers something in
your environment and **tags it**, calibrates risk, or answers a plain-English
question — all over a local `navi.db` snapshot, with every write gated behind an
explicit confirmation.

> **Read-only by default. Writes are on purpose.** Nothing is written to your
> tenant unless writes are enabled *and* a confirm is supplied.

> **Using Claude / Cowork?** The same engines are exposed as an MCP server with
> thin, persona-focused artifacts on top — see **[HOUNDS-MCP.md](HOUNDS-MCP.md)**
> for how to run and connect it.

**Docs:** [INSTALL.md](INSTALL.md) (setup, gates, verification) ·
[BYO_MODEL.md](BYO_MODEL.md) (bring your own model) ·
[HOUNDS-MCP.md](HOUNDS-MCP.md) (MCP server) ·
[CONTRIBUTING.md](CONTRIBUTING.md) (add an agent)

---

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

`run.py` needs nothing but **Python 3.10+**. It builds a sample dataset on first
run, uses FastAPI/uvicorn if they're installed, and otherwise falls back to a
zero-dependency stdlib server.

**Point at your real tenant** (live data + tagging):

```bash
export NAVI_DB_PATH=/path/to/navi.db
export NAVI_ALLOW_WRITES=1        # required for any tag/ACR write
export ANTHROPIC_API_KEY=sk-...   # optional: enables the NL features
python3 run.py
```

The app reads whatever `navi.db` navi maintains locally. Keep it fresh with
`navi config update assets` / `navi config update vulns` (the UI has a one-click **Refresh
navi.db**). navi.db is a point-in-time snapshot, so freshness matters.

Full setup — prerequisites, the three server modes, the write/RCE gates, the MCP
server, and verification — is in **[INSTALL.md](INSTALL.md)**.

---

## Configuration

All configuration is environment variables (put them in a `.env` in the repo root —
`run.py` loads it; real shell env always wins). Nothing here is required to boot the
demo; the defaults run the bundled sample read-only.

### Settings page & the config store

Model, keys, gates and paths can also be set on **Settings → 🔑 Environment**. They
take effect live; the **Storage** switch decides whether they survive a restart:

- **💾 Config file** (default) — saved to `hounds.config.json` in the repo root
  (chmod 600, git-ignored) and re-applied on every start of the app and the MCP
  server. Keys are stored in plain text, the same exposure as a `.env`.
- **⏳ Ephemeral** — nothing is written; values last until the server restarts.
  Switching to ephemeral deletes any saved values, leaving only a
  `{"mode": "ephemeral"}` marker so the choice sticks.

Set `HOUNDS_CONFIG=/path/to/file.json` to move the file, or `HOUNDS_CONFIG=off` to
disable the store completely (never read or written). Precedence:
**shell env > config file > `.env` > defaults** — each field on the Settings page
shows where its current value came from.

### Core

| Variable | Default | Purpose |
|---|---|---|
| `NAVI_DB_PATH` | bundled `sample_navi.db` | Path to navi's SQLite database — point this at your real `navi.db`. |
| `NAVI_BIN` | `navi` on `PATH` | Full path to the navi CLI if it isn't on `PATH`. |
| `NAVI_CWD` | repo root | Working directory navi is invoked from (where it looks for its own config/DB). |
| `PORT` | `8000` (stdlib / FastAPI) / `8001` (Flask) | Server port. |

### Gates — writes, email, remote execution

| Variable | Default | Purpose |
|---|---|---|
| `NAVI_ALLOW_WRITES` | `0` | Master gate for **all** writes (tag / ACR / remove / email / push). Must be truthy **and** each action passes `confirm`. (Or drop an empty `ALLOW_WRITES` file in the repo root.) `NAVI_MCP_ALLOW_WRITES` is honoured as an alias. |
| `NAVI_EMAIL` | `0` | **Separate** opt-in required by Gabriel / Alert Raven on top of writes — enables `navi action mail`. (Or an empty `ALLOW_EMAIL` file.) Aliases: `NAVI_MCP_ALLOW_EMAIL`, `NAVI_MAIL`. SMTP must also be set out-of-band via `navi config smtp`. |
| `NAVI_REMOTE_CODE_EXECUTION` | `0` | **Separate** opt-in required by Command & Control (Amarok) on top of writes — enables `navi action push` (SSH RCE) to a single Linux host. (Or an empty `ALLOW_REMOTE_EXEC` file.) Aliases: `NAVI_MCP_ALLOW_REMOTE_CODE_EXECUTION`, `NAVI_RCE`. The highest-risk gate in the pack. |
| `NAVI_ALERT_EMAIL` | — | Recipient for Alert Raven / the contract's per-cycle change email. Falls back to `NAVI_EMAIL_TO`. |

Writes are always double-gated (`NAVI_ALLOW_WRITES=1` **and** a per-action `confirm`);
email and remote execution are **triple-gated** — each additionally requires its own
opt-in flag. Read-only exploration is safe by default. Run `python3 check_writes.py`
to see exactly which gates the server resolved.

### Reasoning layer (optional — see [BYO_MODEL.md](BYO_MODEL.md))

Every model call in the pack funnels through one function, so any of four providers
works. With nothing configured every agent falls back to its deterministic path — the
whole app still runs.

| Variable | Default | Purpose |
|---|---|---|
| `NAVI_LLM_PROVIDER` | auto-detect | `anthropic` · `openai` · `ollama` · `bedrock`. Blank infers from whichever key/endpoint is present. |
| `NAVI_LLM_MODEL` | per-provider default | Model id for the chosen provider. `ANTHROPIC_MODEL` still works for Anthropic. |
| `NAVI_LLM_BASE_URL` | per-provider default | Endpoint override — OpenAI-compatible, Ollama, or self-hosted. |
| `NAVI_LLM_API_KEY` | — | Generic key; the provider-specific key (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY`) wins when both are set. |
| `NAVI_LLM_MAX_TOKENS` | `8000` | Hard ceiling on output tokens for every agent call. `ANTHROPIC_MAX_TOKENS` is still honoured as a fallback. |
| `NAVI_LLM_JSON_MODE` | off | Force provider-native JSON mode where supported. |
| `ANTHROPIC_API_KEY` | — | Anthropic key. Also what auto-detect looks for first. |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` | — | OpenAI or any `/chat/completions` endpoint (OpenRouter, vLLM, Together, Groq, LM Studio, Azure-style). |
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Fully local model — no key, nothing leaves the machine. |
| `AWS_REGION` / `AWS_PROFILE` / `AWS_ACCESS_KEY_ID` | — | Bedrock via the Converse API. The one provider that needs a package (`boto3`). |

Run `python3 check_llm.py` to print the resolved provider/model/endpoint and make one
real call with an actionable failure reason.

### Tagging & jobs

| Variable | Default | Purpose |
|---|---|---|
| `NAVI_TAG_WORKERS` | `4` | Parallel tag writes (1–32). Adjustable live from the Tagging log; persisted in the sidecar. |
| `NAVI_TAG_GAP_MS` | `1500` | Pacing gap between tag writes (rate-limit safety). |
| `NAVI_TAG_TIMEOUT` | `900` | Per-invocation timeout (seconds) for a navi tag/ACR call. |
| `NAVI_TAGLOG_DB` | `tag_jobs.db` (repo root) | Durable, shared **Tagging log** sidecar — survives restarts and is visible across processes. |
| `NAVI_UUID_CAP` | `1999` | Tenable per-call asset-UUID cap; navi loops past it (the app prefers server-side selectors over the cap). |
| `NAVI_JOB_WORKERS` | `3` | Background agent-run workers (1–16). |
| `NAVI_JOB_LOG_MAX` | `200` | Job-log entries retained in memory. |
| `NAVI_PUSH_TIMEOUT` | `300` | Per-host timeout (seconds) for a Command & Control push. |

### Paths, caches & tuning

| Variable | Default | Purpose |
|---|---|---|
| `CONTRACT_DIR` | `contracts/` | Where the AI Contract stores its policy + state. |
| `ALERT_DIR` | `alerts/` | Alert Raven's definitions and fired-state. |
| `NAVI_HISTORY_DIR` | `data/` | Daily snapshots for SLA / trend history. |
| `HOUNDS_CONFIG` | `hounds.config.json` | Settings config-store file path, or `off` to disable it. |
| `NAVI_AGENT_CACHE_TTL_S` | `300` | Agent-result cache lifetime. |

Every tagging agent (manifest category Tagging or Discovery) opens with a **📋 Done so far** strip — last run, runs recorded, tag values applied, how many assets carry them in navi.db now, what's awaiting a sync, failures, emails/pushes/ACR changes, and tags already in navi.db that weren't applied from this install (`core/activity.py`; run history is kept in `tag_jobs.db`, table `runs`, capped by `NAVI_RUN_LOG_MAX`, default 20000).

Each agent page also remembers its last run (24 h) — kept on the server (`data/cache/pages/`), so it's shared across browsers — and restores it when you come back; use **↻ Re-run** on the restore strip for fresh numbers. **🐾 Release the Hounds** on the hub runs every hound in the sidebar's order in the background (reads only, with an estimate first and a Cancel) so every page is already populated when you open it. Per-browser tunables in `localStorage`: `houndsCacheTTLh` (hours) and `houndsCacheOff=1` to disable.
| `NAVI_HEALTH_TTL_S` | `30` | Health-chip cache lifetime. |
| `NAVI_ASSET_COUNT_TTL_S` | `300` | Asset-count cache lifetime. |
| `NAVI_QUERY_BUDGET_MS` | off | Abort a `navi.db` query that exceeds this budget. |
| `SAMPLE_ASSETS` | auto | Asset count when building the sample fixture (`make_sample_db.py`). |
| `HOUNDS_MCP_HTTP` / `HOUNDS_MCP_HOST` / `HOUNDS_MCP_PORT` | stdio / `127.0.0.1` / `8790` | Run the MCP server over HTTP instead of stdio — see [HOUNDS-MCP.md](HOUNDS-MCP.md). |

---

## What's inside — the 41 agents

Naming: the **detection hounds are literal dogs/wolves** (Cerberus, Laelaps, Fenrir,
Sköll, Garmr, Orthrus, Argos, Cavall, Amarok) and the **explorers are dog breeds**; the
**higher-order agents are domain-matched figures** whose myth maps to the job (Charon
ferries EOL to retirement, Anubis weighs criticality, Atlas bears the routes, Gabriel
carries the mail, Daedalus builds, Terminus marks boundaries). Only actual canines keep
the "Hound" suffix.

### Signal & analysis (15)

| Agent | Codename | What it does |
|---|---|---|
| **MITRE ATT&CK Tagging** | Orthrus Hound | Maps CVEs to ATT&CK techniques and tags the affected assets |
| **CISA KEV Tagging** | Laelaps Hound | Tags Known-Exploited vulns off the CISA-KNOWN-EXPLOITED xref, all or by catalog date |
| **EOL / Unsupported** | Charon | Tags end-of-life / unsupported software by plugin lifecycle text |
| **Certificate Agent** | Certania | Tags assets with expired certs (by month, last 12 months + older) and certs failing in 12 months; expiry timeline, crown-jewel / weak-crypto metrics, Cert Issue tagging |
| **IoT Discovery Squad** | Cerberus Hound | Detect → expand → cross-reference → QA; tags IoT / embedded / OT devices |
| **Post-Quantum Cipher Analysis** | Heimdall | Tags assets in Tenable's PQ-cipher plugins (277650 / 277652 / 277653); crown-jewel migration roadmap |
| **AI Inventory** | Pythia | Finds AI / ML software; labels EOL + ATT&CK/ATLAS exposure; tags by role |
| **Identity Inventory** | Janus | Human + non-human identities; tags the hosting assets |
| **Software Analyzer** | Mimir | Version sprawl, most-deployed, and a risk leaderboard (package × its vulns) |
| **Custom App Tagging** | Cavall Hound | Finds custom / in-house apps via routes & paths; tag from plain English |
| **WAS · Web Apps** | Arachne | Consolidated Tenable WAS — severity, OWASP profile, tech inventory, scan coverage; tag web apps |
| **Attack Path Analysis** | Fenrir Hound | Surfaces attack paths and choke points across the estate |
| **Scan Evaluations** | Chronos | Scan-time analysis + credential-failure coverage |
| **Asset Classification** | Linnaeus | Classifies assets (class / subnet / OS) and tags by OS from plain English |
| **Compliance** | Minos | Consolidated audit compliance — pass/fail/warn, top failing controls, framework rollup, per-asset scorecards; assign an Audit Owner |

### Organize (5)

| Agent | Codename | What it does |
|---|---|---|
| **Agent Group Tagging** | Sirius Hound | Tags assets by Tenable agent group (NL list / widget / all) |
| **Exposure Routes** | Atlas | Maps routes / paths to owners (`Owner: <app>: <user>`), with coverage analytics |
| **Asset Ownership** | Terminus | Multi-layer ownership (business owners; technology owners over routes & paths), % owned, unclaimed / blind, crown jewels |
| **ACR Calibration** | Anubis | Adjust Asset Criticality Rating per tag (set / +N / −N), bulk or by NL rules |
| **Custom Audit** | Draco | Author a Tenable `.audit` from plain English or a guided builder; upload & edit existing files; validate; auto-map framework refs |

### Operationalize (6)

| Agent | Codename | What it does |
|---|---|---|
| **SLA Adherence** | Sköll | Findings against their remediation clock — what's overdue, by how long, for whom |
| **Email & Reports** | Gabriel | Emails a dashboard or report as an email-safe HTML digest (gated) |
| **Alerting** | Alert Raven | Baseline + threshold alerts; crafts, tests, and emails the change |
| **Tag Removal** | Garmr Hound | Lists every tag and removes the chosen ones; feeds the contract's removal phase |
| **Command & Control** | Amarok Hound | Remediation executor — `navi action push` (SSH RCE) to **one** Linux host: run a command, ship a file, or apply a vuln-derived patch. Triple-gated (writes + RCE opt-in + per-host confirm), canary-first campaigns with stop-on-failure + abort, Route→Tag→Push→Verify |
| **AI Navi Contract** | Covenant | Orchestrator — capture a policy once; it plans, then tags / sets-ACR on a loop when armed |

### Views & deep-dives (7)

| Agent | Codename | What it does |
|---|---|---|
| **Exposure Score** | Nemesis | Fuses every Hound's signal into one exposure score per asset; worst-from-each, convergence, projected reduction |
| **On the Scent** | Sphinx | The estate brain — posture across every Hound, blind spots, and cross-Hound surprises |
| **Dashboard Builder** | Daedalus | NL → read-only SQL → KPI / bar / line / pie; pin + promote to a Custom Dashboard |
| **Compliance Deep-Dive** | Tiresias | One asset *or* one audit file in full — checks (actual vs expected), framework maps, and inferred audit↔vuln links |
| **Asset Deep-Dive** | Argos Hound | Recognizes one asset across every table — the full dossier |
| **Web App Recon** | Beagle | Per-web-app recon — sitemap, target, screenshot, plugin output |
| **MCP Compare** | — | Tenable MCP vs navi MCP — capability & routing matrix, the limits that force a handoff (rule-tag cap, OS/app/device detection, ACR/AES, dashboards), and a navi-side connection check |

### Explorers (8)

Read-only drill-downs over the estate.

| Agent | Codename | What it searches |
|---|---|---|
| **Asset Explorer** | Bloodhound | `assets` — hostname, IP, OS, network |
| **Vulnerability Explorer** | Hellhound | `vulns` — plugin name, ID, CVE, severity, grouped by plugin |
| **Plugin Explorer** | Foxhound | Every distinct plugin — ID, name, family |
| **Route Explorer** | Wolfhound | `vuln_route` — app name or type |
| **Path Explorer** | Greyhound | `vuln_paths` — filesystem paths discovered on assets |
| **Tag Explorer** | Basset | `tags` — category/value, asset counts per tag, drill-down to the assets carrying each |
| **WAS Apps Explorer** | Vizsla | `apps` — name/target/tech, severity presence, scan recency |
| **Fixed Explorer** | Plott | `fixed` — remediation history + Pass/Fail SLA verdicts |

> Four more manifests exist but are marked `hidden` and don't get a card:
> `_template` (the scaffold you copy), `explore` (backs the drill-down pages),
> `hub` (Release the Hounds), and `settings`.

---

## Layout

```
.
├── run.py                  cross-platform launcher (stdlib, or FastAPI/Flask if installed)
├── app_stdlib.py           zero-dependency server
├── app_fastapi.py          uvicorn server         (optional)
├── app_flask.py            flask server           (optional)
├── make_sample_db.py       seed a fixture navi.db
├── check_writes.py         diagnose the write gates + resolved navi binary
├── check_llm.py            diagnose the reasoning layer (provider / model / one real call)
├── hounds_mcp.py           MCP server — the engines as tools (see HOUNDS-MCP.md)
├── hounds_mcp_selftest.py  parity guardrail: MCP output == core output
├── requirements.txt        optional server frameworks
├── requirements-mcp.txt    optional: fastmcp, for the MCP server only
├── core/                   shared infrastructure
│   ├── db.py               read-only sqlite3 access to navi.db
│   ├── navi_cli.py         gated navi writes (tag by plugin/CVE/xref/group/query, ACR, mail, push)
│   ├── tagq.py             background tag queue (the Tagging log)
│   ├── jobq.py             background agent-run queue
│   ├── contract.py         autonomous policy engine (plan → arm → loop)
│   ├── alerts.py           Alert Raven's definitions, evaluation, and fired-state
│   ├── llm.py              optional reasoning layer — 4 providers (see BYO_MODEL.md)
│   ├── discovery.py        scans agents/*/manifest.json → registry
│   └── launcher.py         generic /api/<id>/<action> dispatch
├── agents/                 ONE folder per agent (manifest.json · agent.py · api.py · page.html)
│   └── _template/          copy this to add your own agent
├── artifacts/              persona artifacts that render the MCP tools
├── contracts/              AI Contract policy + state       (CONTRACT_DIR)
├── alerts/                 Alert Raven definitions + state  (ALERT_DIR)
├── data/                   daily snapshots for SLA/trend history (NAVI_HISTORY_DIR)
└── web/                    hub (index.html) + the shared dashboards
    ├── hounds/             "Meet the Hound" one-pagers
    └── assets/             shared console.css / console.js
        └── crests/         agent crests
```

## Add your own agent

Copy `agents/_template/` to `agents/<your-id>/`, fill in `manifest.json`,
`agent.py`, `api.py`, and `page.html`. The hub discovers it automatically on the
next start. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security model

The console is a **local** tool by default. `core/security.py` is the single policy every
server (stdlib, Flask, FastAPI) applies to every request:

| Control | Default | How to change it |
|---|---|---|
| **Bind address** | `127.0.0.1` — only this machine can connect | `HOUNDS_BIND=0.0.0.0` (or a specific IP) opts in to LAN access; startup prints a loud warning |
| **Host allowlist** (every request, GET too) | `localhost`, `127.0.0.1`, `[::1]` on any port; anything else → `403`. This is what defeats DNS rebinding | `HOUNDS_ALLOWED_HOSTS=hounds.lan,10.0.0.5` adds names/IPs. With a non-loopback `HOUNDS_BIND` the bound IP and this machine's hostname/IPs are added |
| **Access token** | not needed on loopback | With a non-loopback bind every `/api` call needs this launch's token. It is printed **once**, in the startup URL (`http://host:port/?token=…`); opening that URL swaps it for an `HttpOnly; SameSite=Strict` cookie. Scripts send `X-Hounds-Token: <token>`. A new token is generated on every start. `HOUNDS_REQUIRE_TOKEN=1` demands it on loopback too (shared jump boxes, where other local users can reach 127.0.0.1) |
| **POST guard** | JSON `Content-Type` required; a present `Origin` must be same-origin with an allowed host; `Origin: null` and `Sec-Fetch-Site: cross-site` refused | — |
| **Response headers** | `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` | — |
| **Static files** | only page assets (`.html .css .js .json .md` images, fonts) under `/agents/`, `/web/`, `/static/` — never `.py` source, `__pycache__` or dotfiles | — |
| **Limits** | request bodies capped at 80 MB (above the 64 MB page-cache entry) → `413`; socket timeout 120 s | `HOUNDS_MAX_BODY`, `HOUNDS_SOCKET_TIMEOUT` |
| **File modes** | the servers and the MCP server run with `umask 077`; caches, logs, alert state, contracts, C2 uploads are written `0600` (dirs `0700`) | — |

**Settings that can't be changed from the browser.** The Settings page can't set
`NAVI_BIN` or `NAVI_CWD` at all — a browser-settable binary path or working directory is
remote code execution. Set them in the shell, `.env` or `hounds.config.json` and restart.
Turning **on** the write / email / remote-execution gates (`NAVI_ALLOW_WRITES`,
`NAVI_EMAIL`, `NAVI_REMOTE_CODE_EXECUTION`) or changing `NAVI_DB_PATH` needs a browser on
**this machine** (loopback) plus an explicit confirmation; turning a gate **off** never
needs one. `NAVI_DB_PATH` must name an existing SQLite file. Changing the model endpoint
(`NAVI_LLM_BASE_URL`, http/https only) or provider **clears the stored model keys** unless
you enter the new key in the same save, so a changed URL can't receive the old key; the
page only ever shows the endpoint as `scheme://host[:port]/path` (no `user:pass@`, no query).

**SQL a person or the model writes** (Advanced search, Mimir, Alert Raven metrics, the
Dashboard builder) runs under a SQLite authorizer (`core.db.user_query`) that refuses to read
navi's credential tables — `keys`, `smtp`, `ssh`, `resend` — whatever the SQL looks like;
those values are also on the response scrub list.

**Approvals are strict.** Every write / send / remove / push needs `confirm: true` — a JSON
boolean; `"false"`, `"0"`, `1` or `"true"` are refused. Alert Raven only mails the configured
alert address(es) (`NAVI_ALERT_EMAIL`); mail recipients must be plain `user@host` addresses
and subjects are single-line. C2 uploads need the write + remote-exec gates and a confirm,
and the upload folder is capped (200 MB, oldest pruned). The C2 destructive-command list is
**advisory** — a warning that forces an extra confirm, not a guard.

The MCP server's HTTP transport (`HOUNDS_MCP_HTTP=1`) is unauthenticated, so it refuses a
non-loopback `HOUNDS_MCP_HOST` unless you also set `HOUNDS_MCP_ALLOW_REMOTE=1`.

## Security notes

- **Writes are gated** by `NAVI_ALLOW_WRITES=1` *and* a per-action `confirm`.
  Email and remote execution each need a **second** flag on top of that.
- **Never commit `navi.db`** — it's a snapshot of your tenant. It's already in
  `.gitignore` along with sqlite journals, `.env` and `hounds.config.json`.
- Set secrets (model API keys, navi API keys) via environment variables, `.env`, or
  the Settings page — use **Ephemeral** storage (or `HOUNDS_CONFIG=off`) if keys
  must never touch disk. Never put them in code.
- **Keys never reach the browser.** Settings shows only set / not set for a key, and
  every API response is scrubbed (`core/redact.py`) of configured secret values and
  anything shaped like `sk-…` / AWS key ids — including provider error messages.

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

**Tagging is greyed out / "writes disabled".** Run `python3 check_writes.py` in the
same shell you start the server from — it prints the flag the server actually
resolved and the navi binary it found.

**"⚠ Claude: no API key" chip / natural-language features greyed out.** The model
is **optional** — the whole app works without it. It only powers the NL extras
("ask which agent can help", NL→SQL, NL ACR rules, cert reasoning). Run
`python3 check_llm.py` to see the resolved provider and the exact failure reason,
and see [BYO_MODEL.md](BYO_MODEL.md) to point it at Anthropic, an OpenAI-compatible
endpoint, a local Ollama model, or Bedrock.

---

## Credits & license

Built on **navi** by Casey Reid. Released under the [MIT License](LICENSE).
