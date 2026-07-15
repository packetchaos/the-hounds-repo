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
# macOS / Linux
export NAVI_DB_PATH=/path/to/navi.db   # your real navi.db (see "Where is navi.db?" below)
export NAVI_ALLOW_WRITES=1             # required for any tag/ACR write
export ANTHROPIC_API_KEY=sk-ant-...    # optional: enables the NL / NL→SQL features
python3 run.py
```

```powershell
# Windows PowerShell — set in the SAME shell you launch the server from
$env:NAVI_DB_PATH   = "C:\path\to\navi.db"
$env:NAVI_ALLOW_WRITES = "1"
$env:ANTHROPIC_API_KEY = "sk-ant-..."
python run.py
```

The app reads whatever `navi.db` navi maintains locally. Keep it fresh with
`navi update assets` / `navi update vulns` (the UI has a one-click **Refresh
navi.db**). navi.db is a point-in-time snapshot, so freshness matters.

> **Set env vars in the SAME shell you start the server from.** A variable set in
> a different terminal (or after the server started) won't reach the process. On
> Windows, `set NAME=value` only lasts for that Command Prompt session; use the
> System → Environment Variables dialog to make it permanent. Run
> `python check_writes.py` (writes) and `python check_llm.py` (Anthropic key) to
> confirm the server actually sees them.

---

## Configuration — environment variables

Everything is configured through environment variables (never in code). Only
`NAVI_DB_PATH` matters for a basic live run; the rest turn on specific features.

| Variable | Needed for | Notes |
|---|---|---|
| `NAVI_DB_PATH` | Reading your real tenant | Full path to your live `navi.db`. If unset, the app auto-discovers navi's `navi.db` (most-assets wins) and otherwise falls back to the bundled `sample_navi.db`. **This is the #1 thing to set** to get off sample data. |
| `NAVI_ALLOW_WRITES` | Tag / ACR writes | Set to `1`. The master write gate — without it every tag/ACR is blocked (reads still work). Equivalent: create an empty file named `ALLOW_WRITES` in the repo root. |
| `NAVI_EMAIL` | Sending email (Gabriel) | Set to `1`. A **second** opt-in stacked *on top of* `NAVI_ALLOW_WRITES` — enabling writes alone does **not** enable email. Equivalent: an empty `ALLOW_EMAIL` file in the repo root. See **Email setup** below. |
| `ANTHROPIC_API_KEY` | Natural-language features | Optional. Powers ask-which-Hound, NL→SQL, NL ACR rules, cert reasoning. The app works fully without it (those extras are greyed out). Get one at <https://console.anthropic.com> → API Keys. Verify with `python check_llm.py`. |
| `ANTHROPIC_MODEL` | Overriding the model | Optional. Defaults to `claude-haiku-4-5-20251001`. Set only if you need a different model you have access to. |
| `NAVI_BIN` | navi not on `PATH` | Optional. Full path to the `navi` executable if the server can't find it (pipx / Homebrew / pyenv installs). Verify with `python check_writes.py`. |
| `NAVI_CWD` | Read/write DB alignment | Optional. Folder the `navi` CLI runs in (it uses that folder's `navi.db`). Defaults to the folder holding `NAVI_DB_PATH` so reads and tag-writes hit the same database. |
| `PORT` | Changing the port | Optional. Default `8000` (the Flask fallback uses `8001`). e.g. `PORT=8010`. |

### Where is navi.db?

navi keeps `navi.db` in whatever folder you run navi from. If you're not sure,
run `navi` once in your intended working folder and point `NAVI_DB_PATH` at the
`navi.db` it created (or its `~/.navi` / home folder). The write-gate diagnostic
prints exactly which file the app reads and which folder navi writes to:

```bash
python check_writes.py
```

## Email setup (Gabriel / the email agent)

Sending email is **gated in three places** and needs a transport configured inside
navi itself — this is the step that most often trips people up, because the env
var alone is not enough:

1. **Configure a transport in navi, once, out-of-band** (the app never does this
   for you):

   ```bash
   navi config smtp        # a classic SMTP server, OR
   navi config resend      # the Resend email API
   ```

   These are interactive navi commands — run them yourself at a terminal. Without
   one of them, sends fail with *"your email information may be incorrect."*

2. **Enable writes:** `NAVI_ALLOW_WRITES=1` (the master gate).
3. **Enable email on top of writes:** `NAVI_EMAIL=1` (or an `ALLOW_EMAIL` file in
   the repo root). Enabling writes alone does **not** enable email.
4. **Confirm in the UI** — every send needs an explicit approval.

Composing and preview are read-only and always available; only the actual send
needs all of the above. Every send is recorded in the **Tagging log** for
accountability.

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

**Email won't send / "your email information may be incorrect."** Three things
must all be true: (1) a transport is configured in navi — run `navi config smtp`
or `navi config resend` at a terminal; (2) writes are on — `NAVI_ALLOW_WRITES=1`;
(3) email is separately on — `NAVI_EMAIL=1` (or an `ALLOW_EMAIL` file). Enabling
writes alone does **not** enable email. See **Email setup** above.

**"⚠ Claude: no API key" chip / natural-language features greyed out.** The
Anthropic key is **optional** — the whole app works without it. It only powers the
NL extras (ask-which-Hound, NL→SQL, NL ACR rules, cert reasoning). To enable them,
get a key at <https://console.anthropic.com> → API Keys and
`export ANTHROPIC_API_KEY=sk-ant-...` before `python3 run.py`. Run
`python3 check_llm.py` to verify it's picked up.

---

## Credits & license

Built on **navi** by Casey Reid. Released under the [MIT License](LICENSE).
