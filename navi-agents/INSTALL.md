# Install

Getting The Hounds running, from a stock Python install to a live Tenable tenant.
Five minutes for the demo; add ten if you're wiring it to a real `navi.db`.

**Contents** — [Prerequisites](#prerequisites) · [Fastest path](#fastest-path-demo-data)
· [Server modes](#server-modes) · [Real tenant](#point-it-at-your-real-tenant)
· [Configuration](#configuration) · [Gates](#turning-writes-on)
· [Reasoning layer](#optional-the-reasoning-layer) · [MCP server](#optional-the-mcp-server)
· [Verify](#verify-the-install) · [Upgrading](#upgrading) · [Uninstall](#uninstall)
· [Troubleshooting](#troubleshooting)

---

## Prerequisites

| | Requirement | Notes |
|---|---|---|
| **Required** | **Python 3.10 or newer** | The code uses `X \| None` type hints. On 3.9 or older it fails to import — the single most common "it won't run" cause. Check with `python3 --version`. |
| **Required** | The repo | Run everything from the folder that contains `run.py`, `core/`, `agents/`, and `web/`. |
| **Production** | [**navi**](https://github.com/packetchaos/navi) with a synced `navi.db` | The app never talks to Tenable directly for reads — it reads navi's local SQLite snapshot. |
| **Production** | A Tenable VM / Tenable One account | With API keys configured *in navi* (`navi config keys`), not in this app. |
| **Optional** | A model API key or a local model | Only powers the natural-language extras. Everything else works without it. |
| **Optional** | `fastapi`+`uvicorn` or `flask` | The bundled stdlib server needs neither. |

No third-party packages are required for the default server.

---

## Fastest path (demo data)

```bash
cd navi-agents
python3 run.py
```

On first run it builds a bundled sample dataset (`sample_navi.db`) so every agent
has something to chew on. Then open the URL it prints:

> ### → http://localhost:8000

> ⚠️ **Open that URL — do not double-click `web/index.html`.** A `file://…` path
> gives you a blank page: the browser can't load `/static` or reach `/api`.

Everything will be labelled **SAMPLE data** until you point it at a real `navi.db`.

---

## Server modes

`run.py` picks the best available server and falls back gracefully. You can force one:

```bash
python3 run.py            # auto — FastAPI if installed, else Flask, else stdlib
python3 run.py stdlib     # force the zero-dependency built-in server
python3 run.py fastapi    # FastAPI + uvicorn (pip-installs them if missing)
python3 run.py flask      # Flask (pip-installs it if missing)
```

| Mode | Default port | Dependencies |
|---|---|---|
| stdlib | `8000` | none |
| FastAPI | `8000` | `fastapi`, `uvicorn[standard]` |
| Flask | `8001` | `flask` |

Override with `PORT=8010 python3 run.py`.

### Who can connect (security model)

Every server listens on **127.0.0.1** only. Open the URL printed at startup.

- **Access from another machine** is an explicit opt-in: `HOUNDS_BIND=0.0.0.0 python3 run.py`.
  Startup then prints a warning and a URL with a one-time access token
  (`http://<host>:8000/?token=…`, like Jupyter). Open that URL once — it becomes an HttpOnly
  cookie — or send the header `X-Hounds-Token: <token>` from scripts. The token changes on
  every restart. Prefer an SSH tunnel (`ssh -L 8000:127.0.0.1:8000 jumpbox`) when you can.
- **Host names**: requests must name the console as `localhost`, `127.0.0.1` or `[::1]` (or,
  with `HOUNDS_BIND`, this machine's hostname/IP). Add others with
  `HOUNDS_ALLOWED_HOSTS=hounds.lan,10.0.0.5`. Anything else gets `403` (this blocks DNS
  rebinding).
- **Shared jump box?** `HOUNDS_REQUIRE_TOKEN=1` requires the token even on loopback, so other
  local users can't drive your console.
- Running uvicorn/flask by hand with `--host 0.0.0.0` (without `HOUNDS_BIND`) refuses every
  remote `/api` call — set `HOUNDS_BIND` instead.
- **Env-only settings**: `NAVI_BIN` and `NAVI_CWD` can't be changed from the Settings page
  (set them in the shell / `.env` / `hounds.config.json` and restart). Enabling the write,
  email and remote-execution gates or changing `NAVI_DB_PATH` from Settings needs a browser on
  this machine and a confirmation. See [README → Security model](README.md#security-model).

To install the optional frameworks yourself:

```bash
pip install -r requirements.txt
```

A virtualenv keeps this tidy and is recommended if you'll also run the MCP server:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

---

## Point it at your real tenant

The app is a **reader of navi's database**, so the install order is: navi first,
sync, then this app.

**1. Install and configure navi** (separate project — see
[packetchaos/navi](https://github.com/packetchaos/navi)):

```bash
navi config keys        # your Tenable access + secret key
navi config update assets
navi config update vulns
```

**2. Point the app at the resulting `navi.db`:**

```bash
export NAVI_DB_PATH=/absolute/path/to/navi.db
python3 run.py
```

The "SAMPLE data" labels disappear and the header shows your real asset count.

**3. If `navi` isn't on `PATH`** (needed for any tagging/ACR write):

```bash
export NAVI_BIN=/full/path/to/navi
```

`navi.db` is a **point-in-time snapshot** — freshness matters. Re-run
`navi config update assets` / `navi config update vulns` on your normal cadence, or use the
one-click **Refresh navi.db** button in the UI.

> **Never commit `navi.db`.** It's a snapshot of your tenant. It's already in
> `.gitignore`, along with sqlite journals, `.env` and `hounds.config.json`.

---

## Configuration

Everything is environment variables. Rather than exporting them in every shell,
drop a `.env` in the repo root — `run.py` loads it at startup, and **real shell
environment always wins** over the file.

```bash
# .env
NAVI_DB_PATH=/Users/you/navi/navi.db
NAVI_BIN=/usr/local/bin/navi
NAVI_ALLOW_WRITES=0
ANTHROPIC_API_KEY=sk-ant-...
NAVI_TAG_WORKERS=4
```

### Or: the Settings page & the config store

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

The full variable table — core, gates, reasoning layer, tagging/jobs, caches — is in
the [README](README.md#configuration).

---

## Turning writes on

**Nothing is ever written to your tenant by default.** The app boots read-only and
stays that way until you opt in. There are three independent gates, and every gated
action *additionally* requires a per-action `confirm` from the UI.

### Gate 1 — writes (tags, ACR, tag removal)

```bash
export NAVI_ALLOW_WRITES=1
```

Or drop an empty file named `ALLOW_WRITES` in the repo root (`.allow_writes` and
`allow_writes` also work). `NAVI_MCP_ALLOW_WRITES` is honoured as an alias.

### Gate 2 — email (Gabriel, Alert Raven)

Needs gate 1 **plus** its own flag:

```bash
export NAVI_ALLOW_WRITES=1
export NAVI_EMAIL=1
export NAVI_ALERT_EMAIL=security@example.com
```

Or an empty `ALLOW_EMAIL` file. Aliases: `NAVI_MCP_ALLOW_EMAIL`, `NAVI_MAIL`.
SMTP itself is configured **in navi**, out of band:

```bash
navi config smtp
```

### Gate 3 — remote execution (Command & Control / Amarok)

The highest-risk capability in the pack: `navi action push` runs a command over SSH
on **one** Linux host. Needs gate 1 **plus**:

```bash
export NAVI_ALLOW_WRITES=1
export NAVI_REMOTE_CODE_EXECUTION=1
```

Or an empty `ALLOW_REMOTE_EXEC` file. Aliases:
`NAVI_MCP_ALLOW_REMOTE_CODE_EXECUTION`, `NAVI_RCE`. On top of the flags: Linux-only,
a destructive-command denylist, canary-first campaigns with stop-on-failure and an
abort switch, and a per-host confirm. SSH credentials come from `navi config ssh`.

> Enabling writes alone never enables email or push. Each is a deliberate,
> separate decision.

**Check what the server actually resolved:**

```bash
python3 check_writes.py
```

Run it in the *same shell* you start the server from. It prints the write flag, any
enable-file it found, and the navi binary it resolved.

---

## Optional: the reasoning layer

The pack uses a model for its "propose" steps — cert triage, ACR planning, ownership
mapping, NL→SQL, contract policy. **The model only proposes**; the UI previews and a
human approves before any gated write. With nothing configured, every agent falls
back to a deterministic path and the whole app still runs.

Quickest setup (Anthropic):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python3 check_llm.py     # prints resolved provider/model/endpoint + makes one real call
```

Four providers are supported — Anthropic, any OpenAI-compatible endpoint, local
Ollama, and AWS Bedrock. Bedrock is the only one that needs a package (`boto3`).
Full per-provider setup is in **[BYO_MODEL.md](BYO_MODEL.md)**.

---

## Optional: the MCP server

`hounds_mcp.py` exposes the same engines as MCP tools for Claude Desktop, Claude
Code, and Cowork. It's additive — the base app doesn't need it.

```bash
pip install -r requirements-mcp.txt

# verify before connecting anything:
NAVI_DB_PATH=./sample_navi.db python3 hounds_mcp_selftest.py     # → ALL PASSED

# run it:
NAVI_DB_PATH=/absolute/path/to/navi.db python3 hounds_mcp.py
```

The server is **read-only** — it cannot modify `navi.db` and exposes no tag/ACR/push
tools. The server name must be `hounds`. Client config, HTTP mode
(`HOUNDS_MCP_HTTP` / `HOUNDS_MCP_HOST` / `HOUNDS_MCP_PORT`), and the persona
artifacts are documented in **[HOUNDS-MCP.md](HOUNDS-MCP.md)**.

---

## Verify the install

Work down this list; each step is independent.

```bash
python3 --version                 # 3.10 or newer
python3 -m compileall core agents # everything imports cleanly
python3 run.py                    # server starts, prints a URL
```

Then in the browser at `http://localhost:8000`:

1. The hub (**Release the Hounds**) lists **41 agents**. If it says
   "discovering agents…" forever, you're not on the served URL or you started
   `run.py` from the wrong folder.
2. The header shows your asset count, and **doesn't** say "SAMPLE data" once
   `NAVI_DB_PATH` points at a real database.
3. Open any explorer (e.g. **Asset Explorer / Bloodhound**) and search — read-only
   queries confirm the DB is wired correctly.

And from the shell:

```bash
python3 check_writes.py   # gate state + resolved navi binary
python3 check_llm.py      # reasoning layer, if you configured one
```

---

## Upgrading

```bash
git pull
python3 -m compileall core agents
python3 run.py
```

New agents are discovered automatically from `agents/*/manifest.json` — there's no
registry to edit. Two things to know:

- **The sample DB rebuilds itself** if it's missing or empty. It's guarded to the
  `sample_navi.db` filename, so a real `navi.db` you point `NAVI_DB_PATH` at is
  never touched.
- **`tag_jobs.db` (the Tagging log) survives upgrades** by design — it's the durable
  record of what the pack wrote. Delete it only if you want to start that ledger over.

---

## Uninstall

There's no installer and nothing lands outside the repo folder. Delete the
directory. If you used a virtualenv, remove `.venv` with it. Tags already written to
your Tenable tenant stay there — remove those with the **Tag Removal (Garmr)** agent
*before* deleting, or from the Tenable UI afterward.

---

## Troubleshooting

**`TypeError: unsupported operand type(s) for |` on startup.**
Python older than 3.10. Install 3.10+ (pyenv, Homebrew `python@3.12`, or your
package manager) and re-run.

**Blank / white page.** You opened `web/index.html` directly. Use the
`http://localhost:8000` URL `run.py` printed. Still blank? Hard-refresh
(Ctrl/Cmd-Shift-R) and check the browser console (F12).

**`ModuleNotFoundError: No module named 'fastapi'`.** Use `python3 run.py` (it falls
back to the built-in server) or force it: `python3 run.py stdlib`.

**Port already in use.** `PORT=8010 python3 run.py`.

**"No agents / discovering agents…" forever.** Wrong URL, or `run.py` was started
from the wrong folder. It must be the folder containing `run.py`, `agents/`, `web/`.

**Everything reads "SAMPLE data".** Expected until `NAVI_DB_PATH` points at a real
`navi.db`.

**"no assets table" / the sample looks empty.** A partial `sample_navi.db` from an
interrupted first run. Delete it and re-run `python3 run.py` — it rebuilds, or run
`python3 make_sample_db.py` yourself.

**Tagging is greyed out, or a write returns "writes disabled".** Run
`python3 check_writes.py` in the same shell as the server. Usual causes: the flag
was exported in a *different* terminal, or `.env` was edited after the server
started (it's read once, at startup).

**A tag write fails with "navi: command not found".** Set `NAVI_BIN` to navi's full
path. If navi needs to run from a particular directory, set `NAVI_CWD` too.

**Tags don't appear in the Tenable UI.** Tag propagation takes up to ~30 minutes on
the Tenable side. Check the **Tagging log** first — if the job succeeded there, the
write landed and you're waiting on Tenable.

**Tagging is slow, or you're hitting rate limits.** Tune `NAVI_TAG_WORKERS` (1–32,
default 4) and `NAVI_TAG_GAP_MS` (default 1500). Both are adjustable live from the
Tagging log.

**"⚠ Claude: no API key" chip.** Optional — the app works without it. Run
`python3 check_llm.py` for the exact reason, and see [BYO_MODEL.md](BYO_MODEL.md).

**MCP server won't start / the client can't see it.** Run
`python3 hounds_mcp_selftest.py` first. If that passes, the problem is client-side
config — check that `fastmcp` is installed on the *same* interpreter you pointed the
client at, and that the server is named `hounds`. See [HOUNDS-MCP.md](HOUNDS-MCP.md).
