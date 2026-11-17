# The Hounds MCP + Persona Artifacts

This is the **Claude-native distribution** of The Hounds: a small MCP server that
exposes the pack's engines as tools, and a set of thin, **persona-focused
artifacts** that render them. The full app (`run.py`, the 40+ agent pages) stays
the canonical product — this layer just lets Claude, Cowork, and other MCP clients
feed off the *same* engines without re-implementing anything.

```
  ┌─────────────┐ ┌─────────────┐ ┌──────────────┐ ┌───────────────┐   thin artifacts
  │ Executive   │ │ VM Analyst  │ │ Compliance   │ │ Remediation   │   (render only)
  └──────┬──────┘ └──────┬──────┘ └──────┬───────┘ └───────┬───────┘
         └───────────────┴───────callMcpTool()──────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │  Hounds MCP  (hounds_mcp.py)   one JSON tool per engine
                    └────────────┬─────────────┘
                                 │  imports, does NOT copy
                    ┌────────────▼─────────────┐
                    │  Engines — core/*.py      │   all 40+ agents' logic, once
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │  navi.db + navi CLI       │   reads + gated writes
                    └──────────────────────────┘
```

**Why it's built this way.** Every MCP tool is a three-line wrapper that returns
the *exact* payload the repo's HTTP API already serves (e.g. `hounds_scent_board`
just returns `core.insights.scent_board()`). There is **zero logic in the MCP** —
so an artifact rendering these tools can never drift from the app. Change an engine
once; every surface updates. `hounds_mcp_selftest.py` asserts this on every run.

---

## What's here

| File | Purpose |
| --- | --- |
| `hounds_mcp.py` | The MCP server. Read-only tools over the core engines. |
| `hounds_mcp_selftest.py` | Parity + shape guardrail (tool output == core output; required keys present). |
| `requirements-mcp.txt` | One optional dependency (`fastmcp`). The base app doesn't need it. |
| `artifacts/hounds-exec-brief.html` | The Executive persona artifact (read-only estate brief) — reads the `hounds` tools above. |
| `artifacts/hounds-platform.html` | The shared artifact shell (Platform / Operations) — reads the **navi** MCP (`mcp__navi__*`), not this server; writes go through navi's gated `navi_enrich_tag` / `navi_enrich_acr` behind a confirm. |
| `artifacts/hounds-enrich.html` | The Data Enrichment artifact on the same shell — navi MCP reads, gated tag / ACR writes. |

### Tools (current)

| Tool | Engine | Read-only |
| --- | --- | --- |
| `hounds_exposure_overview` | `core.fused_score.overview` (Nemesis) — fused per-asset score, estate KPIs, factor weights, convergence. | ✅ |
| `hounds_scent_board` | `core.insights.scent_board` (Sphinx) — exposure distribution, risk-by-Hound, detection radar, coverage funnel, CVE→Plugin→App→Path reduction, posture, blind spots. | ✅ |

Writes (tag / ACR / push) are **not** exposed here — those stay behind the navi
MCP's own gates. This server cannot modify `navi.db`.

---

## Install & run

```bash
# from the repo root (the folder with hounds_mcp.py):
pip install -r requirements-mcp.txt

# run it, pointed at a real navi.db — or the bundled sample to try it out:
NAVI_DB_PATH=/absolute/path/to/navi.db python hounds_mcp.py
```

Verify it works before connecting anything:

```bash
NAVI_DB_PATH=./sample_navi.db python hounds_mcp_selftest.py
# → ALL PASSED
```

> **Tip:** use a virtual environment so `fastmcp` lands on the same interpreter
> you point Claude at:
> ```bash
> python3 -m venv .venv && source .venv/bin/activate
> pip install -r requirements-mcp.txt
> ```
> Then use `.venv/bin/python` as the `command` below.

---

## Connect it

The server name **must be `hounds`** — the artifacts call `mcp__hounds__<tool>`.

> **Which surface are you on?** This matters.
> - **Claude Desktop / Claude Code** → use the **local (stdio)** setup below
>   (Options A/B). Local MCP servers are *only* available on these surfaces.
> - **Cowork / web / mobile** (where the persona artifacts run) → a local server
>   is **not reachable**; you'll get a `400` and the artifact stays on demo data.
>   You need the **remote (HTTP) connector** in Option C.
>
> Anthropic's docs: local/desktop MCP servers are "only available in Claude
> Desktop and Claude Code — not on web or mobile"; remote connectors work
> everywhere including Cowork.

### Option A — manual config (fastest)

Edit (or create) your Claude Desktop config file:

| OS | Path |
| --- | --- |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Add the `hounds` block (merge alongside any existing `mcpServers`):

```json
{
  "mcpServers": {
    "hounds": {
      "command": "python3",
      "args": ["/absolute/path/to/the-hounds/navi-agents/hounds_mcp.py"],
      "env": {
        "NAVI_DB_PATH": "/absolute/path/to/navi.db"
      }
    }
  }
}
```

- Point `command` at the Python that has `fastmcp` (e.g. `.venv/bin/python`).
- Point `NAVI_DB_PATH` at a real `navi.db`, or the repo's `sample_navi.db` to demo.
- **Fully quit and restart** Claude Desktop — the config only loads on launch.
- Verify: click **+** in the chat box → **Connectors** to see `hounds` and its
  tools, or check **Settings → Developer** for status and logs.

### Option B — desktop extension (`.mcpb`, for sharing)

Package the server as a one-click extension so `NAVI_DB_PATH` becomes a settings
field: add a `manifest.json`, run `mcpb pack`, then **Settings → Extensions →
Advanced → Install Extension…** and select the `.mcpb`. See the
[MCPB docs](https://github.com/anthropics/mcpb).

### Option C — remote (HTTP) connector, **required for Cowork / web / mobile**

The persona artifacts run in Cowork, so the server has to be reachable as a
**remote connector** — a local stdio server returns `400` there. Run it over HTTP:

```bash
# on the machine that holds your navi.db:
HOUNDS_MCP_HTTP=1 NAVI_DB_PATH=/path/to/navi.db python hounds_mcp.py
# → serves http://127.0.0.1:8790/mcp   (override with HOUNDS_MCP_HOST / HOUNDS_MCP_PORT)
```

Then make that URL reachable by Claude's cloud and add it under
**Settings → Connectors → Add custom connector** (server id **`hounds`**).

- **Quick test:** front it with a tunnel, e.g. `cloudflared tunnel --url
  http://127.0.0.1:8790`, and register the tunnel's HTTPS URL.
- **Real use:** host it inside your network/VPC **behind authentication** — it
  reads your `navi.db`, so never expose it publicly unprotected.
- The HTTP transport has no authentication of its own, so `hounds_mcp.py` **refuses** a
  non-loopback `HOUNDS_MCP_HOST` unless you also set `HOUNDS_MCP_ALLOW_REMOTE=1` (and then
  prints a warning). Keep it on `127.0.0.1` behind the tunnel / an authenticating proxy.

> Rule of thumb: **stdio for Desktop/Code, HTTP for Cowork/web.** Same server, same
> tools — only the transport and how it's registered differ.

---

## The persona artifacts

Each artifact is a self-contained HTML page that calls the Hounds MCP via
`window.cowork.callMcpTool` and renders the result. Every artifact ships with an
**embedded sample fallback**, so it always renders (a chip shows *live* vs *demo*)
and flips to live data the moment the `hounds` server is connected.

| Persona | Ships | Reads |
| --- | --- | --- |
| **Executive / CISO** | ✅ PoC | `hounds_scent_board`, `hounds_exposure_overview` |
| VM Analyst | planned | KEV, attack paths, VPR/AES, software, EOL, certs, Argos |
| Compliance Officer | planned | compliance, deep-dive, custom audit |
| Remediation / Ops | planned | SLA, ownership, ACR, email, alerting, tag removal, C2, contract |

The persona split is by **job**, and every one of the pack's hounds lands in
exactly one persona (a few drill-downs, like Argos, appear in two). The mapping is
locked before each persona's tools are built, so coverage is guaranteed.

---

## Keeping it in sync

Because the artifacts consume the tools' JSON, **most engine changes propagate
automatically** — you only touch an artifact when a *new field needs new
rendering*. Before each release:

1. `python hounds_mcp_selftest.py` — proves tool output still equals core output
   and that every field the artifacts render is present.
2. Re-capture the embedded sample payloads if the shape changed.

The repo pages remain the reference renderer; when an artifact and its repo page
disagree, the repo wins and the artifact is fixed.

---

## Security notes

- **Read-only.** No tool here writes to `navi.db` or your tenant.
- **Local.** By default the server is a local stdio process reading *your* `navi.db`
  from *your* machine; the HTTP mode binds `127.0.0.1` unless you opt in with
  `HOUNDS_MCP_ALLOW_REMOTE=1`.
- **Gated writes stay gated.** Tagging, ACR, and remediation still go through the
  navi MCP's own double-gates and per-action confirms — this shim never bypasses
  them.
