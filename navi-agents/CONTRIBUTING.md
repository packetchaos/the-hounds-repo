# Contributing

Thanks for helping grow the pack. Adding an agent is intentionally small: **one
folder, four files**. The hub auto-discovers it on the next start — no core
changes needed.

## Add an agent

```bash
cp -r agents/_template agents/<your-id>
```

Then edit the four files:

| File | Purpose |
|---|---|
| `manifest.json` | id, name, icon, category, codename, summary, and the actions your API exposes |
| `agent.py` | the read-only discovery — subclass `core.agents.base.Agent`, implement `_run()` returning a dict |
| `api.py` | HTTP actions: `ACTIONS = {"run": ..., ...}`; each returns `(payload, status)` |
| `page.html` | the agent's UI; loads `/static/console.js` and calls `agentApi('<your-id>')` |

Restart (`python3 run.py`) and your agent appears in **Release the Hounds**.

## Ground rules

- **Reads** go through `core.db` (read-only sqlite over `navi.db`). Never open the
  DB read-write.
- **Writes** go through `core.navi_cli` and must be gated (`NAVI_ALLOW_WRITES=1`)
  **and** confirmed. Only the Tag Removal agent may remove tags.
- **Be honest about coverage** — surface blind/uncredentialed hosts, don't hide them.
- Prefer navi **built-in selectors** (`--plugin/--output`, `--cve`, `--cpe`,
  `--xrefs`, `--group`) over raw `--query` where one exists.
- Keep secrets in environment variables; never commit `navi.db` or `.env`.

## Before a PR

- `python3 -m compileall core agents` passes.
- `python3 run.py` starts and your agent runs against the sample DB.
- No `navi.db` / `sample_navi.db` / secrets in the diff (see `.gitignore`).
