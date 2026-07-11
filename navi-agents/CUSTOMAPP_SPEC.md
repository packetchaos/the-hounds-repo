# Custom App Name Agent — Specification

Finds software that Tenable's **software inventory** misses, and lets an operator
name & tag custom apps in plain English. Software the platform doesn't package
(in-house apps, unpackaged binaries, web apps) still leaves a trail in the
**vuln routes** and **filesystem paths** — this agent mines that trail.

## Discovery
- Reads `vuln_route.app_name` (named app/components) and `vuln_paths.path`
  (filesystem evidence), and the `software` inventory (`software_string`).
- Tokenizes paths (drops infra dirs, version suffixes, container hashes, and
  `/plugins/` sub-components) and takes route app-names.
- Surfaces every candidate **not present in the software inventory**, ranked by
  evidence (route vuln count or distinct asset count), with an example path.
- Result on the lab data: routes CENTOS / TENABLE NESSUS / JENKINS / APACHE /
  NAVI, plus path-only `nessus`, `nessus_agent`, `spring-boot-application`.
  `docker` and `urllib3` are correctly **filtered** (they're in inventory as
  `docker-ce` / `urllib3`).

## Natural-language tag ("Tag my custom app navi")
1. **Interpret** — the free-form instruction → `{name, keywords}` via on-device
   inference (artifact: `window.cowork.askClaude`) or the Anthropic API
   (standalone: `ANTHROPIC_API_KEY`); naive fallback (quoted/last word) if no LLM.
2. **Search** — `SELECT … FROM vuln_paths WHERE path LIKE '%<keyword>%'` shows the
   matched paths + affected assets, so the human sees exactly what will be tagged.
3. **Confirm & tag** — gated `navi_enrich_tag(category="Custom App", value="<name>",
   query="SELECT DISTINCT asset_uuid FROM vuln_paths WHERE path LIKE '%<keyword>%';", confirm=True)`.

> Example: navi installed in `/opt/navi` and `/home/.../navi/navi.db` → "Tag my
> custom app navi" finds both paths and tags `Custom App:navi` on those assets.

## REST API
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/agents/customapp/run` | Discovery — candidate custom apps not in inventory. |
| POST | `/api/customapp/interpret` | NL → `{name, keywords[]}`. |
| POST | `/api/customapp/search` | `{keyword}` → matching paths + assets + tag query. |
| POST | `/api/customapp/tag` | `{name, keyword, confirm}` → gated `Custom App:<name>` tag. |

## Notes
- Tag is accumulative (no `remove`) — a stable classification.
- Discovery is heuristic by design; the human reviews candidates before tagging
  (HITL). Tune the stop-word list / `/plugins/` rule in `core/agents/customapp_agent.py`.
- Validated on the sample DB: discovery, NL interpret (fallback), keyword search,
  and the write gate all confirmed on FastAPI and Flask; also live in the artifact.
