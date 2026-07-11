# ACR Calibration Agent — Specification

Adjusts the **Asset Criticality Rating (ACR, 1–10)** for all assets carrying a
tag, so Tenable One's Asset Exposure Score (AES) reflects business reality.

## Tag source — the live command (not the tags table)
The agent lists tags via **`navi explore info tags`** (parsed Category / Value /
Value UUID), per requirement — *not* a `SELECT` on the local `tags` table. In the
standalone app this runs through `navi_cli.list_tags()` (subprocess); in the live
artifact it runs through `navi_explore_info(subcommand="tags")`.

## What the operator can do
- **Set** — absolute ACR 1–10 for every asset on the tag (`mod="set"`).
- **Increase by N** — `mod="inc"`: each asset's ACR goes up by N (capped at 10).
- **Decrease by N** — `mod="dec"`: each asset's ACR goes down by N (floored at 1).
  So an asset at **9** with −1 becomes **8**; an asset at **3** with −1 becomes **2**.
- **Business justification** — a free-text note (required for inc/dec) carried into
  the change for audit.
- **Change Reason** — at least one of business / compliance / mitigation /
  development (Tenable One mandates a reason on every ACR change).

## Apply (gated)
`navi_enrich_acr(category, value, score, mod, note, <reason>=True, confirm=True)`
— needs `confirm=true` (the UI's Apply) **and** `NAVI_ALLOW_WRITES=1` with `navi`
on PATH. Validates score 1–10 and ≥1 reason before calling. Handles navi 8.6.2's
cosmetic `job_uuid` crash as applied-with-warning. Allow ~30 min for AES recompute.

## Bulk ACR — free-form natural language (LLM)
A prompt box lets you calibrate many tags from one plain-English instruction,
e.g.:

> *Drop all IoT and lab gear by 5, set anything internet-facing to 9, bump
> production databases to 10, and leave the vuln-route tags alone.*

**Interpret with AI** sends the instruction + the live tag list to a model,
which returns proposed ACR changes. The model only *proposes* — output is then
**validated** against the current tags (tag must exist, `mod ∈ set/inc/dec`,
score 1–10; anything else is rejected and shown) and rendered as a per-tag
preview. Nothing is written until you click **Apply all**, which runs one gated
`navi_enrich_acr` per change (the instruction + the model's "why" become the
audit note).

- **Artifact**: uses on-device inference (`window.cowork.askClaude`).
- **Standalone**: uses the Anthropic API via `ANTHROPIC_API_KEY` (model from
  `ANTHROPIC_MODEL`, default `claude-haiku-4-5-20251001`) at `/api/acr/interpret`.
- **Fallback**: with no key / no inference available, the box is parsed by the
  deterministic rule grammar instead (`Parse as rules`):
  `if <keyword> reduce|increase|set by|to N` (first match wins). Always available,
  fully offline, auditable.

## REST API
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/agents/acr/run` | List tags from `navi explore info tags`. |
| POST | `/api/acr/apply` | Apply one ACR change. Body: `{category, value, score, mod, note, reasons[], confirm}`. |
| POST | `/api/acr/bulk_apply` | Apply a batch. Body: `{changes:[{category,value,score,mod,note,reasons[]}], confirm}`. |

## Suggested tier mapping (set)
Prod+PII 10 · Internet-facing 9 · Production 8 · Staging 6 · Dev/Test 3 · Isolated 2.

## Validated
Tag-listing parser handles values containing colons (e.g. Mitre "Primary Impact: T1574").
Gates verified: confirm required, score 1–10, ≥1 reason, justification required for
inc/dec, and writes blocked without `NAVI_ALLOW_WRITES`. Identical on FastAPI and Flask;
also live in the artifact tab.
