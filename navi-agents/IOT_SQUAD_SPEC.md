# IoT Discovery Squad — Specification

Four cooperating agents that discover IoT/OT devices in Tenable via navi, tag
them, and **learn new detections over time** under human review. Built on the
same shared core as the Certificate Agent (read-only `navi.db`, gated `navi`
CLI writes).

```
Discovery (A1) ──hand off iot_name + plugins──▶ Expansion (A2)
      │                                              │ expanded plugin list
      │ IoT:<name> tag actions (Gate 1)              ▼
      ▼                                       Cross-Reference (A3)
  human approves tags                     ┌── other matching assets (candidates)
                                          └── propose new detections (Gate 2) ──▶ human
                         Orchestrator / QA (A4) chains all three + quality checks
```

## Agent 1 — IoT Discovery
- Loads the detection registry (`data/iot_detections.json`).
- For each detection, finds assets whose vulns match by `plugin_id`,
  `plugin_name LIKE`, or `output LIKE` (conservative; ultra-short output terms skipped).
- **Action 1:** emits `IoT:<name>` tag actions (ephemeral `remove=True`, so
  membership always reflects current detections; UUID preserved).
- **Action 2 (hand-off):** sends `{iot_name, trigger_plugins, asset_uuids}` to A2.

## Agent 2 — Plugin Expansion
- For each `iot_name`, searches **every** plugin name and output for that name.
- Guardrails (false-positive control):
  - drop plugins on the generic/enumeration **denylist** (10863, 11936, 54615, 35716, …);
  - drop plugins firing on **> 50%** of assets (too prevalent);
  - skip `iot_name`s shorter than 5 chars or on the stoplist (cast, camera, server, …).
- Kept plugins not yet in the registry's explicit `plugins` list (and not previously
  rejected) become **proposals**. Hands the expanded list to A3.

## Agent 3 — Cross-Reference
- Uses the kept expanded plugins to find **other assets** (not already discovered)
  that share those signatures → cross-reference candidates (with evidence count).
- Sends the proposed new detections to the **human (Gate 2)**: "add these plugins
  to the default detection for `<iot_name>`?"
  - **Approve** → persisted into `iot_detections.json` with provenance; reused next run.
  - **Reject** → remembered in `rejected[]`, never re-proposed.

## Agent 4 — Orchestrator / QA
- Runs A1 → A2 → A3 as one pipeline, pausing at the two human gates.
- Quality checks: ambiguous plugins (proposed for >1 device), generic-denylist leaks,
  weak (single-plugin) candidate evidence. Returns flags for review.

## Human-in-the-loop gates
1. **Tag approval** (A1): approve `IoT:<name>` → gated `navi enrich tag … -remove`
   (needs `NAVI_ALLOW_WRITES=1` + `navi` on PATH). Handles the navi 8.6.2
   cosmetic `job_uuid` crash as applied-with-warning.
2. **Detection approval** (A3): approve/reject proposals → writes the local registry.

## REST API
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/agents/iot_squad/run` | Run the whole pipeline; returns discovery/expansion/xref/qa + the two gates. |
| POST | `/api/agents/iot_squad/tags/apply` | Apply approved `IoT:<name>` tags (`{values, confirm}`). |
| GET | `/api/iot/registry` | Current default detections + rejected list. |
| POST | `/api/iot/detections/decide` | Persist approve/reject decisions (`{decisions, confirm}`). |

## Detection registry (`data/iot_detections.json`)
Seeded from the navi device-fingerprinting playbook (plugin 10863 cert appliances,
66717 mDNS, 35716 MAC OUI): Chromecast, pfSense, Ubiquiti, TeraStation,
Samsung SmartTV. Grows via Gate 2. Path override: `IOT_REGISTRY_PATH`.

## Validated (sample dataset)
- A1 discovers all 5 seed device types and emits 5 tag actions.
- A2 keeps device-specific plugins; drops the generic 10863 via the denylist.
- A3 surfaces a cross-reference candidate (`edge-fw-02` via the pfSense HTTP plugin)
  and 4 detection proposals.
- Approving a proposal persists it (and stops it being re-proposed); rejecting is remembered.
- A4 QA returns no false flags on clean data.
- Identical results via FastAPI and Flask; tag + detection writes both gated.

## Things to keep tuning
- **Generic terms / prevalence cap** are the main false-positive levers (`core/iot_common.py`).
- **Stale navi.db** still applies — run `navi config update full` so discovery sees live assets.
- **Loop bounds:** the pipeline runs one expansion pass per execution; re-run after
  approving detections to pick up the newly-promoted plugins (the UI does this automatically).
