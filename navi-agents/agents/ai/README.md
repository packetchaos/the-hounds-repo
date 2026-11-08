# AI Inventory (Pythia)

Finds AI/ML on your assets by **content**, not just by Tenable's **Artificial
Intelligence** plugin family. It also reads the `software` and `cpes` inventories,
plugin output, and network endpoints (Ollama, Jupyter, MLflow, vLLM, …), so it picks
up AI workloads the plugin family doesn't report.

Each asset is classified by **role** (Model Serving, Vector DB / RAG, GPU / Training,
MLOps, Notebook / Dev, AI Dev Tool, LLM API Client). Every row has a **🔍 Why** that
shows the navi.db evidence, with false-positive suppression.

## Page
- **Metrics** (click to filter the asset list):
  - **Footprint:** share of the estate, found beyond the AI plugins, products, already tagged.
  - **By role:** each role with its suggested ACR.
  - **Exposure:** exposed and unauthenticated endpoints, shadow egress, destinations.
  - **Risk:** CISA KEV, critical findings, end-of-life software, MITRE ATLAS.
  - **Governance:** below the suggested ACR, crown jewels, median ACR, not tagged.
- **Jump to** sections:
  - AI assets
  - AI software (framework inventory)
  - ACR alignment by role
  - Data egress (sanctioned allowlist)
  - MITRE ATLAS matrix — click a technique (or a tactic heading) to list the AI assets
    behind it, with the evidence that mapped each one (endpoint:port, framework, egress
    destination), role, ACR and a Tenable link; ✕ clears. Same interaction as the MITRE
    ATT&CK agent's matrix. Tag the listed set from there.

## Tagging (gated, `confirm=true` + `NAVI_ALLOW_WRITES=1`)
Tags **assets** by explicit UUID set via navi tag-by-query (never removes tags):

| Category | Values |
|---|---|
| `AI` | `Present` |
| `AI Role` | `<role>` |
| `AI Software` | `<product>` |
| `AI Exposed` | `Endpoint` |
| `AI Priority` | `KEV-exposed` |
| `AI Egress` | `Shadow` or `<destination>` |
| `AI ATLAS` | `<technique id>` or `Tactic : <tactic>` (from the ATLAS drill-down) |

**ACR:** `acr_roles` sets ACR by the `AI Role : <role>` tag to the role's suggested
value: Model Serving 9; Vector DB, Training and MLOps 8; Notebook 7; Dev tools and
API clients 6. It only takes effect once the AI Role tag is in Tenable.

Each write is recorded in the Tagging log.

## Actions
- `run {fp, allow}` → discovery + metrics (read-only)
- `tag {category, value, uuids, confirm}` → gated tag-by-query (any AI category except `AI ATLAS`)
- `tag_atlas {key, fp, allow, confirm}` → gated ATLAS tag. `key` is `tech:<AML id>` or
  `tactic:<tactic>`; the server re-runs the scan (with the page's suppressions and egress
  allowlist) and tags exactly that technique's / tactic's asset set → `AI ATLAS`. No uuids
  are taken from the page; unknown keys are refused.
- `acr_roles {roles, confirm}` → gated ACR by AI Role tag
- `tag_underrated {role, uuids, confirm}` → gated: the role's assets below its suggested ACR → `AI ACR Raise : <role>`
- `apply {confirm}` → gated legacy shortcut: whole AI plugin family → `AI : Present`
