# AI Inventory

Find and tag assets carrying **Artificial Intelligence** software.

Tenable ships an **Artificial Intelligence** plugin family that fingerprints
AI/ML software (model servers, frameworks, GenAI tooling). This agent lists every
asset with a finding in that family, shows the AI plugins detected, and links each
asset straight to its **Tenable One platform** page (from `assets.url` in navi.db).

## Tagging
Uses navi's own **tag-by-query** selector — nothing reimplemented:

```
navi enrich tag --c AI --v "Artificial Intelligence" --query "SELECT asset_uuid FROM vulns WHERE plugin_family LIKE '%Artificial Intelligence%'"
```

The category and tag value are editable in the UI before applying. Writes are
gated (`confirm=true` + `NAVI_ALLOW_WRITES=1`).

## Actions
- `run` → assets with AI software (read-only) + platform URLs
- `apply {category, value, confirm}` → gated tag-by-query
