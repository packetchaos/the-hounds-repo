# ACR Calibration Agent
Lists tags from the live `navi explore info tags` command (not the tags table)
and adjusts Asset Criticality Rating per tag — **set** absolute, or **+N / −N**
relative — with a required business justification and Change Reason. Bulk mode
takes **free-form natural language** ("drop all IoT and lab gear by 5 …") via an
LLM, validated and previewed before any gated write.

- **UI:** `page.html` · **API:** `/api/acr/run`, `apply`, `bulk_apply`, `interpret`
- **Config:** `ANTHROPIC_API_KEY` enables NL bulk (else deterministic fallback).
