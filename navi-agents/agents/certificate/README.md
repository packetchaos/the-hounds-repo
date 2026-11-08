# Certificate Agent (Certania)
Finds certificates that have **expired** — month by month over the last 12 months,
plus everything older — and those **failing** (expiring) in the next 12 months, and
tags their assets `Cert failure : <Mon>-<dd>-<yyyy>` (the exact expiry date).

The page shows the expiry timeline (older | last 12 months | next 12 months), metrics
(how long expired, due in 30 / 90 days, crown jewels, weak crypto, self-signed), the
certificate list for date tagging, cert-issue plugins tagged `Cert Issue : <plugin>`
(navi `--plugin`), crown jewels, and an IoT/application cache fingerprinted from
certificate fields (plugin 10863).

Deterministic — there is no free-form LLM reasoning step. Ad-hoc certificate
questions go through the MCP.

- **UI:** `page.html` · **API:** `/api/certificate/run`, `tags_apply`, `tags_issues`
- **Writes:** gated `navi enrich tag` (needs `NAVI_ALLOW_WRITES=1`), add-only; each
  job is recorded in the Tagging log.
- **Deploy alone:** drop this folder into `agents/` and start the launcher.
