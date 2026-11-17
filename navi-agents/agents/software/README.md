# Software Analyzer (Mimir)

Turns the `software` table into an enterprise software-version picture.

Parses each `software_string` (RPM/NVR `name-version-release`, or Windows-style
`Name - 1.2.3 [version 1.2.3]`) into a product + version — reconciled with the `cpes`
inventory — then aggregates across the estate to surface:

- **Version sprawl** — products running more than one version, fragmentation first.
- **Most deployed** — software by asset count (your de-facto enterprise standard).
- **Single-install** — software found on only one asset (rare / shadow / one-off).
- **Per-product drill-down** — every version, asset share, and the assets stuck on
  older versions (upgrade/consolidation targets).
- KPIs: unique products, product+version pairs, assets with software,
  multi-version count, single-install count.

navi stores **one row per software string**, with `asset_uuid` holding every asset that has it
as list text (`"['uuid-1', 'uuid-2']"`). `core/software.py` (`sw_assets_sql()`,
`inventory_assets()`) expands that list, so installs and coverage are counted per asset; older
one-uuid-per-row databases give the same answers.

Tagging (gated): tag every asset running a product as `Software:<product>`, or the
assets on a specific version as `Software:<product> <version>` — applied by
`navi enrich tag --query` over the exact asset set. Writes need
`NAVI_ALLOW_WRITES=1` and `navi` on PATH.

Scale (build 455): the analysis runs on the server (`core/software.py` — the page's parsers,
ported) and the page receives decision data only: `inventory` (▶ Run — KPIs + page 1),
`drill` (page / filter / search the products), `product` (one product's versions),
`eol_plan` + `lifecycle` (endoflife.date verdicts → asset counts), `crown`, `risk` (top 40).
`tag` takes a KEY (`{product}`, `{product, version}`, `{product, kind:"eol"|"behind"}`,
`{role}`) and rebuilds the asset set server-side; `run_sql` (✨ Ask only) is capped at 200
rows a page / 10,000 in all.
