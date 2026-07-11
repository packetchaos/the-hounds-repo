# Software Analyzer (Mimir Hound)

Turns the `software` table into an enterprise software-version picture.

Parses each `software_string` (RPM/NVR style: `name-version-release`) into a
product + version, then aggregates across the estate to surface:

- **Version sprawl** — products running more than one version, fragmentation first.
- **Most deployed** — software by asset count (your de-facto enterprise standard).
- **Single-install** — software found on only one asset (rare / shadow / one-off).
- **Per-product drill-down** — every version, asset share, and the assets stuck on
  older versions (upgrade/consolidation targets).
- KPIs: unique products, product+version pairs, assets with software,
  multi-version count, single-install count.

Tagging (gated): tag every asset running a product as `Software:<product>`, or the
assets on a specific version as `Software:<product> <version>` — applied by
`navi enrich tag --query` over the exact asset set. Writes need
`NAVI_ALLOW_WRITES=1` and `navi` on PATH.

Actions: `run` (analyze), `tag` (gated `Software:` tag for a set of assets).
