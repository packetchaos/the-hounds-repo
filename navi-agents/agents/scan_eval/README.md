# Scan Evaluations

Reproduce `navi scan evaluate`, cleaned up and interactive — then tag the problems.

`navi scan evaluate` analyses **plugin 19506 (Nessus Scan Information)** in navi.db
and reports average scan time per asset by **scanner**, **policy**, and **scan**.
This agent computes the same breakdowns directly from navi.db (so it also runs in the
artifact), flags outliers (avg > 1.5× the overall average), and adds **credential
coverage** from **plugin 104410** (total assets vs. assets with credential failures).

## Tagging (gated, via navi)
- **Scanner IP** → `navi enrich tag --plugin 19506 --output "<ip>"`
- **Policy** → `navi enrich tag --plugin 19506 --output "<policy>"`
- **Scan** → `navi enrich tag --scanid <id>` (when an id is supplied), otherwise
  matched by scan name in the 19506 output
- **Credential failures** → `navi enrich tag --plugin 104410 -remove`

All tag values are editable before the gated write.

## Actions
- `run` → `{scanners[], policies[], scans[], credential{total_assets, cred_fail_assets, ok_assets, assets[]}}`
- `tag {kind: scanner|policy|scan|cred, value, output?, scanid?, confirm}`
