# Scan Evaluations (Chronos)

What your scans can and can't see — and where they spend their time.

Chronos reads **plugin 19506 (Nessus Scan Information)** and the **Target Credential Status /
Issues** plugin family from navi.db. It started as a cleaned-up `navi scan evaluate` (average scan
time per asset by scanner, policy and scan) and now reports scan **coverage** per asset.

## Per asset

- **Credential state.** Each asset takes the worst state any source reports:

  | State | Evidence |
  |---|---|
  | Failed | 104410 — credentials provided but rejected |
  | Insufficient privilege | 110385, 102094 — logged in, can't run every check |
  | Intermittent | 117885 — login worked only some of the time |
  | Uncredentialed | 110723 (none provided) or 19506 `Credentialed checks : no` |
  | Credentialed OK | 141118, 110095 or 19506 `Credentialed checks : yes` |
  | No scan data | in navi.db with no 19506 |

  A 110723 for one protocol doesn't override a successful login on another.
- **Patch assessment:** 21745 (failed) and 117886 (not available).
- **Freshness:** days since the latest `Scan Start Date` — ≤ 7, 8–30, 31–90, > 90, never.
- **Agent vs network** from 19506 `Scan type`.
- **Crown-jewel blind spots:** ACR ≥ 7 and not credentialed, or last scanned > 90 days ago / never.

## Per scanner, policy and scan

- Average and max time per asset; **⚠ slow** when the average is > 1.5× the overall average.
- Load share, credential success rate, last scan.
- Scanners: Nessus version(s) and **plugin feed**; flagged when the feed is more than 7 days
  behind the newest feed in navi.db.
- Policies: assets scanned with **safe checks off** and with **thorough tests** on.
- Slowest assets (scan over 1 hour).

Only open / reopened findings count when navi.db has a `state` column.

## Tagging (gated)

Category is always **`Scan Health`**. The page sends a key; the server re-runs the evaluation and
tags the exact assets behind it by uuid (`navi enrich tag --query`), never by `--plugin` / `--output`.

| Key | Value |
|---|---|
| `status:failed` | Cred Failure |
| `status:insufficient` | Insufficient Privilege |
| `status:intermittent` | Intermittent Auth |
| `status:uncredentialed` | Uncredentialed |
| `patch:failed` | Patch Assessment Failed |
| `fresh:31-90` / `fresh:90+` / `fresh:never` | Stale Scan 30d+ / Stale Scan 90d+ / Never Scanned |
| `slow` | Slow Scan |
| `crown:blind` | Crown Jewel Blind Spot |
| `scanner` / `policy` / `scan` + `name` | Scanner : &lt;ip&gt; / Policy : &lt;name&gt; / Scan : &lt;name&gt; |

## Actions

- `run` → `{metrics, assets[], scanners[], policies[], scans[], slowest[], credential{…}}`
  (`credential` is kept for Alerts and the Contract).
- `tag {key, name?, confirm}`
