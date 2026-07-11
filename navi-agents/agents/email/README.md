# Gabriel — Email & Reports (`email`)

*The messenger of the pack — carries findings to the humans who own them.*

Gabriel is the **loop-closer**: it turns the pack's findings into email that lands with
the right person, with **deep-links straight back into the Tenable platform**.

## What it sends

- **Owner-routed remediation** — reads **Atlas** `Owner:` tags and emails each owner
  **only their** assets (the personalization that makes the loop cohesive). Each asset
  carries its Tenable **asset URL**; the *technical* template lists the top findings with
  their **plugin deep-links**, plus a **tag filter** link to view the whole set in-platform.
- **🔥 CISA KEV fire-alarm** (Laelaps) — assets carrying an actively-exploited vuln.
- **⏳ Certificate countdown** (Certania) — certs expiring within *N* days.
- **🌅 Morning briefing** (On the Scent) — exposure at a glance for leadership.
- **🐾 Agent findings hand-off** — the generic second option for **every** Hound: email
  the **finding IDs (plugins) that made up the asset search**, the matched assets, the tag
  that was applied, and a high-level overview — labelled with **which Hound produced it**.

## Templates

- **Technical** — per-asset findings + Tenable plugin deep-links (for the people who fix it).
- **Board** — summary counts (for leadership).

## Gating (double-gated, on top of the write gate)

Composing and **preview are read-only** and always available. Sending requires ALL of:

1. **`NAVI_ALLOW_WRITES=1`** (or `ALLOW_WRITES` file) — the master write gate.
2. **`NAVI_EMAIL=1`** (or an `ALLOW_EMAIL` file) — a *separate* email opt-in.
3. **`confirm=true`** on the send call — the UI's explicit approval.

SMTP is configured once, out-of-band, with `navi config smtp` (not exposed to the agent).
Every send is recorded in the **Tagging log** as the accountability ledger (who was
notified, when).

## Actions
| action | payload | returns |
|--------|---------|---------|
| `run` | — | readiness + gate status |
| `status` | — | the email gate (writes + email opt-in) |
| `recipients` | `{domain?}` | owner-routing table from Atlas `Owner:` tags |
| `preview` | `{report, template, domain?, days?, to?, owner?, payload?}` | composed emails (no send) |
| `send` | `{confirm:true, messages:[…]}` | per-recipient send results |

### Report types (`report`)
`owner_remediation` · `vuln_detail` · `kev_alarm` · `cert_countdown` · `briefing` ·
`contract_plan` · `contract_result` · `agent_findings`

## Hand-off contract (for other agents)

Any Hound can route its findings here. Open `page.html` after stashing a JSON payload in
`sessionStorage['gabriel_handoff']` (the shared `emailFindings()` helper in `console.js`
does this):

```json
{
  "source_agent": "cisakev",
  "source_hound": "Laelaps",
  "headline": "CISA KEV exposure",
  "finding_ids": ["19506", "104410"],
  "asset_uuids": ["6f2c…", "…"],
  "tag": { "category": "CISA KEV", "value": "Vulnerable" }
}
```

Gabriel resolves the plugin names, pulls each asset's Tenable URL, and composes the
overview + detection-signal list + asset list, ready to preview and send.

Reads `navi.db` read-only. Sends via `navi action mail` through the gated `core/navi_cli.py`.
