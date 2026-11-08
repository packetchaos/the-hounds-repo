# Identity Inventory (Janus)

Finds **human, service / non-human (NHI) and machine identities** by content. It
reads local-user enumeration plugins and their output: Linux user list `95928`, SMB
local users `10860`, non-expiring passwords `83303`, host SID `10859`, SNMP `41028`
and others.

Built-in accounts are classified by external authority:
- Microsoft well-known SIDs/RIDs
- AD machine `$` accounts
- the Linux `login.defs` UID convention

The agent keeps the **asset_uuid(s)** behind each identity so it can tag the hosting
assets.

## Page
- **Metrics** (click to filter the identity list):
  - **Inventory:** identities, human, service/NHI, machine.
  - **Visibility:** credential coverage %, uncredentialed hosts, scan credentials, risk-flagged.
  - **Account hygiene:** privileged, account reuse, never-expiring passwords, SSH password auth.
  - **Priority:** privileged on an exploitable host, on a KEV host, on crown jewels (ACR ≥ 7), on a critical host.
- **At a glance:** identities by class, credential coverage, most common risk flags.
- **Jump to** sections:
  - **Identities:** column picker, class filter, tag shown.
  - **Account reuse:** the same account name on 5 or more hosts; the scan credential is excluded. That is not proof of a shared password, and nothing in The Hounds infers password reuse from it.
  - **Authentication weaknesses by host.**
  - **Coverage gap:** uncredentialed hosts and scan credentials.
- **✨ Ask:** natural-language tagging. The model proposes per-identity tags and you
  approve them before the gated write.

## Tagging (gated, tracked in the Tagging log)
Tags the hosting assets via navi **tag-by-query**:

| Category | Values |
|---|---|
| `Identity` | `<name>` |
| `NHI` | `Non-human identity` |
| `Machine ID` | `Machine` |
| `Owner` | `<human>` |
| `Identity Risk` | `Account Reuse`, `Account Reuse : <user>`, `SSH Password Auth`, `Weak Password Policy`, `Default Credentials`, `AD Attack Path`, `KEV Host` |
| `Identity Coverage` | `No Credentials` |

## Actions
- `run` → identities, host signal sets, metrics (read-only)
- `tag {category, value, asset_uuids | items[], confirm}` → gated tag-by-query
- `interpret {prompt, accounts}` → LLM → per-identity `{category, value}` assignments
