# Identity Inventory

Find **NHI and human identities** the way SHROUD does — and tag them like the other
agents.

This agent parses usernames from local-user **enumeration plugins** (Linux user
list `95928`, SMB local users `10860`, password-policy plugins, etc.) and classifies
each as a **non-human identity (NHI)**, **service**, **human**, or **system**
account — exactly the logic behind SHROUD's Identity lens — but it also keeps the
**asset_uuid(s)** behind each identity so it can tag the hosting assets.

## Tagging (gated)
Uses navi's own **tag-by-query** selector on the identity's hosting assets:

```
navi enrich tag --c NHI --v "Non-human identity" --query "SELECT asset_uuid FROM vulns WHERE asset_uuid IN (…)"
```

Three ways to tag, all with editable values:
- **Per identity** — rename the value, then apply.
- **By class** — tag all NHI / Human / Service at once.
- **Natural language** — describe what you want ("tag every non-human identity as
  NHI : automation"); the model proposes per-identity tags and you approve before
  the gated write.

## Actions
- `run` → identities (read-only) + asset_uuids + platform URLs
- `tag {category, value, asset_uuids | items[], confirm}` → gated tag-by-query
- `interpret {prompt, accounts}` → LLM → per-identity `{category, value}` assignments
