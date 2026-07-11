# Exposure Routes — owner mapping (Atlas Hound)

Map exposure **routes** (`vuln_route`) and filesystem **paths** (`vuln_paths`) to
the people who own them, in plain English.

- **Owners** come from navi (`navi explore info users | user_groups | agent_groups`,
  live Tenable API). The Tenable MCP is a backup/validator in the desktop console.
- **Routes & paths** come from navi.db.
- A natural-language instruction (e.g. *"give all payment routes to VM Team, put
  /opt and nginx paths under Networking Systems"*) is mapped per item to an owner.
- Applying a mapping tags every asset on the matched route/path with
  `Owner:<group-or-user>` via the gated navi tag path (route → `--route_id`,
  path → `--query`). Writes need `NAVI_ALLOW_WRITES=1` and `navi` on PATH.

The natural-language step needs `ANTHROPIC_API_KEY` on the server; without it the
NL box is hidden (the rest of the page still loads owners, routes, and paths).

Actions: `load` (owners + routes + paths), `interpret` (NL → mappings), `apply`
(gated Owner tag).
