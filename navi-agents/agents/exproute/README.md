# Exposure Routes — owner mapping (Atlas)

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

## One run, cached

**▶ Run** calls `snapshot`: owners, routes, paths, coverage and the ownership map from **one
server-side pass**, cached on disk (`data/cache/exproute_<db>.json.gz`, gzipped) and in memory,
keyed by navi.db's signature (size + mtime of the db and its `-wal`).

- navi.db unchanged → the cached snapshot renders at once (a Run or reopening the page).
- navi.db changed (e.g. after `navi update assets`) → the build runs on the **job queue**. You
  can leave the page; it keeps running (Runs log), and reopening the page re-attaches to it.
- Opening the page only *peeks*: it shows a cached snapshot or follows a running build, and
  never starts a computation.
- **↻ Rebuild** (Sankey) / "rebuild" forces a fresh build. **↻ Refresh owners** re-pulls the
  owner directory, which is otherwise cached for 6 h (`NAVI_OWNERS_TTL_S`) — it's a live
  Tenable API call through navi. A failed pull keeps the last good list.

The one result feeds the **Sankey**, the embedded **Ownership Map** (`/web/ownermap.html?embed=1`,
handed the result with `omLoad()`; its own header, sidebar and refresh are hidden) and the
metrics. `map` and `coverage` are still available and are served from the snapshot.

Speed: membership (route → assets, route ↔ path) is built from linear scans in Python instead
of the old `LIKE '%…%'` cross-joins. 100K findings / 300 routes went from ~3 minutes to 0.4 s;
600K findings / 1,500 routes builds in ~5 s.

## Ownership rules

- An asset is **owned** for a route/path only by a real owner tag `<name>: <user>` — not
  `Ignored` / `Accepted` / `Mitigated`, not a bare `<name>`. Names compare case- and
  whitespace-insensitively with no wildcards. An owner containing `': '` splits at the known
  route/path name.
- A route is owned when every asset on it is; a path when every asset is **or** the route
  covering it is owned (marked `inherited`; it doesn't add to anyone's workload).
- **Ownerless Risk** = assets with neither an owner nor a decision on any route/path they sit on.
- Owner workload counts only the assets tagged to that owner.
- Routes that share an app name are one route; tagging it tags every `route_id` with the name.
- Re-tagging an unmatched Owner name (`retag`) moves only the assets carrying the old tag,
  per owner, onto the exact route/path name.
Ticking gaps in the embedded map and sending them to Atlas opens the quick-assign card on this
page. The standalone `/web/ownermap.html` works as before.

## Metrics

- **Attack surface:** routes (with / without paths), distinct paths (under a route / orphan),
  assets in scope and routes per asset, and the route-findings → routes reduction.
- **Ownership:** routes fully owned (owned · partial · none), paths owned (incl. via their
  route), **Ownerless Risk** assets, assets closed (every route owned).
- **Risk without an owner:** unowned or partially owned routes/paths with VPR ≥ 7 and the
  unowned assets behind them, critical (VPR ≥ 9) ones and the worst, dispositions
  (mitigated · accepted · ignored), Owner tags whose app name misses every route.
- **People:** owners with work vs users & groups available, the busiest owner's share of
  owner-assigned assets, routes + paths per owner.
- **At a glance:** routes and paths by ownership, Ownerless Risk by VPR band, owner workload.

The jump panel links the Ask box, coverage, the Sankey, the Ownership Map and Owners.

Actions: `snapshot` (`peek` / `force` / `refresh_owners`), `load` (owners + routes + paths),
`coverage`, `map` (routes/paths ↔ owners, gaps, workload, reduction funnel), `interpret`
(NL → mappings), `apply` (gated Owner tag), `retag` (gated), `refresh` (background
`navi update assets`), `path_detail`.
