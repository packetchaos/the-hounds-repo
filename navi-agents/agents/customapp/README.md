# Custom App Name Agent
Finds software the inventory misses by mining vuln **routes** and filesystem
**paths**, comparing against the `software` table. Also a natural-language flow:
"Tag my custom app navi" → searches `vuln_paths` for the keyword, shows the
matched paths/assets, then gated-tags `Custom App:<name>` after you confirm.

- **UI:** `page.html` · **API:** `/api/customapp/run`, `interpret`, `search`, `tag`

## Page

- **Metrics** (click to filter the candidates, or jump):
  - **Discovery:** apps outside the inventory (from routes / from paths), hidden by the ignore list.
  - **Exposure:** assets running custom software, apps on crown jewels (ACR ≥ 7), apps with no
    owner on any of their assets, candidates with no assets.
  - **Naming progress:** % already tagged `Custom App`, still to name, inventory size compared.
- **At a glance:** routes vs paths, named vs unnamed, ownership of their assets, biggest by assets.
- **Jump panel:** Ask · Discovered candidates · Ignore list.
- Candidate **Assets** — routes: assets with any of the route's plugins (one linear scan of
  `vulns`); paths: assets with that folder/file token in a vulnerable path. **Status** shows
  named / 👑 crown jewels / no owner.
