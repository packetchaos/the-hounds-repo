# Custom App Name Agent
Finds software the inventory misses by mining vuln **routes** and filesystem
**paths**, comparing against the `software` table. Also a natural-language flow:
"Tag my custom app navi" → searches `vuln_paths` for the keyword, shows the
matched paths/assets, then gated-tags `Custom App:<name>` after you confirm.

- **UI:** `page.html` · **API:** `/api/customapp/run`, `interpret`, `search`, `tag`
