# Tag Explorer (Basset)

Read-only navi.db search over the `tags` table, paginated 500/page.

- **search** — one row per tag (`tag_key : tag_value`) with a DISTINCT asset count.
- **assets** — the assets carrying one tag, joined to the `assets` table
  (hostname, IP, OS, ACR/AES, platform link), so you can see what's in each tag.
