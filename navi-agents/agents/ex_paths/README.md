# Path Explorer (Greyhound)

Filesystem paths discovered on assets (vuln_paths) — search by path text. Read-only search over navi.db via the UI.

Actions: `search {q}` → rows · `count` · `tag` (gated tag of the assets on a path).
The ✨ Ask box turns a plain-English question into one read-only SQL query on `vuln_paths` (needs a model).
