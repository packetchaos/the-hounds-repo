# EOL / Unsupported Software Tagging Agent

Tags assets running **Unsupported** or **End-of-Life** software. Rather than a
hard-coded product list, it keys off **lifecycle language in the plugin name**
("Unsupported", "End of Life", "SEoL", "End of Support") and tags the affected
assets with navi's **tag-by-plugin-name** selector
(`navi enrich tag --c "Lifecycle" --v "<group>" --name "<text>"`). Because the
match is on the live plugin name, coverage **expands automatically** as Tenable
ships new end-of-life / unsupported detection plugins — nothing to maintain.

## Actions
- `run` — scan navi.db; returns each lifecycle group with its matching plugins
  and distinct affected-asset counts. (Optional `groups` override:
  `[["Label",["pattern","pattern"]]]`.)
- `apply` — gated; for each approved group (the built-in groups only — the page names a
  group and any plugin ids it opted out of), runs `navi enrich tag --name` once per
  pattern (a `--query` that excludes the opted-out plugins when there are any). Needs
  `NAVI_ALLOW_WRITES=1` and `navi` on PATH.
- `tag_eol_date` — gated; tags the assets running software that reached end of life on
  each chosen date `Lifecycle EOL : <YYYY-MM-DD>`, by the exact assets whose plugin output
  states that date.
