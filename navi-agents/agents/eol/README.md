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
- `apply` — gated; for each approved group, runs `navi enrich tag --name` once
  per pattern. Needs `NAVI_ALLOW_WRITES=1` and `navi` on PATH.
