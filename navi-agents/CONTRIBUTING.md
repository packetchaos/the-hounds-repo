# Contributing

Thanks for helping grow the pack. Adding an agent is intentionally small: **one
folder, four files**. The hub auto-discovers it on the next start — no core
changes needed.

## Add an agent

```bash
cp -r agents/_template agents/<your-id>
```

Then edit the four files:

| File | Purpose |
|---|---|
| `manifest.json` | id, name, icon, category, codename, summary, and the actions your API exposes |
| `agent.py` | the read-only discovery — subclass `core.agents.base.Agent`, implement `_run()` returning a dict |
| `api.py` | HTTP actions: `ACTIONS = {"run": ..., ...}`; each returns `(payload, status)` |
| `page.html` | the agent's UI; loads `/static/console.js` and calls `agentApi('<your-id>')` — follow the [page conventions](#page-conventions) |

Restart (`python3 run.py`) and your agent appears in **Release the Hounds**.

## Ground rules

- **Reads** go through `core.db` (read-only sqlite over `navi.db`). Never open the
  DB read-write.
- **Writes** go through `core.navi_cli` and must be gated (`NAVI_ALLOW_WRITES=1`)
  **and** confirmed. Only the Tag Removal agent may remove tags.
- **Be honest about coverage** — surface blind/uncredentialed hosts, don't hide them.
- Prefer navi **built-in selectors** (`--plugin/--output`, `--cve`, `--cpe`,
  `--xrefs`, `--group`) over raw `--query` where one exists.
- Keep secrets in environment variables; never commit `navi.db` or `.env`.
- **Check approval with `confirmed(p)`** (`from core.gates import confirmed`) — never
  `if not p.get("confirm")`. `confirmed(p)` is true only for a JSON `true`; the strings
  `"false"` / `"0"` are truthy in Python and used to approve writes. Use `gates.flag(p, "armed")`
  (or `"force"`, `"send"`) for other safety switches. Every write / send / remove / apply / run
  action must call it before doing anything; `tests/test_security_server.py` auto-enumerates
  them and fails if one accepts a non-true confirm.
- **SQL that a person or the model wrote runs through `db.user_query(sql)`** (or
  `db.harden(con)` on your own connection) — never plain `db.query`. Its SQLite authorizer
  blocks navi's credential tables (`keys`, `smtp`, `ssh`, `resend`), PRAGMA, ATTACH and file
  functions. The SELECT-only regex checks are a first filter, not the guard.
- Don't add routes outside `core/launcher` / `core/security`: every server runs
  `security.check()` (Host allowlist, token, POST guard) on every request. Files an agent writes
  go through `core.security.private_open()` (0600).
- Settings fields that would let a browser choose a binary, a working directory or a path the
  server executes are `env_only`; gate-opening fields are `guarded` (loopback + confirm).

## Page conventions

Every hound behaves the same way, so a user who knows one knows them all.

**Button verbs** — the glyph tells you what a button does before you read it:

| Glyph + verb | Meaning | Example |
|---|---|---|
| `▶ Run` | The hound's primary read. Exactly one per page, in the title card's toolbar (right-aligned). | `<button class="btn run sm" id="run" data-run>▶ Run</button>` |
| `▶ Run <phase>` | A later read phase on the same page. | `▶ Run Sankey`, `▶ Run roadmap`, `▶ Run SQL` |
| `▶ Run all` | Any hound with more than one `▶ Run` step: runs every step in order, waiting for each. Declarative — `data-run-all="<id>,<id>,…"` on the button (plus `data-run`, so the cache restores the whole sequence). Human approval gates (e.g. Mitre's ✓ Approve) and `✨ Ask` prompts are never part of it. | `<button class="btn run sm" id="runAll" data-run data-run-all="load,pqcRun,pqtRun,pqrRun">▶ Run all</button>` |
| `▶ Search` | Explorer pages only (`ex_*`) — a query box plus Search. | |
| `✨ Ask` | Any natural-language box (NL→SQL, interpret, draft). | |
| `🏷️ Tag …` | A tag write (gated; confirm() first). Always the 🏷️ icon + the word Tag — never icon-only, Apply, Assign or Claim. | `🏷️ Tag selected` |
| `⚖ Apply …` | An ACR write (gated). | `⚖ Apply ACR change` |
| `📧 Send …` | Email via Gabriel (gated). | `📧 Send (gated)` |
| `⚡ …` | Execution with side effects beyond tagging (C2, contract cycles). | `⚡ Arm & run` |
| `↻ Refresh navi.db` | Re-sync navi.db only — never used to mean "run the hound". | |
| `↻ Reload` (ghost) | Re-fetch the live list on a page that loads it on open (see *No auto-run*). | ACR, Agent Groups, Tag Removal |

`▶` is reserved for reads; a write never starts with `▶`.

**Layout, top to bottom:** title card (codename, title, one-line description, `▶ Run`,
flash, KPIs) → **the `✨ Ask` card, if the hound has one** (headed `✨ Ask — …`) →
results → write actions. Natural-language prompts always sit directly under the
title card.

**No auto-run — except live lists.** A hound that *analyses* does nothing until `▶ Run`
is pressed; before the first run it shows a `setupcard` ("Press ▶ Run"). A page whose
"run" would only *load the list you act on* — no analysis, no navi.db crunch — loads it
on open instead, has a ghost `↻ Reload` rather than `▶ Run`, and sets
`<body data-page-cache="off">` so it always shows live state: ACR Calibration, Agent
Groups, Tag Removal, Exposure Routes, MCP Compare. The Search Hounds (Argos, Advanced and the `ex_*` explorers) are never cached either:
they set `data-page-cache="off"` and are listed in `core/launcher._NOCACHE_AGENTS`, so every
search — and every `?target=` deep link — reads navi.db as it is now. (Asset Ownership stays on `▶ Run`:
its load rolls up every asset in navi.db.) Explorers and asset/app pickers also list on
open.

**Heavy results → snapshot cache.** When a `▶ Run` crunches navi.db for more than a second
or two, build it as a snapshot with `core/snapcache.py` (Exposure Score uses it; Exposure
Routes and SLA follow the same pattern): one `snapshot` action answering `{peek:true}`
(what's cached or building — never computes), `{}` (cached if navi.db and the view are
unchanged, else start a background build on the job queue) and `{force:true}`. The result
is gzipped to `data/cache/` (git-ignored) keyed by navi.db's size+mtime plus whatever
changes the answer (weights, thresholds, a view), so it survives restarts. The page peeks
on open, polls `/api/jobs/<id>` while a build runs (the user can leave the page) and shows
a "snapshot built … · ↻ rebuild" line.

**Page cache.** Pages under `/agents/` remember their last run **on the server**
(`core/pagecache.py`, `data/cache/pages/`, via `/api/hub/pc_*`; the browser's IndexedDB is
only a fallback when the server can't be reached) and restore it on return — inputs
refilled, `data-run` buttons replayed, reads served from the saved copy, with a
“↺ Restored your last run” strip offering
`↻ Re-run` (fresh, bypasses the server cache too) and `✕ Clear`. To opt a page in:

- put `data-run` on every button that produces results (the `▶ Run`, each
  `▶ Run <phase>`, each `✨ Ask`) — and give it an `id`;
  pressing Enter in a box counts as clicking the nearest `data-run` button, and a
  deep link that runs the page on open (`?target=…`, `?q=…`) is restored too;
- add `data-autorun` to `<body>` if the page lists results on open by itself
  (explorers, pickers);
- add `data-cache-inputs="off"` to `<body>` if its fields mirror server-side state
  (an editor such as Contract or Alert) so stale values are never restored.

Writes are never cached or replayed (tag/apply/send/delete… actions and anything
sent with `confirm:true`), live state endpoints (`status`, `log`, `list`, `get`,
`applied`…) always go to the server, and any write a page fires while it is being
restored is swallowed. The implementation is the `HC` block at the top of
`web/assets/console.js`; the read/write action lists there mirror
`core/launcher._MUTATING`, so add new write action names to both.

**📊 At a glance — the shared template.** Every hound's headline numbers use one template:
`renderGlance(target, groups, opts)` in `web/assets/console.js`, styled by the `.glx…` classes in
`web/assets/console.css` (light + dark tokens, phone-safe grid). Don't hand-build `.mkpi` / `.mk`
cards or page-local glance CSS any more. One panel per group: a small uppercase label, one
**headline** (big number + label), an optional muted detail line, an optional stacked mini-bar
with legend, the group's other metrics as **chips**, and an optional **ranked** mini-bar list.

```js
renderGlance(target, groups, opts)   // → the <div class="glx"> root; target = element or id; content replaced
groups = [{ title, t?,                         // label (+ tooltip, e.g. a caption)
            hero?:  METRIC,                    // headline; hero.u = the muted line under it
            bar?:   [{label, value, color?}],  legend?: false,
            chips?: [METRIC, …],               // chip.u = tooltip detail
            ranked?: {title?, items:[{label, value, sev?, t?, href|filter|onClick}], max?, sev?, empty?} }]
METRIC = { v, l, u?, t?, sev?, zero?, href | filter | onClick }
opts   = { onFilter?(filter, el, on), active?: string | string[] | (filter)=>bool, cls? }
glanceNum(n)                  // 1234 → "1,234", null → "—"   (use for counts)
glanceSetActive(root, filter) // mark one filter chip .on without re-rendering (null clears)
```

- `v` is shown as given (format it first: `glanceNum(n)`, `pct+'%'`); every string is escaped.
- `sev`: `crit | high | med | low | ok | info | none` — the chip's left border (and the headline
  number's colour). `color` for bars/ranked: a sev name, `s1`…`s8` (series palette with dark
  variants) or `var(--token)`; anything else falls back to the palette.
- **Zero dimming** is automatic when `v` parses to 0 (`0`, `"0"`, `"0%"`); set `zero:true/false`
  when the dim depends on something else (WAS: no app in that cohort).
- **Clicks** (first one set wins): `href` — same-tab link via `safeHref`; `'#secX'` smooth-scrolls to
  that section and flashes it. `filter` — calls `opts.onFilter(filter, el, on)` and toggles `.on`
  on the chip (`on` = false when the active chip is clicked again); re-render with `opts.active`
  to keep the marks. `onClick(el, ev)` — custom. Clickable items are links or `role="button"
  tabindex="0"` (Enter/Space) with a focus ring; never inline handlers.
- Put the glance in the first card (`<section class="card" id="secMetrics" data-nav="At a glance"
  data-nav-icon="📊">` or the title card) and call it from the function that renders the
  `▶ Run` result, so the page cache's replay re-renders it.

```js
renderGlance('glx', [
  {title:'Account hygiene',
   hero:{v:glanceNum(m.reused), l:'accounts reused across hosts', u:`on ${glanceNum(m.reused_hosts)} hosts`, filter:'f:reused', sev:'high'},
   chips:[{v:glanceNum(m.privileged), l:'privileged accounts', u:'root / Administrator', sev:'crit', filter:'f:privileged'},
          {v:glanceNum(m.blind), l:"hosts you can't see into", href:'#secCov'}]},
  {title:'Findings', hero:{v:glanceNum(sv.total), l:'findings', href:'/agents/was_asset/page.html'},
   bar:[{label:'Critical', value:sv.critical, color:'crit'}, {label:'High', value:sv.high, color:'high'}],
   ranked:{title:'Top flags', items:top.map(([l,n])=>({label:l, value:n})), sev:'crit', empty:'No flags.'}}
], {active:FILTER?['f:'+FILTER]:[], onFilter:(f, el, on)=>{ FILTER=on?f.slice(2):null; renderTable(); }});
```

Migrating a page: one old `.mhead` heading = one group; its most important `.mk` card = the
`hero`, the rest = `chips` (`.mk .u` text → `u`, `title` → `t`, `--rc` colour → `sev`,
`data-f` → `filter`, `<a class="mk" href>` → `href`, `.zero` → automatic or `zero`). Fold a
"chart row" into its group when it is a split (→ `bar`) or a top-N list (→ `ranked`); keep
bigger charts in their own `data-nav` sections. Rename any page-local `function renderGlance`
(a later declaration silently replaces the shared one), delete the page's `.mkpi/.mk/.mhead`
CSS, and keep `mountSectionNav()` / `setNavCount()` as they were. Reference pages:
`agents/identity/page.html` (filters + bars + ranked) and `agents/was/page.html` (links).

## Release the Hounds

The hub's **🐾 Release the Hounds** runs every hound in the left-sidebar order, in the
background (`core/release.py`), so each page is populated when it's opened. Reads only —
nothing is tagged, applied or sent. What each hound's `▶ Run` does is recorded in
`core/release_recipes.json`:

- `page` — the run button id(s) (`steps`) and the read requests they send. They're run
  through the launcher and saved as that page's page-cache entry, so opening the page
  replays the click and every read is answered from the entry.
- `snapshot` — hounds with their own server snapshot (Exposure Routes, SLA, Exposure
  Score): the release builds it and the page peeks it on open.
- `live` — pages that load a live list on open (nothing to pre-run).

**If you change what a hound's ▶ Run sends, update its recipe** (a request that no longer
matches is simply fetched live on replay — slower, never wrong). `tests/test_release.py`
checks the order, the button ids and that every request is a read. Add new hounds in their
sidebar position; hands-on tools (ACR, Contract, Email, Alert, Tag Removal, C2, Custom Audit,
Dashboards) and the Search Hounds stay out. External catalog downloads (MITRE, CISA KEV) run
only when approved. Estimates come from the last release's measured times (scaled to the
current navi.db), else the recipe's `rate_s_per_mrow`; cached or sub-second runs don't
replace a measurement.

A body field that comes from one browser's localStorage (the AI page's `fp` / `allow`) would
make another browser's replay miss: list it in `<body data-cache-ignore="fp,allow">` and in
the recipe's `key_ignore`. A step that only sometimes shows (MITRE / CISA KEV `✓ Approve`) is
`"optional": true` — clicked only if visible. A release never overwrites a run the user made
after it started.

**On the Scent depends on Release.** On the Scent (insights) is built only from Release the
Hounds output — the page-cache entries plus the Exposure Score / Exposure Routes / SLA
snapshots — and never reads navi.db. It is the LAST recipe (`scent`), opening it peeks
`scent {peek:true}`, and ↻ Rebuild re-reads the caches. A hound whose cached response shape
changes must keep the fields `core/insights.scent_digest()` reads (`tests/test_insights.py`
checks this). A new hound joins the picture by adding its reads there; every link must point
at an existing `/agents/<id>/page.html#id`.

**Page cache rules** (`core/pagecache.py`): an entry is tied to the navi.db it was computed
from (another navi.db gets nothing); field edits after a run go to the small `.meta.json`
(`pc_patch`), not a re-upload of every response; an entry over the size cap falls back to
the browser's IndexedDB and the stale server copy is dropped; a browser's own TTL only skips
an old entry, never deletes the shared one.

## "Done so far" panel

Every **tagging** hound gets a **📋 Done so far** strip at the top automatically — no
per-page code. Which hounds count: manifest `"category"` of `Tagging` or `Discovery`
(override either way with `"status_panel": true/false`); Risk, Explore, Views and other
hounds get no panel. It answers "has this hound already tagged, and what?" from two sources (`core/activity.py`, served
live by `/api/explore/activity`):

- **The Hounds log** (`tag_jobs.db`): every tag / removal / ACR / email / push job with
  its agent, value, outcome and time; plus a `runs` table — one row per `▶ Run`
  (a `▶ Run all` counts as one run). The browser marks only requests set off by a
  `data-run` click or Enter (`_run=<id>`), so page-load helpers never count as runs and
  a cache restore never records one.
- **navi.db `tags`**: how many assets carry each value now. Status per value: *on
  assets*, *awaiting sync* (applied after navi.db's last update), *no assets* (applied
  before the last update, still on none — the selector matched nothing), *removed*
  (a later Tag Removal), *failed*. Values in the hound's categories that this install
  never applied are listed separately as *already in navi.db*.

For it to work, tag through `core.navi_cli.tag/tag_capped` (or `tagq.submit/record`)
with `agent="<your-id>"`, and add your hound's well-known categories to
`activity.DEFAULT_CATEGORIES` so pre-existing tags show up before its first run.

## External downloads

A hound that fetches data from outside Tenable / navi.db (MITRE's ATT&CK→CVE CSV, CISA's
KEV catalog, …) asks a human first — the **Human approval — external download** card —
unless **Settings → Auto-approve downloads** (`NAVI_AUTO_APPROVE_DOWNLOADS=1`, default off)
is on. Every source goes through `core/downloads.py` so that one switch covers it and
Settings lists it:

1. **Register** the source where its URL lives (imported at startup via your `api.py`):
   `downloads.register("<id>", "<name>", [url, fallback_url…], agent="<your-id>", purpose="…", fallback="bundled snapshot …")`.
2. **Gate the fetch server-side**: in the action that downloads,
   `live, by = downloads.allowed(p)` — `live` is True when auto-approve is on or the page sent
   `approved:true`; pass it to your fetcher (`allow_live=live`). Not approved → use the bundled
   snapshot, no network. Always keep an offline fallback.
3. **Page**: on open, `if(await downloadsAutoApproved('<id>'))` show a one-line
   *“Auto-approved download: &lt;url&gt; (Settings)”* note, else show the approval card. On `▶ Run`,
   the same check either runs straight away or shows the card; the card's `✓ Approve` sets
   `approved:true` on the run request. Never auto-run on open. See `agents/mitre/page.html`.

A source the page only fetches on its own explicit `▶` button with no approval card (Mimir's
endoflife.date lookup) registers with `approval=False`, so it is listed but not affected.

## Test run (tag prefix)

**Settings → Test run** (`NAVI_TAG_TEST_RUN=1`, default off) writes every tag CATEGORY a hound
creates as `<phrase>-<category>` (**Prefix phrase**, `NAVI_TAG_PREFIX`, default `Hounds`):
`Lifecycle : EOL` → `Hounds-Lifecycle : EOL`. `core/tagname.py` owns the rules:

- **Writes**: `navi_cli.tag` / `tag_capped` apply `tagname.effective()` to every add, so a new
  hound needs no change. Never prefix by hand; never prefix the value. The contract's `plan()`
  carries the prefix on its specs (so the export and Run Tag Sequence do too).
- **Exact**: removals (`remove=True`, `delete_tag`), the contract's removal list and ACR on a
  category a human typed. A hound raising ACR on a tag it wrote itself passes
  `tagname.effective("<category>")` (see `agents/ai/api.py` → AI ACR Raise).
- **Reads** that recognise a hound's own output or a signal (Owner, Lifecycle, CISA KEV…) match
  the plain AND the prefixed name — on or off — via `tagname.names()` / `sql_in()` /
  `sql_lit()` / `sql_base()` / `base()`; `activity.allowed_category` accepts both. Always show
  the real tag name. Pages show the name about to be written with `tagCat('<category>')`.
- Clean-up: Tag Removal's **🧪 test-run tags** filter lists `<phrase>-*` (removal unchanged).
- **Exempt**: `tagname.EXEMPT` (`{"NO"}`) is never prefixed — the ACR-protection tag must be
  exactly `NO : UPDATE` or navi ignores it.

## ACR protection & the ACR log

`navi enrich acr` resolves its assets from navi.db and **skips every asset tagged exactly
`NO : UPDATE`** (case-sensitive) and every asset with no ACR. The Hounds mirror that:

- **One choke point**: every ACR write goes through `core.navi_cli.acr(..., agent=)` (ACR agent
  `acr`, AI Contract `contract`, AI inventory `ai`; `mcp` for an MCP path). Never shell out
  to `navi enrich acr` elsewhere. It runs `core.acr_protect.preview()` (navi's selection, read
  only) right before navi, then writes the Tagging log entry (with `business_case`) and one
  **ACR log** row per asset (`core/acrlog.py`, tables `acr_log` / `acr_protect` in the Tagging
  log's `tag_jobs.db`): before → after, result `applied | blocked | failed | skipped_protected |
  skipped_no_acr`. Writes off → `blocked`, never `applied`.
- **Business case** = navi's Change Reason labels + the note (`acr_protect.business_case`) —
  the field users sort and filter by (ACR log, Tagging log column + CSV).
- **Protect** = `acr_protect.protect()` → a gated `navi_cli.tag("NO", "UPDATE", …)`, one job per
  business case. It counts for navi only after the next `navi update assets` (show "pending").
  **Removing** protection is a tag removal → Tag Removal (Garmr) only.
- **Refused up front** (never sent; logged `failed` with the reason): a `'` in the category /
  value (navi formats it into its SQL → DB ERROR, nothing changes), a score that isn't a whole
  number 1–10, and inc/dec over an ACR navi can't `int()` (it would crash part-way). Preview
  mirrors navi group by group (duplicate `assets` rows → one update per ACR group, last wins).
- Pending protection ends when the job fails / is cleared, a NO : UPDATE removal runs, or 24 h
  pass without the tag reaching navi.db. CSV exports guard `= + - @` cells. The Tagging-log
  replay export includes ACR changes only on opt-in, and only applied ones.
- Show the preview (change / protected / no ACR) in every ACR confirm(). Pages: the ACR agent
  (At a glance + Protection), `web/acr-log.html`; the contract's `protect_acr` option tags the
  assets its ACR rules applied to, after all rules.

## Command & Control (remote execution)

`navi action push` (SSH to Linux hosts) is the pack's highest-risk capability. Rules:

- **One choke point**: every push goes through `core.navi_cli.push(target, command|file, agent=, source=,
  run_id=, catalog_id=, plan_sha256=, timeout=, strict_host_keys=, retries=)`. Never shell out to
  `navi action push` elsewhere and never call `_push_exec` directly (`tests/test_c2.py` greps for both).
  It validates the target (navi's own rule: a plain IP / hostname, nothing that starts with `-`),
  classifies navi's per-host lines into one status vocabulary (`ok · changed · failed · unreachable ·
  auth_failed · hostkey_mismatch · hostkey_unknown · port_closed · dns_failed · timeout · skipped ·
  not_applicable · cancelled · blocked · refused · no_credentials` — navi itself exits 0 when a host
  fails), and writes ONE row to the **C2 log** (`core/c2log.py`, table `c2_log` in `tag_jobs.db`).
- **The C2 log never stores output** — what ran, where, when, who asked, status, exit code, duration,
  host-key policy. Commands are masked (`c2log.mask`) before storage; `command_sha256` hashes the exact
  bytes sent. Rows are append-only (triggers) and hash-chained (`verify_chain()`); `web/c2-log.html`
  shows the chain status. Output lives only in the C2 page's in-memory run registry.
- **Gates never weaken**: read-only checks and credential tests are still remote execution —
  `NAVI_ALLOW_WRITES` + `NAVI_REMOTE_CODE_EXECUTION` + `confirmed(p)`, one confirm per click naming the
  checks and hosts (public / off-inventory / crown-jewel targets called out). `dry_run:true` shows
  exactly what would run where and sends nothing.
- **Built-in checks** live in `core/c2_catalog.py`: fixed POSIX-sh strings, read-only, `sudo -n` only,
  wrapped in a remote `timeout`, one SSH session per host (markers spelled with split quotes). The only
  input is a validated parameter passed through `shlex.quote`. Add a check there, not in a page.
- **Host keys**: checks / credential tests use navi's default (record a NEW key, refuse a CHANGED one);
  free-form commands, files and campaigns default to `--strict-host-keys` (`accept_new_hostkey:true`
  relaxes it); remediation is always strict. Retries only after a transport failure — never after an
  auth failure (lockout) or a host-key problem.
- **AI remediation** (`core/c2_remediate.py`): Tenable's plugin text + output are the source; the model
  only translates it to a strict JSON plan; `validate()` (deterministic allow-list + deny-list, one simple
  command per step, package names must appear in the plugin text) decides what may deploy, and `deploy`
  re-validates server-side. Without a model the deterministic templates are used and the page says so.
- **navi rewrites the command line**: it turns the FIRST `\bsudo\b` anywhere into its sudo-prompt form and drops
  every output line containing `NAVI_EXIT` (its exit sentinel is appended on the same line). So: `sudo` only ever
  leads a command; any other `sudo` / `NAVI_` in a value goes through `c2_catalog.qword()` (quote-split
  `'su''do'`); plan commands are sent via `c2_remediate.wrap()` (marker line + trailing newline + restored exit
  code) and judged on `unwrap()`ped output. Test against `tests/c2_realnavi.py` (navi's real handling), not only
  the canned fake.
- **Authority split**: only Tenable-authored plugin text (name / solution / synopsis / description) may name
  packages, services and paths. Per-host plugin output only supplies line-leading Installed/Fixed version facts,
  for packages the plugin text names. Plans may upgrade packages and restart/reload named, non-core services —
  never rm / chmod / chown. A rollback may only name packages its own step changes, pinned to the installed
  version in the same upstream release; at rollback time each host is re-pinned from ITS OWN plugin output
  (and cross-checked with what the deploy precheck read) — a host without that fact is skipped, never touched. A non-empty C2 log without its head file is reported *unverifiable*.
- **Plans live server-side**: `plan_ai` / `plan_validate` store the validated plan by `plan_id`; `deploy` runs only
  that stored version (the page's copy must hash the same), a deployed `plan_id` can't be re-pointed, and
  `rollback` (needs the deploy `run_id`) undoes per host only the steps that ran there. Checks compare versions
  (`fixed_version` + dpkg/rpm compare) when the plugin output states a fixed package; otherwise say "manual".
- **Hand-offs**: link a path or a vuln to C2 with `c2Link('validate_path'|'remediate'|'diagnose',
  {targets:[{ip,uuid,hostname}], path, plugin_id, cve, source}, label)` (or `c2Handoff(...)`). The request
  travels in sessionStorage only (never the URL); the C2 page pre-fills and never runs anything itself.

## Before a PR

- `python3 -m compileall core agents` passes.
- `python3 tests/test_attackpath.py` passes (0 failures) if you touched `core/attackpath.py`,
  `core/identity.py`, or anything they read.
- `python3 tests/test_agents.py` passes (0 failures) if you touched an agent or `core/`.
- `python3 tests/test_exproute.py` passes (0 failures) if you touched the Exposure Routes agent or the Ownership Map.
- `python3 run.py` starts and your agent runs against the sample DB.
- Run it, navigate away and back: the page restores from the cache with no re-run.
- No `navi.db` / `sample_navi.db` / secrets in the diff (see `.gitignore`).

## Tests

`tests/` holds regression tests that run against a generated fixture navi.db, so they need
no real Tenable data and leave nothing behind.

- `python3 tests/test_attackpath.py` — prints PASS/FAIL per check and exits non-zero on any
  failure. `python3 -m pytest tests/` runs every suite.
- `python3 tests/test_agents.py` — regression checks for the other agents (EOL dates per asset,
  OS vs application, MITRE ICS ids, the cross-site POST guard, per-agent tag categories,
  Certificate on Feb 29).
- `python3 tests/test_security_server.py` — the server security model: Host allowlist, token,
  POST guard, headers, env-only settings, strict confirm on every gated action, the SQL
  authorizer, file modes. Run it whenever you touch a server, `core/launcher`, `core/security`,
  Settings, or add an action that takes `confirm`.
- `tests/attackpath_fixture.py` builds the fixture: five segments with realistic exploit chains,
  failed CIS/STIG controls, shared accounts, an internet-facing host, and an isolated lab that
  must reach nothing. `python3 tests/attackpath_fixture.py out.db` writes one you can open in
  the app (`NAVI_DB_PATH=out.db python3 run.py`).
- When you fix a bug, add the row that reproduces it to the fixture and a `check(...)` for it,
  so it can't come back.
