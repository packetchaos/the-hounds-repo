# Dashboard Builder

Build a dashboard from a prompt — without leaving the app.

You type what you want to see ("top 10 plugins by affected assets", "assets by
operating system", "certs expiring per month"). The model translates it into
**one read-only SQL `SELECT`** over `navi.db`, and the result is rendered in the
project style — **KPI tiles**, bar / column, line, pie / donut and other charts, or a
**table**. Pin results to the page's grid and **🚀 Promote** them to a standalone Custom
Dashboard (`/web/customdash.html`). A set of one-click, ready-made views needs no model.

## Why it exists
The suite ships fixed pages for the things we anticipated. This agent covers the
long tail — any view we *didn't* build — so an analyst can explore navi.db
visually and stay inside the console.

## Safety
- `navi.db` is opened in **SQLite read-only mode** (`mode=ro`).
- The query runs under the SQLite authorizer that blocks navi's credential tables
  (`keys`, `smtp`, `ssh`, `resend`).
- The generated SQL is validated to a **single `SELECT`/`WITH`** — `INSERT`,
  `UPDATE`, `DELETE`, DDL, `PRAGMA`, `ATTACH`, and multi-statements are rejected.
- The exact SQL is shown in the UI before/after it runs (click **View SQL**).
- This agent **never writes** anything — no tags, no ACR, no DB mutations.

## Config
The English → SQL step needs a configured model — any provider in
[BYO_MODEL.md](../../BYO_MODEL.md) (e.g. `ANTHROPIC_API_KEY`, or `NAVI_LLM_PROVIDER` +
`NAVI_LLM_MODEL`). The ready-made views run without one.

## Action
- `build {prompt}` → `{title, viz, sql, columns, rows, note}`
