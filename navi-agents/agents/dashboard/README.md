# Dashboard Builder

Build a dashboard from a prompt — without leaving the app.

You type what you want to see ("top 10 plugins by affected assets", "assets by
operating system", "certs expiring per month"). The model translates it into
**one read-only SQL `SELECT`** over `navi.db`, and the result is rendered in the
project style as **KPI tiles**, a **bar chart**, or a **table**.

## Why it exists
The suite ships fixed pages for the things we anticipated. This agent covers the
long tail — any view we *didn't* build — so an analyst can explore navi.db
visually and stay inside the console.

## Safety
- `navi.db` is opened in **SQLite read-only mode** (`mode=ro`).
- The generated SQL is validated to a **single `SELECT`/`WITH`** — `INSERT`,
  `UPDATE`, `DELETE`, DDL, `PRAGMA`, `ATTACH`, and multi-statements are rejected.
- The exact SQL is shown in the UI before/after it runs (click **View SQL**).
- This agent **never writes** anything — no tags, no ACR, no DB mutations.

## Config
Needs the model to translate English → SQL: set `ANTHROPIC_API_KEY`
(and optionally `ANTHROPIC_MODEL`). In the live artifact this uses on-device
inference, so no key is required there.

## Action
- `build {prompt}` → `{title, viz, sql, columns, rows, note}`
