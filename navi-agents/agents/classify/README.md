# Asset Classification · Linnaeus 📇

Classifies **every** asset by what it *is* — so nothing is unknown, because unknown
assets are what stall ownership (you can't assign an owner to a device you can't name).
Argos closes the ownership loop per-asset; Linnaeus closes the **detection** loop in
aggregate.

## Classes (IoT and OT are separate)

`Windows` · `Linux` · `macOS` · `IoT` (by device type: Camera / NAS / Printer / Media / …)
· `OT` (PLC / HMI / Engineering Workstation) · `Network` (firewall/appliance) · `Virtual
Infrastructure` (hypervisors) · `Unclassified`. `Cloud` (AWS/Azure/GCP) is shown as a
cross-cutting attribute.

## The rule that makes it work

**You cannot pull a software inventory off an embedded/IoT device.** So software
enumeration ⇒ general-purpose host, not IoT. That single subtractive filter is what
kills the false positives (management software / drivers tagged as devices). OS is only
a *minimal* signal (Windows/macOS) because IoT is so often embedded Linux.

## The page

A sticky **Jump to** nav (At a glance · Ask · Explorer · OS Signals · Classes · the drilled
class) and a **📊 At a glance** section of metric cards, each linking to where you act on it:

- **Classification** — assets, classified (coverage %), unclassified (→ the hand-classify
  worklist), untagged assets with an OS/device signal (→ OS Signals), cloud-by-metadata.
- **Class breakdown** — servers, workstations, network, IoT (→ IoT Discovery), OT, hypervisors.
- **Operating systems** — Windows / Linux / macOS classified, untagged OS hosts detected,
  assets on an **unsupported / EOL OS** (open findings, Charon's selector → EOL hound),
  **low-confidence OS fingerprints** (plugin 11936 < 70% → pre-fills the ✨ Ask prompt).
- **Risk & ownership** — the class with the most KEV / critical assets (→ that class), unclassified
  assets with a KEV, the riskiest unclassified asset (→ Argos), assets with open criticals
  (→ Exposure Score), classified assets without an Owner (→ Atlas Ownership Map).

All from the ▶ Run's four reads (`run`, `tree`, `os_breakdown`, `signals`); KEV / critical
count **open** findings only. Every tag write asks for confirmation first.

## What it gives you

- **Coverage %** — the health of your whole ownership pipeline in one number.
- **Per-class ownership overlay** — owned vs unowned, with a one-click hand-off to Atlas.
- **Risk overlay** — KEV / critical counts per class, so you triage classes, not just count.
- **Unclassified worklist** — every unknown with a *reason* (uncredentialed → add creds +
  rescan; no-fingerprint) — a bucket that shrinks over time.
- **Gated `Class:<type>` tags** — persist the classification so it's queryable and can
  drive dynamic ownership rules. Same gated `navi enrich tag` path as every other agent.

Read-only until you approve a tag write.
