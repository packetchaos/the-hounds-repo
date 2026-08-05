# Asset Classification · Linnaeus Hound 📇

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

## What it gives you

- **Coverage %** — the health of your whole ownership pipeline in one number.
- **Per-class ownership overlay** — owned vs unowned, with a one-click hand-off to Atlas.
- **Risk overlay** — KEV / critical counts per class, so you triage classes, not just count.
- **Unclassified worklist** — every unknown with a *reason* (uncredentialed → add creds +
  rescan; no-fingerprint) — a bucket that shrinks over time.
- **Gated `Class:<type>` tags** — persist the classification so it's queryable and can
  drive dynamic ownership rules. Same gated `navi enrich tag` path as every other agent.

Read-only until you approve a tag write.
