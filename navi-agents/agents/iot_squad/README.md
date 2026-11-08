# IoT Discovery Squad
Four cooperating agents: **Discovery** (detect known IoT, tag `IoT:<name>`),
**Plugin Expansion** (search plugin name/output for the IoT name, guardrailed),
**Cross-Reference** (find more assets, propose new detections), and
**Orchestrator/QA**. Detections persist to a learning-loop registry on approval.

- **UI:** `page.html` · **API:** `/api/iot_squad/run`, `tags_apply`, `detections_decide`, `registry`
- **Writes:** gated `navi enrich tag`. Detection approvals write a local registry file.
- **Page:** sticky jump nav + **📊 At a glance** (devices found / registry vs signal-fusion,
  exposure on the devices — criticals, highs, CISA KEV, highest AES → Argos — learning-loop
  counts, identity-signal coverage) and a filterable **Discovered devices** list. The run result
  adds `available`, `missing`, `signal_coverage` and `exposure` (reads only); every older key is kept.
