# IoT Discovery Squad
Four cooperating agents: **Discovery** (detect known IoT, tag `IoT:<name>`),
**Plugin Expansion** (search plugin name/output for the IoT name, guardrailed),
**Cross-Reference** (find more assets, propose new detections), and
**Orchestrator/QA**. Detections persist to a learning-loop registry on approval.

- **UI:** `page.html` · **API:** `/api/iot_squad/run`, `tags_apply`, `detections_decide`, `registry`
- **Writes:** gated `navi enrich tag`. Detection approvals write a local registry file.
