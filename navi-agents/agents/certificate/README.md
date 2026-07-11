# Certificate Agent
Tags assets whose certificates fail (expire) within the next 12 months as
`Cert failure : <Mon>-<dd>-<yyyy>`, builds a 12-month failure heat map and a
cert-issue × asset heat map, and caches IoT/application devices fingerprinted
from certificate fields (plugin 10863).

- **UI:** `page.html` · **API:** `/api/certificate/run`, `/api/certificate/tags_apply`
- **Writes:** gated `navi enrich tag … -remove` (needs `NAVI_ALLOW_WRITES=1`).
- **Deploy alone:** drop this folder into `agents/` and start the launcher.
