"""Beagle — the WAS asset deep-dive (per web-app recon).

A beagle works a scent trail to map where its quarry has been; Beagle does the same
for a web app, following navi's WAS *info plugins* to lay out the terrain — the
sitemap the crawler discovered, scan telemetry, target facts, the screenshot,
external URLs, cookies and allowed methods — with every plugin clickable to its raw
stored output. The VM asset deep-dive is Argos's job; Beagle is Argos for web apps.
Read-only; core.was does the work. Driven by ?app=<uuid> from the WAS dashboards.
"""
from core import was
from core.agents.base import Agent


class BeagleAgent(Agent):
    id = "was_asset"
    name = "Web App Recon"
    icon = "🐾"
    description = ("Beagle — the WAS asset deep-dive. Maps one web app from navi's info "
                   "plugins (sitemap, scan info, target, screenshot, external URLs, "
                   "cookies, methods), each clickable to its raw plugin output.")

    def summary(self):
        return {"hint": "Open Beagle from a web app in the WAS dashboards to map its recon."}

    def _run(self, db_path=None, **kwargs):
        # Landing/readiness stub — the real work is the `info` action (api.py), driven
        # from the page with an app uuid (falls back to the top-risk app).
        return {"hint": "Pick a web app on the Beagle page to map its recon plugins.",
                "ready": bool(was.status(path=db_path).get("ready"))}
