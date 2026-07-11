"""Agent discovery — scan agents/<id>/manifest.json and import each module.

An agent is "deployed" when its folder is present AND (for backend agents) its
api.py imports cleanly. Static agents (needs_backend=false) are
deployed whenever the folder + page are present. The launcher uses this to
serve a generic /api/<id>/<action> dispatch and a /api/registry the hub reads.
"""
import importlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AGENTS_DIR = os.path.join(ROOT, "agents")


def _load_manifest(d):
    try:
        with open(os.path.join(d, "manifest.json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def discover():
    """Return a list of agent records sorted by manifest 'order' then id."""
    out = []
    if not os.path.isdir(AGENTS_DIR):
        return out
    for name in sorted(os.listdir(AGENTS_DIR)):
        d = os.path.join(AGENTS_DIR, name)
        if not os.path.isdir(d):
            continue
        meta = _load_manifest(d)
        if not meta:
            continue
        rec = {"id": meta.get("id", name), "dir": d, "meta": meta,
               "actions": {}, "deployed": False, "error": None,
               "has_page": os.path.exists(os.path.join(d, meta.get("page", "page.html"))),
               "has_readme": os.path.exists(os.path.join(d, "README.md"))}
        if meta.get("needs_backend", True):
            try:
                mod = importlib.import_module(f"agents.{name}.api")
                rec["actions"] = dict(getattr(mod, "ACTIONS", {}))
                rec["deployed"] = True
            except Exception as e:  # import failed → not deployed; hub shows README
                rec["error"] = f"{type(e).__name__}: {e}"
        else:
            rec["deployed"] = rec["has_page"]
        out.append(rec)
    out.sort(key=lambda r: (r["meta"].get("order", 99), r["id"]))
    return out


def registry(records=None):
    """Public, JSON-safe registry for the hub (no callables)."""
    records = records if records is not None else discover()
    items = []
    for r in records:
        m = r["meta"]
        if m.get("hidden"):          # hidden services (e.g. explore) back pages but aren't cards
            continue
        items.append({
            "id": r["id"], "name": m.get("name", r["id"]), "icon": m.get("icon", "🤖"),
            "summary": m.get("summary", ""), "category": m.get("category", "Agent"),
            "deployed": r["deployed"], "error": r["error"],
            "needs_backend": m.get("needs_backend", True),
            "page": f"/agents/{r['id']}/{m.get('page','page.html')}" if r["has_page"] else None,
            "readme": f"/agents/{r['id']}/README.md" if r["has_readme"] else None,
            # "Meet the Hound" dark one-pager card, when one exists for this agent
            "hound": (f"/web/hounds/{r['id']}.html"
                      if os.path.exists(os.path.join(ROOT, "web", "hounds", f"{r['id']}.html"))
                      else None),
            "actions": sorted(r["actions"].keys()),
        })
    return {"agents": items, "count": len(items),
            "deployed": sum(1 for i in items if i["deployed"])}
