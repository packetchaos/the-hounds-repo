"""Tag Explorer — read-only navi.db search over the tags table (paginated).

`search` → one row per tag (tag_key : tag_value) with a DISTINCT asset count.
`assets` → drill-down: the assets carrying one tag, joined to the assets table
           (hostname, IP, OS, ACR/AES, platform url) so you can see exactly
           which assets are in each tag.
"""
from core import search


def run(p):
    try:
        res = search.tags((p.get("q") or "").strip(), int(p.get("offset") or 0))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "result": res}, 200


def assets(p):
    key = (p.get("key") or "").strip()
    value = (p.get("value") or "").strip()
    if not key:
        return {"ok": False, "error": "key (tag category) required"}, 400
    try:
        res = search.tag_assets(key, value, (p.get("q") or "").strip(),
                                int(p.get("offset") or 0))
    except Exception as e:
        return {"ok": False, "error": str(e)}, 200
    return {"ok": True, "result": res}, 200


ACTIONS = {"search": run, "assets": assets}
