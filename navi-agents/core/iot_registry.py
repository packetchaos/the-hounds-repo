"""Persistent IoT detection registry — the learning loop.

Default detections + human-approved additions live in iot_detections.json
(path via IOT_REGISTRY_PATH). Agent 3 proposes new detections; on approval they
are appended here with provenance and reused on future runs. Rejected proposals
are remembered so they are not re-proposed.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PATH = os.path.join(os.path.dirname(HERE), "data", "iot_detections.json")


def registry_path() -> str:
    return os.environ.get("IOT_REGISTRY_PATH", DEFAULT_PATH)


def load() -> dict:
    p = registry_path()
    if not os.path.exists(p):
        return {"version": 1, "detections": [], "rejected": []}
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    data.setdefault("detections", [])
    data.setdefault("rejected", [])
    return data


def save(data: dict) -> None:
    p = registry_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def detection_for(name: str, data: dict | None = None) -> dict | None:
    data = data or load()
    for d in data["detections"]:
        if d["iot_name"].lower() == name.lower():
            return d
    return None


def proposal_key(iot_name: str, plugin_id: str) -> str:
    return f"{iot_name}::{plugin_id}"


def is_rejected(iot_name: str, plugin_id: str, data: dict | None = None) -> bool:
    data = data or load()
    return proposal_key(iot_name, plugin_id) in set(data.get("rejected", []))


def all_terms(data: dict | None = None) -> list[dict]:
    """Every searchable term in the registry, mapped to its owning device — the
    base vocabulary for Agent 3's cross-term sweep. Includes terms whose device
    found NOTHING on pass 1 (that's the whole point: a device with no working
    plugin can still be discovered riding inside a carrier plugin)."""
    data = data or load()
    out, seen = [], set()
    for d in data["detections"]:
        for t in (list(d.get("name_contains") or []) + list(d.get("output_contains") or [])
                  or [d["iot_name"]]):
            k = (t or "").strip().lower()
            if k and (k, d["iot_name"].lower()) not in seen:
                seen.add((k, d["iot_name"].lower()))
                out.append({"term": t, "iot_name": d["iot_name"],
                            "vendor": d.get("vendor", ""), "source": "registry"})
    return out


def apply_decisions(decisions: list[dict]) -> dict:
    """decisions: [{iot_name, plugin_id, plugin_name, term?, approve(bool)}].
    Approved: merge the plugin id into that device's detection (creating it if
    new), AND seed the matched term into output_contains so the device carries a
    real term signature — not just an opaque plugin id. Rejected keys remembered."""
    data = load()
    by_name = {d["iot_name"].lower(): d for d in data["detections"]}
    rejected = set(data.get("rejected", []))
    added, refused = 0, 0
    for dec in decisions:
        name = dec["iot_name"]
        pid = str(dec["plugin_id"])
        term = (dec.get("term") or "").strip()
        key = proposal_key(name, pid)
        if dec.get("approve"):
            det = by_name.get(name.lower())
            if not det:
                det = {"iot_name": name, "vendor": dec.get("vendor", ""),
                       "plugins": [], "name_contains": [], "output_contains": [],
                       "source": "approved", "provenance": []}
                data["detections"].append(det)
                by_name[name.lower()] = det
            det.setdefault("output_contains", [])
            if term and term not in det["output_contains"] \
                    and term not in det.get("name_contains", []):
                det["output_contains"].append(term)
            if pid not in det["plugins"]:
                det["plugins"].append(pid)
                det.setdefault("provenance", []).append(
                    {"plugin_id": pid, "plugin_name": dec.get("plugin_name", ""),
                     "term": term, "kind": dec.get("kind", ""), "added_by": "agent3-hitl"})
                added += 1
            rejected.discard(key)
        else:
            rejected.add(key)
            refused += 1
    data["rejected"] = sorted(rejected)
    save(data)
    return {"added": added, "rejected": refused,
            "detections": len(data["detections"]), "path": registry_path()}


def export_base(proposals: list[dict], merge: bool = False) -> dict:
    """Base-building: turn a rich-db hunt's confirmed proposals into a fresh
    detections base WITHOUT touching the live registry. Writes a reviewable file
    next to the registry (iot_detections.learned.json) that the operator can swap
    in to replace the thin seed base. If merge=True, the current registry
    detections are folded in as a starting point."""
    base = {}
    if merge:
        for d in load()["detections"]:
            base[d["iot_name"].lower()] = {
                "iot_name": d["iot_name"], "vendor": d.get("vendor", ""),
                "plugins": list(d.get("plugins") or []),
                "name_contains": list(d.get("name_contains") or []),
                "output_contains": list(d.get("output_contains") or []),
                "source": d.get("source", "seed"), "provenance": list(d.get("provenance") or [])}
    for p in proposals:
        name = p.get("iot_name")
        if not name:
            continue
        det = base.setdefault(name.lower(), {
            "iot_name": name, "vendor": p.get("vendor", ""), "plugins": [],
            "name_contains": [], "output_contains": [], "source": "learned", "provenance": []})
        pid, term = str(p.get("plugin_id")), (p.get("term") or "").strip()
        if pid and pid not in det["plugins"]:
            det["plugins"].append(pid)
        if term and term not in det["output_contains"] and term not in det["name_contains"]:
            det["output_contains"].append(term)
        det["provenance"].append({"plugin_id": pid, "term": term, "kind": p.get("kind", ""),
                                  "asset_count": p.get("asset_count", 0), "added_by": "agent3-hunt"})
    out = {"version": 1, "note": "Learned IoT detection base built from a navi.db hunt "
           "(Agent 3 confirmed carrier-plugin → term → device mappings). Review, then "
           "replace iot_detections.json with this file to adopt it.",
           "detections": list(base.values()), "rejected": []}
    path = os.path.join(os.path.dirname(registry_path()), "iot_detections.learned.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    return {"path": path, "detections": len(out["detections"]),
            "merged_seeds": bool(merge)}
