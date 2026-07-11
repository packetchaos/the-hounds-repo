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


def apply_decisions(decisions: list[dict]) -> dict:
    """decisions: [{iot_name, plugin_id, plugin_name, approve(bool)}].
    Approved plugins are merged into that IoT's detection (creating it if new);
    rejected keys are remembered. Returns a summary."""
    data = load()
    by_name = {d["iot_name"].lower(): d for d in data["detections"]}
    rejected = set(data.get("rejected", []))
    added, refused = 0, 0
    for dec in decisions:
        name = dec["iot_name"]
        pid = str(dec["plugin_id"])
        key = proposal_key(name, pid)
        if dec.get("approve"):
            det = by_name.get(name.lower())
            if not det:
                det = {"iot_name": name, "vendor": dec.get("vendor", ""),
                       "plugins": [], "name_contains": [], "output_contains": [],
                       "source": "approved", "provenance": []}
                data["detections"].append(det)
                by_name[name.lower()] = det
            if pid not in det["plugins"]:
                det["plugins"].append(pid)
                det.setdefault("provenance", []).append(
                    {"plugin_id": pid, "plugin_name": dec.get("plugin_name", ""),
                     "added_by": "agent3-hitl"})
                added += 1
            rejected.discard(key)
        else:
            rejected.add(key)
            refused += 1
    data["rejected"] = sorted(rejected)
    save(data)
    return {"added": added, "rejected": refused,
            "detections": len(data["detections"]), "path": registry_path()}
