"""The IoT agent squad — four cooperating agents.

A1 IoTDiscoveryAgent   — detect known IoT devices; emit IoT:<name> tag actions;
                          hand off (iot_name, trigger plugins) to A2.
A2 PluginExpansionAgent — for each iot_name, search every plugin name+output for
                          that name; capture matching plugins (with guardrails);
                          hand the expanded plugin list to A3.
A3 CrossReferenceAgent  — use the expanded plugin list to find OTHER assets that
                          look like the same device; propose the newly-found
                          plugins as default detections for human review.
A4 IoTSquadOrchestrator — run A1->A2->A3, enforce quality, expose the two HITL
                          gates (tag approval, detection approval).

All reads are read-only sqlite3. Tag writes and registry writes are gated and
happen in the service layer after human approval.
"""
from core import iot_common as ic
from core import iot_registry as reg
from core.agents.base import Agent


def _sh(s):
    return '"' + str("" if s is None else s).replace('"', '\\"') + '"'


def _sel_cmd(cat, val, s):
    """Human-readable navi command for one selector (for the HITL preview)."""
    if s.get("plugin"):
        return ('navi enrich tag --c %s --v %s --plugin %s%s'
                % (_sh(cat), _sh(val), s["plugin"],
                   (" --output " + _sh(s["output"])) if s.get("output") else ""))
    if s.get("name"):
        return 'navi enrich tag --c %s --v %s --name %s' % (_sh(cat), _sh(val), _sh(s["name"]))
    return 'navi enrich tag --c %s --v %s --query %s' % (_sh(cat), _sh(val), _sh(s.get("query", "")))


def _iot_selectors(det, trig_plugins):
    """Reproduce a registry detection with navi BUILT-INS instead of a giant
    --query UUID list (the Tenable tag endpoint caps at 1999 UUIDs and navi loops
    internally past that). Maps:
      det.plugins       -> --plugin <id>                 (specific plugin)
      det.name_contains -> --name "<text>"               (tag-by-plugin-name)
      det.output_contains -> --plugin <trig> --output "<text>"  (narrow a broad
                            plugin that matched by output, for triggers not already
                            covered by an explicit plugin id)
    --query is used ONLY when a device has no plugin/name signature (signal-fusion
    OUI / mDNS / cert groups)."""
    plugins = [str(p) for p in (det.get("plugins") or [])]
    explicit = set(plugins)
    sels = [{"plugin": p} for p in plugins]
    for t in (det.get("name_contains") or []):
        if t:
            sels.append({"name": t})
    for t in (det.get("output_contains") or []):
        if len(str(t)) < 4:
            continue
        for pid in trig_plugins:
            if str(pid) not in explicit and str(pid) != "signal-fusion":
                sels.append({"plugin": str(pid), "output": t})
    seen, out = set(), []
    for s in sels:
        k = tuple(sorted(s.items()))
        if k not in seen:
            seen.add(k)
            out.append(s)
    return out


def _iot_tag_action(name, h):
    """Build one IoT tag action from a handoff entry — using its navi built-in
    selectors, or falling back to a UUID --query only for signal-fusion groups
    (no plugin signature)."""
    uuids = h.get("asset_uuids", []) or []
    sels = h.get("selectors")
    if not sels:
        q = ("SELECT asset_uuid FROM vulns WHERE asset_uuid IN ("
             + ",".join("'" + u + "'" for u in uuids) + ");") if uuids else ""
        sels = [{"query": q}] if q else []
    cmds = [_sel_cmd("IoT", name, s) for s in sels]
    return {"category": "IoT", "value": name, "asset_count": len(uuids),
            "asset_uuids": uuids, "selectors": sels, "vendor": h.get("vendor", ""),
            "tool_call": "\n".join(cmds),
            "query": (sels[0].get("query", "") if sels else "")}


# ---------------------------------------------------------------- A1
class IoTDiscoveryAgent(Agent):
    id = "iot_discovery"
    name = "IoT Discovery Agent"
    icon = "📡"
    description = ("Detects known IoT devices from navi signatures, tags each "
                   "IoT:<name>, and hands the plugin + IoT name to expansion.")

    def summary(self):
        if not self.result:
            return {}
        return {"devices": len(self.result["detected"]),
                "tags": len(self.result["tag_actions"])}

    def _run(self, db_path=None):
        data = reg.load()
        detected, handoff = [], {}
        for det in data["detections"]:
            rows = ic.assets_for_detection(det, db_path)
            assets, trig_plugins = {}, set()
            for r in rows:
                trig_plugins.add(str(r["plugin_id"]))
                u = r["asset_uuid"]
                if u not in assets:
                    assets[u] = {"asset_uuid": u,
                                 "hostname": (r["hostname"] or "").strip() or "(none)",
                                 "ip": r["ip_address"]}
            if not assets:
                continue
            for a in assets.values():
                detected.append({"iot_name": det["iot_name"], "vendor": det.get("vendor", ""), **a})
            handoff[det["iot_name"]] = {"iot_name": det["iot_name"],
                                        "vendor": det.get("vendor", ""),
                                        "trigger_plugins": sorted(trig_plugins),
                                        "asset_uuids": list(assets.keys()),
                                        # navi BUILT-IN selectors for this device (no UUID --query)
                                        "selectors": _iot_selectors(det, sorted(trig_plugins))}
        # IoT:<name> tag actions (ADD only — removals are the Tag Removal agent's job)
        tag_actions = [_iot_tag_action(name, h) for name, h in handoff.items()]
        return {"detected": detected, "handoff": handoff, "tag_actions": tag_actions}


# ---------------------------------------------------------------- A2
class PluginExpansionAgent(Agent):
    id = "iot_expansion"
    name = "Plugin Expansion Agent"
    icon = "🔎"
    description = ("Searches every plugin name and output for each IoT name and "
                   "captures the plugins that mention it (guardrailed).")

    def summary(self):
        if not self.result:
            return {}
        return {"names": len(self.result["expanded"]),
                "kept_plugins": sum(len(e["kept"]) for e in self.result["expanded"].values())}

    def _run(self, db_path=None, handoff=None):
        handoff = handoff or {}
        data = reg.load()
        expanded = {}
        for name, h in handoff.items():
            if not ic.valid_iot_name(name):
                expanded[name] = {"skipped": "name too short/ambiguous", "kept": [], "dropped": []}
                continue
            # 'known' = plugins already promoted into the registry's explicit
            # plugins list for this device. Kept plugins not yet promoted become
            # proposals (Agent 3 asks the human to add them as defaults), even if
            # they also triggered discovery this run via name/output match.
            det = reg.detection_for(name, data)
            known = set(det.get("plugins", []) if det else [])
            kept, dropped, new = [], [], []
            for p in ic.plugins_mentioning(name, db_path):
                (kept if p["kept"] else dropped).append(p)
                if p["kept"] and p["plugin_id"] not in known and not reg.is_rejected(name, p["plugin_id"], data):
                    new.append(p)
            expanded[name] = {"vendor": h.get("vendor", ""), "kept": kept,
                              "dropped": dropped, "new": new}
        return {"expanded": expanded}


# ---------------------------------------------------------------- A3
class CrossReferenceAgent(Agent):
    id = "iot_xref"
    name = "Cross-Reference Agent"
    icon = "🕸️"
    description = ("Uses the expanded plugin list to find other matching assets "
                   "and proposes new default detections for human review.")

    def summary(self):
        if not self.result:
            return {}
        return {"candidates": len(self.result["candidates"]),
                "proposals": len(self.result["proposals"])}

    def _run(self, db_path=None, expanded=None, discovery=None):
        expanded = expanded or {}
        discovery = discovery or {}
        # assets already detected per name (to exclude from cross-ref)
        already = {}
        for name, h in (discovery.get("handoff", {}) or {}).items():
            already[name] = set(h.get("asset_uuids", []))

        candidates, proposals = [], []
        for name, e in expanded.items():
            kept_ids = [p["plugin_id"] for p in e.get("kept", [])]
            # 1) cross-reference: other assets sharing the expanded plugins
            for c in ic.assets_with_plugins(kept_ids, already.get(name, set()), db_path):
                candidates.append({"iot_name": name, "asset_uuid": c["asset_uuid"],
                                   "hostname": (c["hostname"] or "").strip() or "(none)",
                                   "ip": c["ip_address"], "evidence_plugins": c["evidence"],
                                   "pids": [p for p in str(c.get("pids") or "").split(",") if p]})
            # 2) propose newly-found plugins as default detections (HITL gate)
            for p in e.get("new", []):
                proposals.append({"key": reg.proposal_key(name, p["plugin_id"]),
                                  "iot_name": name, "vendor": e.get("vendor", ""),
                                  "plugin_id": p["plugin_id"], "plugin_name": p["plugin_name"],
                                  "asset_count": p["asset_count"], "prevalence": p["prevalence"]})
        return {"candidates": candidates, "proposals": proposals}


# ---------------------------------------------------------------- A4
class IoTSquadOrchestrator(Agent):
    id = "iot_squad"
    name = "IoT Discovery Squad"
    icon = "🤖"
    description = ("Runs Discovery → Expansion → Cross-Reference as one pipeline, "
                   "enforces data-quality checks, and surfaces the two HITL gates.")

    def __init__(self):
        super().__init__()
        self.a1 = IoTDiscoveryAgent()
        self.a2 = PluginExpansionAgent()
        self.a3 = CrossReferenceAgent()

    def summary(self):
        if not self.result:
            return {}
        return {"devices": len(self.result["discovery"]["detected"]),
                "candidates": len(self.result["xref"]["candidates"]),
                "proposals": len(self.result["xref"]["proposals"]),
                "qa_flags": len(self.result["qa"]["flags"])}

    def _run(self, db_path=None):
        d = self.a1.run(db_path)
        e = self.a2.run(db_path=db_path, handoff=d["handoff"])
        x = self.a3.run(db_path=db_path, expanded=e["expanded"], discovery=d)

        # --- Signal-fusion discovery: device-type / OUI / mDNS / cert ---
        # Surfaces a broad embedded/OT footprint, grouped into
        # IoT:<class> tag actions. These are discovery-only (no plugin expansion).
        try:
            from core import signals
            devs = (signals._iot(db_path) or {}).get("devices", [])
            seen = {a["asset_uuid"] for a in d["detected"] if a.get("asset_uuid")}
            for dev in devs:
                u = dev.get("asset_uuid")
                if not u:
                    continue
                klass, vendor, typ = dev.get("klass"), dev.get("vendor"), dev.get("type")
                name = (klass if klass and klass != "Embedded / candidate"
                        else (vendor.split(",")[0] if vendor and vendor != "—"
                              else (typ if typ and typ not in ("unknown", "general-purpose") else "Embedded device")))
                h = d["handoff"].setdefault(name, {"iot_name": name, "vendor": vendor or "",
                                                   "trigger_plugins": ["signal-fusion"], "asset_uuids": [], "fused": True})
                h["fused"] = True
                if u not in h["asset_uuids"]:
                    h["asset_uuids"].append(u)
                if u not in seen:
                    seen.add(u)
                    d["detected"].append({"iot_name": name, "vendor": vendor or "", "asset_uuid": u,
                                          "hostname": dev.get("host", ""), "ip": dev.get("ip", ""), "fused": True})
            # rebuild tag_actions to include the fused groups — registry devices keep
            # their native --plugin/--output/--name selectors; fused groups (no plugin
            # signature) fall back to --query.
            d["tag_actions"] = [_iot_tag_action(nm, h) for nm, h in d["handoff"].items()]
        except Exception:
            pass

        # ---- A4 quality assurance ----
        flags = []
        # a) the same plugin proposed for >1 IoT name = ambiguous signal
        seen = {}
        for p in x["proposals"]:
            seen.setdefault(p["plugin_id"], set()).add(p["iot_name"])
        for pid, names in seen.items():
            if len(names) > 1:
                flags.append({"type": "ambiguous_plugin", "plugin_id": pid,
                              "iot_names": sorted(names),
                              "detail": "proposed for multiple IoT names — review carefully"})
        # b) any generic plugin that slipped into a kept list
        for name, ex in e["expanded"].items():
            for p in ex.get("kept", []):
                if p["plugin_id"] in ic.GENERIC_PLUGIN_DENYLIST:
                    flags.append({"type": "generic_leak", "plugin_id": p["plugin_id"],
                                  "iot_name": name})
        # c) candidates with weak (single-plugin) evidence
        weak = [c for c in x["candidates"] if c["evidence_plugins"] < 2]
        qa = {"flags": flags, "weak_candidates": len(weak),
              "checks": ["ambiguous_plugin", "generic_leak", "weak_evidence"],
              "agents": {"discovery": self.a1.status, "expansion": self.a2.status,
                         "xref": self.a3.status}}

        return {
            "registry": {"detections": len(reg.load()["detections"]),
                         "rejected": len(reg.load()["rejected"])},
            "discovery": d, "expansion": e, "xref": x, "qa": qa,
            # HITL gates surfaced for the UI / API:
            "tag_actions": d["tag_actions"],          # gate 1 (Agent 1)
            "proposals": x["proposals"],              # gate 2 (Agent 3)
        }
