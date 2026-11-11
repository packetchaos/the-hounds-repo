"""The IoT agent squad — four cooperating agents.

A1 IoTDiscoveryAgent   — detect known IoT devices from the registry; emit
                          IoT:<name> tag actions; hand the confirmed hosts to A2.
A2 CarrierHarvestAgent  — HOST-SCOPED: for each confirmed host, look at THAT
                          host's own findings and capture the plugins whose
                          name/output carry the device term ("carrier plugins").
                          Optionally union an operator-supplied carrier list so
                          you can hunt a rich db without waiting for a light-up.
A3 CrossTermAgent       — sweep every carrier plugin for the whole term
                          VOCABULARY (registry terms, incl. ones that found
                          nothing on pass 1, + an optional known-IoT term pack)
                          across the ENTIRE population. A term found inside a
                          carrier plugin on >= max(2, 5%) assets becomes a
                          (plugin -> term -> device) proposal: confirm / cross /
                          new. Nothing is silently dropped — a coverage ledger
                          records every combination tested.
A4 IoTSquadOrchestrator — run A1->A2->A3, build the QA coverage ledger, surface
                          the two HITL gates + the base-building export.

All reads are read-only sqlite3. Registry writes are gated behind human approval.
"""
from core import iot_common as ic
from core import iot_registry as reg
from core import navi_cli, tagname
from core.agents.base import Agent


def _sh(s):
    return '"' + str("" if s is None else s).replace('"', '\\"') + '"'


def _sel_cmd(cat, val, s):
    cat = tagname.effective(cat)      # preview the name navi_cli.tag will write (Settings → Test run)
    if s.get("plugin"):
        return ('navi enrich tag --c %s --v %s --plugin %s%s'
                % (_sh(cat), _sh(val), s["plugin"],
                   (" --output " + _sh(s["output"])) if s.get("output") else ""))
    if s.get("name"):
        return 'navi enrich tag --c %s --v %s --name %s' % (_sh(cat), _sh(val), _sh(s["name"]))
    return 'navi enrich tag --c %s --v %s --query %s' % (_sh(cat), _sh(val), _sh(s.get("query", "")))


def _cover_selectors(det, rows):
    """Minimal BUILT-IN selectors covering all detected assets: the fewest trigger
    plugins (greedy set cover), each narrowed by the device's output term. Used when
    the set is over the ~1999 UUID cap so navi tags by SIGNATURE server-side in one
    shot per plugin, instead of looping UUID pages from a --query."""
    detected = {r.get("asset_uuid") for r in rows if r.get("asset_uuid")}
    p2a = {}
    for r in rows:
        pid = str(r.get("plugin_id") or "")
        if pid:
            p2a.setdefault(pid, set()).add(r.get("asset_uuid"))
    cover, remaining = [], set(detected)
    while remaining and p2a:
        best = max(p2a, key=lambda p: len(p2a[p] & remaining))
        gain = p2a[best] & remaining
        if not gain:
            break
        cover.append(best)
        remaining -= gain
        p2a.pop(best)
    out_terms = [str(t).strip() for t in (det.get("output_contains") or []) if len(str(t).strip()) >= 4]
    if out_terms:
        return [{"plugin": pid, "output": out_terms[0]} for pid in cover]
    names = [str(t).strip() for t in (det.get("name_contains") or []) if str(t).strip()]
    if names:
        return [{"name": names[0]}]
    return [{"plugin": pid} for pid in cover]


def _iot_selectors(det, rows=None, db_path=None):
    """ONE broad, correct navi selector for a device — never 20× per asset, and never
    a --query that would loop past the ~1999-UUID cap.

      1) DEVICE-SPECIFIC plugins (`det.plugins`) → `--plugin <id>` each (built-in,
         server-side, cap-proof).
      2) else if the detected set is <= the UUID cap → ONE `--query` reproducing the
         candidate-filtered detection (precise: tags exactly the detected assets).
      3) else (> cap) → minimal BUILT-IN --plugin/--output set-cover, so navi tags by
         signature server-side instead of paging UUIDs.
    """
    plugins = [str(p) for p in (det.get("plugins") or []) if str(p).strip()]
    if plugins:
        return [{"plugin": p} for p in dict.fromkeys(plugins)]
    rows = rows or []
    n = len({r.get("asset_uuid") for r in rows if r.get("asset_uuid")})
    if n and n > navi_cli.UUID_CAP:
        return _cover_selectors(det, rows)
    q = ic.detection_query(det, db_path)
    return [{"query": q}] if q else []


# Default facet for a discovered device under the unified inventory scheme. 'Device Type'
# is what the Classifier maps into the IoT / OT class, so these tags land on the graphs.
IOT_DEFAULT_FACET = "Device Type"
INVENTORY_CAT = "Asset Inventory"


def _iot_tag_action(name, h, facet=IOT_DEFAULT_FACET):
    uuids = h.get("asset_uuids", []) or []
    sels = h.get("selectors")
    if not sels:
        # no signature selector: the detected set (Python) in ≤1,999-UUID batches
        sels = [{"query": sp["query"]} for sp in
                navi_cli.uuid_specs(INVENTORY_CAT, "", uuids, col="asset_uuid", table="vulns")]
    # Unified inventory scheme (matches the Classifier): category 'Asset Inventory',
    # value '<Facet>: <Value>'. The operator can change the facet in the UI before writing.
    tagval = f"{facet}: {name}"
    cmds = [_sel_cmd(INVENTORY_CAT, tagval, s) for s in sels]
    return {"category": INVENTORY_CAT, "facet": facet, "value": name, "tag_value": tagval,
            "asset_count": len(uuids), "asset_uuids": uuids, "selectors": sels,
            "vendor": h.get("vendor", ""), "tool_call": "\n".join(cmds),
            "query": (sels[0].get("query", "") if sels else "")}


# ---------------------------------------------------------------- A1
class IoTDiscoveryAgent(Agent):
    id = "iot_discovery"
    name = "IoT Discovery Agent"
    icon = "📡"
    description = ("Detects known IoT devices from the registry, tags each "
                   "IoT:<name>, and hands the confirmed hosts to carrier harvest.")

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
                                        "terms": ic.detection_terms(det),
                                        "trigger_plugins": sorted(trig_plugins),
                                        "asset_uuids": list(assets.keys()),
                                        "selectors": _iot_selectors(det, rows, db_path)}
        tag_actions = [_iot_tag_action(name, h) for name, h in handoff.items()]
        return {"detected": detected, "handoff": handoff, "tag_actions": tag_actions}


# ---------------------------------------------------------------- A2
class CarrierHarvestAgent(Agent):
    id = "iot_carrier"
    name = "Carrier Harvest Agent"
    icon = "🔎"
    description = ("Host-scoped: captures the carrier plugins on each confirmed "
                   "host that leak the device term, plus any supplied carrier list.")

    def summary(self):
        if not self.result:
            return {}
        return {"carriers": len(self.result["carriers"]),
                "supplied": len(self.result["supplied"])}

    def _run(self, db_path=None, handoff=None):
        handoff = handoff or {}
        carriers = {}   # plugin_id -> record

        def _rec(pid, pname):
            return carriers.setdefault(str(pid), {
                "plugin_id": str(pid), "plugin_name": pname or "",
                "via_terms": [], "via_devices": [], "host_count": 0,
                "source": "harvest"})

        for name, h in handoff.items():
            # Only harvest carriers from REGISTRY-confirmed hosts. Signal-fusion
            # (OUI/mDNS/cert) devices are a separate Gate-1 tagger and have no
            # plugin-output term signature — letting them harvest would fabricate a
            # term from their display name and make later cross-term hits read as
            # 'confirm' instead of the 'new' discovery they actually are.
            if h.get("fused"):
                continue
            terms = h.get("terms") or ic.detection_terms({"iot_name": name})
            uuids = h.get("asset_uuids", [])
            for row in ic.carrier_plugins_on_assets(uuids, terms, db_path):
                c = _rec(row["plugin_id"], row["plugin_name"])
                if row["term"] not in c["via_terms"]:
                    c["via_terms"].append(row["term"])
                if name not in c["via_devices"]:
                    c["via_devices"].append(name)
                c["host_count"] = max(c["host_count"], row["host_count"])
                if not c["plugin_name"]:
                    c["plugin_name"] = row["plugin_name"]

        # operator-supplied carrier plugins (hunt mode — no light-up required)
        supplied = ic.byo_carrier_plugins()
        for pid in supplied:
            c = _rec(pid, "")
            if c["source"] == "harvest":
                c["source"] = "harvest+supplied"
            else:
                c["source"] = "supplied"
        return {"carriers": carriers, "supplied": supplied}


# ---------------------------------------------------------------- A3
class CrossTermAgent(Agent):
    id = "iot_xterm"
    name = "Cross-Term Agent"
    icon = "🕸️"
    description = ("Sweeps each carrier plugin for the whole term vocabulary "
                   "across the population; proposes plugin→term→device detections.")

    def summary(self):
        if not self.result:
            return {}
        return {"proposals": len(self.result["proposals"]),
                "tested": self.result["tested"]}

    def _run(self, db_path=None, carriers=None, use_pack=False):
        carriers = carriers or {}
        total = ic.asset_total(db_path)
        floor = ic.cluster_floor(total)

        # vocabulary: registry terms (incl. zero-hit devices) + optional pack.
        # The registry is authoritative on naming: a pack term that duplicates a
        # registry term (case-insensitive) is DROPPED so we don't propose the same
        # device under a second name — it just confirms the registry device. This
        # is the pack-vs-registry de-dupe (noise reduction).
        vocab, seen = [], set()
        reg_terms = set()
        for t in reg.all_terms():
            term_l = t["term"].strip().lower()
            k = (term_l, t["iot_name"].lower())
            if t["term"] and k not in seen and ic.valid_term(t["term"]):
                seen.add(k)
                reg_terms.add(term_l)
                vocab.append({"term": t["term"], "iot_name": t["iot_name"],
                              "vendor": t.get("vendor", ""), "source": "registry"})
        pack_terms, pack_deduped = 0, 0
        if use_pack:
            for term, device in ic.term_pack().items():
                term_l = term.strip().lower()
                k = (term_l, device.lower())
                if not term or not ic.valid_term(term):
                    continue
                if term_l in reg_terms:          # registry already owns this term
                    pack_deduped += 1
                    continue
                if k in seen:
                    continue
                seen.add(k)
                pack_terms += 1
                vocab.append({"term": term, "iot_name": device, "vendor": "",
                              "source": "pack"})

        proposals, ledger = {}, []
        tested = 0
        for pid, c in carriers.items():
            via_dev = {d.lower() for d in c.get("via_devices", [])}
            via_terms = {t.lower() for t in c.get("via_terms", [])}
            for v in vocab:
                term, device = v["term"], v["iot_name"]
                res = ic.plugin_carries_term(pid, term, db_path, total=total)
                tested += 1
                cnt, prev = res["count"], res["prevalence"]
                if cnt < floor:
                    if cnt > 0:
                        ledger.append({"plugin_id": pid, "term": term, "iot_name": device,
                                       "count": cnt, "floor": floor, "reason": "below_floor"})
                    continue
                if reg.is_rejected(device, pid):
                    ledger.append({"plugin_id": pid, "term": term, "iot_name": device,
                                   "count": cnt, "reason": "previously_rejected"})
                    continue
                reg_det = reg.detection_for(device)
                already = reg_det and str(pid) in [str(x) for x in reg_det.get("plugins", [])]
                if device.lower() in via_dev or term.lower() in via_terms:
                    kind = "confirm"
                elif reg_det:
                    kind = "cross"
                else:
                    kind = "new"
                warns = []
                if str(pid) in ic.GENERIC_PLUGIN_DENYLIST:
                    warns.append("generic/enumeration plugin — verify the term isn't incidental")
                if prev > ic.PREVALENCE_MAX:
                    warns.append(f"(plugin+term) on {prev*100:.0f}% of assets — unusually broad")
                key = reg.proposal_key(device, pid)
                cand = {"key": key, "plugin_id": str(pid),
                        "plugin_name": c.get("plugin_name", ""), "term": term,
                        "iot_name": device, "vendor": v.get("vendor", ""), "kind": kind,
                        "source": v["source"], "asset_count": cnt, "prevalence": prev,
                        "already_registered": bool(already),
                        "asset_uuids": res["asset_uuids"][:200], "warnings": warns}
                cur = proposals.get(key)
                if not cur or cnt > cur["asset_count"]:
                    proposals[key] = cand

        plist = sorted(proposals.values(), key=lambda x: (-x["asset_count"], x["iot_name"]))
        return {"proposals": plist, "ledger": ledger, "floor": floor, "total": total,
                "vocab_size": len(vocab), "pack_terms": pack_terms,
                "pack_deduped": pack_deduped, "tested": tested,
                "floor_note": ic.floor_explainer(total)}


# ---------------------------------------------------------------- A4
class IoTSquadOrchestrator(Agent):
    id = "iot_squad"
    name = "IoT Discovery Squad"
    icon = "🤖"
    description = ("Runs Discovery → Carrier harvest → Cross-term as one pipeline, "
                   "builds the QA coverage ledger, and surfaces the HITL gates.")

    def __init__(self):
        super().__init__()
        self.a1 = IoTDiscoveryAgent()
        self.a2 = CarrierHarvestAgent()
        self.a3 = CrossTermAgent()

    def summary(self):
        if not self.result:
            return {}
        return {"devices": len(self.result["discovery"]["detected"]),
                "carriers": len(self.result["carriers"]["carriers"]),
                "proposals": len(self.result["xterm"]["proposals"]),
                "qa_flags": len(self.result["qa"]["flags"])}

    def _empty(self, missing):
        """Every result key, empty — for a navi.db without the vulns table (fresh install,
        WAS-only db). The contract + page read these keys; nothing crashes."""
        cov = {"carriers": 0, "supplied_carriers": 0, "vocab_terms": 0, "pack_terms": 0,
               "pack_deduped": 0, "combinations_tested": 0, "proposals": 0,
               "warned_proposals": 0, "dropped_below_floor": 0, "skipped_rejected": 0,
               "floor": ic.CLUSTER_MIN, "assets": 0, "floor_note": ""}
        regd = reg.load()
        return {"registry": {"detections": len(regd["detections"]), "rejected": len(regd["rejected"])},
                "discovery": {"detected": [], "handoff": {}, "tag_actions": []},
                "carriers": {"carriers": {}, "supplied": []},
                "xterm": {"proposals": [], "ledger": [], "floor": ic.CLUSTER_MIN, "total": 0,
                          "vocab_size": 0, "pack_terms": 0, "pack_deduped": 0, "tested": 0,
                          "floor_note": ""},
                "qa": {"flags": [], "checks": [], "coverage": cov, "ledger": [], "agents": {}},
                "tag_actions": [], "proposals": [],
                "available": False, "missing": missing,
                "signal_coverage": [], "exposure": {"assets": [], "summary": {}}}

    def _run(self, db_path=None, use_pack=False):
        missing = [t for t in ("vulns", "assets") if not ic.table_cols(t, db_path)]
        if missing:                          # both are needed (devices join vulns → assets)
            return self._empty(missing)
        d = self.a1.run(db_path)

        # signal-fusion discovery (device-type / OUI / mDNS / cert) — Gate-1 tags.
        # Only devices the registry did NOT already confirm: a registry-confirmed asset
        # must not get a second Device Type tag under the fusion label (it used to be
        # tagged both "Chromecast" and "Chromecast / Nest"). Virtual NICs / hypervisors
        # (VMware OUI, Device Type "hypervisor") are infrastructure, not IoT.
        try:
            from core import signals
            devs = (signals._iot(db_path) or {}).get("devices", [])
            seen = {a["asset_uuid"] for a in d["detected"] if a.get("asset_uuid")}
            for dev in devs:
                u = dev.get("asset_uuid")
                if not u or u in seen:
                    continue
                klass, vendor, typ = dev.get("klass"), dev.get("vendor"), dev.get("type")
                if typ == "hypervisor" or signals._vendor_class(vendor or "") == "virtual":
                    continue
                name = (klass if klass and klass != "Embedded / candidate"
                        else (vendor.split(",")[0] if vendor and vendor != "—"
                              else (typ if typ and typ not in ("unknown", "general-purpose") else "Embedded device")))
                h = d["handoff"].setdefault(name, {"iot_name": name, "vendor": vendor or "",
                                                   "terms": [], "trigger_plugins": ["signal-fusion"],
                                                   "asset_uuids": [], "fused": True})
                h["fused"] = True
                if u not in h["asset_uuids"]:
                    h["asset_uuids"].append(u)
                seen.add(u)
                d["detected"].append({"iot_name": name, "vendor": vendor or "", "asset_uuid": u,
                                      "hostname": dev.get("host", ""), "ip": dev.get("ip", ""), "fused": True,
                                      "signals": dev.get("signals") or []})
            d["tag_actions"] = [_iot_tag_action(nm, h) for nm, h in d["handoff"].items()]
        except Exception:
            pass

        c = self.a2.run(db_path=db_path, handoff=d["handoff"])
        x = self.a3.run(db_path=db_path, carriers=c["carriers"], use_pack=use_pack)

        # ---- A4 quality assurance: coverage ledger (nothing silently skipped) ----
        flags = []
        # same plugin proposed for >1 device via cross-term = ambiguous carrier
        by_plugin = {}
        for p in x["proposals"]:
            by_plugin.setdefault(p["plugin_id"], set()).add(p["iot_name"])
        for pid, names in by_plugin.items():
            if len(names) > 1:
                flags.append({"type": "multi_device_carrier", "plugin_id": pid,
                              "iot_names": sorted(names),
                              "detail": "one carrier plugin proposed for multiple devices "
                                        "— expected for banner plugins, but review"})
        warnings = [p for p in x["proposals"] if p["warnings"]]
        dropped_below = [l for l in x["ledger"] if l["reason"] == "below_floor"]
        rejected_skips = [l for l in x["ledger"] if l["reason"] == "previously_rejected"]
        qa = {
            "flags": flags,
            "checks": ["multi_device_carrier", "generic_carrier", "broad_prevalence",
                       "below_floor_ledger", "rejected_ledger"],
            "coverage": {
                "carriers": len(c["carriers"]),
                "supplied_carriers": len(c["supplied"]),
                "vocab_terms": x["vocab_size"], "pack_terms": x["pack_terms"],
                "pack_deduped": x.get("pack_deduped", 0),
                "combinations_tested": x["tested"],
                "proposals": len(x["proposals"]),
                "warned_proposals": len(warnings),
                "dropped_below_floor": len(dropped_below),
                "skipped_rejected": len(rejected_skips),
                "floor": x["floor"], "assets": x["total"],
                "floor_note": x.get("floor_note", ""),
            },
            "ledger": (dropped_below + rejected_skips)[:500],
            "agents": {"discovery": self.a1.status, "carrier": self.a2.status,
                       "xterm": self.a3.status},
        }

        regd = reg.load()
        return {
            "registry": {"detections": len(regd["detections"]),
                         "rejected": len(regd["rejected"])},
            "discovery": d, "carriers": c, "xterm": x, "qa": qa,
            "tag_actions": d["tag_actions"],   # gate 1
            "proposals": x["proposals"],       # gate 2
            # page metrics (read-only; additive — every key above is unchanged)
            "available": True, "missing": missing,
            "signal_coverage": ic.identity_signal_coverage(db_path),
            "exposure": ic.device_exposure([a.get("asset_uuid") for a in d["detected"]], db_path),
        }
