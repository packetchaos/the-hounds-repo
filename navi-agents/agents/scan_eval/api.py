"""Scan Evaluations — self-contained HTTP actions.

`run` — compute scanner/policy/scan averages (plugin 19506) + credential coverage
        (plugin 104410). Read-only.
`tag` — gated. One of:
        {kind:'scanner', value, output}   -> navi enrich tag --plugin 19506 --output "<ip>"
        {kind:'policy',  value, output}   -> navi enrich tag --plugin 19506 --output "<policy>"
        {kind:'scan',    value, scanid}   -> navi enrich tag --scanid <id>
        {kind:'cred',    value}           -> navi enrich tag --plugin 104410
"""
from core import scan_eval, navi_cli

AGENT = None


def _agent():
    global AGENT
    if AGENT is None:
        from .agent import ScanEvalAgent
        AGENT = ScanEvalAgent()
    return AGENT


def run(p):
    try:
        res = scan_eval.evaluate()
    except Exception as e:
        return {"ok": False, "error": f"scan evaluation failed: {e}"}, 200
    return {"ok": True, "agent": _agent().meta(), "result": res}, 200


def tag(p):
    if not p.get("confirm"):
        return {"ok": False, "error": "confirm=true required to write tags"}, 400
    kind = p.get("kind")
    value = (p.get("value") or "").strip()
    if not value:
        return {"ok": False, "error": "value required"}, 400
    if kind == "scanner":
        r = navi_cli.tag(p.get("category", "Scan Health"), value, plugin="19506",
                         output=p.get("output", ""), remove=False)
    elif kind == "policy":
        r = navi_cli.tag(p.get("category", "Scan Health"), value, plugin="19506",
                         output=p.get("output", ""), remove=False)
    elif kind == "scan":
        sid = str(p.get("scanid") or "").strip()
        if sid:                                   # tag every asset in the scan (by id)
            r = navi_cli.tag(p.get("category", "Scan Health"), value, scanid=sid, remove=False)
        else:                                     # no id available -> match the scan name in 19506 output
            r = navi_cli.tag(p.get("category", "Scan Health"), value, plugin="19506",
                             output=p.get("output", "") or value, remove=False)
    elif kind == "cred":
        r = navi_cli.tag(p.get("category", "Scan Health"), value or "Cred Failure",
                         plugin="104410", remove=False)
    else:
        return {"ok": False, "error": "unknown kind"}, 400
    return {"ok": True, "result": r, "writes_enabled": navi_cli.writes_enabled()}, 200


ACTIONS = {"run": run, "tag": tag}
