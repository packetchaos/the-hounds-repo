"""Sirius — Tenable Agent Group tagging agent.

Lists Tenable **agent groups** (live, via `navi explore info agent-groups`) and
tags every asset in a group with ``Agent Group:<name>`` using navi's ``--group``
selector — the same operation as the classic pyTenable agent-group-tags script,
exposed three ways (NL list, checkbox widget, tag-all).
"""
import re

from core import navi_cli
from core.agents.base import Agent

_SPLIT = re.compile(r"\s{2,}")
_DIV = re.compile(r"^-{5,}$")


def groups() -> list[dict]:
    """Parse `navi explore info agent-groups` → [{name, uuid, gid}]."""
    r = navi_cli.explore_info("agent_groups")
    out, started = [], False
    for ln in (r.get("stdout", "") or "").splitlines():
        s = ln.strip()
        if _DIV.match(s):
            started = True
            continue
        if not started or not s:
            continue
        if s.lower().startswith("group name"):     # header line (no divider variants)
            continue
        f = [c.strip() for c in _SPLIT.split(s)]
        if not f or not f[0]:
            continue
        out.append({"name": f[0],
                    "uuid": f[1] if len(f) > 1 else "",
                    "gid": f[2] if len(f) > 2 else ""})
    return out


def tag_group(name: str) -> dict:
    """Tag every asset in one agent group: navi enrich tag --c 'Agent Group' --v <name> --group <name>."""
    name = (name or "").strip()
    if not name:
        return {"ok": False, "message": "empty group name"}
    return navi_cli.tag("Agent Group", name, group=name, remove=False, agent="agentgroup")


class AgentGroupAgent(Agent):
    id = "agentgroup"
    name = "Agent Group Tagging"
    icon = "🛰️"
    description = ("Sirius — tags every asset in a Tenable agent group with "
                  "Agent Group:<name> via navi --group. NL list, checkbox widget, "
                  "or tag-all.")

    def summary(self):
        if not self.result:
            return {}
        return {"groups": len(self.result.get("groups", []))}

    def _run(self, db_path=None, **kwargs):
        g = groups()
        return {"ok": True, "groups": g, "count": len(g),
                "source": "navi explore info agent-groups"}
