"""AI Inventory (Pythia) — MITRE ATLAS drill-down + server-side tag_atlas.

Builds a tiny navi.db, checks the per-technique / per-tactic asset sets, and checks that
`tag_atlas` rebuilds the set on the server (ignoring any client uuids), refuses unknown
techniques / tactics and foreign categories, and always tags with remove=False.
navi_cli.tag_capped is monkeypatched, so nothing is queued or written.
Run: python3 tests/test_ai_atlas.py  (or pytest)."""
import atexit
import os
import shutil
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix="hounds-ai-atlas-")
atexit.register(shutil.rmtree, TMP, ignore_errors=True)

fails = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        fails.append(msg)


# ---------------------------------------------------------------- fixture
U_OLLAMA = "11111111-1111-1111-1111-111111111111"   # Model Serving, exposed + unauth endpoint
U_CHROMA = "22222222-2222-2222-2222-222222222222"   # Vector DB / RAG (software inventory)
U_OPENAI = "33333333-3333-3333-3333-333333333333"   # LLM API Client → egress to api.openai.com (shadow)
U_TORCH = "44444444-4444-4444-4444-444444444444"    # GPU / Training (PyTorch + HF Transformers)
U_PLAIN = "55555555-5555-5555-5555-555555555555"    # not AI at all

DB = os.path.join(TMP, "navi.db")
c = sqlite3.connect(DB)
c.executescript("""
CREATE TABLE assets(uuid TEXT, hostname TEXT, ip_address TEXT, acr REAL, url TEXT);
CREATE TABLE vulns(asset_uuid TEXT, plugin_id TEXT, plugin_name TEXT, plugin_family TEXT, output TEXT,
                   port TEXT, severity TEXT, xrefs TEXT, score TEXT, url TEXT, state TEXT);
CREATE TABLE software(asset_uuid TEXT, software_string TEXT);
CREATE TABLE cpes(asset_uuid TEXT, cpe_string TEXT);
CREATE TABLE tags(asset_uuid TEXT, tag_key TEXT, tag_value TEXT);
""")
for u, h, ip, acr in [(U_OLLAMA, "llm-gw", "10.0.0.1", 5), (U_CHROMA, "rag-db", "10.0.0.2", 9),
                      (U_OPENAI, "app-1", "10.0.0.3", 4), (U_TORCH, "gpu-1", "10.0.0.4", 8),
                      (U_PLAIN, "file-1", "10.0.0.5", 3)]:
    c.execute("INSERT INTO assets VALUES (?,?,?,?,?)", (u, h, ip, acr, ""))
c.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?)",
          (U_OLLAMA, "999001", "Ollama API Detection", "Service detection",
           "The Ollama API is listening on port 11434 and requires no authentication.", "11434",
           "medium", "", "0", "", "open"))
c.execute("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?)",
          (U_PLAIN, "10287", "Traceroute Information", "General", "hop 1 10.0.0.254", "0",
           "info", "", "0", "", "open"))
c.execute("INSERT INTO software VALUES (?,?)", (U_CHROMA, "chromadb 0.4.22"))
c.execute("INSERT INTO software VALUES (?,?)", (U_OPENAI, "openai 1.12.0 (python package)"))
c.execute("INSERT INTO software VALUES (?,?)", (U_TORCH, "pytorch 2.2.0"))
c.execute("INSERT INTO software VALUES (?,?)", (U_TORCH, "transformers 4.38"))
c.commit()
c.close()
os.environ["NAVI_DB_PATH"] = DB   # tag_atlas re-runs the scan against navi.db

from core import activity, ai_assets, navi_cli  # noqa: E402
from agents.ai import api  # noqa: E402

res = ai_assets.scan()
by = {x["asset_uuid"]: x for x in res["assets"]}
check(set(by) == {U_OLLAMA, U_CHROMA, U_OPENAI, U_TORCH}, "scan finds the four AI assets, not the plain host")
check(by[U_OLLAMA]["role"] == "Model Serving" and by[U_OLLAMA]["exposed"]
      and by[U_OLLAMA]["exposed"][0]["auth"] == "unauth", "Ollama: Model Serving, exposed, unauthenticated")

sets = ai_assets.atlas_sets(res["assets"])
T = sets["tech"]
check(T.get("AML.T0047") == set(by), "AML.T0047 (ML-enabled service) holds every AI asset")
check(T.get("AML.T0040") == {U_OLLAMA}, "AML.T0040 (inference API) = the serving / exposed asset only")
check(T.get("AML.T0012") == {U_OLLAMA} and T.get("AML.T0034") == {U_OLLAMA},
      "AML.T0012 / T0034 = the unauthenticated endpoint only")
check(T.get("AML.T0057") == {U_CHROMA}, "AML.T0057 (RAG leakage) = the vector DB only")
check(T.get("AML.T0025") == {U_OPENAI, U_TORCH},
      "AML.T0025 (shadow egress) = the assets calling api.openai.com / huggingface.co")
check(T.get("AML.T0010") == {U_TORCH}, "AML.T0010 (supply chain) = the HF Transformers asset")
check(T.get("AML.T0002") == {U_TORCH}, "AML.T0002 (public artifacts) = the training asset")
check(T.get("AML.T0049") == {U_OLLAMA}, "AML.T0049 (public-facing) = the exposed asset only")
exfil = {i for i, (_n, tac) in ai_assets.ATLAS_TECH.items() if tac == "Exfiltration"}
check(sets["tactic"].get("Exfiltration") == set().union(*(T.get(i, set()) for i in exfil))
      and sets["tactic"]["Exfiltration"] == {U_CHROMA, U_OPENAI, U_TORCH},
      "tactic set = union of its techniques' assets (Exfiltration)")
check(all(t.get("tactic") in ai_assets.ATLAS_TACTIC_ORDER for x in res["assets"] for t in x["atlas"]),
      "every mapped technique sits under a known ATLAS tactic")

# per-asset evidence for the drill-down
t40 = next(t for t in by[U_OLLAMA]["atlas"] if t["id"] == "AML.T0040")
check(any("11434" in e for e in t40["ev"]), "drill-down evidence: AML.T0040 names the endpoint:port")
t25 = next(t for t in by[U_OPENAI]["atlas"] if t["id"] == "AML.T0025")
check(any("api.openai.com" in e for e in t25["ev"]), "drill-down evidence: AML.T0025 names the shadow destination")
t18 = next(t for t in by[U_TORCH]["atlas"] if t["id"] == "AML.T0018")
check(len(t18["whys"]) == 2 and t18["why"] == t18["whys"][0],
      "a technique implied twice keeps both reasons (whys) and the first as why")

# a sanctioned destination drops the asset out of the shadow technique
res2 = ai_assets.scan(allow=["api.openai.com"])
check(ai_assets.atlas_sets(res2["assets"])["tech"].get("AML.T0025") == {U_TORCH},
      "allowlisting a destination removes AML.T0025 from the asset calling it")

# ---------------------------------------------------------------- tag_atlas (server-side)
calls = []


def fake_tag_capped(category, value, uuids=None, query="", remove=False, agent="", **kw):
    calls.append({"category": category, "value": value, "uuids": list(uuids or []),
                  "query": query, "remove": remove, "agent": agent, **kw})
    return [{"job_id": len(calls), "ok": True}]


_real = navi_cli.tag_capped
navi_cli.tag_capped = fake_tag_capped
try:
    out, code = api.tag_atlas({"key": "tech:AML.T0040"})
    check(code == 400 and not calls, "tag_atlas: confirm=true required")

    out, code = api.tag_atlas({"confirm": True, "key": "tech:AML.T0040",
                               "uuids": [U_PLAIN, U_CHROMA], "category": "Owner", "value": "x"})
    c0 = calls[-1] if calls else {}
    check(code == 200 and out.get("ok") and out["count"] == 1, "tag_atlas: technique tags its server-built set")
    check(c0.get("uuids") == [U_OLLAMA] and U_PLAIN not in c0.get("query", ""),
          "tag_atlas: client-supplied uuids are ignored — the set is rebuilt server-side")
    check(c0.get("category") == "AI ATLAS" and c0.get("value") == "AML.T0040",
          "tag_atlas: category is always AI ATLAS, value is the technique id")
    check(c0.get("remove") is False and c0.get("agent") == "ai", "tag_atlas: remove=False, agent=ai")

    out, code = api.tag_atlas({"confirm": True, "key": "tactic:Exfiltration"})
    c1 = calls[-1]
    check(code == 200 and set(c1["uuids"]) == sets["tactic"]["Exfiltration"]
          and c1["value"] == "Tactic : Exfiltration" and c1["remove"] is False,
          "tag_atlas: tactic key tags the tactic's union → AI ATLAS : Tactic : <tactic>")

    out, code = api.tag_atlas({"confirm": True, "key": "tech:AML.T0025", "allow": ["api.openai.com", "huggingface.co"]})
    check(code == 200 and not out.get("ok"), "tag_atlas: the page's allowlist is honoured (no shadow assets → nothing queued)")

    out, code = api.tag_atlas({"confirm": True, "key": "tech:AML.T0040",
                               "fp": {"assets": {U_OLLAMA: 1}}})
    check(not out.get("ok"), "tag_atlas: an asset dismissed as a false positive is not tagged")

    n = len(calls)
    for bad in ["tech:AML.T9999", "tech:T1059", "tactic:Lateral Movement", "tactic:Other",
                "AML.T0040", "", "tech:", "cve:CVE-2024-0001"]:
        out, code = api.tag_atlas({"confirm": True, "key": bad})
        check(code == 400 and not out.get("ok"), f"tag_atlas: unknown key {bad!r} refused")
    check(len(calls) == n, "tag_atlas: refused keys queue nothing")
    check(all(c["remove"] is False for c in calls), "tag_atlas: every call passed remove=False")

    # the generic tag action no longer writes ATLAS from a client uuid list
    out, code = api.tag({"confirm": True, "category": "AI ATLAS", "value": "AML.T0040", "uuids": [U_PLAIN]})
    check(code == 400, "generic tag refuses AI ATLAS (only tag_atlas writes it)")
    out, code = api.tag({"confirm": True, "category": "Owner", "value": "x", "uuids": [U_PLAIN]})
    check(code == 400, "generic tag still refuses a foreign category")
    check(activity.allowed_category("ai", "AI ATLAS"), "AI ATLAS is one of the AI agent's categories")
    check("tag_atlas" in api.ACTIONS and "tag" in api.ACTIONS, "tag_atlas exposed; generic tag kept")
finally:
    navi_cli.tag_capped = _real


def test_ai_atlas():
    """pytest entry point — every check above ran at import; fail with the list."""
    assert not fails, "\n".join(fails)


if __name__ == "__main__":
    print(f"\n{len(fails)} failure(s)")
    sys.exit(1 if fails else 0)
