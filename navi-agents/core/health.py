"""Shared health probe — navi.db status, write-gate state, and DATA SOURCE.

Pure infra (db + navi_cli only), so any agent repo can include it without
pulling in other agents. `data_source` tells the UI whether it's reading a
crafted sample fixture or a real navi.db, so demo data is never mistaken for
live Tenable data.
"""
import os

from . import db, navi_cli


def data_source(path: str) -> dict:
    """Classify the database: 'fixture' (crafted sample), 'live' (real navi.db),
    or 'unknown'. A fixture is marked by a _provenance table (preferred) or the
    bundled sample_navi.db filename."""
    note = None
    try:
        rows = db.query("SELECT source, note FROM _provenance LIMIT 1;", path=path)
        if rows:
            return {"data_source": rows[0].get("source", "fixture"),
                    "provenance_note": rows[0].get("note"), "is_fixture": True}
    except Exception:
        pass
    base = os.path.basename(path or "")
    if base in ("sample_navi.db", "fixture.db") or "sample" in base.lower():
        return {"data_source": "fixture", "is_fixture": True,
                "provenance_note": "Filename indicates a bundled sample dataset."}
    return {"data_source": "live", "is_fixture": False, "provenance_note": None}


def health() -> dict:
    path = db.db_path()
    # soft LLM probe — true only when an ANTHROPIC_API_KEY is configured; the UI
    # hides natural-language features when this is false instead of failing.
    try:
        from . import llm as _llm
        llm_ok = _llm.available()
    except Exception:
        llm_ok = False
    info = {"db_path": path, "writes_enabled": navi_cli.writes_enabled(),
            "navi_available": navi_cli.navi_available(),
            "allow_writes_flag": navi_cli.allow_writes(),
            "write_gate_reason": navi_cli.write_gate_reason(),
            "navi_resolved": navi_cli._resolve_navi(),
            "navi_cli_cwd": navi_cli._navi_cwd(),
            "enable_file": navi_cli._enable_file() or None, "llm": llm_ok}
    try:
        info["asset_total"] = db.scalar("SELECT count(uuid) FROM assets;")
        try:
            info["db_fresh"] = db.scalar("SELECT MAX(last_found) FROM vulns;")
        except Exception:
            info["db_fresh"] = None
        info["db_ok"] = True
        info.update(data_source(path))
    except Exception as e:
        info["db_ok"] = False
        info["error"] = str(e)
        info["data_source"] = "unknown"
    return info
