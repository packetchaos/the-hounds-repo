"""Shared health probe — navi.db status, write-gate state, and DATA SOURCE.

Pure infra (db + navi_cli only), so any agent repo can include it without
pulling in other agents. `data_source` tells the UI whether it's reading a
crafted sample fixture or a real navi.db, so demo data is never mistaken for
live Tenable data.
"""
import os
import threading
import time

from . import db, navi_cli

# health runs on EVERY page load (the header awaits it). Cache it so we don't
# re-touch navi.db on every navigation; on a huge db even a cheap probe adds up.
_H_CACHE = {"t": 0.0, "v": None}
_H_TTL = float(os.environ.get("NAVI_HEALTH_TTL_S", "30"))


def invalidate():
    """Drop the cached health snapshot. Call this after anything that changes what
    health() reports mid-process — e.g. the Settings page switching model provider,
    write gates or the db path — so the header chips don't lag by up to _H_TTL."""
    _H_CACHE["t"], _H_CACHE["v"] = 0.0, None

# The asset count on a 200 GB db can take a while (count(*) scans the assets
# table). We NEVER block the header on it: compute it in the BACKGROUND and let
# the header show "—" until the first result lands, then the real number.
_ASSETS = {"t": 0.0, "n": None, "busy": False}
_ASSETS_TTL = float(os.environ.get("NAVI_ASSET_COUNT_TTL_S", "300"))


def _asset_count_bg():
    try:
        _ASSETS["n"] = db.scalar("SELECT count(*) FROM assets;", budget=0)  # run to completion
        _ASSETS["t"] = time.time()
    except Exception:
        pass
    finally:
        _ASSETS["busy"] = False


def _asset_total():
    """Non-blocking: returns the cached count (or None), kicking off a background
    recompute when stale. The header fills in the number on a later poll."""
    now = time.time()
    fresh = _ASSETS["n"] is not None and (now - _ASSETS["t"]) < _ASSETS_TTL
    if not fresh and not _ASSETS["busy"]:
        _ASSETS["busy"] = True
        threading.Thread(target=_asset_count_bg, daemon=True).start()
    return _ASSETS["n"]


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
    now = time.time()
    if _H_CACHE["v"] is not None and (now - _H_CACHE["t"]) < _H_TTL:
        v = _H_CACHE["v"]
        if v.get("db_ok"):
            v["asset_total"] = _asset_total()   # keep the count live even from cache
        return v
    path = db.db_path()
    # soft LLM probe — true when ANY configured provider is reachable (Claude API, an
    # OpenAI-compatible endpoint, local Ollama, or Bedrock). The UI hides the
    # natural-language features when this is false instead of failing.
    llm_ok, llm_provider, llm_model, llm_why = False, "", "", ""
    try:
        from . import llm as _llm
        llm_ok = _llm.available()
        llm_provider, llm_model = _llm.PROVIDER, _llm.DEFAULT_MODEL
        llm_why = "" if llm_ok else _llm.why_unavailable()
    except Exception:
        llm_ok = False
    info = {"db_path": path, "writes_enabled": navi_cli.writes_enabled(),
            "navi_available": navi_cli.navi_available(),
            "allow_writes_flag": navi_cli.allow_writes(),
            "write_gate_reason": navi_cli.write_gate_reason(),
            "navi_resolved": navi_cli._resolve_navi(),
            "navi_cli_cwd": navi_cli._navi_cwd(),
            "enable_file": navi_cli._enable_file() or None, "llm": llm_ok,
            "llm_provider": llm_provider, "llm_model": llm_model, "llm_why": llm_why}
    try:
        from . import tagname as _tagname
        info["tag_prefix"] = _tagname.status()     # Settings → Test run (header chip)
    except Exception:
        info["tag_prefix"] = None
    try:
        from . import version as _version
        info["version"] = _version.version_string()
    except Exception:
        info["version"] = None
    # Reachability + cheap fields ONLY. We do NOT scan vulns here: MAX(last_found)
    # is a full-table scan (minutes on a 200 GB db) and would hang every page. The
    # asset count is budgeted and may come back None on a very large table — that's
    # fine, the header just shows "—". Freshness is available on demand elsewhere.
    info["db_fresh"] = None
    try:
        db.query("SELECT 1 FROM assets LIMIT 1;", budget=3)   # cheap reachability (reads 1 row)
        info["db_ok"] = True
        info.update(data_source(path))
        info["asset_total"] = _asset_total()     # background-computed; None until ready
    except Exception as e:
        info["db_ok"] = False
        info["asset_total"] = None
        info["error"] = str(e)
        info["data_source"] = "unknown"
    _H_CACHE["t"], _H_CACHE["v"] = now, info
    return info
