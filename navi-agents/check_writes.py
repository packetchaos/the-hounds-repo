#!/usr/bin/env python3
"""Diagnose why the repo can (or can't) write tags via the navi CLI.

Run this from the repo root, in the SAME shell / environment you start the server
with:

    python3 check_writes.py

It prints exactly what the server sees — the write flag, the navi binary it
resolved, and (optionally) does a real dry probe of `navi enrich tag`.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import navi_cli  # noqa: E402


def main():
    s = navi_cli.write_status()
    print("=" * 68)
    print(" The Hounds — write-gate diagnostic")
    print("=" * 68)
    print(f"  repo root ................ {s['repo_root']}")
    print(f"  NAVI_ALLOW_WRITES ........ {s['NAVI_ALLOW_WRITES']!r}")
    print(f"  NAVI_MCP_ALLOW_WRITES .... {s['NAVI_MCP_ALLOW_WRITES']!r}")
    print(f"  ALLOW_WRITES file ........ {s['enable_file'] or '(none)'}")
    print(f"  -> allow_writes() ........ {s['allow_writes']}")
    print()
    print(f"  NAVI_BIN ................. {s['NAVI_BIN']!r}")
    print(f"  navi resolved to ......... {s['navi_resolved'] or '(NOT FOUND)'}")
    print()
    print("  --- read/write database alignment (the tags-not-applying trap) ---")
    print(f"  repo READS navi.db at .... {s.get('read_navi_db')}")
    print(f"  navi CLI RUNS in cwd ..... {s.get('navi_cli_cwd')}  (it uses THIS folder's navi.db)")
    rd, cw = s.get('read_navi_db'), s.get('navi_cli_cwd')
    if rd and cw and os.path.dirname(rd) == cw:
        print("  -> aligned ✓  (reads and tag-writes hit the same navi.db)")
    else:
        print("  -> ⚠ reads and writes may target DIFFERENT navi.db files — set")
        print("       NAVI_DB_PATH to navi's real db (or NAVI_CWD to its folder) so they match.")
    print(f"  PATH ..................... {os.environ.get('PATH','')}")
    print()
    print(f"  writes_enabled() ......... {s['writes_enabled']}")
    print(f"  reason ................... {s['reason'] or '(writes OK)'}")
    print("=" * 68)

    if not s["allow_writes"]:
        print("\n✗ Writes are DISABLED. Fix it one of these ways, then restart the server:")
        print("    export NAVI_ALLOW_WRITES=1        # in the SAME shell you launch the server")
        print(f"    touch {os.path.join(s['repo_root'], 'ALLOW_WRITES')}   # env-independent toggle")
        return

    navi = s["navi_resolved"]
    if not navi:
        print("\n✗ Writes are enabled but the navi CLI was not found.")
        print("    Find it:  which navi")
        print("    Then:     export NAVI_BIN=/full/path/to/navi   (or add it to PATH), and restart")
        return

    print(f"\n● Probing the navi CLI at {navi} …")
    try:
        p = subprocess.run([navi, "--version"], capture_output=True, text=True, timeout=30)
        out = (p.stdout or p.stderr or "").strip().splitlines()
        print(f"    navi --version -> exit {p.returncode}: {out[0] if out else '(no output)'}")
    except Exception as e:
        print(f"    ✗ could not run navi: {e}")
        print("      The path exists but isn't executable in this environment.")
        return

    print("\n✓ Writes are enabled and navi is runnable. Tagging should work.")
    print("  If tags still fail, the navi CLI itself is erroring (API keys / workspace).")
    print("  Test directly:")
    print(f"    {navi} enrich tag --c 'Test' --v 'Hound' --query \"SELECT asset_uuid FROM assets LIMIT 1\"")


if __name__ == "__main__":
    main()
