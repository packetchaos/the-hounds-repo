#!/usr/bin/env python3
"""Diagnose ANTHROPIC_API_KEY / LLM failures.

Run:  python3 check_llm.py
It makes one tiny real call and prints the EXACT status + reason from Anthropic,
so a vague "HTTP 400 Bad Request" becomes something actionable (credit balance,
model access, bad key, SSL, …).
"""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

KEY = os.environ.get("ANTHROPIC_API_KEY", "")
MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

if not KEY:
    print("✗ ANTHROPIC_API_KEY is not set in this shell.\n"
          "  export ANTHROPIC_API_KEY=sk-ant-...   then re-run.")
    sys.exit(1)

print(f"key: {KEY[:10]}…{KEY[-4:]}  (len {len(KEY)})")
if not KEY.startswith("sk-ant-"):
    print("⚠ This doesn't look like an API key. Real keys start with 'sk-ant-'. "
          "A Claude.ai login / OAuth token will NOT work here.")
print(f"model: {MODEL}\n")

try:
    import certifi
    ctx = ssl.create_default_context(cafile=certifi.where())
    print(f"SSL: using certifi bundle ({certifi.where()})")
except Exception:
    ctx = ssl.create_default_context()
    print("SSL: certifi not installed — using system CA bundle "
          "(if you see CERTIFICATE_VERIFY_FAILED: pip install --upgrade certifi)")

body = {"model": MODEL, "max_tokens": 16,
        "messages": [{"role": "user", "content": "ping"}]}
req = urllib.request.Request(
    "https://api.anthropic.com/v1/messages", data=json.dumps(body).encode(),
    headers={"x-api-key": KEY, "anthropic-version": "2023-06-01",
             "content-type": "application/json"})
try:
    with urllib.request.urlopen(req, timeout=40, context=ctx) as r:
        resp = json.loads(r.read().decode())
    txt = "".join(b.get("text", "") for b in resp.get("content", []))
    print(f"\n✓ SUCCESS — the key + model work. Model replied: {txt!r}")
    print("  If the app still fails, restart it in THIS shell so it inherits "
          "the same ANTHROPIC_API_KEY.")
except urllib.error.HTTPError as e:
    detail = ""
    try:
        detail = e.read().decode("utf-8", "replace")
    except Exception:
        pass
    msg = detail
    try:
        msg = (json.loads(detail).get("error") or {}).get("message") or detail
    except Exception:
        pass
    print(f"\n✗ HTTP {e.code}: {msg}")
    low = (msg or "").lower()
    if "credit balance" in low:
        print("  → FIX: add a payment method / buy credits at "
              "console.anthropic.com → Plans & Billing. A valid key with $0 "
              "credit returns exactly this 400.")
    elif "model" in low and ("not found" in low or "invalid" in low or "access" in low):
        print(f"  → FIX: '{MODEL}' isn't available to this key. Try "
              "  export ANTHROPIC_MODEL=claude-3-5-haiku-latest   and re-run.")
    elif e.code in (401, 403):
        print("  → FIX: key rejected. Generate a fresh key at "
              "console.anthropic.com → API Keys (must start with sk-ant-).")
except urllib.error.URLError as e:
    print(f"\n✗ Network/SSL error: {e}")
    if "CERTIFICATE_VERIFY_FAILED" in str(e):
        print("  → FIX: pip install --upgrade certifi   (or run macOS "
              "'Install Certificates.command').")
