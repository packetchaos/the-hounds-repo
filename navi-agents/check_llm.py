#!/usr/bin/env python3
"""Diagnose the pack's reasoning layer — whichever model you brought.

Run:  python3 check_llm.py

Prints the resolved provider / model / endpoint, then makes ONE tiny real call and
reports the EXACT failure reason, so a vague "HTTP 400 Bad Request" becomes
something actionable (no credit, model not enabled, wrong endpoint, Ollama not
running, missing boto3, …).

Providers: anthropic | openai (any /chat/completions endpoint) | ollama | bedrock
Config:    NAVI_LLM_PROVIDER, NAVI_LLM_MODEL, NAVI_LLM_BASE_URL, NAVI_LLM_API_KEY
See BYO_MODEL.md for per-provider setup.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import llm  # noqa: E402


def mask(v):
    if not v:
        return "(none)"
    return (v[:6] + "…" + v[-4:]) if len(v) > 12 else "set"


cfg = llm.config()
print("provider : %s%s" % (cfg["provider"],
                           "" if os.environ.get("NAVI_LLM_PROVIDER") else "   (auto-detected)"))
print("model    : %s" % cfg["model"])
print("endpoint : %s" % (cfg["base_url"] or ("bedrock-runtime." + (cfg["region"] or "?")
                                             + ".amazonaws.com")))
if cfg["provider"] == "bedrock":
    print("region   : %s" % (cfg["region"] or "(unset — set AWS_REGION)"))
    if os.environ.get("AWS_ACCESS_KEY_ID"):
        print("aws creds: %s" % mask(os.environ.get("AWS_ACCESS_KEY_ID")))
    elif os.environ.get("AWS_PROFILE"):
        print("aws creds: profile %s" % os.environ["AWS_PROFILE"])
    else:
        print("aws creds: (from the standard AWS chain)")
    try:
        import boto3  # noqa: F401
        print("boto3    : installed")
    except ImportError:
        print("boto3    : NOT installed  →  pip install boto3")
else:
    print("key      : %s" % mask(llm.api_key()))
print("max out  : %s tokens" % cfg["max_tokens"])
print()

if cfg["provider"] not in llm.PROVIDERS:
    print("✗ %s" % llm.why_unavailable())
    sys.exit(1)
if not cfg["available"]:
    print("✗ not configured — %s" % llm.why_unavailable())
    sys.exit(1)
if cfg["provider"] == "anthropic":
    k = llm.api_key()
    if k and not k.startswith("sk-ant-"):
        print("⚠ That doesn't look like an Anthropic API key. Real keys start with "
              "'sk-ant-'. A Claude.ai login / OAuth token will NOT work here.\n")

print("→ one test call…")
try:
    out = llm._messages("Reply with exactly: pong", "ping", max_tokens=16, timeout=60)
except Exception as e:                                    # noqa: BLE001 — printing it IS the job
    print("\n✗ %s: %s" % (type(e).__name__, e))
    print("\nStill stuck? Switch providers to isolate it — a local model needs no "
          "account at all:\n"
          "    NAVI_LLM_PROVIDER=ollama NAVI_LLM_MODEL=llama3.1 python3 check_llm.py")
    sys.exit(1)

u = llm.usage()
print("✓ reply   : %r" % (out or "")[:120])
print("✓ tokens  : %s in / %s out  (provider %s)" % (u["input_tokens"], u["output_tokens"],
                                                     u["provider"]))
print("\nThe reasoning layer is live — every agent's ▶ Reason / NL query will use it.")
