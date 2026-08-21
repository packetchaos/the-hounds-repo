"""The pack's reasoning layer — BRING YOUR OWN MODEL.

Every agent's "propose" step (cert triage, ACR planning, ownership mapping,
NL→SQL, contract policy…) funnels through ONE function here: `_messages()`.
The model only *proposes*; the UI previews and the human approves before any
gated write — so a smaller / local model is noisier, never more dangerous.

Four providers, selected with NAVI_LLM_PROVIDER:
  anthropic  (default)  ANTHROPIC_API_KEY               api.anthropic.com
  openai                OPENAI_API_KEY / NAVI_LLM_API_KEY + NAVI_LLM_BASE_URL
                        → OpenAI, OpenRouter, vLLM, Together, Groq, LM Studio,
                          Azure-style deployments — anything /chat/completions
  ollama                NAVI_LLM_BASE_URL (default http://127.0.0.1:11434)
                        → fully local, no key, no data leaves the machine
  bedrock               AWS creds + AWS_REGION, via the model-agnostic Converse
                        API (needs boto3 — the only optional dependency)

Common env:
  NAVI_LLM_PROVIDER   anthropic | openai | ollama | bedrock  (blank = auto-detect)
  NAVI_LLM_MODEL      model id for the chosen provider
  NAVI_LLM_BASE_URL   endpoint override (OpenAI-compatible / Ollama / self-hosted)
  NAVI_LLM_API_KEY    generic key (per-provider keys still work)
  NAVI_LLM_MAX_TOKENS output ceiling (ANTHROPIC_MAX_TOKENS still honoured)

With nothing configured, `available()` is False and every caller falls back to
its deterministic path, so the whole pack still runs — see BYO_MODEL.md.
"""
import json
import os
import re
import ssl
import urllib.error
import urllib.request

# --------------------------------------------------------------------------- #
#  Provider selection                                                          #
# --------------------------------------------------------------------------- #
PROVIDERS = ("anthropic", "openai", "ollama", "bedrock")

_MODEL_DEFAULTS = {
    "anthropic": "claude-haiku-4-5-20251001",
    "openai": "gpt-4o-mini",
    "ollama": "llama3.1",
    "bedrock": "anthropic.claude-3-5-haiku-20241022-v1:0",
}
_BASE_DEFAULTS = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com/v1",
    "ollama": "http://127.0.0.1:11434",
    "bedrock": "",                       # region-derived, see _bedrock_url()
}


def _detect_provider() -> str:
    """Explicit NAVI_LLM_PROVIDER wins; otherwise infer from whichever key/endpoint
    is present. Falls back to 'anthropic' so existing installs behave identically."""
    p = (os.environ.get("NAVI_LLM_PROVIDER") or "").strip().lower()
    if p:
        return p                          # validated at call time, with a clear error
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("OLLAMA_HOST"):
        return "ollama"
    if os.environ.get("NAVI_LLM_BASE_URL"):
        return "openai"                   # a bare endpoint = OpenAI-compatible
    return "anthropic"


PROVIDER = _detect_provider()


def _model_default(provider=None) -> str:
    return _MODEL_DEFAULTS.get(provider or PROVIDER, _MODEL_DEFAULTS["anthropic"])


# NAVI_LLM_MODEL wins everywhere; ANTHROPIC_MODEL still works (back-compat).
DEFAULT_MODEL = (os.environ.get("NAVI_LLM_MODEL") or os.environ.get("ANTHROPIC_MODEL")
                 or _model_default())


def base_url(provider=None) -> str:
    """Endpoint for the active provider, without a trailing slash."""
    p = provider or PROVIDER
    v = (os.environ.get("NAVI_LLM_BASE_URL") or "").strip()
    if not v and p == "openai":
        v = (os.environ.get("OPENAI_BASE_URL") or "").strip()
    if not v and p == "ollama":
        v = (os.environ.get("OLLAMA_HOST") or "").strip()
        if v and not v.startswith(("http://", "https://")):
            v = "http://" + v
    return (v or _BASE_DEFAULTS.get(p, "")).rstrip("/")


def api_key(provider=None) -> str:
    """The provider-specific key wins over the generic one, so a leftover
    NAVI_LLM_API_KEY from another provider can't shadow a real ANTHROPIC_API_KEY /
    OPENAI_API_KEY after you switch."""
    p = provider or PROVIDER
    generic = (os.environ.get("NAVI_LLM_API_KEY") or "").strip()
    if p == "anthropic":
        return (os.environ.get("ANTHROPIC_API_KEY") or "").strip() or generic
    if p == "openai":
        return (os.environ.get("OPENAI_API_KEY") or "").strip() or generic
    return generic                        # ollama needs none; bedrock uses AWS creds


def _aws_region() -> str:
    return (os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "").strip()


API_URL = base_url("anthropic") + "/v1/messages"      # kept for back-compat


def _int_env(name: str, default: int) -> int:
    """Read a positive int from the environment, falling back on empty/garbage."""
    try:
        v = int(os.environ.get(name, "").strip())
        return v if v > 0 else default
    except (ValueError, AttributeError):
        return default


# Ceiling on model output tokens for every reasoning call. Per-item agents (cert
# triage, ownership mapping, ACR/identity/contract planning) size their request to
# the input count but never exceed this; it is also enforced centrally in
# _messages(), so lowering it forces EVERY agent down. Configurable for older models
# with a smaller output cap, or to allow larger estates. Default 8000 suits haiku-4.5.
MAX_TOKENS_CAP = _int_env("NAVI_LLM_MAX_TOKENS", _int_env("ANTHROPIC_MAX_TOKENS", 8000))


def _scaled_budget(n_items: int, per_item: int = 90, base: int = 400) -> int:
    """Token budget for a response that carries ONE object per input item (the JSON
    grows with the item count). Scales with the count so large estates don't
    truncate, keeps a sane floor for tiny inputs, and is capped at MAX_TOKENS_CAP."""
    floor = min(1500, MAX_TOKENS_CAP)
    return max(floor, min(MAX_TOKENS_CAP, base + max(0, n_items) * per_item))


def _ssl_context():
    """Build an SSL context that can verify api.anthropic.com. Prefer certifi's CA
    bundle (fixes the common macOS 'CERTIFICATE_VERIFY_FAILED' with python.org
    Python); fall back to the system default."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


_SSL_CTX = _ssl_context()

SYSTEM = (
    "You convert an operator's plain-English instruction into Asset Criticality "
    "Rating (ACR) changes for Tenable tags. You are given the full list of tags "
    "(category + value). The instruction may contain SEVERAL distinct rules in one "
    "explanation (e.g. 'drop all IoT and lab gear by 5, set internet-facing to 9, "
    "bump production databases to 10, leave route tags alone'). Evaluate EVERY rule "
    "against EVERY tag and emit ONE change per tag that any rule matches — different "
    "tags get different mod/score depending on which rule applies. A tag matches a "
    "rule when the rule's subject keyword(s) appear in its category or value "
    "(case-insensitive / semantic). If several rules match one tag, use the most "
    "specific; skip tags no rule mentions. Return ONLY a JSON object, no prose:\n"
    '{"changes":[{"category":"<exact category>","value":"<exact value>",'
    '"mod":"set|inc|dec","score":<integer 1-10>,'
    '"reason":"business|compliance|mitigation|development","why":"<=8 words: which rule"}]}\n'
    "mod=set is an absolute ACR; mod=inc increases each asset's ACR by score; "
    "mod=dec decreases it by score. score is 1-10. NEVER invent a tag not in the "
    'provided list. If nothing should change, return {"changes":[]}.')


def available() -> bool:
    """Is a model reachable with the current configuration? Never raises — the whole
    pack treats False as 'use the deterministic path'."""
    if PROVIDER == "ollama":
        return bool(base_url())                       # local endpoint, no key
    if PROVIDER == "bedrock":
        return bool(_aws_region()) and bool(
            os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE")
            or os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
            or os.environ.get("AWS_ROLE_ARN"))
    if PROVIDER in ("anthropic", "openai"):
        return bool(api_key())
    return False                                      # unknown provider → disabled


def config() -> dict:
    """What the reasoning layer is pointed at — for the Settings page, /api/health
    and check_llm.py. Never includes the key itself."""
    return {"provider": PROVIDER, "model": DEFAULT_MODEL, "base_url": base_url(),
            "available": available(), "max_tokens": MAX_TOKENS_CAP,
            "region": (_aws_region() if PROVIDER == "bedrock" else ""),
            "key_set": bool(api_key()), "providers": list(PROVIDERS)}


def why_unavailable() -> str:
    """One actionable sentence for the operator when available() is False."""
    if PROVIDER not in PROVIDERS:
        return (f"NAVI_LLM_PROVIDER='{PROVIDER}' is not recognised — use one of: "
                + ", ".join(PROVIDERS) + ".")
    if PROVIDER == "anthropic":
        return ("No ANTHROPIC_API_KEY. Create one at platform.claude.com/settings/keys "
                "(starts sk-ant-), or switch NAVI_LLM_PROVIDER to ollama for a local model.")
    if PROVIDER == "openai":
        return ("No API key for the OpenAI-compatible endpoint. Set OPENAI_API_KEY or "
                "NAVI_LLM_API_KEY (and NAVI_LLM_BASE_URL if you're not using api.openai.com).")
    if PROVIDER == "ollama":
        return ("No endpoint for Ollama. Set NAVI_LLM_BASE_URL (default "
                "http://127.0.0.1:11434) and make sure `ollama serve` is running.")
    if PROVIDER == "bedrock":
        return ("Bedrock needs AWS_REGION plus credentials (AWS_ACCESS_KEY_ID/"
                "AWS_SECRET_ACCESS_KEY, AWS_PROFILE, or an instance/task role).")
    return "No model configured."


# ---- token usage (in-memory tally since server start; surfaced on the Settings page) ----
USAGE = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "last": None}


def usage() -> dict:
    u = dict(USAGE)
    u["total_tokens"] = u["input_tokens"] + u["output_tokens"]
    u["model"] = DEFAULT_MODEL
    u["provider"] = PROVIDER
    return u


def _tally(inp, out):
    """Normalise every provider's token accounting into one tally."""
    try:
        inp, out = int(inp or 0), int(out or 0)
        USAGE["calls"] += 1
        USAGE["input_tokens"] += inp
        USAGE["output_tokens"] += out
        USAGE["last"] = {"model": DEFAULT_MODEL, "provider": PROVIDER,
                         "input": inp, "output": out}
    except Exception:
        pass


def reset_usage():
    USAGE.update(calls=0, input_tokens=0, output_tokens=0, last=None)


def set_model(m):
    """Change the model live (NAVI_LLM_MODEL is otherwise bound at import)."""
    global DEFAULT_MODEL
    if m:
        DEFAULT_MODEL = str(m).strip()
    return DEFAULT_MODEL


def set_provider(p):
    """Switch provider live from the Settings page. When the model still looks like
    the previous provider's default, move it to the new provider's default too —
    otherwise 'ollama' would inherit a claude-* model id and fail confusingly."""
    global PROVIDER, DEFAULT_MODEL, API_URL
    p = (str(p or "").strip().lower() or _detect_provider())
    was_default = DEFAULT_MODEL in _MODEL_DEFAULTS.values()
    PROVIDER = p
    if was_default and not (os.environ.get("NAVI_LLM_MODEL") or "").strip():
        DEFAULT_MODEL = _model_default(p)
    API_URL = base_url("anthropic") + "/v1/messages"
    return PROVIDER


def set_max_tokens(n):
    """Change the output-token ceiling live (ANTHROPIC_MAX_TOKENS is otherwise import-bound)."""
    global MAX_TOKENS_CAP
    try:
        n = int(n)
        if n > 0:
            MAX_TOKENS_CAP = n
    except (TypeError, ValueError):
        pass
    return MAX_TOKENS_CAP


def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.lstrip().startswith("json"):
            text = text.lstrip()[4:]
    s, e = text.find("{"), text.rfind("}")
    if s >= 0 and e > s:
        text = text[s:e + 1]
    return json.loads(text)


def _post_json(url: str, body: dict, headers: dict, timeout: int, label: str) -> dict:
    """One HTTP POST + JSON parse, with the error mapping every provider shares.
    Keeps the actionable-message behaviour the pack has always had."""
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"content-type": "application/json", **headers})
    ctx = _SSL_CTX if url.lower().startswith("https") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        msg = raw
        try:                                   # {"error":{"message":…}} or {"error":"…"}
            j = json.loads(raw)
            err = j.get("error") if isinstance(j, dict) else None
            msg = (err.get("message") if isinstance(err, dict) else err) or j.get("message") or raw
        except Exception:
            pass
        raise RuntimeError(f"{label} HTTP {e.code}: {msg or e.reason}"
                           f"{_http_hint(e.code, msg)}") from e
    except urllib.error.URLError as e:
        s = str(e)
        if "CERTIFICATE_VERIFY_FAILED" in s:
            raise RuntimeError(
                f"SSL certificate verification failed reaching {url}. "
                "Fix: run  pip install --upgrade certifi  (the app picks it up "
                "automatically), or on macOS run the 'Install Certificates.command' "
                "that ships with your python.org Python.") from e
        if PROVIDER == "ollama" and ("refused" in s.lower() or "timed out" in s.lower()):
            raise RuntimeError(
                f"Can't reach Ollama at {base_url()} ({e.reason}). Start it with "
                "`ollama serve`, pull the model (`ollama pull " + DEFAULT_MODEL + "`), "
                "or point NAVI_LLM_BASE_URL somewhere else.") from e
        raise


def _http_hint(code: int, msg: str) -> str:
    """Provider-specific 'here's how to fix it' text appended to HTTP errors."""
    low = (msg or "").lower()
    if PROVIDER == "anthropic":
        if code == 400 and "credit balance" in low:
            return ("  → Your Anthropic account has no usable credit. Add a payment "
                    "method / buy credits at platform.claude.com → Billing.")
        if code == 400 and "model" in low and ("not found" in low or "invalid" in low):
            return (f"  → The model '{DEFAULT_MODEL}' isn't available to this key. Set "
                    "NAVI_LLM_MODEL to one you have access to (e.g. claude-3-5-haiku-latest).")
        if code in (401, 403):
            return ("  → The key was rejected. Use a real API key that starts with "
                    "'sk-ant-' from platform.claude.com → API keys (not a Claude.ai "
                    "login or OAuth token).")
    if PROVIDER == "openai":
        if code in (401, 403):
            return ("  → Key rejected by " + base_url() + ". Check OPENAI_API_KEY / "
                    "NAVI_LLM_API_KEY, and that the key belongs to THAT endpoint.")
        if code == 404:
            return (f"  → Not found at {base_url()}/chat/completions. Check "
                    "NAVI_LLM_BASE_URL includes the version path (e.g. .../v1) and that "
                    f"the model '{DEFAULT_MODEL}' exists there.")
        if code == 429:
            return "  → Rate-limited or out of quota on this endpoint."
    if PROVIDER == "ollama" and code == 404:
        return (f"  → Ollama doesn't have '{DEFAULT_MODEL}'. Run: ollama pull {DEFAULT_MODEL}")
    return ""


def _call_anthropic(system, user, max_tokens, timeout):
    resp = _post_json(base_url() + "/v1/messages",
                      {"model": DEFAULT_MODEL, "max_tokens": max_tokens, "system": system,
                       "messages": [{"role": "user", "content": user}]},
                      {"x-api-key": api_key(), "anthropic-version": "2023-06-01"},
                      timeout, "Anthropic API")
    u = resp.get("usage") or {}
    text = "".join(b.get("text", "") for b in resp.get("content", []))
    return text, u.get("input_tokens"), u.get("output_tokens")


def _call_openai(system, user, max_tokens, timeout):
    """OpenAI /chat/completions — also OpenRouter, vLLM, Together, Groq, LM Studio,
    llama.cpp server, and Azure-style deployments (point NAVI_LLM_BASE_URL at them)."""
    key = api_key()
    body = {"model": DEFAULT_MODEL, "max_tokens": max_tokens, "temperature": 0,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}]}
    if (os.environ.get("NAVI_LLM_JSON_MODE") or "").strip() in ("1", "true", "yes"):
        body["response_format"] = {"type": "json_object"}    # opt-in: many servers 400 on it
    resp = _post_json(base_url() + "/chat/completions", body,
                      ({"authorization": "Bearer " + key} if key else {}),
                      timeout, "OpenAI-compatible API")
    ch = (resp.get("choices") or [{}])[0]
    text = ((ch.get("message") or {}).get("content")) or ch.get("text") or ""
    u = resp.get("usage") or {}
    return text, u.get("prompt_tokens"), u.get("completion_tokens")


def _call_ollama(system, user, max_tokens, timeout):
    """Native Ollama /api/chat — local, keyless. num_predict is Ollama's max_tokens."""
    resp = _post_json(base_url() + "/api/chat",
                      {"model": DEFAULT_MODEL, "stream": False,
                       "options": {"num_predict": max_tokens, "temperature": 0},
                       "messages": [{"role": "system", "content": system},
                                    {"role": "user", "content": user}]},
                      {}, timeout, "Ollama")
    text = ((resp.get("message") or {}).get("content")) or resp.get("response") or ""
    return text, resp.get("prompt_eval_count"), resp.get("eval_count")


def _call_bedrock(system, user, max_tokens, timeout):
    """AWS Bedrock via the model-agnostic Converse API — one shape for Claude, Llama,
    Mistral, Nova, Titan. Uses boto3 so AWS credential resolution (env, profile, SSO,
    instance/task role) and SigV4 signing stay AWS's problem, not ours."""
    try:
        import boto3                                        # optional dependency
    except ImportError as e:
        raise RuntimeError(
            "Bedrock needs boto3 (the pack's only optional dependency). "
            "Install it with:  pip install boto3   — then set AWS_REGION and your "
            "AWS credentials. Every other provider is pure stdlib.") from e
    region = _aws_region()
    if not region:
        raise RuntimeError("Bedrock needs AWS_REGION (or AWS_DEFAULT_REGION) set.")
    kw = {"region_name": region}
    if base_url():                                          # VPC endpoint / gateway
        kw["endpoint_url"] = base_url()
    client = boto3.client("bedrock-runtime", **kw)
    try:
        resp = client.converse(
            modelId=DEFAULT_MODEL,
            system=[{"text": system}],
            messages=[{"role": "user", "content": [{"text": user}]}],
            inferenceConfig={"maxTokens": max_tokens, "temperature": 0})
    except Exception as e:
        name = type(e).__name__
        hint = ""
        if "AccessDenied" in name or "AccessDenied" in str(e):
            hint = ("  → The IAM principal needs bedrock:InvokeModel, and the model must be "
                    "enabled in this region (Bedrock console → Model access).")
        elif "ValidationException" in name:
            hint = (f"  → Check the model id '{DEFAULT_MODEL}' is valid in {region} "
                    "(some models require an inference-profile id, e.g. us.anthropic.…).")
        elif "ResourceNotFound" in name:
            hint = f"  → Model '{DEFAULT_MODEL}' not found in {region}."
        raise RuntimeError(f"Bedrock {name}: {e}{hint}") from e
    blocks = (((resp.get("output") or {}).get("message") or {}).get("content") or [])
    text = "".join(b.get("text", "") for b in blocks)
    u = resp.get("usage") or {}
    return text, u.get("inputTokens"), u.get("outputTokens")


_CALLS = {"anthropic": _call_anthropic, "openai": _call_openai,
          "ollama": _call_ollama, "bedrock": _call_bedrock}


def _messages(system: str, user: str, max_tokens: int = 1000, timeout: int = 40) -> str:
    """Low-level single-turn call against the CONFIGURED provider; returns the model's
    text. Raises on failure — callers catch and fall back to their deterministic path."""
    if not available():
        raise RuntimeError(why_unavailable())
    fn = _CALLS.get(PROVIDER)
    if not fn:
        raise RuntimeError(f"unknown NAVI_LLM_PROVIDER '{PROVIDER}' — use one of: "
                           + ", ".join(PROVIDERS))
    # Every agent respects the configured ceiling — a caller can never request more
    # than MAX_TOKENS_CAP, so one env var governs them all regardless of provider.
    max_tokens = max(1, min(max_tokens, MAX_TOKENS_CAP))
    text, inp, out = fn(system, user, max_tokens, timeout)
    _tally(inp, out)
    return text


APP_SYSTEM = (
    "Extract the custom application the user wants to tag from their message. "
    'Return ONLY JSON: {"name":"<short tag name>","keywords":["<path search term>",...]}. '
    "name is what the tag value should be (e.g. 'navi'). keywords are lowercase "
    "substrings to search filesystem paths for (usually the app name and obvious "
    "folder/binary variants). Keep keywords short and specific.")


def extract_app(prompt: str) -> dict:
    """NL → {ok, name, keywords[]}. Falls back to a naive parse if no LLM."""
    if not available():
        # naive fallback: last quoted term, else last word
        import re as _re
        m = _re.findall(r"['\"]([^'\"]+)['\"]", prompt or "")
        name = (m[-1] if m else (prompt or "").strip().split()[-1] if prompt.strip() else "")
        name = name.strip().lower()
        return {"ok": bool(name), "fallback": True, "name": name,
                "keywords": [name] if name else []}
    try:
        data = _extract_json(_messages(APP_SYSTEM, prompt, max_tokens=300))
        kws = [k.lower() for k in data.get("keywords", []) if k]
        name = (data.get("name") or (kws[0] if kws else "")).strip()
        return {"ok": bool(name), "name": name, "keywords": kws or ([name] if name else []),
                "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": str(e)}


def cert_plan(system_prompt: str, certs: list[dict], timeout: int = 40) -> dict:
    """Certificate triage: the (editable) static system prompt + the failing-cert
    list → an assessment + per-cert tag/skip decisions. Falls back cleanly with
    no key (caller then tags everything deterministically)."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — tagging all candidates deterministically"}
    user = ("Certificates failing in the next 12 months (JSON):\n"
            + json.dumps(certs) + "\n\nReturn ONLY the JSON described in the system prompt.")
    # One decision per candidate → output grows with the cert count. A fixed cap
    # (was 1400) truncated the JSON on larger estates, the parse failed, and the
    # caller wrongly reported "no working model key". Scale to the count, ceiling
    # at ANTHROPIC_MAX_TOKENS (default 8000).
    try:
        data = _extract_json(_messages(system_prompt, user,
                                       max_tokens=_scaled_budget(len(certs)), timeout=timeout))
        return {"ok": True, "assessment": data.get("assessment", ""),
                "tag": data.get("tag", []), "skip": data.get("skip", []),
                "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


DASH_SYSTEM = (
    "You are a Tenable security data analyst. Convert the user's request into ONE "
    "read-only SQLite query over the navi.db schema below (you MAY join across tables "
    "using the JOIN KEYS), and pick the best chart for the data's shape. "
    "Return ONLY a JSON object, no prose:\n"
    '{"title":"<short dashboard title>","sql":"SELECT ...","viz":"kpi|bar|column|stacked|grouped|pie|donut|line|multiline|area|combo|scatter|bubble|heatmap|sankey|threads|treemap|funnel|waterfall|radar|gauge|progress|histogram|table",'
    '"label_col":"<category/date column>","value_col":"<numeric column>",'
    '"note":"<=14 word caption"}\n'
    "Rules: query ONLY this navi.db — never ATTACH another database and never use "
    "file/host functions (load_extension, readfile, writefile). sql MUST be a single "
    "SELECT (or WITH ... SELECT) — never INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, "
    "ATTACH, PRAGMA, REPLACE, or multiple statements. Always add a LIMIT (<=50). "
    "SHAPES: single ranking/series → TWO columns, label_col (text/date) then value_col "
    "(numeric); use bar/column/pie/donut/treemap/funnel/waterfall/line/area/radar/progress. "
    "Comparison across a SECOND dimension → THREE columns (label, series text, value) in "
    "long format; use stacked/grouped/multiline/heatmap. A FLOW between two categories → "
    "the SAME three long-format columns (source, target, value), label_col=source; use "
    "sankey (proportional bands) or threads (thin links) — e.g. severity→asset class, "
    "owner→severity, plugin family→severity. Correlation → label + TWO numeric "
    "columns (x,y); use scatter (add a 3rd numeric for bubble). 'kpi' for one row of scalar "
    "totals; 'table' otherwise. Prefer line/area for time series, funnel/waterfall for "
    "reduction or running totals, treemap for top-N by size, heatmap for category×category. "
    "Prefer COUNT(*) aggregates and GROUP BY for distributions.\n\n")


def dashboard(prompt: str, schema: str, timeout: int = 40) -> dict:
    """NL request → {ok, title, sql, viz, label_col, value_col, note}. The model
    only proposes SQL; the caller validates it is read-only and runs it against the
    read-only DB connection."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — the Dashboard Builder needs the model to write SQL"}
    try:
        data = _extract_json(_messages(
            DASH_SYSTEM + schema,
            "Request: " + (prompt or "") + "\n\nReturn ONLY the JSON object.",
            max_tokens=700, timeout=timeout))
        return {"ok": True, "title": data.get("title", "Dashboard"),
                "sql": data.get("sql", ""), "viz": data.get("viz", "table"),
                "label_col": data.get("label_col"), "value_col": data.get("value_col"),
                "note": data.get("note", ""), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


IDENTITY_SYSTEM = (
    "You convert an operator's plain-English instruction into TAG assignments for "
    "discovered identities (accounts) on Tenable assets. You are given the list of "
    "identities (user + class: nhi|human|service|system). Return ONLY JSON:\n"
    '{"assignments":[{"user":"<exact user>","category":"<tag category>","value":"<tag value>"}]}\n'
    "Rules: include ONLY identities that should be tagged. Use the user names exactly "
    "as given. Pick a sensible category (e.g. NHI, Identity) and a concise value. If "
    "nothing should be tagged, return {\"assignments\":[]}.")


def identity_plan(prompt: str, accounts: list[dict], timeout: int = 40) -> dict:
    """NL instruction + identities -> {ok, assignments:[{user,category,value}]}."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — use the per-row Tag buttons instead"}
    slim = [{"user": a.get("user"), "class": a.get("klass")} for a in accounts]
    user = ("Identities (JSON):\n" + json.dumps(slim) + "\n\nInstruction:\n" + (prompt or "")
            + "\n\nReturn ONLY the JSON described in the system prompt.")
    try:
        data = _extract_json(_messages(IDENTITY_SYSTEM, user,
                                       max_tokens=_scaled_budget(len(slim)), timeout=timeout))
        return {"ok": True, "assignments": data.get("assignments", []), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


OWNER_SYSTEM = (
    "You map exposure ROUTES and filesystem PATHS to OWNERS (a user or a group) per "
    "the operator's instruction. You are given the list of ROUTES (by app_name), PATHS, "
    "and OWNERS (name + type). The instruction may contain several rules. For every "
    "route/path the instruction refers to, output one mapping to the owner it names. "
    "Match routes/paths by keyword/semantics against app_name or path text; match the "
    "owner (case-insensitive) to an EXACT entry in the OWNERS list — an owner may be named "
    "by its `name` (login/username), its `alt` (friendly/full name), or a first name that "
    "appears in `alt`. Always OUTPUT the entry's exact `name` (the username or group name), "
    "never the friendly name. Use the exact app_name / path from the lists — never invent. "
    "Skip anything no rule mentions.\n"
    "CURRENT STATE (when provided): `already_assigned` maps route/path names to their "
    "EXISTING owner, and `owner_load` gives each owner's current number of assigned items. "
    "Use them to honor the instruction precisely:\n"
    "- 'the remaining' / 'unassigned' / 'not yet assigned' / 'the rest' → map ONLY "
    "routes/paths that are NOT keys in already_assigned. Never touch an already-assigned "
    "item unless the instruction explicitly says to reassign or rebalance existing ones.\n"
    "- 'balance the work' / 'keep it even' / 'distribute evenly' / 'fairly' → pick owners so "
    "the FINAL per-owner totals (owner_load + what you add this run) are as equal as "
    "possible; prefer owners with the lowest current load. If told to spread across a "
    "specific set of owners, use only those.\n"
    "- 'routes then paths' → assign all in-scope routes first, then paths, keeping balance "
    "across the combined result.\n"
    'Return ONLY JSON: {"mappings":[{"kind":"route|path","match":"<exact '
    'app_name or path>","owner":"<exact owner name>"}]}.')


def _salvage_mappings(text: str) -> list:
    """Recover every complete {kind,match,owner} object from a possibly-TRUNCATED
    JSON response. A bulk instruction ('assign the remaining routes/paths') can make
    the model emit hundreds of mappings that overflow max_tokens and get cut off
    mid-object — strict json.loads then throws and discards the whole plan. Here we
    pull out the objects that DID come through intact (they're flat, no nesting)."""
    out = []
    for m in re.finditer(r"\{[^{}]*\}", text):
        try:
            o = json.loads(m.group(0))
        except Exception:
            continue
        if isinstance(o, dict) and o.get("match") and o.get("owner"):
            out.append({"kind": o.get("kind", "route"), "match": o["match"], "owner": o["owner"]})
    return out


def owner_plan(prompt: str, routes: list[str], paths: list[str],
               owners: list[dict], assigned: dict | None = None,
               owner_load: dict | None = None, timeout: int = 60) -> dict:
    """NL + routes/paths/owners (+ current assignments) -> {ok, mappings:[{kind,match,owner}]}.

    `assigned` = {'routes': {name: owner}, 'paths': {name: owner}} of what's ALREADY
    owned, and `owner_load` = {owner: count} let the model honor 'assign the remaining'
    and 'keep it balanced' precisely instead of guessing.

    Bulk prompts produce large responses, so we allow a big token budget AND salvage a
    truncated tail rather than failing the whole plan. When salvage kicks in, `truncated`
    is set so the caller can tell the user to re-run to assign the rest."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — natural-language owner mapping needs the model"}
    payload = {"routes": routes, "paths": paths, "owners": owners}
    if assigned:
        payload["already_assigned"] = assigned
    if owner_load:
        payload["owner_load"] = owner_load
    user = ("Lists (JSON):\n" + json.dumps(payload) + "\n\nInstruction:\n" + (prompt or "")
            + "\n\nReturn ONLY the JSON described in the system prompt.")
    try:
        raw = _messages(OWNER_SYSTEM, user,
                        max_tokens=_scaled_budget(len(routes) + len(paths)), timeout=timeout)
        truncated = False
        try:
            mappings = _extract_json(raw).get("mappings", [])
        except Exception:
            mappings = _salvage_mappings(raw)      # recover the intact objects
            truncated = True
            if not mappings:
                raise
        return {"ok": True, "mappings": mappings, "model": DEFAULT_MODEL,
                "truncated": truncated}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


ASSET_OWNER_SYSTEM = (
    "You assign OWNERSHIP of assets from a plain-English instruction. You are given the live "
    "TAG SCHEMA (tag keys and their values, each with an asset count), the available OWNERS "
    "(navi users/groups), and a sample of asset hostnames. Decide who the owner is, which LAYER, "
    "and which assets to match.\n"
    "LAYER: 'business' = a business leader accountable for a GROUP of assets (the DEFAULT when the "
    "selection is a tag-group/app). 'asset' = a SINGLE owner who owns the WHOLE asset — every route "
    "and path — use ONLY when the instruction says complete/single/sole/whole-asset ownership or "
    "'owns the rest'.\n"
    "MODE (asset layer only): 'complete' = owns every route & path; 'remainder' = owns only the "
    "routes/paths not already owned ('the rest'); otherwise null.\n"
    "FILTER selects assets by attributes AND tags: {\"crown\":bool (ACR>=9 or a crown-jewel tag), "
    "\"acr_min\":int, \"acr_max\":int, \"cloud\":bool, \"tags\":[{\"key\":..,\"value\":..}] (match the "
    "asset's tags; omit value to require the key), \"host_like\":[substrings]}. Use ONLY tag keys/"
    "values that appear in the schema.\n"
    "Return ONLY JSON: {\"owner\":\"..\",\"layer\":\"business|asset\",\"mode\":\"complete|remainder|null\","
    "\"filter\":{..}}. owner = the name from the instruction (a navi user/group when one clearly "
    "matches, else the literal name)."
)


def asset_owner_plan(prompt: str, schema: dict, owners: list, sample_hosts: list | None = None,
                     timeout: int = 45) -> dict:
    """NL + tag schema + owners -> {ok, owner, layer, mode, filter} for the Asset Ownership
    (Terminus) view. The model reasons over each asset's tags + attributes."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — natural-language ownership needs the model"}
    payload = {"tag_schema": schema, "owners": owners, "sample_hosts": (sample_hosts or [])[:40]}
    user = ("Context (JSON):\n" + json.dumps(payload, default=str) + "\n\nInstruction:\n"
            + (prompt or "") + "\n\nReturn ONLY the JSON described in the system prompt.")
    try:
        raw = _messages(ASSET_OWNER_SYSTEM, user, max_tokens=700, timeout=timeout)
        obj = _extract_json(raw)
        return {"ok": True, "owner": obj.get("owner"), "layer": obj.get("layer"),
                "mode": obj.get("mode"), "filter": obj.get("filter") or {}, "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


AUDIT_SYSTEM = (
    "You are Draco, an expert author of Tenable Nessus .audit compliance checks. "
    "Given a plain-English requirement and the target platform's available check "
    "types and keywords, produce concrete, valid checks. Return ONLY JSON: "
    '{"title":"<short file title>","checks":[{"type":"<CHECK_TYPE>",'
    '"description":"<concise imperative check title>","info":"<why it matters>",'
    '"fields":{"<keyword>":"<value>", "...":"..."},"solution":"<remediation>",'
    '"references":[{"framework":"<one of 800-53|PCI-DSSv3.2.1|HIPAA|CSCv8|ISO/IEC-27001>",'
    '"control":"<id>"}]}],"notes":"<assumptions or caveats>"}. '
    "Rules: use ONLY the check types and keywords listed for the platform; fill "
    "EVERY required keyword; keep any regex valid; auto-map each check to the most "
    "relevant framework control(s); never invent keywords or check types. If the "
    "request is broad, break it into several focused checks. No prose outside the JSON. "
    "FIELD SEMANTICS — for content/command checks (FILE_CONTENT_CHECK, "
    "FILE_CONTENT_CHECK_NOT, CMD_EXEC), `regex` and `expect` are REGEXES over the file "
    "or command text, NEVER a boolean like 'true'/'false'. `regex` locates the relevant "
    "line; `expect` is the pattern the content must satisfy. Correct example — "
    'regex: "^\\\\s*PermitRootLogin", expect: "^\\\\s*PermitRootLogin\\\\s+no". '
    "For a value comparison (REGISTRY_SETTING/PASSWORD_POLICY/WMI_POLICY/AUDIT_POWERSHELL), "
    "put the required value in `value_data` (e.g. 1, 14, \"Running\"), not in expect.")


def audit_plan(prompt: str, platform: str, vocab: str, timeout: int = 60) -> dict:
    """NL requirement + a platform's check-type vocabulary -> structured .audit checks
    for Draco (the custom-audit agent). Returns {ok, title, checks:[...], notes} or a
    graceful fallback when no model key is configured (the guided builder still works)."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — the natural-language audit box needs the "
                           "model. Use the guided builder, or set ANTHROPIC_API_KEY in Settings."}
    user = ("Target platform: " + (platform or "") + "\n\nAvailable check types & keywords:\n"
            + (vocab or "") + "\n\nRequirement:\n" + (prompt or "")
            + "\n\nReturn ONLY the JSON described in the system prompt.")
    try:
        raw = _messages(AUDIT_SYSTEM, user, max_tokens=1600, timeout=timeout)
        obj = _extract_json(raw)
        checks = obj.get("checks")
        if not isinstance(checks, list):
            checks = []
        return {"ok": True, "title": obj.get("title") or "Custom Audit",
                "checks": checks, "notes": obj.get("notes") or "", "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


def table_query(prompt: str, table: str, columns: list, timeout: int = 40,
                value_hint: str = "") -> dict:
    """NL question -> ONE read-only SELECT over a single navi.db table.
    Returns {ok, sql} or {ok:False, fallback, message}. The caller still
    validates the SQL is read-only before running it. value_hint carries the
    actual distinct values of categorical columns so casing/enums match."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — natural-language SQL needs the model"}
    sys = (
        "You convert a question into ONE read-only SQLite SELECT over the navi.db "
        f"table {table}({', '.join(columns)}). Return ONLY the SQL — no prose, no "
        "markdown fence. Query ONLY this table (filter/aggregate/GROUP BY/ORDER BY "
        "allowed). Always include a LIMIT (<=500). NEVER write/UPDATE/DELETE/DROP/"
        "ALTER/CREATE/ATTACH/PRAGMA. Notes: cves looks like \"['CVE-2023-...']\" "
        "(match LIKE '%CVE-%'); acr/aes/score are numbers stored as text (use "
        "CAST(col AS REAL)); score on vulns is the VPR." + (value_hint or ""))
    try:
        txt = _messages(sys, "Question: " + (prompt or ""), max_tokens=400, timeout=timeout)
        sql = (txt or "").strip()
        if sql.startswith("```"):
            sql = sql.split("```", 2)[1]
            if sql.lstrip().lower().startswith("sql"):
                sql = sql.lstrip()[3:]
        return {"ok": True, "sql": sql.strip().rstrip(";").strip(), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


def contract_select(agent_name: str, logic: str, items: list, top_n: int = 50,
                    timeout: int = 40) -> dict:
    """Apply a human's plain-English logic to an agent's candidate list and return
    which items to KEEP (by index). items: [{i, label, rank}]. Falls back to the
    caller's risk-ranked top_n when no key/logic. Returns {ok, keep:[i,...], note}."""
    if not logic or not available():
        return {"ok": False, "fallback": True,
                "message": "no logic or no ANTHROPIC_API_KEY — using risk-ranked top-N"}
    import json
    listing = "\n".join(f'{it["i"]}: {it["label"]} (rank {it.get("rank","?")})' for it in items)
    sys = (
        f"You apply a human's tagging policy to the '{agent_name}' agent's candidate "
        "list. Decide which candidates to tag. Honor inclusions AND exclusions in the "
        "policy (e.g. 'tag all IoT but not Dell or Intel — those are laptops'). If the "
        "policy doesn't restrict, keep the highest-rank items. Return ONLY JSON: "
        '{"keep":[<indices to tag>],"note":"<one line>"}.\n\nPolicy: ' + logic +
        "\n\nCandidates (index: label):\n" + listing)
    try:
        # keep-list is one index (+ optional note) per candidate → scale with count.
        txt = _messages(sys, "Return the JSON.",
                        max_tokens=_scaled_budget(len(items), per_item=12), timeout=timeout)
        t = (txt or "").strip()
        if t.startswith("```"):
            t = t.split("```", 2)[1]
            if t.lstrip().lower().startswith("json"):
                t = t.lstrip()[4:]
        a, b = t.find("{"), t.rfind("}")
        data = json.loads(t[a:b + 1] if a >= 0 and b > a else t)
        keep = [int(x) for x in data.get("keep", []) if str(x).strip().lstrip("-").isdigit()]
        return {"ok": True, "keep": keep, "note": data.get("note", ""), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


def advanced_query(prompt: str, schema_text: str, join_text: str, timeout: int = 40,
                   value_hint: str = "") -> dict:
    """NL question -> ONE read-only SELECT that may JOIN across navi.db tables.
    schema_text lists table(columns); join_text lists the available join keys;
    value_hint carries the actual distinct values of categorical columns."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — advanced cross-table search needs the model"}
    sys = (
        "You convert a question into ONE read-only SQLite SELECT over a Tenable "
        "navi.db. You MAY join across any of these tables as needed.\nTables:\n"
        + schema_text + "\n\nJOIN KEYS (use these exact relationships):\n" + join_text +
        "\n\nRules: Return ONLY the SQL — no prose, no markdown fence. Use table "
        "aliases and qualify columns. Prefer the asset_uuid foreign keys. For EPSS, "
        "ALWAYS join the small zipper table on plugin_id (JOIN zipper z ON "
        "z.plugin_id=v.plugin_id, CAST(z.epss_value AS REAL)); do NOT join the huge "
        "epss table by cves LIKE unless zipper is absent (epss has 300k+ rows and will "
        "time out). For CERTIFICATE questions use the certs table; for SOFTWARE / "
        "installed-product questions use the software table (software_string) — they "
        "give better results than scanning vulns. Use GROUP BY / MAX / aggregates when "
        "the question implies highest/most/per. Always include a LIMIT (<=500). NEVER "
        "write/UPDATE/DELETE/DROP/ALTER/CREATE/ATTACH/PRAGMA. Notes: "
        "acr/aes/epss_value/score are numeric-as-text "
        "(CAST(col AS REAL)); tags identify a tag via tag_key (category) + tag_value."
        + (value_hint or ""))
    try:
        txt = _messages(sys, "Question: " + (prompt or ""), max_tokens=600, timeout=timeout)
        sql = (txt or "").strip()
        if sql.startswith("```"):
            sql = sql.split("```", 2)[1]
            if sql.lstrip().lower().startswith("sql"):
                sql = sql.lstrip()[3:]
        return {"ok": True, "sql": sql.strip().rstrip(";").strip(), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


def which_agent(prompt: str, agents: list, timeout: int = 40) -> dict:
    """Recommend 1–3 agents for a task. `agents` is a list of dicts with id/name/
    summary (and optional codename). Returns {ok, picks:[{id,why}], note}."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — the agent recommender needs the model"}
    import json
    roster = "\n".join(
        f"{a.get('id')} — {a.get('codename') or a.get('name')}: {a.get('summary','')}"
        for a in agents if a.get("id"))
    sys = (
        'You are a router for a Tenable/navi security agent suite called "The Hounds". '
        "Given the user's task, pick the 1-3 most relevant agents from the roster and "
        'explain briefly why each fits. Return ONLY JSON: {"picks":[{"id":"<exact id>",'
        '"why":"<one sentence>"}],"note":"<optional one-line tip>"}.\n\n'
        "Roster (id — name — what it does):\n" + roster)
    try:
        txt = _messages(sys, "Task: " + prompt, max_tokens=500, timeout=timeout)
        t = (txt or "").strip()
        if t.startswith("```"):
            t = t.split("```", 2)[1]
            if t.lstrip().lower().startswith("json"):
                t = t.lstrip()[4:]
        a, b = t.find("{"), t.rfind("}")
        data = json.loads(t[a:b + 1] if a >= 0 and b > a else t)
        return {"ok": True, "picks": data.get("picks", []),
                "note": data.get("note", ""), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


def software_query(prompt: str, sw_cols: list, asset_cols: list, vuln_cols: list,
                   timeout: int = 40, value_hint: str = "") -> dict:
    """NL question -> ONE read-only SELECT over the software inventory, joining
    software ⋈ assets ⋈ vulns on the asset_uuid primary key. Returns {ok, sql}
    or {ok:False, fallback, message}. Caller still validates read-only SQL."""
    if not available():
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY — natural-language SQL needs the model"}
    sys = (
        "You convert a question into ONE read-only SQLite SELECT over a navi.db "
        "software inventory.\nTables and columns:\n"
        f"  software({', '.join(sw_cols)})  -- software_string is a free-text "
        "product+version string, e.g. \"openssl-1.1.1k-7.el8\"\n"
        f"  assets({', '.join(asset_cols)})\n"
        f"  vulns({', '.join(vuln_cols)})\n"
        "JOIN KEYS (primary keys): software.asset_uuid = assets.uuid ; "
        "software.asset_uuid = vulns.asset_uuid ; vulns.asset_uuid = assets.uuid.\n"
        "Always start FROM software and LEFT JOIN assets/vulns only when the question "
        "needs them. When joining vulns (one row per finding) use DISTINCT or GROUP BY "
        "to avoid duplicating software rows.\n"
        "Return ONLY the SQL — no prose, no markdown fence. Always include a LIMIT "
        "(<=500). NEVER write/UPDATE/DELETE/DROP/ALTER/CREATE/ATTACH/PRAGMA.\n"
        "Notes: match products with software.software_string LIKE '%name%'; "
        "cves looks like \"['CVE-2023-...']\" "
        "(match LIKE '%CVE-%'); acr/aes/score are numbers stored as text (use "
        "CAST(col AS REAL)); vulns.score is the VPR; a cloud asset has a non-empty "
        "aws_id/azure_vm_id/gcp_instance_id." + (value_hint or ""))
    try:
        txt = _messages(sys, "Question: " + (prompt or ""), max_tokens=500, timeout=timeout)
        sql = (txt or "").strip()
        if sql.startswith("```"):
            sql = sql.split("```", 2)[1]
            if sql.lstrip().lower().startswith("sql"):
                sql = sql.lstrip()[3:]
        return {"ok": True, "sql": sql.strip().rstrip(";").strip(), "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True, "message": f"LLM call failed ({e})"}


def interpret(prompt: str, tags: list[dict], timeout: int = 40) -> dict:
    """Return {"ok":True,"changes":[...]} or {"ok":False,"fallback":True,...}."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return {"ok": False, "fallback": True,
                "message": "no ANTHROPIC_API_KEY set — using the deterministic rule parser"}
    tag_lines = "\n".join(f"- {t['category']} : {t['value']}" for t in tags)
    try:
        # one change per matching tag → scale with the tag count.
        text = _messages(SYSTEM, f"Instruction:\n{prompt}\n\nTags:\n{tag_lines}",
                         max_tokens=_scaled_budget(len(tags)), timeout=timeout)
        data = _extract_json(text)
        return {"ok": True, "changes": data.get("changes", []),
                "model": DEFAULT_MODEL}
    except Exception as e:
        return {"ok": False, "fallback": True,
                "message": f"LLM call failed ({e}) — using the deterministic parser"}
