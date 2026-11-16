# Bring Your Own Model

The Hounds use a model for their **propose** steps — cert triage, ACR planning,
ownership mapping, NL→SQL, contract policy, correlation narration. Every one of
those calls funnels through a single function in `core/llm.py`, so swapping
providers is a matter of environment variables. No code changes, no adapters.

> **The model only proposes.** The UI previews what it suggested and a human
> approves before any gated write lands in your tenant. A smaller or local model is
> noisier — it is never more dangerous.

> **It's optional.** With nothing configured, `available()` is `False` and every
> caller falls back to its deterministic path. The whole pack still runs; you just
> lose the natural-language extras.

**Contents** — [The four providers](#the-four-providers) · [Anthropic](#anthropic) ·
[OpenAI-compatible](#openai-compatible) · [Ollama](#ollama-fully-local) ·
[Bedrock](#aws-bedrock) · [Common settings](#common-settings) ·
[Auto-detection](#how-the-provider-is-chosen) · [What degrades](#what-degrades-without-a-model)
· [Diagnosing](#diagnosing)

---

## The four providers

| Provider | Set `NAVI_LLM_PROVIDER` to | Credential | Default model | Needs a package? |
|---|---|---|---|---|
| Anthropic | `anthropic` *(default)* | `ANTHROPIC_API_KEY` | `claude-haiku-4-5-20251001` | no |
| OpenAI-compatible | `openai` | `OPENAI_API_KEY` / `NAVI_LLM_API_KEY` | `gpt-4o-mini` | no |
| Ollama (local) | `ollama` | none | `llama3.1` | no |
| AWS Bedrock | `bedrock` | AWS credentials | `anthropic.claude-3-5-haiku-20241022-v1:0` | **yes — `boto3`** |

Everything but Bedrock runs on the standard library. Bedrock is the one exception
because it needs AWS credential resolution and SigV4 signing.

---

## Anthropic

The default. Nothing to set but a key.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Get one at <https://platform.claude.com/settings/keys>. Optionally pick a model:

```bash
export NAVI_LLM_MODEL=claude-sonnet-4-5-20250929
```

`ANTHROPIC_MODEL` still works as a fallback for existing installs.

---

## OpenAI-compatible

Anything that speaks `/chat/completions` — OpenAI itself, OpenRouter, vLLM,
Together, Groq, LM Studio, or an Azure-style deployment.

**OpenAI:**

```bash
export NAVI_LLM_PROVIDER=openai
export OPENAI_API_KEY=sk-...
export NAVI_LLM_MODEL=gpt-4o-mini
```

**Any other compatible endpoint** — point `NAVI_LLM_BASE_URL` at it:

```bash
export NAVI_LLM_PROVIDER=openai
export NAVI_LLM_BASE_URL=https://openrouter.ai/api/v1
export NAVI_LLM_API_KEY=sk-or-...
export NAVI_LLM_MODEL=meta-llama/llama-3.1-70b-instruct
```

A locally-hosted vLLM or LM Studio server is the same shape:

```bash
export NAVI_LLM_PROVIDER=openai
export NAVI_LLM_BASE_URL=http://127.0.0.1:1234/v1
export NAVI_LLM_API_KEY=not-needed
export NAVI_LLM_MODEL=your-local-model
```

`OPENAI_BASE_URL` is honoured if `NAVI_LLM_BASE_URL` isn't set.

---

## Ollama (fully local)

No key, no network egress — nothing leaves the machine. Good for regulated
environments where estate data can't reach a hosted API.

```bash
ollama serve                 # in another terminal
ollama pull llama3.1

export NAVI_LLM_PROVIDER=ollama
export NAVI_LLM_MODEL=llama3.1
# export NAVI_LLM_BASE_URL=http://127.0.0.1:11434   # only if not the default
```

Local models are noticeably noisier at the JSON-shaped tasks (ACR rule extraction,
NL→SQL). Review the proposals before approving — which the gates already force you
to do. A larger local model helps; `NAVI_LLM_JSON_MODE=1` helps where the runtime
supports native JSON mode.

---

## AWS Bedrock

Uses the model-agnostic **Converse** API, so any Bedrock-hosted model works.

```bash
pip install 'boto3>=1.34'

export NAVI_LLM_PROVIDER=bedrock
export AWS_REGION=us-east-1
export NAVI_LLM_MODEL=anthropic.claude-3-5-haiku-20241022-v1:0
```

Credentials resolve the normal AWS way — `AWS_ACCESS_KEY_ID` +
`AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE`, an instance/task role
(`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`), or `AWS_ROLE_ARN`. `AWS_DEFAULT_REGION`
is accepted if `AWS_REGION` isn't set.

Make sure the model is **enabled in your account** for that region — Bedrock model
access is opt-in per model, and a model you haven't enabled returns a bare
`HTTP 400`. `check_llm.py` translates that into something readable.

---

## Common settings

| Variable | Default | Purpose |
|---|---|---|
| `NAVI_LLM_PROVIDER` | auto-detect | `anthropic` · `openai` · `ollama` · `bedrock` |
| `NAVI_LLM_MODEL` | per-provider (table above) | Model id for the chosen provider |
| `NAVI_LLM_BASE_URL` | per-provider | Endpoint override |
| `NAVI_LLM_API_KEY` | — | Generic key; a provider-specific key wins when both are set |
| `NAVI_LLM_MAX_TOKENS` | `8000` | Output-token ceiling for **every** call. Lower it and every agent comes down with it. `ANTHROPIC_MAX_TOKENS` is honoured as a fallback |
| `NAVI_LLM_JSON_MODE` | off | Set `1` to request provider-native JSON mode |

**Key precedence.** The provider-specific key beats the generic one, deliberately —
a leftover `NAVI_LLM_API_KEY` from a previous provider can't shadow a real
`ANTHROPIC_API_KEY` after you switch.

**Token budgets.** Agents that emit one object per input item size their request to
the item count so large estates don't truncate, floored at 1500 and capped at
`NAVI_LLM_MAX_TOKENS`. Raise the cap for very large estates; lower it for older
models with a small output limit. The default of 8000 suits Haiku 4.5.

**Switching live.** The Settings page can change provider, model, and the token cap
without a restart. When you switch provider and the model is still the previous
provider's default, it moves to the new provider's default too — so you don't end up
asking Ollama for `gpt-4o-mini`.

---

## How the provider is chosen

`NAVI_LLM_PROVIDER` always wins. Left blank, detection runs in this order:

1. `ANTHROPIC_API_KEY` present → **anthropic**
2. `OPENAI_API_KEY` present → **openai**
3. `OLLAMA_HOST` present → **ollama**
4. `NAVI_LLM_BASE_URL` present → **openai** (a bare endpoint is assumed OpenAI-compatible)
5. otherwise → **anthropic** (so existing installs behave exactly as before)

Bedrock is never auto-detected — set `NAVI_LLM_PROVIDER=bedrock` explicitly.

A provider is considered **available** when: Ollama has an endpoint; Anthropic or
OpenAI has a key; Bedrock has a region *and* credentials. Anything else is treated
as "no model configured", which is a supported state, not an error.

---

## What degrades without a model

Everything below still works — it just loses its plain-English front door. Nothing
breaks, and no agent disappears from the hub.

| Feature | Without a model |
|---|---|
| "Ask which agent can help" (the hub search box) | Unavailable |
| NL → SQL (Dashboard Builder / Daedalus, KEV hunt) | Unavailable; hand-written queries still run |
| NL ACR rules (Anubis) | Unavailable; per-tag set / +N / −N still works |
| NL tagging (Linnaeus, Cavall, Janus, Sirius) | Unavailable; widget + list selection still works |
| Certificate triage narration (Certania) | Deterministic ranking, no reasoning text |
| Ownership plans (Atlas, Terminus) | Deterministic mapping from routes/paths |
| Custom Audit authoring (Draco) | Guided field-by-field builder still works; the "describe it" path doesn't |
| Alert crafting (Alert Raven) | Threshold alerts still work; NL alert authoring doesn't |
| Contract policy capture (Covenant) | Needs a model to plan |
| Every explorer, dashboard, tagger, export | **Unaffected** |

---

## Diagnosing

```bash
python3 check_llm.py
```

It prints the resolved provider, model, endpoint, and whether a key was found, then
makes **one tiny real call** and reports the exact failure — so a vague
`HTTP 400 Bad Request` becomes "no credit", "model not enabled in this region",
"wrong endpoint", "Ollama isn't running", or "boto3 missing".

The same state is on the **Settings** page (with a running token tally since server
start) and in `/api/health`.

Common fixes:

| Symptom | Fix |
|---|---|
| "⚠ Claude: no API key" chip | Key isn't in the server's environment. Export it in the *same* shell, or put it in `.env` and restart — `.env` is read once, at startup. |
| `CERTIFICATE_VERIFY_FAILED` on macOS | Usually a python.org Python without CA certs. `pip install certifi` — `core/llm.py` prefers its bundle automatically. |
| Ollama: connection refused | `ollama serve` isn't running, or `NAVI_LLM_BASE_URL` points somewhere else. |
| Bedrock: `ModuleNotFoundError: boto3` | `pip install 'boto3>=1.34'`. |
| Bedrock: bare `HTTP 400` | The model isn't enabled for your account in that region. |
| Model returns malformed JSON | Try a larger model, or set `NAVI_LLM_JSON_MODE=1` if the endpoint supports it. |

---

See also: [INSTALL.md](INSTALL.md) · [README.md](README.md#configuration) ·
[HOUNDS-MCP.md](HOUNDS-MCP.md)
