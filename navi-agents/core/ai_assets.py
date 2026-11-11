"""AI inventory (Pythia) — content-first discovery of AI/ML across the estate.

Repo-native port of the live console's AI engine. Discovers AI/ML by CONTENT from
FIVE sources — the Tenable AI plugin family, the `software` and `cpes` inventories,
plugin name/output, and network endpoints — classifies each asset by role, flags
exposed endpoints (with an unauth parse), maps data-egress (capability + observed,
sanctioned vs shadow), correlates KEV/critical risk, and maps MITRE ATLAS techniques.

Accuracy levers ported from the console:
  * port-CONTEXT matching (`:8888`, `8888/tcp`, `port 8888`) — never a bare substring
  * CPE `:product` boundary match (so `libwayland-cursor` != `cursor`)
  * evidence per hit (source + term + plugin + snippet) -> the "why" + FP suppression
  * FP suppression (per-asset / per-framework / global-framework) via a passed-in map
  * egress sanctioned-vs-shadow off an editable allowlist

Read-only; the tag writes are gated (navi_cli). scan() returns structured JSON.
"""
import re

from core import db, hx_summary, tagname

FAMILY = "Artificial Intelligence"

# role -> priority (which role wins when an asset matches several) + suggested ACR
ROLE_PRI = {"Model Serving": 6, "Vector DB / RAG": 5, "GPU / Training": 5, "MLOps": 4,
            "Notebook / Dev": 3, "AI Dev Tool": 2, "LLM API Client": 2, "Tenable AI plugin": 1}
ROLE_ACR = {"Model Serving": 9, "Vector DB / RAG": 8, "GPU / Training": 8, "MLOps": 8,
            "Notebook / Dev": 7, "AI Dev Tool": 6, "LLM API Client": 6, "Tenable AI plugin": 7, "AI": 7}

# (keyword, role, display name) — the software/output/cpe catalog
CATALOG = [
    ("tensorflow", "GPU / Training", "TensorFlow"), ("pytorch", "GPU / Training", "PyTorch"),
    ("torchvision", "GPU / Training", "PyTorch"), ("keras", "GPU / Training", "Keras"),
    ("scikit-learn", "GPU / Training", "scikit-learn"), ("xgboost", "GPU / Training", "XGBoost"),
    ("lightgbm", "GPU / Training", "LightGBM"), ("onnxruntime", "GPU / Training", "ONNX Runtime"),
    ("transformers", "GPU / Training", "HF Transformers"), ("huggingface", "GPU / Training", "Hugging Face"),
    ("sentence-transformers", "GPU / Training", "SentenceTransformers"), ("cuda", "GPU / Training", "NVIDIA CUDA"),
    ("cudnn", "GPU / Training", "cuDNN"), ("tensorrt", "GPU / Training", "TensorRT"),
    ("ollama", "Model Serving", "Ollama"), ("vllm", "Model Serving", "vLLM"),
    ("triton", "Model Serving", "Triton Server"), ("torchserve", "Model Serving", "TorchServe"),
    ("llama.cpp", "Model Serving", "llama.cpp"), ("gpt4all", "Model Serving", "GPT4All"),
    ("text-generation-webui", "Model Serving", "text-generation-webui"), ("localai", "Model Serving", "LocalAI"),
    ("comfyui", "Model Serving", "ComfyUI"), ("stable-diffusion", "Model Serving", "Stable Diffusion"),
    ("automatic1111", "Model Serving", "AUTOMATIC1111"),
    ("jupyter", "Notebook / Dev", "Jupyter"), ("anaconda", "Notebook / Dev", "Anaconda"),
    ("chromadb", "Vector DB / RAG", "ChromaDB"), ("milvus", "Vector DB / RAG", "Milvus"),
    ("weaviate", "Vector DB / RAG", "Weaviate"), ("qdrant", "Vector DB / RAG", "Qdrant"),
    ("faiss", "Vector DB / RAG", "FAISS"), ("pinecone", "Vector DB / RAG", "Pinecone"),
    ("pgvector", "Vector DB / RAG", "pgvector"),
    ("mlflow", "MLOps", "MLflow"), ("kubeflow", "MLOps", "Kubeflow"),
    ("wandb", "MLOps", "Weights & Biases"), ("bentoml", "MLOps", "BentoML"),
    ("openai", "LLM API Client", "OpenAI SDK"), ("anthropic", "LLM API Client", "Anthropic SDK"),
    ("cohere", "LLM API Client", "Cohere SDK"), ("google-generativeai", "LLM API Client", "Google GenAI"),
    ("langchain", "LLM API Client", "LangChain"), ("llama-index", "LLM API Client", "LlamaIndex"),
    ("llamaindex", "LLM API Client", "LlamaIndex"), ("litellm", "LLM API Client", "LiteLLM"),
]
# keywords too generic to match on free-text plugin output (would false-positive)
OUT_BLOCK = {"cuda", "cudnn", "keras", "anaconda", "sentence-transformers", "transformers",
             "openai", "anthropic", "cohere", "pinecone"}
OUT_CATALOG = [e for e in CATALOG if e[0] not in OUT_BLOCK]

ENDPOINTS = [
    {"name": "Ollama", "port": "11434", "role": "Model Serving", "distinct": True, "kw": ["ollama"]},
    {"name": "Jupyter", "port": "8888", "role": "Notebook / Dev", "distinct": False, "kw": ["jupyter"]},
    {"name": "Ray Dashboard", "port": "8265", "role": "MLOps", "distinct": True, "kw": ["ray dashboard", "ray cluster", "raylet"]},
    {"name": "ComfyUI", "port": "8188", "role": "Model Serving", "distinct": True, "kw": ["comfyui"]},
    {"name": "LM Studio", "port": "1234", "role": "Model Serving", "distinct": False, "kw": ["lm studio", "lmstudio"]},
    {"name": "Gradio", "port": "7860", "role": "Model Serving", "distinct": False, "kw": ["gradio"]},
    {"name": "Streamlit", "port": "8501", "role": "Notebook / Dev", "distinct": False, "kw": ["streamlit"]},
    {"name": "MLflow", "port": "5000", "role": "MLOps", "distinct": False, "kw": ["mlflow"]},
    {"name": "text-generation-webui", "port": "7860", "role": "Model Serving", "distinct": False, "kw": ["text-generation-webui", "oobabooga"]},
    {"name": "vLLM", "port": "8000", "role": "Model Serving", "distinct": False, "kw": ["vllm"]},
    {"name": "Triton Server", "port": "8000", "role": "Model Serving", "distinct": False, "kw": ["triton inference"]},
    {"name": "Open WebUI", "port": "8080", "role": "Model Serving", "distinct": False, "kw": ["open-webui", "open webui"]},
]
CPE_EXTRA = [
    ("cursor", "AI Dev Tool", "Cursor"), ("claude_code", "AI Dev Tool", "Claude Code"),
    ("claude-code", "AI Dev Tool", "Claude Code"), ("github_copilot", "AI Dev Tool", "GitHub Copilot"),
    ("copilot", "AI Dev Tool", "Copilot"), ("tabnine", "AI Dev Tool", "Tabnine"),
    ("codeium", "AI Dev Tool", "Codeium"), ("windsurf", "AI Dev Tool", "Windsurf"),
    ("aider", "AI Dev Tool", "Aider"), ("cody", "AI Dev Tool", "Sourcegraph Cody"),
    ("openai", "LLM API Client", "OpenAI"), ("ollama", "Model Serving", "Ollama"),
    ("anthropic", "LLM API Client", "Anthropic"),
]
CPE_ALL = CPE_EXTRA + CATALOG

# egress: framework -> (category, destination)
EGRESS = {
    "OpenAI SDK": ("LLM API", "api.openai.com"), "Anthropic SDK": ("LLM API", "api.anthropic.com"),
    "Cohere SDK": ("LLM API", "api.cohere.ai"), "Google GenAI": ("LLM API", "generativelanguage.googleapis.com"),
    "LiteLLM": ("LLM API", "(multi-provider)"),
    "HF Transformers": ("Model Hub", "huggingface.co"), "Hugging Face": ("Model Hub", "huggingface.co"),
    "SentenceTransformers": ("Model Hub", "huggingface.co"),
    "Weights & Biases": ("Experiment Telemetry", "api.wandb.ai"), "MLflow": ("Experiment Telemetry", "(tracking server)"),
    "Pinecone": ("Managed Vector Store", "*.pinecone.io"), "Weaviate": ("Managed Vector Store", "*.weaviate.network"),
    "LangChain": ("LLM Orchestration", "(provider-dependent)"), "LlamaIndex": ("LLM Orchestration", "(provider-dependent)"),
    "Cursor": ("LLM API", "api2.cursor.sh"), "Claude Code": ("LLM API", "api.anthropic.com"),
    "GitHub Copilot": ("LLM API", "api.githubcopilot.com"), "Copilot": ("LLM API", "api.githubcopilot.com"),
    "Tabnine": ("LLM API", "api.tabnine.com"), "Codeium": ("LLM API", "server.codeium.com"),
    "Windsurf": ("LLM API", "server.codeium.com"), "Aider": ("LLM API", "(provider-dependent)"),
    "Sourcegraph Cody": ("LLM API", "sourcegraph.com"), "OpenAI": ("LLM API", "api.openai.com"),
    "Anthropic": ("LLM API", "api.anthropic.com"),
}
EGRESS_HOSTS = [
    (re.compile(r"api\.openai\.com", re.I), "LLM API", "api.openai.com"),
    (re.compile(r"[a-z0-9-]+\.openai\.azure\.com", re.I), "LLM API", "*.openai.azure.com"),
    (re.compile(r"api\.anthropic\.com", re.I), "LLM API", "api.anthropic.com"),
    (re.compile(r"api\.cohere\.(ai|com)", re.I), "LLM API", "api.cohere.ai"),
    (re.compile(r"(generativelanguage|aiplatform)\.googleapis\.com", re.I), "LLM API", "googleapis.com (Gemini/Vertex)"),
    (re.compile(r"api\.mistral\.ai", re.I), "LLM API", "api.mistral.ai"),
    (re.compile(r"api\.together\.(ai|xyz)", re.I), "LLM API", "api.together.ai"),
    (re.compile(r"api\.replicate\.com", re.I), "LLM API", "api.replicate.com"),
    (re.compile(r"(huggingface\.co|hf\.co)", re.I), "Model Hub", "huggingface.co"),
    (re.compile(r"[a-z0-9-]+\.pinecone\.io", re.I), "Managed Vector Store", "*.pinecone.io"),
    (re.compile(r"[a-z0-9-]+\.weaviate\.(network|cloud)", re.I), "Managed Vector Store", "*.weaviate.network"),
    (re.compile(r"(api\.)?wandb\.ai", re.I), "Experiment Telemetry", "wandb.ai"),
    (re.compile(r"serpapi\.com|api\.serper\.dev|api\.tavily\.com", re.I), "Tool / Search API", "external search API"),
]
EGRESS_TERMS = ["openai.com", "anthropic.com", "cohere", "googleapis.com", "huggingface", "hf.co",
                "pinecone.io", "weaviate", "wandb.ai", "mistral.ai", "together.a", "replicate.com",
                "openai.azure.com", "serpapi", "serper.dev", "tavily.com"]
ALLOW_DEFAULT = ["localhost", "127.0.0.1", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
                 "172.19.", "172.2", "172.30.", "172.31.", ".internal", ".corp", ".local", ".lan",
                 ".svc", "(tracking server)", "(provider-dependent)", "(multi-provider)"]

# MITRE ATLAS (AI-specific adversary techniques): id -> (name, tactic)
ATLAS_TECH = {
    "AML.T0047": ("ML-Enabled Product or Service", "ML Model Access"),
    "AML.T0040": ("ML Model Inference API Access", "ML Model Access"),
    "AML.T0049": ("Exploit Public-Facing Application", "Initial Access"),
    "AML.T0012": ("Valid Accounts", "Initial Access"),
    "AML.T0010": ("ML Supply Chain Compromise", "Resource Development"),
    "AML.T0002": ("Acquire Public ML Artifacts", "Resource Development"),
    "AML.T0018": ("Manipulate ML Model (Backdoor)", "Persistence"),
    "AML.T0043": ("Craft Adversarial Data", "ML Attack Staging"),
    "AML.T0051": ("LLM Prompt Injection", "Execution"),
    "AML.T0054": ("LLM Jailbreak", "Privilege Escalation"),
    "AML.T0057": ("LLM Data Leakage", "Exfiltration"),
    "AML.T0024": ("Exfiltration via ML Inference API", "Exfiltration"),
    "AML.T0025": ("Exfiltration via Cyber Means", "Exfiltration"),
    "AML.T0031": ("Erode ML Model Integrity", "Impact"),
    "AML.T0034": ("Cost Harvesting", "Impact"),
}
ATLAS_TACTIC_ORDER = ["Reconnaissance", "Resource Development", "Initial Access", "ML Model Access",
                      "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
                      "Credential Access", "Discovery", "Collection", "ML Attack Staging",
                      "Exfiltration", "Impact"]

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)



def _bulk_hint(n_assets, db_path=None):
    """' NOT INDEXED' when a per-asset IN (…) list covers more than ~5% of all assets (build 455).
    Past that, hx_v_asset makes the planner fetch each finding by random row reads (the
    selected columns aren't in the index) — measured 6 s → 27 s; one sequential scan is cheaper.
    Small lists keep the index (milliseconds)."""
    try:
        total = int(db.scalar("SELECT MAX(rowid) FROM assets", path=db_path) or 0)
    except Exception:
        return ""
    return " NOT INDEXED" if total and n_assets > 0.05 * total else ""

def _cols(table):
    try:
        return {r["name"] for r in db.query(f'PRAGMA table_info("{table}");')}
    except Exception:
        return set()


def _lit(s):
    return str(s).replace("'", "''")


def _uuids(val):
    """software.asset_uuid can be a bracketed list; return the bare uuids (or the value)."""
    s = str(val or "")
    found = _UUID_RE.findall(s)
    if found:
        return found
    return [s] if (s and "[" not in s) else []


def _match(hay, catalog):
    for kw, role, name in catalog:
        if kw in hay:
            return {"name": name, "role": role, "kw": kw}
    return None


def _cpe_boundary(kw, s):
    try:
        return re.search(":" + re.escape(kw) + r"(?![a-z0-9])", s) is not None
    except Exception:
        return False


def _port_hit(hay, port):
    try:
        return re.search(r"(?::%s\b)|(?:\b%s/(?:tcp|udp)\b)|(?:\b(?:tcp|udp)/%s\b)|(?:\bport[ :=]+%s\b)"
                         % (port, port, port, port), hay, re.I) is not None
    except Exception:
        return False


def _snip(txt, term):
    txt = re.sub(r"\s+", " ", str(txt or "")).strip()
    if not term:
        return txt[:180] + ("…" if len(txt) > 180 else "")
    i = txt.lower().find(str(term).lower())
    if i < 0:
        return txt[:180] + ("…" if len(txt) > 180 else "")
    s, e = max(0, i - 70), min(len(txt), i + len(str(term)) + 100)
    return ("…" if s > 0 else "") + txt[s:e] + ("…" if e < len(txt) else "")


def _sanctioned(dest, allow):
    d = str(dest or "").lower()
    for p in allow:
        p = str(p or "").lower().lstrip("*")
        if p and p in d:
            return True
    return False


def _fp_has(fp, uuid, term):
    if not fp:
        return False
    if fp.get("assets", {}).get(uuid):
        return True
    if fp.get("gfw", {}).get(term):
        return True
    if fp.get("fw", {}).get(f"{uuid}|{term}"):
        return True
    return False


def _like_where(col, kws):
    return " OR ".join(f"{col} LIKE '%{_lit(k)}%'" for k in kws)


def _atlas_for(x):
    """AI-specific ATLAS techniques implied by an asset's role/exposure/egress.

    Each entry: id, name, tactic, `why` (the first reason — kept for older callers),
    `whys` (every reason that implied it) and `ev` (the concrete navi.db evidence behind
    those reasons: endpoint:port, framework, egress destination, …), so a drill-down can
    show exactly why an asset sits under a technique."""
    t = {}

    def add(i, why, ev=()):
        d = t.setdefault(i, {"whys": [], "ev": []})
        if why not in d["whys"]:
            d["whys"].append(why)
        for e in ev or ():
            if e and e not in d["ev"]:
                d["ev"].append(e)
    role = x.get("role", "")
    fws = list(x.get("frameworks", []))
    fw = " ".join(fws).lower()
    exp = x.get("exposed") or []
    exposed = bool(exp)
    unauth_eps = [e for e in exp if e.get("auth") == "unauth"]
    unauth = exposed and bool(unauth_eps)
    kev = bool(x.get("risk", {}).get("kev"))
    eg = x.get("egress") or []
    egress = bool(eg)
    shadow_eg = [e for e in eg if not e.get("sanctioned")]
    shadow = egress and bool(shadow_eg)
    llm_rx = (r"ollama|vllm|llama|gpt|openai|anthropic|localai|text-generation|lm studio|open webui|"
              r"mistral|cohere|gemini|langchain|llamaindex|litellm|cursor|copilot|claude|tabnine|"
              r"codeium|windsurf|aider|cody")
    llm_fws = [f for f in fws if re.search(llm_rx, f.lower())]
    is_llm = bool(re.search(llm_rx, fw)) or role in ("LLM API Client", "Model Serving", "AI Dev Tool")
    hub_fws = [f for f in fws if re.search(r"hugging|transformers|sentencetransformers", f.lower())]
    hub_eg = [e for e in eg if e.get("cat") == "Model Hub"]
    model_hub = bool(hub_fws) or bool(hub_eg)
    ep = lambda e: f"{e.get('name')}:{e.get('port')}" + (" unauth" if e.get("auth") == "unauth" else "")
    dst = lambda e: f"→ {e.get('dest')}" + ("" if e.get("sanctioned") else " (shadow)")
    exp_ev = [ep(e) for e in exp]
    add("AML.T0047", "Runs an ML-enabled service", fws[:4])
    add("AML.T0043", "Model can be probed with adversarial inputs", fws[:4])
    if role == "Model Serving" or exposed:
        ev = exp_ev or [f"role: {role}"]
        add("AML.T0040", "Serves/exposes a model inference API", ev)
        add("AML.T0031", "Model integrity can be eroded via the serving path", ev)
    if exposed:
        add("AML.T0049", "Public-facing AI endpoint is an initial-access vector", exp_ev)
    if unauth:
        add("AML.T0012", "Unauthenticated endpoint = access without valid accounts", [ep(e) for e in unauth_eps])
        add("AML.T0034", "Open inference API can be abused for cost/resource harvesting", [ep(e) for e in unauth_eps])
    if kev:
        add("AML.T0049", "Carries a CISA-KEV (actively exploited) vuln", ["CISA KEV finding"])
    if is_llm:
        ev = llm_fws[:4] or [f"role: {role}"]
        add("AML.T0051", "LLM is susceptible to prompt injection", ev)
        add("AML.T0054", "LLM can be jailbroken past guardrails", ev)
    if role == "Vector DB / RAG":
        add("AML.T0057", "RAG/vector store can leak embedded sensitive data", fws[:4] or [f"role: {role}"])
    if egress:
        add("AML.T0024", "Egress path enables exfiltration via the inference API", [dst(e) for e in eg][:4])
    if shadow:
        add("AML.T0025", "Unsanctioned egress = exfiltration via cyber means", [dst(e) for e in shadow_eg][:4])
    if model_hub:
        ev = hub_fws[:3] + [dst(e) for e in hub_eg][:2]
        add("AML.T0010", "Pulls models from a public hub (supply-chain risk)", ev)
        add("AML.T0018", "Downloaded models could be backdoored", ev)
    if role == "GPU / Training":
        add("AML.T0002", "Uses public ML artifacts in training", fws[:4] or [f"role: {role}"])
        add("AML.T0018", "Training pipeline could embed a model backdoor", fws[:4] or [f"role: {role}"])
    return [{"id": i, "why": d["whys"][0], "whys": d["whys"], "ev": d["ev"],
             "name": ATLAS_TECH.get(i, (i, ""))[0],
             "tactic": ATLAS_TECH.get(i, ("", "Other"))[1]} for i, d in t.items()]


def atlas_sets(assets):
    """The asset set behind every ATLAS technique and tactic, from scan() output.
    Returns {"tech": {id: set(uuid)}, "tactic": {tactic: set(uuid)}} — the single source
    the page's drill-down and the server-side tag_atlas action both use."""
    tech, tac = {}, {}
    for x in assets or []:
        u = x.get("asset_uuid")
        if not u:
            continue
        for t in x.get("atlas") or []:
            tech.setdefault(t["id"], set()).add(u)
            tac.setdefault(t.get("tactic") or "Other", set()).add(u)
    return {"tech": tech, "tactic": tac}


def _output_wheres():
    """(where3, where4): the plugin name / output arms of steps 3 and 4 — one definition shared by
    scan() and signal_predicate() (⚡ Optimize evaluates the same text)."""
    where3 = " OR ".join(f"(plugin_name LIKE '%{_lit(e[0])}%' OR output LIKE '%{_lit(e[0])}%')" for e in OUT_CATALOG)
    clauses = []
    for ep in ENDPOINTS:
        for k in ep["kw"]:
            clauses += [f"plugin_name LIKE '%{_lit(k)}%'", f"output LIKE '%{_lit(k)}%'"]
        if ep["distinct"]:
            clauses.append(f"output LIKE '%{ep['port']}%'")
    return where3, " OR ".join(clauses)


def egress_predicate(vcols):
    """The egress-hostname predicate (build 463): step "egress" reads the output of every finding on
    every AI asset looking for these hosts — 88% of the hound's run time at scale. ⚡ Optimize
    evaluates it once per sync (core/hx_signals, hound "ai_egress") in the same pass that already
    reads each finding's output for AI + Identity, so the run reads only the flagged findings."""
    if "output" not in set(vcols or ()):
        return None
    return _like_where("output", EGRESS_TERMS)


def signal_predicate(vcols):
    """The output predicate core/hx_signals pre-evaluates for this hound (None: not applicable)."""
    if not {"plugin_name", "output"} <= set(vcols or ()):
        return None
    w3, w4 = _output_wheres()
    return "(%s) OR (%s)" % (w3, w4)


def scan(db_path=None, fp=None, allow=None):
    """Discover + classify AI/ML assets. fp = suppression map {assets,fw,gfw};
    allow = egress allowlist (defaults to ALLOW_DEFAULT).
    A step stopped by its time budget no longer vanishes silently: the result says which
    steps are partial (`partial`), and a user's cancel stops the whole scan."""
    allow = allow or ALLOW_DEFAULT
    partial = []

    def _soft(e, step):
        if isinstance(e, db.QueryCancelled):
            raise e
        if isinstance(e, (db.QueryTimeout, db.TooManyRows)):
            partial.append(step)
    vcols = _cols("vulns")
    acols = _cols("assets")
    amap = {}
    for a in db.query("SELECT uuid, hostname, ip_address" + (", url" if "url" in acols else "") +
                      " FROM assets", path=db_path):
        amap[a["uuid"]] = {"host": (a.get("hostname") or a.get("ip_address") or "").strip() or "(none)",
                           "ip": a.get("ip_address") or "", "url": a.get("url") if "url" in a else ""}
    by = {}

    def slot(u):
        return by.setdefault(u, {"asset_uuid": u, "evidence": [], "plugins": [], "url": ""})

    def add_ev(u, ev):
        if not u or _fp_has(fp, u, ev.get("term")):
            return
        slot(u)["evidence"].append(ev)

    # 1) Tenable AI plugin family
    if "plugin_family" in vcols:
        try:
            ucol = ", url" if "url" in vcols else ""
            if hx_summary.usable(db_path):
                # Phase 1: family is a plugin attribute — resolve it on hx_plugin and read only those
                # plugins' findings (hx_v_plugin); rowid order keeps the evidence order of the scan.
                rws = db.query("SELECT rowid AS _rid, asset_uuid, plugin_id, plugin_name" + ucol + " FROM vulns WHERE "
                               + hx_summary.plugins_where("family LIKE '%Artificial Intelligence%'"), path=db_path)
                rws.sort(key=lambda r: r.pop("_rid"))
            else:
                rws = db.query("SELECT asset_uuid, plugin_id, plugin_name" + ucol +
                               " FROM vulns WHERE plugin_family LIKE '%Artificial Intelligence%'", path=db_path)
            for r in rws:
                u = r.get("asset_uuid")
                if not u:
                    continue
                add_ev(u, {"src": "ai-plugin", "term": r.get("plugin_name") or ("Plugin " + str(r.get("plugin_id"))),
                           "role": "Tenable AI plugin", "pid": r.get("plugin_id"),
                           "pname": r.get("plugin_name") or "", "snip": ""})
                a = by.get(u)
                if a:
                    a["plugins"].append({"plugin_id": r.get("plugin_id"), "plugin_name": r.get("plugin_name")})
                    if r.get("url") and not a["url"]:
                        a["url"] = r.get("url")
        except Exception as _e:
            _soft(_e, 'plugin family')

    # 2) software table
    if "software_string" in _cols("software"):
        try:
            for r in db.query("SELECT asset_uuid, software_string FROM software WHERE "
                              + _like_where("software_string", [e[0] for e in CATALOG]), path=db_path):
                hit = _match((r.get("software_string") or "").lower(), CATALOG)
                if not hit:
                    continue
                for u in _uuids(r.get("asset_uuid")):
                    add_ev(u, {"src": "software", "term": hit["name"], "role": hit["role"], "pid": "",
                               "pname": "software inventory", "snip": _snip(r.get("software_string"), hit["kw"])})
        except Exception as _e:
            _soft(_e, 'software inventory')

    # 3) plugin name / output (distinct AI terms; generic terms blocked)
    # 4) exposed AI endpoints — port match requires port CONTEXT, not a bare substring
    # Build 455: steps 3 and 4 used to be two full scans of vulns that both read `output` (the
    # ~5 KB column — 20 s each at 6 M findings, 60 s at 16 M). They are ONE streamed scan now:
    # the two WHERE clauses are evaluated by SQLite in the SELECT list (m3 / m4), so each row
    # set is exactly the old one; step-4 evidence is held back and added after the scan, so
    # every asset's evidence keeps the old order (all step-3 hits, then step-4 hits).
    def step3(r):
        u = r.get("asset_uuid")
        if not u:
            return
        hit = _match(((r.get("plugin_name") or "") + " " + (r.get("output") or "")).lower(), OUT_CATALOG)
        if not hit:
            return
        add_ev(u, {"src": "output", "term": hit["name"], "role": hit["role"], "pid": r.get("plugin_id") or "",
                   "pname": r.get("plugin_name") or "",
                   "snip": _snip((r.get("plugin_name") or "") + " — " + (r.get("output") or ""), hit["kw"])})

    def step4(r, out):
        u = r.get("asset_uuid")
        if not u:
            return
        hay = ((r.get("plugin_name") or "") + " " + (r.get("output") or "")).lower()
        auth = "unauth" if re.search(r"no authentication|unauthenticated|without credentials|anonymous access|"
                                     r"default password|requires no auth|no login required", hay) else ""
        try:
            rport = int(r.get("port") or 0)
        except (TypeError, ValueError):
            rport = 0
        for ep in ENDPOINTS:
            kw_hit = any(w in hay for w in ep["kw"])
            port_hit = ep["distinct"] and _port_hit(hay, ep["port"])
            # EXPOSED needs a network observation: the finding sits on a real port, or the output
            # names the service port. A keyword in local output alone is presence, not exposure.
            seen_port = str(rport) if rport else (ep["port"] if _port_hit(hay, ep["port"]) else "")
            if kw_hit and not (seen_port or port_hit):
                out.append((u, {"src": "output", "term": ep["name"], "role": ep["role"],
                                "pid": r.get("plugin_id") or "", "pname": r.get("plugin_name") or "",
                                "snip": _snip((r.get("plugin_name") or "") + " — " + (r.get("output") or ""), ep["kw"][0])}))
                continue
            if kw_hit or port_hit:
                out.append((u, {"src": "endpoint", "term": ep["name"], "role": ep["role"],
                                "pid": r.get("plugin_id") or "", "pname": r.get("plugin_name") or "",
                                "snip": _snip((r.get("plugin_name") or "") + " — " + (r.get("output") or ""),
                                              ep["kw"][0] if kw_hit else ep["port"]),
                                "port": seen_port or ep["port"], "auth": auth,
                                "sig": "service name" if kw_hit else "port " + ep["port"]}))

    if vcols:
        where3, where4 = _output_wheres()
        pcol = "port" if "port" in vcols else "NULL AS port"
        held = []
        # Phase 1b: ⚡ Optimize evaluated this exact predicate once (core/hx_signals) — read only
        # the matching findings by rowid instead of every finding's output (same rows, same order)
        hits = ""
        try:
            from core import hx_signals
            if hx_signals.usable_for("ai", signal_predicate(vcols), db_path):
                hits = hx_signals.rows_sql("ai") + " AND "
        except Exception:
            hits = ""
        try:
            for r in db.iter(f"SELECT asset_uuid, plugin_id, plugin_name, output, {pcol}, ({where3}) AS m3, "
                             f"({where4}) AS m4 FROM vulns WHERE {hits}(({where3}) OR ({where4}))", path=db_path):
                if r.get("m3"):
                    step3(r)
                if r.get("m4"):
                    step4(r, held)
        except Exception as _e:
            _soft(_e, 'plugin output / endpoints')
        for u, ev in held:
            add_ev(u, ev)

    # 5) CPE inventory — match on :product boundary
    if "cpe_string" in _cols("cpes"):
        try:
            where = " OR ".join(f"cpe_string LIKE '%:{_lit(e[0])}%'" for e in CPE_ALL)
            seen = set()
            for r in db.query(f"SELECT asset_uuid, cpe_string FROM cpes WHERE {where}", path=db_path):
                u = r.get("asset_uuid")
                if not u:
                    continue
                s = str(r.get("cpe_string") or "").lower()
                for kw, role, name in CPE_ALL:
                    if _cpe_boundary(kw, s):
                        key = f"{u}|{name}"
                        if key not in seen:
                            seen.add(key)
                            add_ev(u, {"src": "cpe", "term": name, "role": role, "pid": "",
                                       "pname": "CPE inventory", "snip": _snip(r.get("cpe_string"), ":" + kw)})
        except Exception as _e:
            _soft(_e, 'CPE inventory')

    # ---- assemble assets ----
    assets = []
    for u, a in by.items():
        if not a["evidence"]:
            continue
        info = amap.get(u, {})
        role_cnt = {}
        for e in a["evidence"]:
            role_cnt[e["role"]] = role_cnt.get(e["role"], 0) + 1
        role = sorted(role_cnt, key=lambda r: (-(ROLE_PRI.get(r, 0)), -role_cnt[r]))[0] if role_cnt else "AI"
        fws = list(dict.fromkeys(e["term"] for e in a["evidence"] if e["src"] != "ai-plugin"))
        if not fws and a["plugins"]:
            fws = [(p.get("plugin_name") or ("#" + str(p.get("plugin_id")))) for p in a["plugins"][:4]]
        exp = {}
        for e in a["evidence"]:
            if e["src"] == "endpoint":
                if e["term"] not in exp or e.get("auth"):
                    exp[e["term"]] = {"port": e.get("port"), "auth": e.get("auth")}
        assets.append({"asset_uuid": u, "host": info.get("host", "(none)"), "ip": info.get("ip", ""),
                       "url": a["url"] or info.get("url"), "role": role, "roles": list(role_cnt),
                       "frameworks": fws, "plugins": a["plugins"], "sources": list({e["src"] for e in a["evidence"]}),
                       "evidence": a["evidence"],
                       "exposed": [{"name": n, "port": v["port"], "auth": v["auth"]} for n, v in exp.items()]})
    assets.sort(key=lambda x: (-(ROLE_PRI.get(x["role"], 0)), -len(x["frameworks"])))

    # ---- risk (KEV / critical / VPR / EOL / MITRE ATT&CK) ----
    if assets and vcols:
        inl = ",".join("'" + _lit(x["asset_uuid"]) + "'" for x in assets)
        rk = {}
        try:
            sev_col = "severity" if "severity" in vcols else "'0'"
            score_col = "score" if "score" in vcols else ("vpr" if "vpr" in vcols else "0")
            # EOL / unsupported is a finding signal, same idea as KEV — Tenable's
            # unsupported-product plugins name the product as end-of-life.
            eol_like = ("lower(plugin_name) LIKE '%unsupported%' OR lower(plugin_name) LIKE '%end of life%' "
                        "OR lower(plugin_name) LIKE '%end-of-life%' OR lower(plugin_name) LIKE '%no longer supported%'")
            if hx_summary.usable(db_path):
                # Phase 1 (S23): index-only over hx_v_asset (asset_uuid, plugin_id, state, severity) —
                # no vulns rows. KEV / EOL / VPR are plugin attributes → hx_plugin (EOL with THIS
                # hound's own name rule on lname); critical stays per finding from the index.
                # All states, like the query below.
                rq = (f"SELECT v.asset_uuid, MAX(p.kev) kev, "
                      f"MAX(CASE WHEN lower(v.severity)='critical' OR v.severity='4' THEN 1 ELSE 0 END) crit, "
                      f"MAX(CASE WHEN {eol_like.replace('lower(plugin_name)', 'p.lname')} THEN 1 ELSE 0 END) eol, "
                      f"MAX(p.vpr) vpr FROM vulns v{db.indexed_by('hx_v_asset', db_path)} "
                      f"LEFT JOIN hx_plugin p ON p.plugin_id = v.plugin_id "
                      f"WHERE v.asset_uuid IN ({inl}) GROUP BY v.asset_uuid")
            else:
                rq = (f"SELECT asset_uuid, "
                      f"MAX(CASE WHEN xrefs LIKE '%CISA-KNOWN-EXPLOITED%' THEN 1 ELSE 0 END) kev, "
                      f"MAX(CASE WHEN lower({sev_col})='critical' OR {sev_col}='4' THEN 1 ELSE 0 END) crit, "
                      f"MAX(CASE WHEN {eol_like} THEN 1 ELSE 0 END) eol, "
                      f"MAX(CAST({score_col} AS REAL)) vpr FROM vulns{_bulk_hint(len(assets), db_path)} "
                      f"WHERE asset_uuid IN ({inl}) GROUP BY asset_uuid")
            for r in db.query(rq, path=db_path):
                rk[r["asset_uuid"]] = {"kev": int(r.get("kev") or 0), "crit": int(r.get("crit") or 0),
                                       "eol": int(r.get("eol") or 0), "vpr": float(r.get("vpr") or 0)}
        except Exception as _e:
            _soft(_e, 'risk rollup')
        # MITRE ATT&CK techniques (Orthrus) + Lifecycle/EOL tags (Charon) the pack has applied
        mit, eol_tag = {}, set()
        try:
            for r in db.query(f"SELECT asset_uuid, tag_key, tag_value FROM tags WHERE asset_uuid IN ({inl}) "
                              "AND " + tagname.sql_lit("tag_key", "Mitre", "Lifecycle"), path=db_path):
                if tagname.base(r.get("tag_key") or "") == "Mitre":     # plain or test-run name
                    mit.setdefault(r["asset_uuid"], []).append((r.get("tag_value") or "").strip())
                else:
                    eol_tag.add(r.get("asset_uuid"))
        except Exception as _e:
            _soft(_e, 'tags (MITRE / EOL)')
        for x in assets:
            base = rk.get(x["asset_uuid"], {"kev": 0, "crit": 0, "eol": 0, "vpr": 0})
            techs = sorted({t for t in mit.get(x["asset_uuid"], []) if t})
            base["eol"] = 1 if (base.get("eol") or x["asset_uuid"] in eol_tag) else 0
            base["mitre"] = 1 if techs else 0
            x["risk"] = base
            x["mitre_techniques"] = techs
    else:
        for x in assets:
            x["risk"] = {"kev": 0, "crit": 0, "eol": 0, "vpr": 0, "mitre": 0}
            x["mitre_techniques"] = []

    # ---- egress (capability + observed) ----
    for x in assets:
        eg = {}
        for fw in x["frameworks"]:
            m = EGRESS.get(fw)
            if m:
                eg[m[0] + "|" + m[1]] = {"cat": m[0], "dest": m[1], "via": "capability", "snip": ""}
        x["_eg"] = eg
    if assets and vcols:
        inl = ",".join("'" + _lit(x["asset_uuid"]) + "'" for x in assets)
        idx = {x["asset_uuid"]: x for x in assets}
        try:
            where = egress_predicate(vcols) or _like_where("output", EGRESS_TERMS)
            # Build 463: ⚡ Optimize flagged the findings whose output names an egress host (same
            # predicate) — read only those by rowid; the AI-asset filter is the idx lookup below.
            # Within an asset rows still come in rowid order, as the asset_uuid index gave them,
            # so the same snippet wins. Fallback: every finding of every AI asset, as before.
            fast = False
            try:
                from core import hx_signals
                fast = hx_signals.usable_for("ai_egress", where, db_path)
            except Exception:
                fast = False
            if fast:
                sql = (f"SELECT asset_uuid, output FROM vulns WHERE {hx_signals.rows_sql('ai_egress')} "
                       f"AND ({where})")
            else:
                sql = f"SELECT asset_uuid, output FROM vulns WHERE asset_uuid IN ({inl}) AND ({where})"
            for r in db.iter(sql, path=db_path):
                x = idx.get(r.get("asset_uuid"))
                if not x:
                    continue
                out = str(r.get("output") or "")
                for rx, cat, dest in EGRESS_HOSTS:
                    m = rx.search(out)
                    if m:
                        x["_eg"][cat + "|" + dest] = {"cat": cat, "dest": dest, "via": "observed",
                                                      "snip": _snip(out, m.group(0))}
        except Exception:
            pass
    for x in assets:
        x["egress"] = [{"cat": e["cat"], "dest": e["dest"], "via": e["via"], "snip": e["snip"],
                        "sanctioned": _sanctioned(e["dest"], allow)} for e in x["_eg"].values()]
        x.pop("_eg", None)
        x["atlas"] = _atlas_for(x)

    by_role = {}
    for x in assets:
        by_role[x["role"]] = by_role.get(x["role"], 0) + 1
    return {"ok": True, "assets": assets, "asset_count": len(assets), "byRole": by_role,
            "exposedCount": sum(1 for x in assets if x["exposed"]),
            "kevCount": sum(1 for x in assets if x["risk"]["kev"]),
            "eolCount": sum(1 for x in assets if x["risk"].get("eol")),
            "mitreCount": sum(1 for x in assets if x["risk"].get("mitre")),
            "egressCount": sum(1 for x in assets if x["egress"]),
            "shadowCount": sum(1 for x in assets if any(not e["sanctioned"] for e in x["egress"])),
            "role_acr": ROLE_ACR, "allow": list(allow),
            "atlas_tactic_order": ATLAS_TACTIC_ORDER,
            "partial": partial,
            **({"budget_partial": True,
                "budget_message": "stopped at its time budget: " + ", ".join(partial)
                                  + " — the inventory may be missing assets those steps would add"}
               if partial else {})}


# ---- gated tag helper (used by api.py) --------------------------------------
def tag_uuids(category, value, uuids, agent="ai"):
    """A Python-computed AI asset set → core.navi_cli.tag_uuids_batched (≤1,999 UUIDs per navi
    job, add-only). Returns the first job stub plus {jobs, job_ids} for the whole series."""
    from core import navi_cli
    uu = [u for u in (uuids or []) if u]
    if not uu:
        return {"ok": False, "message": "no asset uuids supplied"}
    jobs = navi_cli.tag_uuids_batched(category, value, uu, agent=agent)
    sm = navi_cli.jobs_summary(jobs)
    return {**(sm["result"] or {}), "jobs": sm["jobs"], "job_ids": sm["job_ids"]}
