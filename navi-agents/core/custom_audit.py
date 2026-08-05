"""Draco — the custom .audit authoring engine.

Turns a structured check spec (or a Claude-drafted one) into a valid Tenable
Nessus ``.audit`` file you can drop into a compliance scan. Two producers feed it:
the natural-language box (via core.llm.audit_plan) and the guided builder (the
platform catalog below). Everything renders through render_file() and is checked
by validate() so what you download actually loads.

Scope (v1): Windows (config) and Unix/Linux/macOS — the two deepest platforms.
Check-type vocabulary is grounded in the navi-audit-platforms skill; the .audit
grammar (custom_item fields, quoting, group_policy wrapper) follows Tenable's
Compliance Checks reference.
"""
import re

# Frameworks we auto-map to (the reference: tag uses "FRAMEWORK|CONTROL,...").
FRAMEWORKS = ["800-53", "PCI-DSSv3.2.1", "HIPAA", "CSCv8", "ISO/IEC-27001"]

# ---------------------------------------------------------------------------
# Platform catalog — check types + their keywords. Drives the guided builder and
# constrains the LLM. Field: {key, label, required, enum?, example?, token?}.
# token=True means the value is a bare .audit token (never quoted).
# ---------------------------------------------------------------------------
_VALUE_TYPE = ["POLICY_DWORD", "POLICY_TEXT", "POLICY_SET", "POLICY_MULTI_TEXT"]
# In-item comparison operator (the `check_type:` keyword INSIDE a custom_item — not the
# file-level wrapper). Used by WMI_POLICY, AUDIT_POWERSHELL, and other output checks.
_CHECK_OP = ["CHECK_EQUAL", "CHECK_NOT_EQUAL", "CHECK_REGEX", "CHECK_GREATER_THAN",
             "CHECK_GREATER_THAN_OR_EQUAL", "CHECK_LESS_THAN", "CHECK_LESS_THAN_OR_EQUAL"]

CATALOG = {
    "Windows": {
        "label": "Windows (config)",
        "check_type": '<check_type:"Windows" version:"2">',
        "group": True,   # wrap items in <group_policy:"...">
        "types": {
            "REGISTRY_SETTING": {
                "desc": "Check a Windows registry value.",
                "fields": [
                    {"key": "reg_key", "label": "Registry key", "required": True,
                     "example": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"},
                    {"key": "reg_item", "label": "Value name", "required": True, "example": "EnableLUA"},
                    {"key": "value_type", "label": "Value type", "required": True,
                     "enum": _VALUE_TYPE, "token": True, "example": "POLICY_DWORD"},
                    {"key": "value_data", "label": "Expected value", "required": True, "example": "1"},
                    {"key": "reg_option", "label": "Presence", "required": False, "token": True,
                     "enum": ["CANNOT_BE_NULL", "CAN_BE_NULL", "MUST_EXIST"]},
                ],
            },
            "PASSWORD_POLICY": {
                "desc": "Check a local/domain password policy setting.",
                "fields": [
                    {"key": "password_policy", "label": "Policy setting", "required": True,
                     "enum": ["MinimumPasswordLength", "MaximumPasswordAge", "MinimumPasswordAge",
                              "PasswordHistorySize", "PasswordComplexity", "ClearTextPassword",
                              "ForceLogoffWhenHourExpire", "LSAAnonymousNameLookup"],
                     "example": "MinimumPasswordLength"},
                    {"key": "value_type", "label": "Value type", "required": True, "token": True,
                     "enum": _VALUE_TYPE, "example": "POLICY_DWORD"},
                    {"key": "value_data", "label": "Expected value", "required": True, "example": "14"},
                ],
            },
            "LOCKOUT_POLICY": {
                "desc": "Check an account lockout policy setting.",
                "fields": [
                    {"key": "lockout_policy", "label": "Lockout setting", "required": True,
                     "enum": ["LockoutBadCount", "ResetLockoutCount", "LockoutDuration"],
                     "example": "LockoutBadCount"},
                    {"key": "value_type", "label": "Value type", "required": True, "token": True,
                     "enum": _VALUE_TYPE, "example": "POLICY_DWORD"},
                    {"key": "value_data", "label": "Expected value", "required": True, "example": "5"},
                ],
            },
            "AUDIT_POLICY_SUBCATEGORY": {
                "desc": "Check an advanced audit-policy subcategory.",
                "fields": [
                    {"key": "audit_policy_subcategory", "label": "Subcategory", "required": True,
                     "example": "Credential Validation"},
                    {"key": "value_data", "label": "Setting", "required": True, "token": False,
                     "enum": ["No Auditing", "Success", "Failure", "Success, Failure"],
                     "example": "Success, Failure"},
                ],
            },
            "USER_RIGHTS_POLICY": {
                "desc": "Check who holds a Windows user right.",
                "fields": [
                    {"key": "right_type", "label": "User right", "required": True,
                     "example": "SeRemoteInteractiveLogonRight"},
                    {"key": "value_data", "label": "Allowed principals", "required": True,
                     "example": "Administrators"},
                ],
            },
            "SERVICE_POLICY": {
                "desc": "Check a Windows service start mode.",
                "fields": [
                    {"key": "service_name", "label": "Service name", "required": True, "example": "RemoteRegistry"},
                    {"key": "value_data", "label": "Start mode", "required": True,
                     "enum": ["Disabled", "Manual", "Automatic", "Automatic (Delayed Start)"],
                     "example": "Disabled"},
                ],
            },
            "REG_CHECK": {
                "desc": "Check that a registry key exists (or must not exist).",
                "fields": [
                    {"key": "reg_key", "label": "Registry key", "required": True,
                     "example": "HKLM\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client"},
                    {"key": "reg_option", "label": "Presence", "required": True, "token": True,
                     "enum": ["MUST_EXIST", "MUST_NOT_EXIST"], "example": "MUST_EXIST"},
                    {"key": "reg_item", "label": "Value name (optional)", "required": False, "example": "AllowBasic"},
                ],
            },
            "AUDIT_POLICY": {
                "desc": "Check a legacy category-level audit policy.",
                "fields": [
                    {"key": "audit_policy", "label": "Audit category", "required": True,
                     "example": "Audit account logon events"},
                    {"key": "value_data", "label": "Setting", "required": True,
                     "enum": ["No auditing", "Success", "Failure", "Success, Failure"], "example": "Success, Failure"},
                ],
            },
            "WMI_POLICY": {
                "desc": "Check a value returned by a WMI (WQL) query.",
                "fields": [
                    {"key": "wmi_namespace", "label": "WMI namespace", "required": True, "example": "root/cimv2"},
                    {"key": "wmi_request", "label": "WQL query", "required": True,
                     "example": "SELECT DNSHostName FROM Win32_ComputerSystem"},
                    {"key": "wmi_attribute", "label": "Attribute", "required": True, "example": "DNSHostName"},
                    {"key": "wmi_key", "label": "Key attribute", "required": True, "example": "DNSHostName"},
                    {"key": "value_type", "label": "Value type", "required": True, "token": True,
                     "enum": _VALUE_TYPE, "example": "POLICY_TEXT"},
                    {"key": "value_data", "label": "Expected value", "required": True, "example": ".+"},
                    {"key": "check_type", "label": "Comparison", "required": False, "token": True, "enum": _CHECK_OP},
                ],
            },
            "AUDIT_POWERSHELL": {
                "desc": "Run a PowerShell expression and check its output.",
                "fields": [
                    {"key": "powershell_args", "label": "PowerShell expression", "required": True,
                     "example": "Get-MpComputerStatus | Select -ExpandProperty RealTimeProtectionEnabled"},
                    {"key": "value_type", "label": "Value type", "required": True, "token": True,
                     "enum": _VALUE_TYPE, "example": "POLICY_TEXT"},
                    {"key": "value_data", "label": "Expected value", "required": True, "example": "True"},
                    {"key": "check_type", "label": "Comparison", "required": False, "token": True, "enum": _CHECK_OP},
                    {"key": "only_show_cmd_output", "label": "Only show output", "required": False,
                     "token": True, "enum": ["YES", "NO"]},
                ],
            },
        },
    },
    "WindowsFiles": {
        "label": "Windows (file content)",
        "check_type": '<check_type:"WindowsFiles">',
        "group": True,
        "types": {
            "FILE_CONTENT_CHECK": {
                "desc": "Require a regex to MATCH inside files of a given type.",
                "fields": [
                    {"key": "file_extension", "label": "File extension", "required": True, "example": "xml"},
                    {"key": "regex", "label": "Regex", "required": True, "example": "PermitEmptyPasswords"},
                    {"key": "expect", "label": "Expected match", "required": True, "example": "PermitEmptyPasswords\\s+no"},
                    {"key": "file_name", "label": "File name (optional)", "required": False, "example": "unattend.xml"},
                ],
            },
            "FILE_CONTENT_CHECK_NOT": {
                "desc": "Require a regex to NOT match inside files of a given type.",
                "fields": [
                    {"key": "file_extension", "label": "File extension", "required": True, "example": "config"},
                    {"key": "regex", "label": "Regex (must be absent)", "required": True, "example": "(?i)password\\s*="},
                ],
            },
        },
    },
    "Unix": {
        "label": "Unix / Linux / macOS",
        "check_type": '<check_type:"Unix">',
        "group": False,
        "types": {
            "FILE_CHECK": {
                "desc": "Check a file's owner, group, and mode.",
                "fields": [
                    {"key": "file", "label": "File path", "required": True, "example": "/etc/ssh/sshd_config"},
                    {"key": "owner", "label": "Owner", "required": False, "example": "root"},
                    {"key": "group", "label": "Group", "required": False, "example": "root"},
                    {"key": "mode", "label": "Mode (octal)", "required": False, "example": "0600"},
                ],
            },
            "FILE_CONTENT_CHECK": {
                "desc": "Require a regex to MATCH in a file's contents.",
                "fields": [
                    {"key": "file", "label": "File path", "required": True, "example": "/etc/ssh/sshd_config"},
                    {"key": "regex", "label": "Regex (locate the line)", "required": True,
                     "hint": "regex that LOCATES the line", "example": "^\\s*PermitRootLogin"},
                    {"key": "expect", "label": "Expected content (regex)", "required": True,
                     "hint": "regex the found line MUST match — a pattern, never true/false",
                     "example": "^\\s*PermitRootLogin\\s+no"},
                ],
            },
            "FILE_CONTENT_CHECK_NOT": {
                "desc": "Require a regex to NOT match in a file's contents.",
                "fields": [
                    {"key": "file", "label": "File path", "required": True, "example": "/etc/shadow"},
                    {"key": "regex", "label": "Regex (must be absent)", "required": True, "example": "^\\+:"},
                ],
            },
            "CMD_EXEC": {
                "desc": "Run a command and match its output.",
                "fields": [
                    {"key": "cmd", "label": "Command", "required": True, "example": "/sbin/sysctl net.ipv4.ip_forward"},
                    {"key": "expect", "label": "Expected output (regex)", "required": True,
                     "hint": "regex over the command's stdout — a pattern, never true/false",
                     "example": "net.ipv4.ip_forward = 0"},
                    {"key": "dont_expect", "label": "Must NOT match (regex)", "required": False,
                     "hint": "regex that must NOT appear in stdout"},
                ],
            },
            "RPM_CHECK": {
                "desc": "Check an installed RPM version.",
                "fields": [
                    {"key": "rpm", "label": "RPM (name-version-release)", "required": True, "example": "openssl-1.1.1k-0"},
                    {"key": "operator", "label": "Operator", "required": True, "token": True,
                     "enum": ["gte", "gt", "lte", "lt", "eq"], "example": "gte"},
                ],
            },
            "PROCESS_CHECK": {
                "desc": "Check whether a process is running.",
                "fields": [
                    {"key": "proc", "label": "Process name", "required": True, "example": "auditd"},
                    {"key": "status", "label": "Status", "required": True, "token": True,
                     "enum": ["ON", "OFF"], "example": "ON"},
                ],
            },
            "SVC_PROP": {
                "desc": "Check a systemd service property.",
                "fields": [
                    {"key": "service", "label": "Service", "required": True, "example": "auditd"},
                    {"key": "property", "label": "Property", "required": True, "example": "ActiveState"},
                    {"key": "value", "label": "Expected value", "required": True, "example": "active"},
                ],
            },
            "CHKCONFIG": {
                "desc": "Check a SysV service run-level status.",
                "fields": [
                    {"key": "service", "label": "Service", "required": True, "example": "telnet"},
                    {"key": "level", "label": "Run level", "required": True, "example": "3"},
                    {"key": "status", "label": "Status", "required": True, "token": True,
                     "enum": ["ON", "OFF"], "example": "OFF"},
                ],
            },
        },
    },
}

# Field order for the fixed (non-type-specific) parts of a custom_item.
_TOKEN_KEYS = {"value_type", "reg_option", "status", "operator", "check_type"}


def platforms() -> dict:
    """The catalog the guided builder + LLM constrain to."""
    return {"frameworks": FRAMEWORKS, "platforms": [
        {"id": pid, "label": p["label"],
         "types": [{"type": t, "desc": d["desc"], "fields": d["fields"]}
                   for t, d in p["types"].items()]}
        for pid, p in CATALOG.items()]}


def _q(v) -> str:
    """Quote a value for .audit (integers and empty stay bare; strings get quotes)."""
    s = "" if v is None else str(v)
    if re.fullmatch(r"-?\d+", s):
        return s
    return '"%s"' % s.replace('"', "'")


def _line(key, val, token=False):
    val = "" if val is None else str(val)
    if val == "":
        return None
    rendered = val if token else _q(val)
    return "    %-16s: %s" % (key, rendered)


def _refs_str(references) -> str:
    parts = []
    for r in references or []:
        fw = (r.get("framework") or "").strip()
        ctrl = (r.get("control") or "").strip()
        if fw and ctrl:
            parts.append("%s|%s" % (fw, ctrl))
    return ",".join(parts)


def render_check(platform: str, spec: dict) -> str:
    """One <custom_item> block from a spec:
       {type, description, info, fields:{...}, solution, references:[{framework,control}], see_also}."""
    pdef = CATALOG.get(platform) or {}
    tdef = (pdef.get("types") or {}).get(spec.get("type") or "")
    lines = ["<custom_item>"]
    lines.append(_line("type", spec.get("type"), token=True))
    lines.append(_line("description", spec.get("description") or spec.get("type") or "check"))
    if spec.get("info"):
        lines.append(_line("info", spec.get("info")))
    fields = spec.get("fields") or {}
    # Emit the type's declared fields in catalog order (keeps a valid, tidy shape).
    seen = set()
    for f in (tdef.get("fields") if tdef else []):
        k = f["key"]
        seen.add(k)
        if k in fields and str(fields[k]).strip() != "":
            lines.append(_line(k, fields[k], token=f.get("token", False)))
    # Any extra fields the model returned that we don't model — pass through quoted.
    for k, v in fields.items():
        if k not in seen and str(v).strip() != "":
            lines.append(_line(k, v, token=k in _TOKEN_KEYS))
    if spec.get("solution"):
        lines.append(_line("solution", spec.get("solution")))
    refs = _refs_str(spec.get("references"))
    if refs:
        lines.append(_line("reference", refs))
    if spec.get("see_also"):
        lines.append(_line("see_also", spec.get("see_also")))
    lines.append("</custom_item>")
    return "\n".join(x for x in lines if x is not None)


def _render_block(platform, c):
    """A check may be a structured spec, or carry a verbatim `raw` block (an
    uploaded/pasted <custom_item> or preserved structural text) — emit raw as-is."""
    raw = (c or {}).get("raw")
    if raw and str(raw).strip():
        return str(raw).strip("\n")
    return render_check(platform, c)


def render_file(meta: dict, checks: list) -> str:
    """Full .audit text: header comment + check_type wrapper (+ group_policy).

    meta may override the opening wrapper + group flag so an UPLOADED file
    round-trips against its own header:
      platform — a catalog id (Windows/WindowsFiles/Unix) or falsy for a custom/
                 uploaded wrapper.
      wrapper  — exact opening ``<check_type ...>`` line (preserved on upload).
      group    — bool; whether to wrap items in <group_policy>.
    """
    meta = meta or {}
    platform = meta.get("platform") or None
    pdef = CATALOG.get(platform) if platform else None
    title = (meta.get("title") or "Custom Audit").strip()
    wrapper = meta.get("wrapper") or (pdef["check_type"] if pdef else CATALOG["Unix"]["check_type"])
    group = meta.get("group") if meta.get("group") is not None else (pdef["group"] if pdef else False)
    label = pdef["label"] if pdef else "custom (uploaded wrapper)"
    body = [_render_block(platform, c) for c in (checks or [])]
    out = []
    out.append("#")
    out.append("# %s" % title)
    out.append("# Custom .audit — edited with The Hounds · Draco")
    out.append("# Platform: %s" % label)
    out.append("#")
    out.append(wrapper)
    if group:
        out.append('<group_policy:"%s">' % title.replace('"', "'"))
    out.append("")
    out.append("\n\n".join(body) if body else "# (no checks yet)")
    out.append("")
    if group:
        out.append("</group_policy>")
    out.append("</check_type>")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Parse an uploaded .audit into editable checks (each custom_item preserved
# verbatim) so the user can quickly remove checks or add new ones and re-download.
# ---------------------------------------------------------------------------
_WRAPPER_PLATFORM = [
    (re.compile(r'check_type\s*:\s*"WindowsFiles"', re.I), "WindowsFiles"),
    (re.compile(r'check_type\s*:\s*"Windows"', re.I), "Windows"),
    (re.compile(r'check_type\s*:\s*"(Unix|FileContent)"', re.I), "Unix"),
]


def _parse_item(block: str) -> dict:
    """block = full <custom_item>...</custom_item> text. Parse the display fields;
    keep the whole block as raw so re-rendering reproduces it exactly."""
    inner = re.search(r"<custom_item>(.*?)</custom_item>", block, re.S)
    body = inner.group(1) if inner else block
    spec = {"kind": "item", "raw": block.strip("\n"), "fields": {}, "references": []}
    for m in re.finditer(r"^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*:[ \t]*(.*?)[ \t]*$", body, re.M):
        key, val = m.group(1), m.group(2).strip()
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1]
        if key == "type":
            spec["type"] = val
        elif key == "description":
            spec["description"] = val
        elif key == "info":
            spec["info"] = val
        elif key == "solution":
            spec["solution"] = val
        elif key == "see_also":
            spec["see_also"] = val
        elif key == "reference":
            for part in val.split(","):
                if "|" in part:
                    fw, ctrl = part.split("|", 1)
                    spec["references"].append({"framework": fw.strip(), "control": ctrl.strip()})
        else:
            spec["fields"][key] = val
    spec.setdefault("type", "custom_item")
    spec.setdefault("description", "")
    return spec


def parse(text: str) -> dict:
    """Turn uploaded .audit text into {platform, wrapper, title, group, checks[...]}.
    Every <custom_item> becomes a removable check (raw-preserved); non-item content
    between items is kept as raw blocks so structure survives a round-trip."""
    text = text or ""
    wm = re.search(r"<check_type\s*:[^>]*>", text, re.I)
    if not wm:
        return {"ok": False, "error": "no <check_type:...> wrapper found — is this a .audit file?"}
    wrapper = wm.group(0)
    platform = None
    for rx, pid in _WRAPPER_PLATFORM:
        if rx.search(wrapper):
            platform = pid
            break
    gm = re.search(r'<group_policy\s*:\s*"([^"]*)"\s*>', text, re.I)
    title = (gm.group(1) if gm else "").strip()
    group = bool(gm)
    # Body = between the wrapper (or the group_policy open) and the final </check_type>.
    start = (gm.end() if gm else wm.end())
    cend = text.rfind("</check_type>")
    body = text[start:cend if cend != -1 else len(text)]
    body = re.sub(r"</group_policy>\s*$", "", body.strip())
    checks, items, unknown = [], 0, set()
    known = {t for p in CATALOG.values() for t in p["types"]}
    parts = re.split(r"(<custom_item>.*?</custom_item>)", body, flags=re.S)
    for seg in parts:
        if seg.strip() == "":
            continue
        if seg.strip().startswith("<custom_item>"):
            spec = _parse_item(seg)
            items += 1
            if spec.get("type") not in known:
                unknown.add(spec.get("type"))
            checks.append(spec)
        else:
            # structural content between items (comments, <if>/<report>…) — preserve verbatim
            checks.append({"kind": "raw", "raw": seg.strip("\n"),
                           "type": "(raw)", "description": _raw_label(seg)})
    if not title:
        title = "Imported Audit"
    return {"ok": True, "platform": platform, "wrapper": wrapper, "title": title,
            "group": group, "checks": checks,
            "counts": {"items": items, "raw": sum(1 for c in checks if c.get("kind") == "raw"),
                       "unknown_types": sorted(t for t in unknown if t)}}


def _raw_label(seg: str) -> str:
    s = seg.strip()
    m = re.match(r"<\s*([a-zA-Z_]+)", s)
    if m:
        return "<%s> block" % m.group(1)
    if s.startswith("#"):
        return "comment"
    return "raw text"


# ---------------------------------------------------------------------------
# Validation — catch the mistakes that stop a file loading in a scan.
# ---------------------------------------------------------------------------
def validate(text: str) -> dict:
    text = text or ""
    errors, warnings = [], []
    if "<check_type:" not in text:
        errors.append("missing an opening <check_type:...> wrapper.")
    if text.count("<check_type:") != text.count("</check_type>"):
        errors.append("unbalanced <check_type> / </check_type>.")
    if text.count("<group_policy") != text.count("</group_policy>"):
        errors.append("unbalanced <group_policy> / </group_policy>.")
    opens = text.count("<custom_item>")
    closes = text.count("</custom_item>")
    if opens != closes:
        errors.append("unbalanced <custom_item> / </custom_item> (%d open, %d close)." % (opens, closes))
    blocks = re.findall(r"<custom_item>(.*?)</custom_item>", text, re.S)
    if not blocks:
        warnings.append("no <custom_item> checks found — add at least one.")
    known_types = {t for p in CATALOG.values() for t in p["types"]}
    # A type name (e.g. FILE_CONTENT_CHECK) can exist on more than one platform with
    # different required fields — scope the per-type checks to THIS file's wrapper.
    wm = re.search(r"<check_type\s*:[^>]*>", text, re.I)
    plat = None
    if wm:
        for rx, pid in _WRAPPER_PLATFORM:
            if rx.search(wm.group(0)):
                plat = pid
                break

    def _type_def(typ):
        if plat and typ in CATALOG.get(plat, {}).get("types", {}):
            return CATALOG[plat]["types"][typ]
        for pdef in CATALOG.values():
            if typ in pdef["types"]:
                return pdef["types"][typ]
        return None

    for i, b in enumerate(blocks, 1):
        def _get(key):
            m = re.search(r"^\s*%s\s*:\s*(.+?)\s*$" % re.escape(key), b, re.M)
            return m.group(1).strip().strip('"') if m else None
        typ = _get("type")
        if not typ:
            errors.append("check #%d: missing 'type'." % i)
            continue
        if typ not in known_types:
            warnings.append("check #%d: type '%s' isn't in Draco's v1 catalog — verify it's valid for the platform." % (i, typ))
        if not _get("description"):
            errors.append("check #%d (%s): missing 'description'." % (i, typ))
        # light per-type required-field checks (scoped to the file's platform)
        td = _type_def(typ)
        if td:
            for f in td["fields"]:
                if f.get("required") and not _get(f["key"]):
                    errors.append("check #%d (%s): missing required '%s'." % (i, typ, f["key"]))
        ref = _get("reference")
        if ref and not re.search(r"[^|,]+\|[^|,]+", ref):
            warnings.append("check #%d: reference should look like 'FRAMEWORK|CONTROL,...'." % i)
        # content/command checks: `expect` is a regex over the text, never a boolean
        if typ in ("FILE_CONTENT_CHECK", "CMD_EXEC"):
            exp = (_get("expect") or "").strip().lower()
            if exp in ("true", "false", "yes", "no"):
                warnings.append("check #%d (%s): 'expect' should be the regex the content must "
                                "match (e.g. '^\\s*PermitRootLogin\\s+no'), not '%s'." % (i, typ, exp))
    return {"ok": not errors, "errors": errors, "warnings": warnings, "checks": len(blocks)}


# ---------------------------------------------------------------------------
# Rule-based framework auto-map — the fallback the guided builder uses, and a
# floor under the LLM's suggestions. Keyword → likely controls.
# ---------------------------------------------------------------------------
_MAP = [
    (r"password|passwd|complexity|min.*length|history", [
        ("800-53", "IA-5"), ("PCI-DSSv3.2.1", "8.2.3"), ("CSCv8", "5.2"), ("ISO/IEC-27001", "A.9.4.3")]),
    (r"lockout|failed.*logon|bad.*count", [
        ("800-53", "AC-7"), ("PCI-DSSv3.2.1", "8.1.6"), ("CSCv8", "6.2")]),
    (r"audit|logging|log\b|event log", [
        ("800-53", "AU-2"), ("PCI-DSSv3.2.1", "10.2"), ("CSCv8", "8.2"), ("ISO/IEC-27001", "A.12.4.1")]),
    (r"firewall|ip_forward|routing|listen|port", [
        ("800-53", "SC-7"), ("PCI-DSSv3.2.1", "1.3"), ("CSCv8", "4.4")]),
    (r"encrypt|tls|ssl|cipher|fips", [
        ("800-53", "SC-8"), ("PCI-DSSv3.2.1", "4.1"), ("CSCv8", "3.10"), ("ISO/IEC-27001", "A.10.1.1")]),
    (r"root login|permitroot|least privilege|admin|user right|sudo", [
        ("800-53", "AC-6"), ("PCI-DSSv3.2.1", "7.1"), ("CSCv8", "5.4")]),
    (r"service|daemon|telnet|remote registry|disabled", [
        ("800-53", "CM-7"), ("PCI-DSSv3.2.1", "2.2.2"), ("CSCv8", "4.8")]),
    (r"patch|update|version|openssl|outdated", [
        ("800-53", "SI-2"), ("PCI-DSSv3.2.1", "6.2"), ("CSCv8", "7.3")]),
    (r"antivirus|malware|defender", [
        ("800-53", "SI-3"), ("PCI-DSSv3.2.1", "5.1"), ("CSCv8", "10.1")]),
    (r"permission|mode|owner|acl|0600|0644", [
        ("800-53", "AC-3"), ("PCI-DSSv3.2.1", "7.1"), ("ISO/IEC-27001", "A.9.4.1")]),
]


def suggest_refs(text: str) -> list:
    text = (text or "").lower()
    out, seen = [], set()
    for pat, refs in _MAP:
        if re.search(pat, text):
            for fw, ctrl in refs:
                k = (fw, ctrl)
                if k not in seen:
                    seen.add(k)
                    out.append({"framework": fw, "control": ctrl})
    return out


def vocab_text(platform: str) -> str:
    """A compact vocabulary string for the LLM system prompt (one platform)."""
    p = CATALOG.get(platform)
    if not p:
        return ""
    def _fs(f):
        s = f["key"] + ("*" if f.get("required") else "")
        if f.get("enum"):
            s += "[%s]" % "/".join(f["enum"])
        if f.get("hint"):
            s += " {%s}" % f["hint"]
        return s
    lines = ["Platform %s — opening tag %s" % (platform, p["check_type"])]
    for t, d in p["types"].items():
        lines.append("  %s (%s): %s" % (t, d["desc"], ", ".join(_fs(f) for f in d["fields"])))
    lines.append("(* = required; {…} = how to fill the field. Every check also takes: "
                 "description*, info, solution, see_also.)")
    return "\n".join(lines)
