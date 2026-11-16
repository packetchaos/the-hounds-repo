"""Is this asset a cloud asset? — ONE answer for every hound (build 473).

An asset is CLOUD only when navi synced a real AWS / Azure / GCP identifier for it. navi's
asset export writes a single space (" ") for any cloud field Tenable did not return, and some
paths store the text "None" — so a plain truthiness test (`if a.get("aws_id")`) marked EVERY
asset as cloud. present() treats NULL, "", whitespace and placeholder text as absent.
"""

# navi assets columns that carry a cloud identity → provider (first real value wins)
CLOUD_COLS = (("aws_id", "AWS"), ("aws_ec2_name", "AWS"), ("aws_ec2_region", "AWS"),
              ("azure_vm_id", "Azure"), ("azure_resource_id", "Azure"), ("azure_subscription_id", "Azure"),
              ("gcp_instance_id", "GCP"), ("gcp_project_id", "GCP"))
_EMPTY = ("", "none", "null", "nil", "nan", "n/a", "na", "-", "0", "[]", "{}", "undefined", "unknown")


def present(v):
    """True when v is a real value, not NULL / blank / a placeholder like ' ' or 'None'."""
    if v is None:
        return False
    s = str(v).strip().strip("'\"").strip()
    return s.lower() not in _EMPTY


def provider(row, cols=None):
    """'AWS' | 'Azure' | 'GCP' | '' for an assets row (dict)."""
    for c, prov in CLOUD_COLS:
        if (cols is None or c in cols) and present(row.get(c)):
            return prov
    return ""


def columns(available):
    """The cloud columns this navi.db's assets table actually has."""
    return [c for c, _ in CLOUD_COLS if c in available]


def sql_present(col, alias=""):
    """SQL predicate: this column holds a real value (same rule as present())."""
    c = (alias + "." if alias else "") + '"%s"' % col
    vals = ",".join("'%s'" % v for v in _EMPTY)
    return "(%s IS NOT NULL AND lower(trim(trim(trim(CAST(%s AS TEXT)), '''\"'))) NOT IN (%s))" % (c, c, vals)


def sql_is_cloud(available, alias=""):
    """SQL predicate: the asset has any real cloud identifier ('0' when the table has none)."""
    cols = columns(available)
    return "(" + " OR ".join(sql_present(c, alias) for c in cols) + ")" if cols else "0"
