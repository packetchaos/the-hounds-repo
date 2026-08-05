"""App-owned metric history — the substrate the trending agent (Hati, coming next)
will chart over time.

Why a separate file and not a navi.db table: navi.db is navi's, rebuilt by
`navi config update` and DELETED on a navi upgrade (see navi-core recovery steps).
Trend history must OUTLIVE that, so we keep it in the repo's own `data/` dir as
JSONL — one line per (agent, day). Re-recording the same day overwrites that day's
line (latest-wins), so a dashboard that's opened five times a day still yields one
clean point per day.

Format (one JSON object per line):
    {"date": "2026-07-31", "ts": "2026-07-31T18:04:02+00:00",
     "metrics": {"open_breached": 1996, "verdict_adherence_pct": 88.6, ...},
     "dims": {"tag_key": "Owner"}}

Public API:
    record(agent, metrics, dims=None, date=None) -> the stored point
    series(agent, keys=None, since=None, limit=None) -> [points] oldest→newest
    latest(agent) -> the most recent point or None
    agents() -> [agent ids that have history]
"""
import datetime
import json
import os

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA_DIR = os.environ.get("NAVI_HISTORY_DIR") or os.path.join(_REPO_ROOT, "data")


def _today():
    return datetime.date.today().isoformat()


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _safe(agent):
    return "".join(c for c in str(agent or "agent") if c.isalnum() or c in "-_") or "agent"


def _path(agent):
    return os.path.join(_DATA_DIR, "history_%s.jsonl" % _safe(agent))


def _read_all(agent):
    p = _path(agent)
    out = []
    if not os.path.exists(p):
        return out
    try:
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return out


def record(agent, metrics, dims=None, date=None):
    """Store today's (or `date`'s) snapshot for `agent`, replacing any existing point
    for that day. Best-effort: never raises — history is a nice-to-have, not load-bearing."""
    point = {"date": date or _today(), "ts": _now_iso(),
             "metrics": {k: v for k, v in (metrics or {}).items() if v is not None},
             "dims": dims or {}}
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        rows = [r for r in _read_all(agent) if r.get("date") != point["date"]]
        rows.append(point)
        rows.sort(key=lambda r: r.get("date", ""))
        tmp = _path(agent) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        os.replace(tmp, _path(agent))
    except Exception:
        pass
    return point


def series(agent, keys=None, since=None, limit=None):
    """Return points oldest→newest. `keys` narrows each point's metrics to those keys;
    `since` is an inclusive 'YYYY-MM-DD' floor; `limit` keeps the newest N."""
    rows = _read_all(agent)
    rows.sort(key=lambda r: r.get("date", ""))
    if since:
        rows = [r for r in rows if r.get("date", "") >= since]
    if keys:
        ks = set(keys)
        rows = [{**r, "metrics": {k: v for k, v in (r.get("metrics") or {}).items() if k in ks}}
                for r in rows]
    if limit and len(rows) > limit:
        rows = rows[-int(limit):]
    return rows


def latest(agent):
    rows = series(agent)
    return rows[-1] if rows else None


def agents():
    try:
        return sorted(f[len("history_"):-len(".jsonl")]
                      for f in os.listdir(_DATA_DIR)
                      if f.startswith("history_") and f.endswith(".jsonl"))
    except Exception:
        return []
