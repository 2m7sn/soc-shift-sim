"""Grade a trainee case-report against hidden ground truth, with partial credit.

parse_report(text) -> dict             tiny YAML subset reader (no PyYAML)
grade(report, truth, hints=0, elapsed_s=None) -> dict   scorecard

Blank means missing and scores 0. Where the truth has no artifact (no C2, no
exfil) the trainee must write an explicit `none` / `0` to earn the points;
leaving it blank is not an answer.
"""
from __future__ import annotations

from datetime import datetime

# weights sum to 100
WEIGHTS = {
    "patient_zero_host": 15,
    "initial_access_time": 15,
    "compromised_accounts": 15,
    "c2_ip": 10,
    "c2_domain": 10,
    "attack_techniques": 20,
    "exfil_bytes": 15,
}
HINT_PENALTY = 5

_NONE_WORDS = {"none", "n/a", "na", "null", "nil", "-"}


def parse_report(text: str) -> dict:
    """Read the flat case-report YAML subset: `key: scalar` and `- item` lists.

    Bare `-` placeholder lines and comments are skipped.
    ponytail: hand-rolled for this fixed template only; swap in PyYAML if the
    report schema ever grows nested maps.
    """
    data: dict = {}
    cur_list_key = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        stripped = line.strip()
        if not stripped or stripped == "-":
            continue
        if stripped.startswith("- "):
            if cur_list_key is None:
                raise ValueError(f"list item with no preceding key: {raw!r}")
            data[cur_list_key].append(_scalar(stripped[2:]))
            continue
        if ":" not in line:
            raise ValueError(f"bad line (expected key: value): {raw!r}")
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if val == "":
            data[key] = []
            cur_list_key = key
        else:
            data[key] = _scalar(val)
            cur_list_key = None
    return data


def _scalar(v: str):
    v = v.strip().strip('"').strip("'")
    if v.lstrip("-").isdigit():
        return int(v)
    return v


def _missing(v) -> bool:
    return v is None or v == [] or (isinstance(v, str) and v.strip() == "")


def _explicit_none(v) -> bool:
    return isinstance(v, str) and v.strip().lower() in _NONE_WORDS


def _norm_set(v):
    if _missing(v) or _explicit_none(v):
        return set()
    items = v if isinstance(v, (list, tuple)) else str(v).replace(",", " ").split()
    return {str(x).strip().lower() for x in items if str(x).strip()}


def _score_time(got, want):
    if _missing(got):
        return 0.0, "missing"
    try:
        g = datetime.fromisoformat(str(got).replace("Z", ""))
        w = datetime.fromisoformat(str(want))
    except ValueError:
        return 0.0, f"unparseable time {got!r}"
    diff = abs((g - w).total_seconds())
    if diff <= 600:
        return 1.0, f"within {int(diff)}s of truth"
    if diff <= 1800:
        return 0.5, f"off by {int(diff // 60)}m (half credit)"
    return 0.0, f"off by {int(diff // 60)}m (truth {want})"


def _score_set(got, want):
    g, w = _norm_set(got), _norm_set(want)
    if not g:
        return 0.0, "missing"
    hit = g & w
    fp = sorted(g - w)
    frac = len(hit) / len(g | w)  # Jaccard: listing everything is not a strategy
    note = f"found {len(hit)}/{len(w)}"
    if w - g:
        note += f"; missed {sorted(w - g)}"
    if fp:
        shown = fp[:5] + ([f"+{len(fp) - 5} more"] if len(fp) > 5 else [])
        note += f"; {len(fp)} extra {shown}"
    return frac, note


def _score_exact(got, want):
    if _missing(got):
        return 0.0, "missing (write 'none' if you concluded there is none)"
    if want is None:
        return (1.0, "correctly none") if _explicit_none(got) else (0.0, "truth is none")
    if _explicit_none(got):
        return 0.0, f"truth {want}"
    return (1.0, "correct") if str(got).strip().lower() == str(want).lower() else (0.0, f"truth {want}")


def _score_bytes(got, want):
    if _missing(got):
        return 0.0, "missing (write 0 if you concluded nothing left)"
    if _explicit_none(got):
        got = 0
    try:
        g = float(str(got).replace(",", "").replace("_", ""))
    except ValueError:
        return 0.0, f"unparseable {got!r}"
    if not want:
        return (1.0, "correctly 0") if g == 0 else (0.0, "truth is 0 (no exfil)")
    err = abs(g - want) / want
    if err <= 0.2:
        return 1.0, f"within {err * 100:.0f}% of {want}"
    if err <= 0.5:
        return 0.5, f"off by {err * 100:.0f}% (half credit, truth {want})"
    return 0.0, f"off by {err * 100:.0f}% (truth {want})"


def grade(report: dict, truth: dict, hints: int = 0, elapsed_s=None) -> dict:
    items = []
    raw = 0.0
    for field, weight in WEIGHTS.items():
        got, want = report.get(field), truth.get(field)
        if field == "initial_access_time":
            frac, note = _score_time(got, want)
        elif field in ("compromised_accounts", "attack_techniques"):
            frac, note = _score_set(got, want)
        elif field == "exfil_bytes":
            frac, note = _score_bytes(got, want)
        else:
            frac, note = _score_exact(got, want)
        pts = round(weight * frac, 1)
        raw += pts
        items.append(dict(field=field, points=pts, max=weight, note=note, got=got, want=want))
    penalty = HINT_PENALTY * max(0, int(hints))
    total = max(0.0, round(raw - penalty, 1))
    return dict(total=total, raw=round(raw, 1), max=100, penalty=penalty, hints=int(hints),
                elapsed_s=elapsed_s, items=items, scenario=truth.get("scenario"),
                summary=truth.get("summary"))
