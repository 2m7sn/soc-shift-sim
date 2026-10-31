"""Tiny query language over a list of event dicts.

Grammar (pipe-separated):

    <filter> [| <op>]...

<filter> is shlex-split terms `key OP value` (quote values with spaces):
    =   equals            !=  not equals
    ~   contains (substr) !~  not contains
    >= <= > <             datetime if both sides parse as ISO timestamps,
                          else numeric if both parse as numbers, else string

Time ranges use the `time` field, e.g.
    time>=2026-10-20T08:00:00 time<=2026-10-20T09:00:00

<op> is one of:
    fields a,b,c      project columns (order preserved)
    count by field    group and count, rows {field, count} sorted desc
    sort field        ascending   |   sort -field   descending
    head N            first N rows (N >= 0)

run(events, query) -> list[dict]. Raises ValueError with a usage hint on bad
syntax.
"""
from __future__ import annotations

import shlex
from datetime import datetime

_OPS = ["!=", ">=", "<=", "!~", "=", "~", ">", "<"]


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _dt(v):
    try:
        return datetime.fromisoformat(str(v))
    except (TypeError, ValueError):
        return None


def _cmp(ev_val, op, want):
    s = "" if ev_val is None else str(ev_val)
    if op == "=":
        return s == want
    if op == "!=":
        return s != want
    if op == "~":
        return want.lower() in s.lower()
    if op == "!~":
        return want.lower() not in s.lower()
    da, db = _dt(s), _dt(want)
    if da is not None and db is not None:
        left, right = da, db
    else:
        a, b = _num(s), _num(want)
        if a is not None and b is not None:
            left, right = a, b
        else:
            left, right = s, want
    return {">=": left >= right, "<=": left <= right,
            ">": left > right, "<": left < right}[op]


def _split_term(term):
    for op in _OPS:
        i = term.find(op)
        if i > 0:
            key, val = term[:i], term[i + len(op):]
            if val == "":
                raise ValueError(f"empty value in {term!r} (usage: key{op}value)")
            return key, op, val
    raise ValueError(f"cannot parse filter term {term!r} (usage: key=value, key~text, time>=ISO)")


def _apply_filter(events, filt):
    try:
        tokens = shlex.split(filt)
    except ValueError as exc:
        raise ValueError(f"bad quoting in filter: {exc}") from exc
    terms = [_split_term(t) for t in tokens]
    return [ev for ev in events if all(_cmp(ev.get(k), op, w) for k, op, w in terms)]


def _apply_op(rows, op):
    parts = op.split()
    verb = parts[0]
    if verb == "fields":
        cols = [c.strip() for c in op[len("fields"):].strip().split(",") if c.strip()]
        if not cols:
            raise ValueError("usage: fields a,b,c")
        return [{c: r.get(c, "") for c in cols} for r in rows]
    if verb == "count":
        if len(parts) != 3 or parts[1] != "by":
            raise ValueError("usage: count by <field>")
        field = parts[2]
        counts: dict = {}
        for r in rows:
            key = r.get(field, "")
            counts[key] = counts.get(key, 0) + 1
        return [{field: k, "count": c}
                for k, c in sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0])))]
    if verb == "sort":
        if len(parts) != 2:
            raise ValueError("usage: sort <field> | sort -<field>")
        key = parts[1]
        desc = key.startswith("-")
        key = key.lstrip("-")
        if not key:
            raise ValueError("usage: sort <field> | sort -<field>")

        def sort_key(r):
            v = r.get(key, "")
            n = _num(v)
            return (0, n, "") if n is not None else (1, 0.0, str(v))
        return sorted(rows, key=sort_key, reverse=desc)
    if verb == "head":
        if len(parts) != 2 or not parts[1].isdigit():
            raise ValueError("usage: head <N> (N must be a non-negative integer)")
        return rows[: int(parts[1])]
    raise ValueError(f"unknown op {verb!r} (ops: fields, count by, sort, head)")


def run(events, query: str):
    segments = [s.strip() for s in query.split("|")]
    rows = _apply_filter(events, segments[0])
    for op in segments[1:]:
        if not op:
            raise ValueError("empty pipe segment")
        rows = _apply_op(rows, op)
    return rows
