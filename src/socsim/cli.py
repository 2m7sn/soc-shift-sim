"""Command-line interface.

    sim start  --scenario 1 --seed 1337           generate a case folder (starts the timer)
    sim query  --case cases/s1-seed1337 "<query>"  query the logs
    sim hint   --case cases/s1-seed1337            reveal the next true timeline step (-5 pts each)
    sim grade  --case cases/s1-seed1337            grade case-report.yaml, write debrief.html
    sim export --case cases/s1-seed1337 --splunk   per-sourcetype JSON + props.conf for Splunk
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path

from .generator import generate
from .grading import grade, parse_report
from .query import run as run_query
from .report import build_html

TEMPLATE = """# SOC Shift Simulator - case report
# Fill this in from your investigation, then run: sim grade --case <dir>
# Blank = unanswered (0 points). If you conclude an artifact does not exist,
# write 'none' (or 0 for exfil_bytes) explicitly.

analyst: your-name
scenario: {scenario}
patient_zero_host:            # e.g. WS-07
initial_access_time:          # ISO, e.g. 2026-10-20T08:17:00
compromised_accounts:         # one '- name' per line
c2_ip:                        # C2 IP (not the attacker's source IP), or none
c2_domain:                    # domain or none
attack_techniques:            # MITRE ATT&CK v20 IDs, one '- Txxxx.yyy' per line
exfil_bytes:                  # integer bytes, or 0 if none
"""


def _case_dir(scenario, seed, out):
    return (Path(out) if out else Path("cases")) / f"s{scenario}-seed{seed}"


def _state_path(case: Path) -> Path:
    return case / ".state.json"


def _load_state(case: Path) -> dict:
    p = _state_path(case)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def _save_state(case: Path, state: dict):
    _state_path(case).write_text(json.dumps(state, indent=2), encoding="utf-8")


def _write_exports(events, case: Path):
    (case / "logs.jsonl").write_text(
        "\n".join(json.dumps(e, sort_keys=True) for e in events) + "\n", encoding="utf-8")
    fields = sorted({k for e in events for k in e})
    with (case / "logs.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(events)


def _load_events(case: Path):
    p = case / "logs.jsonl"
    if not p.exists():
        raise SystemExit(f"no logs.jsonl in {case} (run `sim start` first)")
    return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _load_truth(case: Path):
    p = case / ".truth.json"
    if not p.exists():
        raise SystemExit(f"no .truth.json in {case} (run `sim start` first)")
    return json.loads(p.read_text(encoding="utf-8"))


def cmd_start(a):
    events, truth = generate(a.scenario, a.seed)
    case = _case_dir(a.scenario, a.seed, a.out)
    case.mkdir(parents=True, exist_ok=True)
    _write_exports(events, case)
    (case / ".truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    report = case / "case-report.yaml"
    if not report.exists():
        report.write_text(TEMPLATE.format(scenario=a.scenario), encoding="utf-8")
    _save_state(case, {"started": time.time(), "hints": 0})
    print(f"Case written to {case}")
    print(f"  {len(events)} events  ->  logs.jsonl, logs.csv")
    print(f"  timer started. fill in {report} then: sim grade --case {case}")


def _print_rows(rows):
    if not rows:
        print("(no results)")
        return
    cols = list(rows[0].keys())
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    print("  ".join(c.ljust(widths[c]) for c in cols))
    print("  ".join("-" * widths[c] for c in cols))
    for r in rows:
        print("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))
    print(f"\n{len(rows)} row(s)")


def cmd_query(a):
    events = _load_events(Path(a.case))
    try:
        rows = run_query(events, a.query)
    except ValueError as exc:
        raise SystemExit(f"query error: {exc}")
    _print_rows(rows)


def cmd_hint(a):
    case = Path(a.case)
    truth = _load_truth(case)
    state = _load_state(case)
    n = int(state.get("hints", 0))
    timeline = truth.get("timeline", [])
    if n >= len(timeline):
        print("No more hints: the whole timeline has been revealed.")
        return
    t, tactic, technique, host, detail = timeline[n]
    state["hints"] = n + 1
    _save_state(case, state)
    print(f"Hint {n + 1}/{len(timeline)}  (-5 points each)")
    print(f"  {t}  {tactic}  {technique}  {host}")
    print(f"  {detail}")


def cmd_grade(a):
    case = Path(a.case)
    truth = _load_truth(case)
    report_path = Path(a.report) if a.report else case / "case-report.yaml"
    if not report_path.exists():
        raise SystemExit(f"report not found: {report_path}")
    try:
        report = parse_report(report_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SystemExit(f"report error in {report_path}: {exc}")
    state = _load_state(case)
    elapsed = time.time() - state["started"] if "started" in state else None
    result = grade(report, truth, hints=state.get("hints", 0), elapsed_s=elapsed)
    print(f"Score: {result['total']} / {result['max']}  (scenario {result['scenario']})")
    if result["hints"]:
        print(f"  raw {result['raw']} minus {result['penalty']} for {result['hints']} hint(s)")
    if elapsed is not None:
        print(f"  time on case: {int(elapsed // 60)}m {int(elapsed % 60)}s")
    print()
    for it in result["items"]:
        print(f"  [{it['points']:>4}/{it['max']:<3}] {it['field']:<22} {it['note']}")
    out = case / "debrief.html"
    out.write_text(build_html(result, truth, report), encoding="utf-8")
    print(f"\nDebrief written to {out}")


_PROPS = """# Splunk props.conf for SOC Shift Simulator exports (one sourcetype per log source)
{stanzas}"""
_STANZA = """[socsim:{src}]
INDEXED_EXTRACTIONS = json
KV_MODE = none
TIMESTAMP_FIELDS = time
TIME_FORMAT = %Y-%m-%dT%H:%M:%S
TZ = Asia/Riyadh
"""


def cmd_export(a):
    case = Path(a.case)
    events = _load_events(case)
    if not a.splunk:
        raise SystemExit("nothing to do: pass --splunk (logs.jsonl / logs.csv already exist)")
    out = case / "export" / "splunk"
    out.mkdir(parents=True, exist_ok=True)
    by_src: dict = {}
    for e in events:
        by_src.setdefault(e["source"], []).append(e)
    for src, evs in sorted(by_src.items()):
        (out / f"{src}.json").write_text(
            "\n".join(json.dumps(e, sort_keys=True) for e in evs) + "\n", encoding="utf-8")
    (out / "props.conf").write_text(
        _PROPS.format(stanzas="\n".join(_STANZA.format(src=s) for s in sorted(by_src))), encoding="utf-8")
    print(f"Splunk export written to {out}")
    for src, evs in sorted(by_src.items()):
        print(f"  {src}.json  {len(evs):>5} events  sourcetype=socsim:{src}")
    print("  props.conf  (add to an app, then upload each file with its sourcetype)")


def build_parser():
    p = argparse.ArgumentParser(prog="sim", description="SOC Shift Simulator (synthetic data only)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("start", help="generate a case folder of logs and start the timer")
    s.add_argument("--scenario", type=int, required=True, choices=[1, 2, 3])
    s.add_argument("--seed", type=int, default=1337)
    s.add_argument("--out", help="base output dir (default: cases/)")
    s.set_defaults(func=cmd_start)

    q = sub.add_parser("query", help="query a case's logs")
    q.add_argument("--case", required=True)
    q.add_argument("query", help="e.g. 'source=vpn action=fail | count by user'")
    q.set_defaults(func=cmd_query)

    h = sub.add_parser("hint", help="reveal the next true timeline step (-5 points each)")
    h.add_argument("--case", required=True)
    h.set_defaults(func=cmd_hint)

    g = sub.add_parser("grade", help="grade the case report and write the HTML debrief")
    g.add_argument("--case", required=True)
    g.add_argument("--report", help="path to case-report.yaml (default: <case>/case-report.yaml)")
    g.set_defaults(func=cmd_grade)

    x = sub.add_parser("export", help="export logs for a SIEM")
    x.add_argument("--case", required=True)
    x.add_argument("--splunk", action="store_true", help="per-sourcetype JSON + props.conf")
    x.set_defaults(func=cmd_export)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
