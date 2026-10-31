"""Render the post-grading HTML debrief: a plain, dense engineer's report.

build_html(grade_result, truth, report) -> str

Deliberately low-chrome: tables and a simple time-ordered list, dark #262626
background, #a68af9 accent used only for the score and timeline rules. No KPI
tiles, eyebrows, gradients, pills, or emoji. Tables scroll inside their own
wrapper so the page never scrolls sideways at 375px.
"""
from __future__ import annotations

import html


def _esc(v) -> str:
    return html.escape("" if v is None else str(v))


def _join(v):
    return ", ".join(str(x) for x in v) if isinstance(v, list) else v


def _scorecard_rows(items):
    out = []
    for it in items:
        got = _esc(_join(it["got"])) or "<span class=miss>(blank)</span>"
        want = _esc(_join(it["want"])) or "none"
        out.append(f"<tr><td>{_esc(it['field'])}</td><td>{got}</td><td>{want}</td>"
                   f"<td class=num>{_esc(it['points'])}/{_esc(it['max'])}</td>"
                   f"<td>{_esc(it['note'])}</td></tr>")
    return "\n".join(out)


def _timeline_rows(timeline):
    out = []
    for t, tactic, technique, host, detail in timeline:
        clock = t.split("T")[1] if "T" in t else t
        out.append(f"<tr><td class=clock>{_esc(clock)}</td><td>{_esc(tactic)}</td>"
                   f"<td class=tech>{_esc(technique)}</td><td>{_esc(host)}</td>"
                   f"<td>{_esc(detail)}</td></tr>")
    return "\n".join(out)


def _fmt_elapsed(s):
    if s is None:
        return "not recorded"
    s = int(s)
    return f"{s // 3600}h {(s % 3600) // 60}m {s % 60}s"


def build_html(grade_result: dict, truth: dict, report: dict) -> str:
    g = grade_result
    penalty_line = (f" (raw {_esc(g.get('raw'))}, minus {_esc(g.get('penalty'))} for "
                    f"{_esc(g.get('hints'))} hint(s))" if g.get("hints") else "")
    return _TEMPLATE.format(
        scenario=_esc(g.get("scenario")),
        score=_esc(g["total"]),
        penalty_line=penalty_line,
        elapsed=_esc(_fmt_elapsed(g.get("elapsed_s"))),
        summary=_esc(g.get("summary")),
        scorecard=_scorecard_rows(g["items"]),
        timeline=_timeline_rows(truth.get("timeline", [])),
        analyst=_esc(report.get("analyst", "trainee")),
    )


_TEMPLATE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Shift Sim - Debrief, scenario {scenario}</title>
<style>
  :root {{ --bg:#262626; --fg:#e6e6e6; --dim:#9a9a9a; --line:#3a3a3a;
           --accent:#a68af9; --miss:#d98b8b; }}
  * {{ box-sizing:border-box; }}
  body {{ background:var(--bg); color:var(--fg); margin:0;
          font:14px/1.5 "SF Mono",Menlo,Consolas,monospace; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:24px 16px 64px; }}
  h1 {{ font-size:18px; margin:0 0 2px; font-weight:600; }}
  h2 {{ font-size:14px; margin:28px 0 8px; color:var(--dim);
        border-bottom:1px solid var(--line); padding-bottom:4px; font-weight:600; }}
  .meta {{ color:var(--dim); font-size:13px; margin-bottom:16px; }}
  .score {{ font-size:15px; margin:12px 0 4px; }}
  .score b {{ color:var(--accent); font-size:22px; }}
  .sub {{ color:var(--dim); font-size:13px; }}
  p.sum {{ max-width:72ch; }}
  .tw {{ overflow-x:auto; -webkit-overflow-scrolling:touch; }}
  table {{ width:100%; border-collapse:collapse; margin:4px 0; font-size:13px; min-width:560px; }}
  th,td {{ text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ color:var(--dim); font-weight:600; }}
  td.num {{ white-space:nowrap; text-align:right; }}
  td.clock {{ white-space:nowrap; color:var(--accent); border-left:2px solid var(--accent); padding-left:10px; }}
  td.tech {{ white-space:nowrap; }}
  .miss {{ color:var(--miss); }}
  .note {{ color:var(--dim); font-size:12px; margin-top:24px; }}
  @media (max-width:560px) {{ td,th {{ padding:5px 6px; }} .wrap {{ padding:16px 12px; }} }}
</style></head>
<body><div class="wrap">
  <h1>SOC Shift Simulator - Investigation Debrief</h1>
  <div class="meta">Khobar Logistics Co. &middot; Scenario {scenario} &middot; Analyst: {analyst}</div>
  <div class="score">Score <b>{score}</b> / 100{penalty_line}</div>
  <div class="sub">Time on case: {elapsed}</div>

  <h2>Scorecard (what you filed vs ground truth)</h2>
  <div class="tw"><table>
    <tr><th>Field</th><th>Your answer</th><th>Ground truth</th><th>Points</th><th>Note</th></tr>
    {scorecard}
  </table></div>

  <h2>True attack timeline</h2>
  <div class="tw"><table>
    <tr><th>Time</th><th>Tactic</th><th>Technique</th><th>Host</th><th>Evidence</th></tr>
    {timeline}
  </table></div>

  <h2>Ground-truth summary</h2>
  <p class="sum">{summary}</p>

  <p class="note">All data in this exercise is synthetic. No real hosts, accounts, or
  attacks. Techniques use MITRE ATT&amp;CK v20.0 IDs.</p>
</div></body></html>
"""
