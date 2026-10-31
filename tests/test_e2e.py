"""End-to-end: run the exact queries from docs/walkthrough-1.md against the
generated logs and verify each surfaces the right evidence, then grade the
answer-key report from that document to 100.
"""
from pathlib import Path

from socsim import generate, grade, parse_report, run_query

SEED = 1337
DOC = Path(__file__).parents[1] / "docs" / "walkthrough-1.md"


def setup_module(_):
    global EVENTS, TRUTH
    EVENTS, TRUTH = generate(1, SEED)


def test_q1_phishing_email_needs_a_second_filter():
    assert len(run_query(EVENTS, "source=email verdict=delivered")) >= 10   # not a one-filter win
    rows = run_query(EVENTS, "source=email attachment~xlsm | fields time,sender,recipient")
    assert len(rows) == 1
    assert rows[0]["recipient"] == "f.alharbi@khobar.local"
    assert "khobar-loglstics" in rows[0]["sender"]


def test_q2_macro_spawns_powershell():
    rows = run_query(EVENTS, "source=sysmon event_id=1 host=WS-07 ParentImage~EXCEL | fields time,user,CommandLine")
    assert len(rows) == 1
    assert rows[0]["time"] == TRUTH["initial_access_time"]
    assert rows[0]["user"] == "f.alharbi" and "-enc" in rows[0]["CommandLine"]


def test_q3_c2_beacon_dominates_counts():
    ips = run_query(EVENTS, "source=sysmon event_id=3 host=WS-07 | count by DestinationIp")
    assert ips[0]["DestinationIp"] == TRUTH["c2_ip"] and len(ips) > 5
    doms = run_query(EVENTS, "source=sysmon event_id=22 host=WS-07 | count by QueryName")
    assert doms[0]["QueryName"] == TRUTH["c2_domain"] and doms[0]["count"] > 20


def test_q4_credential_dump():
    rows = run_query(EVENTS, "source=sysmon event_id=1 CommandLine~lsass | fields time,host,user")
    assert len(rows) == 1 and rows[0]["host"] == "WS-07"


def test_q5_lateral_movement_pivot_on_patient_zero_ip():
    assert len(run_query(EVENTS, "source=security event_id=4624 LogonType=3")) >= 20
    rows = run_query(EVENTS, "source=security event_id=4624 LogonType=3 IpAddress=10.20.10.7 | fields time,host,user")
    assert any(r["host"] == "FS-01" and r["user"] == "svc_backup" for r in rows)
    assert len(rows) <= 3   # small enough to eyeball


def test_q6_staging_and_exfil():
    staged = run_query(EVENTS, "source=sysmon event_id=11 host=WS-07 TargetFilename~ProgramData | fields TargetFilename")
    assert [r["TargetFilename"] for r in staged] == [r"C:\ProgramData\staging\khobar_export.7z"]
    assert len(run_query(EVENTS, "source=proxy method=POST")) >= 50   # plenty of benign uploads
    by_url = run_query(EVENTS, "source=proxy method=POST host=WS-07 | count by url")
    assert by_url[0]["url"] == "https://cdn-telemetry-sync.net/upload"
    rows = run_query(EVENTS, "source=proxy method=POST url~cdn-telemetry-sync | fields bytes_out")
    assert sum(int(r["bytes_out"]) for r in rows) == TRUTH["exfil_bytes"]


def test_answer_key_in_walkthrough_scores_100():
    yaml = DOC.read_text(encoding="utf-8").split("```yaml")[1].split("```")[0]
    assert grade(parse_report(yaml), TRUTH)["total"] == 100.0


def test_walkthrough_queries_all_parse():
    """Every fenced query line in the walkthrough must be valid in the query language."""
    text = DOC.read_text(encoding="utf-8")
    blocks = text.split("```")[1::2]
    queries = [ln.strip() for b in blocks if b.startswith("\nsource=") or b.startswith("\n|")
               for ln in b.splitlines() if ln.strip()]
    assert len(queries) >= 8
    for q in queries:
        run_query(EVENTS, q)  # raises ValueError if the doc drifts from the language
