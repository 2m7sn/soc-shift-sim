import pytest

from socsim import generate, grade, parse_report
from socsim.cli import TEMPLATE

PERFECT_1 = """\
analyst: tester
scenario: 1
patient_zero_host: WS-07
initial_access_time: 2026-10-20T08:17:43
compromised_accounts:
  - f.alharbi
  - svc_backup
c2_ip: 185.220.101.47
c2_domain: cdn-telemetry-sync.net
attack_techniques:
  - T1566.001
  - T1204.002
  - T1059.001
  - T1071.001
  - T1003.001
  - T1021.002
  - T1074.001
  - T1567.002
exfil_bytes: 4718592
"""


def test_parse_report_lists_and_scalars():
    r = parse_report(PERFECT_1)
    assert r["patient_zero_host"] == "WS-07"
    assert r["exfil_bytes"] == 4718592
    assert r["compromised_accounts"] == ["f.alharbi", "svc_backup"]
    assert len(r["attack_techniques"]) == 8


def test_parse_skips_bare_dash_placeholders():
    r = parse_report("accounts:\n  -\n  - a\n  -\nnext: 1\n")
    assert r == {"accounts": ["a"], "next": 1}


def test_raw_template_grades_without_crashing():
    _, truth = generate(1, 1337)
    result = grade(parse_report(TEMPLATE.format(scenario=1)), truth)
    assert result["total"] <= 5


@pytest.mark.parametrize("scenario", [1, 2, 3])
def test_empty_report_scores_near_zero(scenario):
    _, truth = generate(scenario, 1337)
    assert grade({}, truth)["total"] <= 5
    assert grade(parse_report("scenario: %d\n" % scenario), truth)["total"] <= 5


def test_perfect_scores_100():
    _, truth = generate(1, 1337)
    assert grade(parse_report(PERFECT_1), truth)["total"] == 100.0


def test_partial_credit():
    _, truth = generate(1, 1337)
    partial = """\
scenario: 1
patient_zero_host: WS-07
initial_access_time: 2026-10-20T08:35:00
compromised_accounts:
  - f.alharbi
c2_domain: cdn-telemetry-sync.net
attack_techniques:
  - T1059.001
  - T1003.001
exfil_bytes: 5000000
"""
    result = grade(parse_report(partial), truth)
    assert 0 < result["total"] < 100
    by = {it["field"]: it for it in result["items"]}
    assert by["patient_zero_host"]["points"] == 15          # exact
    assert 0 < by["compromised_accounts"]["points"] < 15     # 1 of 2
    assert 0 < by["attack_techniques"]["points"] < 20        # 2 of 8
    assert by["c2_ip"]["points"] == 0                        # blank
    assert by["initial_access_time"]["points"] == 7.5        # ~18m off = half credit
    assert by["exfil_bytes"]["points"] == 15                 # within 20%


def test_false_positive_penalised():
    _, truth = generate(1, 1337)
    base = "scenario: 1\nattack_techniques:\n  - T1059.001\n"
    noisy = base + "  - T9999\n  - T8888\n"
    tech = lambda res: next(i["points"] for i in res["items"] if i["field"] == "attack_techniques")
    assert tech(grade(parse_report(noisy), truth)) < tech(grade(parse_report(base), truth))


def test_listing_every_technique_scores_at_most_half():
    """Jaccard overlap: dumping the union of all scenarios' techniques is not a strategy."""
    everything = sorted({t for s in (1, 2, 3) for t in generate(s, 1)[1]["attack_techniques"]})
    assert len(everything) >= 15
    for s in (1, 2, 3):
        _, truth = generate(s, 1337)
        res = grade({"attack_techniques": everything}, truth)
        tech = next(i for i in res["items"] if i["field"] == "attack_techniques")
        assert tech["points"] <= 10
        assert "+" in tech["note"] and "more" in tech["note"]   # extras capped at 5 in the note


def test_explicit_none_required_when_truth_is_none():
    _, truth = generate(2, 1337)   # scenario 2: no C2, no exfil
    explicit = grade(parse_report("c2_ip: none\nc2_domain: none\nexfil_bytes: 0\n"), truth)
    blank = grade(parse_report("c2_ip:\nc2_domain:\nexfil_bytes:\n"), truth)
    pts = lambda res, f: next(i["points"] for i in res["items"] if i["field"] == f)
    for f in ("c2_ip", "c2_domain", "exfil_bytes"):
        assert pts(explicit, f) > 0
        assert pts(blank, f) == 0


def test_hint_penalty():
    _, truth = generate(1, 1337)
    report = parse_report(PERFECT_1)
    assert grade(report, truth, hints=2)["total"] == 90.0
    assert grade(report, truth, hints=0)["total"] == 100.0
    assert grade({}, truth, hints=3)["total"] == 0.0      # never negative
