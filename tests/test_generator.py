import json

import pytest

from socsim import generate, run_query


def _dump(events):
    return [json.dumps(e, sort_keys=True) for e in events]


@pytest.mark.parametrize("scenario", [1, 2, 3])
def test_determinism(scenario):
    a, ta = generate(scenario, 42)
    b, tb = generate(scenario, 42)
    assert _dump(a) == _dump(b)
    assert ta == tb


def test_seed_changes_output():
    a, _ = generate(1, 1)
    b, _ = generate(1, 2)
    assert _dump(a) != _dump(b)


def test_sorted_by_time():
    events, _ = generate(1, 7)
    times = [e["time"] for e in events]
    assert times == sorted(times)


def test_has_normal_noise_on_every_pivot():
    """No attack stage should be separable by one filter: the noise must cover
    the same event types the scenarios use."""
    events, _ = generate(1, 7)
    q = lambda s: run_query(events, s)
    assert {"security", "sysmon", "firewall", "vpn", "proxy", "dns", "email"} <= {e["source"] for e in events}
    assert len(q("source=email verdict=delivered")) >= 10
    assert len(q("source=security event_id=4624 LogonType=3")) >= 20
    assert len(q("source=proxy method=POST bytes_out>=50000")) >= 30
    assert len(q("source=sysmon event_id=3 Image~chrome")) >= 20
    assert len(q("source=sysmon event_id=11 TargetFilename~Temp")) >= 20
    assert len(q("source=sysmon event_id=22 Image~OUTLOOK")) >= 5
    # backup job = biggest transfers of the day, bigger than the exfil
    assert int(q("source=proxy method=POST | sort -bytes_out | head 1")[0]["bytes_out"]) > 10_000_000


def test_real_field_names():
    events, _ = generate(1, 7)
    sysmon1 = run_query(events, "source=sysmon event_id=1 | head 1")[0]
    assert {"Image", "ParentImage", "CommandLine"} <= set(sysmon1)
    logon = run_query(events, "source=security event_id=4624 | head 1")[0]
    assert {"TargetUserName", "LogonType", "IpAddress"} <= set(logon)


def test_scenario_truth_shape():
    keys = {"scenario", "patient_zero_host", "initial_access_time", "compromised_accounts",
            "c2_ip", "c2_domain", "attack_techniques", "exfil_bytes", "summary", "timeline"}
    for s in (1, 2, 3):
        _, truth = generate(s, 1)
        assert keys <= set(truth)
        assert truth["scenario"] == s
        assert all(t.startswith("T") for t in truth["attack_techniques"])


def test_scenario2_uses_v20_log_clearing_and_4728():
    events, truth = generate(2, 1)
    assert "T1685.005" in truth["attack_techniques"]
    assert "T1070.001" not in truth["attack_techniques"]
    assert run_query(events, "source=security event_id=4728 TargetUserName~Domain")
    assert not run_query(events, "source=security event_id=4732")
    rdp = run_query(events, "source=security event_id=4624 LogonType=10")
    assert rdp and rdp[0]["IpAddress"].startswith("10.20.250.")   # VPN pool, not the internet IP


def test_scenario3_tunnel_by_w3wp_with_dns_mirror():
    events, truth = generate(3, 1)
    rows = run_query(events, "source=sysmon event_id=22 host=WEB-01 QueryName~dns-sync-khobar")
    assert rows and all(r["Image"].endswith("w3wp.exe") for r in rows)
    assert len(run_query(events, "source=dns host=WEB-01 query_type=TXT")) == len(rows)
    assert "T1059.003" in truth["attack_techniques"] and "T1059.001" not in truth["attack_techniques"]


def test_web_server_has_benign_baseline_and_pivotable_attacker():
    events, _ = generate(3, 1)
    q = lambda s: run_query(events, s)
    assert len(q("source=iis")) >= 60                                   # customer traffic
    assert len(q("source=sysmon event_id=1 host=WEB-01 ParentImage~w3wp")) >= 8  # csc + malicious
    assert len(q("source=sysmon event_id=1 host=WEB-01 Image~csc.exe")) >= 3
    assert len(q("source=sysmon event_id=22 host=WEB-01 QueryName!~dns-sync")) >= 18
    assert len(q("source=sysmon event_id=11 host=WEB-01 TargetFilename~inetpub")) >= 7
    # the attacker IP ties the upload to each shell command
    hits = q("source=iis c_ip=91.219.236.14 | fields cs_uri_stem,cs_uri_query")
    assert any(h["cs_uri_stem"] == "/portal/upload.aspx" for h in hits)
    assert sum(h["cs_uri_stem"].endswith("verify.aspx") for h in hits) == 5
    # whoami is whoami.exe, dir stays inside cmd.exe
    assert q("source=sysmon event_id=1 host=WEB-01 Image~whoami.exe")
    assert not q("source=sysmon event_id=1 host=WEB-01 Image~dir")
    # scenario 1 has no inbound proxy rows on WEB-01 any more
    assert not run_query(generate(1, 1)[0], "source=proxy host=WEB-01")


def test_unknown_scenario_rejected():
    with pytest.raises(ValueError):
        generate(9, 1)
