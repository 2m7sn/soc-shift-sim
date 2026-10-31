import pytest

from socsim.query import run

EVENTS = [
    {"time": "2026-10-20T08:00:00", "source": "sysmon", "event_id": 1, "host": "WS-07", "user": "a", "bytes": 100,
     "CommandLine": 'net group "Domain Admins" /domain'},
    {"time": "2026-10-20T08:30:00", "source": "sysmon", "event_id": 3, "host": "WS-07", "user": "a", "bytes": 500},
    {"time": "2026-10-20T09:00:00", "source": "sysmon", "event_id": 1, "host": "WS-08", "user": "b", "bytes": 50},
    {"time": "2026-10-20T10:00:00", "source": "proxy", "host": "WS-07", "user": "a", "bytes": 900},
]


def test_equals_filter():
    rows = run(EVENTS, "source=sysmon event_id=1")
    assert {r["host"] for r in rows} == {"WS-07", "WS-08"}


def test_not_equals_and_contains():
    assert len(run(EVENTS, "source!=sysmon")) == 1
    assert len(run(EVENTS, "host~ws")) == 4            # case-insensitive
    assert len(run(EVENTS, "host!~08")) == 3


def test_quoted_value_with_spaces():
    rows = run(EVENTS, '"CommandLine~Domain Admins"')
    assert len(rows) == 1 and rows[0]["host"] == "WS-07"
    assert len(run(EVENTS, "CommandLine~'Domain Admins' source=sysmon")) == 1


def test_numeric_comparison():
    assert {r["bytes"] for r in run(EVENTS, "bytes>=500")} == {500, 900}


def test_time_range_is_parsed_not_lexical():
    assert len(run(EVENTS, "time>=2026-10-20T08:15:00 time<=2026-10-20T09:30:00")) == 2
    # a space-separated ISO value sorts before 'T' lexically but is later in time
    rows = run(EVENTS, '"time<2026-10-20 08:15:00"')
    assert [r["time"] for r in rows] == ["2026-10-20T08:00:00"]


def test_fields_projection():
    assert run(EVENTS, "source=proxy | fields host,user") == [{"host": "WS-07", "user": "a"}]


def test_count_by():
    rows = run(EVENTS, "| count by host")
    assert rows[0] == {"host": "WS-07", "count": 3}


def test_sort_desc_numeric():
    assert [r["bytes"] for r in run(EVENTS, "| sort -bytes | fields bytes")] == [900, 500, 100, 50]


def test_head_and_chain():
    assert len(run(EVENTS, "| head 2")) == 2
    assert run(EVENTS, "source=sysmon | sort bytes | head 1 | fields bytes") == [{"bytes": 50}]


@pytest.mark.parametrize("bad", [
    "garbage", "host=", "| head -1", "| head x", "| head", "| sort", "| sort a b",
    "| count host", "| count by", "| fields", "| bogus", "source=sysmon |",
    'host="unterminated',
])
def test_bad_queries_raise_valueerror(bad):
    with pytest.raises(ValueError):
        run(EVENTS, bad)
