import pytest

from app.agent.tools import Toolbox, call_tool, haversine_km

LOGIN = {
    "user": "u@acme-corp.com", "src_ip": "1.2.3.4", "device_id": "d1", "user_agent": "x", "auth_method": "password+mfa", "mfa_result": "pass",
    "geo": {"city": "Frankfurt", "country": "DE", "lat": 50.11, "lon": 8.68},
    "previous_login": {"city": "Vancouver", "country": "CA", "lat": 49.28, "lon": -123.12, "minutes_ago": 10},
}


def test_haversine_vancouver_frankfurt():
    assert 8000 < haversine_km(49.28, -123.12, 50.11, 8.68) < 8300


def test_impossible_travel_detected():
    tb = Toolbox("login", LOGIN, lambda k, key: None)
    assert tb.geo_velocity()["impossible_travel"] is True


def test_tool_scope_is_enforced():
    tb = Toolbox("login", LOGIN, lambda k, key: None)
    with pytest.raises(ValueError):
        call_tool(tb, "inspect_attachments", {})  # phishing tool, not allowed on a login alert


def test_tool_args_are_validated():
    tb = Toolbox("login", LOGIN, lambda k, key: None)
    with pytest.raises(ValueError):
        call_tool(tb, "lookup_ip", {"ip": "1.2.3.4; rm -rf /"})
