from fastapi.testclient import TestClient

from app.db import init_db


def test_api_smoke():
    init_db(drop=True)
    from app.main import app
    with TestClient(app) as client:
        s = client.get("/api/summary").json()
        assert s["alerts"] >= 60 and {t["alert_type"] for t in s["types"]} == {"phishing", "login"}
        rows = client.get("/api/investigations?limit=5").json()
        d = client.get(f"/api/investigations/{rows[0]['id']}").json()
        assert d["steps"] and d["findings"]
        r = client.post(f"/api/investigations/{rows[0]['id']}/correct", json={"verdict": "benign", "note": "test"})
        assert r.status_code == 200
        assert "Autonomy evidence report" in client.get("/api/ladder/phishing/report").text
