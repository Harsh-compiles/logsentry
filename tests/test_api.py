import os
import time
from datetime import datetime, timezone

import pytest

from logsentry.api import create_app
from logsentry.collector import Collector
from logsentry.engine import Engine
from logsentry.simulate import sql_injection, ssh_fail, web
from logsentry.store import Store


@pytest.fixture
def setup(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    engine = Engine(store=store)
    app = create_app(store, engine)
    app.testing = True
    return store, engine, app.test_client()


def feed(engine, lines):
    for _, line in lines:
        engine.process_line(line)


def test_dashboard_endpoint(setup):
    store, engine, client = setup
    now = datetime.now(timezone.utc)
    feed(engine, [ssh_fail(now, "web-01", "203.0.113.5", "root") for _ in range(6)])
    data = client.get("/api/dashboard").get_json()
    assert data["stats"]["total_events"] == 6
    assert data["stats"]["alerts_by_severity"]["high"] == 1
    assert data["alerts"][0]["src_ip"] == "203.0.113.5"
    assert data["stats"]["top_attackers"][0]["ip"] == "203.0.113.5"
    assert sum(p["events"] for p in data["stats"]["timeline"]) == 6


def test_alert_status_update(setup):
    store, engine, client = setup
    feed(engine, [web(datetime.now(timezone.utc), "203.0.113.9", "GET", "/.env", 404, "curl")])
    alert_id = client.get("/api/alerts").get_json()[0]["id"]
    assert client.post(f"/api/alerts/{alert_id}/status", json={"status": "bogus"}).status_code == 400
    assert client.post(f"/api/alerts/{alert_id}/status", json={"status": "resolved"}).status_code == 200
    assert client.get("/api/alerts").get_json()[0]["status"] == "resolved"
    assert client.post("/api/alerts/nope/status", json={"status": "resolved"}).status_code == 404


def test_status_update_requires_token_when_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGSENTRY_API_TOKEN", "s3cret")
    store = Store(str(tmp_path / "t.db"))
    client = create_app(store).test_client()
    assert client.post("/api/alerts/x/status", json={"status": "resolved"}).status_code == 401
    r = client.post("/api/alerts/x/status", json={"status": "resolved"}, headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 404  # authorised, alert just doesn't exist


def test_dashboard_page_and_security_headers(setup):
    _, _, client = setup
    r = client.get("/")
    assert r.status_code == 200 and b"LogSentry" in r.data
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"


def test_collector_tails_a_growing_file(tmp_path):
    """End to end: lines appended to a log file become alerts."""
    path = tmp_path / "remote.log"
    path.write_text("")
    engine = Engine()
    collector = Collector(engine, [str(path)], interval=0.05)
    collector.start()
    time.sleep(0.2)
    with open(path, "a") as f:
        for _delay, fn in sql_injection():
            f.write(fn(datetime.now(timezone.utc))[1] + "\n")
    deadline = time.time() + 3
    while time.time() < deadline and engine.events_seen < 6:
        time.sleep(0.05)
    collector.stop()
    assert engine.events_seen == 6
    assert any(a.rule_id == "web_attack.sqli" for _, (a, _) in engine.active.items())


def test_collector_survives_log_rotation(tmp_path):
    path = tmp_path / "remote.log"
    path.write_text("")
    engine = Engine()
    collector = Collector(engine, [str(path)], interval=0.05)
    collector.start()
    time.sleep(0.2)
    now = datetime.now(timezone.utc)
    with open(path, "a") as f:
        f.write(ssh_fail(now, "h", "192.0.2.1", "root")[1] + "\n")
    time.sleep(0.3)
    os.rename(path, tmp_path / "remote.log.1")  # logrotate moves the file ...
    with open(path, "w") as f:                  # ... and a new one is created
        f.write(ssh_fail(now, "h", "192.0.2.1", "root")[1] + "\n")
    deadline = time.time() + 3
    while time.time() < deadline and engine.events_seen < 2:
        time.sleep(0.05)
    collector.stop()
    assert engine.events_seen == 2
