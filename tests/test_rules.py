from datetime import datetime, timedelta, timezone

import pytest

from logsentry.engine import Engine
from logsentry.simulate import ATTACKS, Simulator, fw_block, ssh_fail, ssh_ok, sudo, web

T0 = datetime(2026, 11, 11, 10, 0, tzinfo=timezone.utc)


def run(lines):
    engine = Engine()
    return [a for _, line in lines for a in engine.process_line(line)]


def at(seconds):
    return T0 + timedelta(seconds=seconds)


def test_ssh_bruteforce_fires_at_threshold():
    alerts = run([ssh_fail(at(i), "web-01", "203.0.113.5", "root") for i in range(5)])
    assert [a.rule_id for a in alerts] == ["ssh_bruteforce"]
    assert alerts[0].severity == "high" and alerts[0].mitre == "T1110.001"


def test_ssh_bruteforce_ignores_slow_failures():
    # 5 failures spread over 5 minutes is a forgetful user, not an attack.
    assert run([ssh_fail(at(i * 70), "web-01", "10.0.1.25", "harsh") for i in range(5)]) == []


def test_password_spray_detected():
    users = ["admin", "test", "oracle", "guest", "pi"]
    alerts = run([ssh_fail(at(i), "web-01", "198.51.100.3", u, invalid=True) for i, u in enumerate(users)])
    assert alerts[0].title == "SSH password spraying" and alerts[0].mitre == "T1110.003"


def test_compromise_after_bruteforce_is_critical():
    lines = [ssh_fail(at(i), "web-02", "203.0.113.9", "deploy") for i in range(6)]
    lines.append(ssh_ok(at(30), "web-02", "203.0.113.9", "deploy", method="password"))
    alerts = run(lines)
    crit = [a for a in alerts if a.rule_id == "ssh_compromise"]
    assert len(crit) == 1 and crit[0].severity == "critical" and crit[0].user == "deploy"


def test_normal_login_is_not_compromise():
    lines = [ssh_fail(at(0), "bastion", "10.0.1.25", "harsh"), ssh_ok(at(5), "bastion", "10.0.1.25", "harsh")]
    assert run(lines) == []


def test_port_scan():
    alerts = run([fw_block(at(i * 0.2), "web-01", "192.0.2.50", port) for i, port in enumerate(range(20, 40))])
    assert [a.rule_id for a in alerts] == ["port_scan"]


def test_repeated_blocks_on_one_port_are_not_a_scan():
    assert run([fw_block(at(i), "web-01", "192.0.2.50", 445) for i in range(40)]) == []


@pytest.mark.parametrize("path,rule", [
    ("/item?id=1%27%20OR%20%271%27%3D%271", "web_attack.sqli"),
    ("/item?id=1%20UNION%20SELECT%20password%20FROM%20users", "web_attack.sqli"),
    ("/s?q=%3Cscript%3Ealert(1)%3C/script%3E", "web_attack.xss"),
    ("/dl?f=../../../../etc/passwd", "web_attack.traversal"),
    ("/ping?host=127.0.0.1%3Bwhoami", "web_attack.cmdi"),
    ("/.env", "web_attack.sensitive"),
])
def test_web_attack_signatures(path, rule):
    alerts = run([web(at(0), "203.0.113.20", "GET", path, 200, "curl/8")])
    assert rule in [a.rule_id for a in alerts]


@pytest.mark.parametrize("path", ["/", "/products/42", "/search?q=union+station+hotels", "/blog/select-the-right-laptop",
                                  "/static/app.js", "/api/v1/items?sort=price&order=desc"])
def test_normal_requests_do_not_alert(path):
    assert run([web(at(0), "66.1.2.3", "GET", path, 200, "Mozilla/5.0")]) == []


def test_directory_enumeration():
    alerts = run([web(at(i * 0.1), "203.0.113.30", "GET", f"/dir{i}", 404, "gobuster/3.6") for i in range(25)])
    assert [a.rule_id for a in alerts] == ["web_enumeration"]
    assert "gobuster" in alerts[0].description


def test_service_account_sudo_is_critical():
    alerts = run([sudo(at(0), "web-01", "www-data", "/bin/bash -i")])
    assert alerts[0].rule_id == "sudo_abuse.service_account" and alerts[0].severity == "critical"


def test_routine_admin_sudo_is_quiet():
    assert run([sudo(at(0), "web-01", "ubuntu", "/usr/bin/apt update")]) == []


def test_duplicate_alerts_are_merged():
    # 25 failures = 5 bursts, but the analyst should see one alert with a count.
    alerts = run([ssh_fail(at(i), "web-01", "203.0.113.5", "root") for i in range(25)])
    assert len(alerts) == 1


@pytest.mark.parametrize("name", list(ATTACKS))
def test_every_simulated_attack_is_detected(name):
    assert run(Simulator(realtime=False, seed=7, start=T0).run_scenario(name)), f"{name} went undetected"


def test_background_traffic_has_no_false_positives():
    lines = list(Simulator(realtime=False, seed=11, start=T0).stream(duration=3 * 3600, scenarios=[]))
    assert len(lines) > 15000
    assert run(lines) == []


def test_slow_brute_force_is_a_known_blind_spot():
    """Documented limitation: one guess every 2 minutes stays under the
    60-second window. Catching it needs longer-term per-IP baselining."""
    assert run([ssh_fail(at(i * 120), "web-01", "203.0.113.99", "root") for i in range(30)]) == []
