from log_analyzer.detector import DetectionConfig, detect_threats
from log_analyzer.parser import parse_auth_log


def test_detects_bruteforce_attempts():
    lines = [
        "2026-04-10T10:00:00 srv sshd: Failed password for root from 8.8.8.8 port 50000",
        "2026-04-10T10:01:00 srv sshd: Failed password for root from 8.8.8.8 port 50001",
        "2026-04-10T10:02:00 srv sshd: Failed password for root from 8.8.8.8 port 50002",
        "2026-04-10T10:03:00 srv sshd: Failed password for root from 8.8.8.8 port 50003",
        "2026-04-10T10:04:00 srv sshd: Failed password for root from 8.8.8.8 port 50004",
    ]

    entries = parse_auth_log(lines)
    alerts = detect_threats(
        entries,
        DetectionConfig(brute_force_attempt_threshold=5, brute_force_window_minutes=5),
    )

    brute_force_alerts = [a for a in alerts if a.kind == "brute_force_attempt"]
    assert len(brute_force_alerts) == 1
    assert brute_force_alerts[0].severity == "high"


def test_detects_anomalous_login_activity():
    lines = [
        "2026-04-10T10:00:00 srv sshd: Accepted password for alice from 1.1.1.1 port 50000",
        "2026-04-10T10:15:00 srv sshd: Accepted password for alice from 2.2.2.2 port 50001",
        "2026-04-10T10:20:00 srv sshd: Accepted password for alice from 3.3.3.3 port 50002",
    ]

    entries = parse_auth_log(lines)
    alerts = detect_threats(
        entries,
        DetectionConfig(anomaly_distinct_ip_threshold=3, anomaly_window_minutes=60),
    )

    anomaly_alerts = [a for a in alerts if a.kind == "anomalous_login_activity"]
    assert len(anomaly_alerts) == 1
    assert anomaly_alerts[0].severity == "medium"


def test_ignores_invalid_lines():
    lines = [
        "this line will not parse",
        "2026-04-10T10:00:00 srv sshd: Failed password for root from 9.9.9.9 port 51000",
    ]

    entries = parse_auth_log(lines)
    assert len(entries) == 1
