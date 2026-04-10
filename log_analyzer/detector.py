from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal

from .parser import AuthLogEntry


AlertSeverity = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class DetectionConfig:
    brute_force_attempt_threshold: int = 5
    brute_force_window_minutes: int = 5
    anomaly_distinct_ip_threshold: int = 3
    anomaly_window_minutes: int = 60


@dataclass(frozen=True)
class Alert:
    kind: str
    severity: AlertSeverity
    message: str
    username: str
    ip: str | None
    start_time: str
    end_time: str
    evidence_count: int


def _detect_bruteforce(entries: list[AuthLogEntry], config: DetectionConfig) -> list[Alert]:
    alerts: list[Alert] = []
    failures_by_ip: dict[str, deque[AuthLogEntry]] = defaultdict(deque)
    window = timedelta(minutes=config.brute_force_window_minutes)

    for entry in sorted(entries, key=lambda e: e.timestamp):
        if not entry.is_failed:
            continue

        bucket = failures_by_ip[entry.ip]
        bucket.append(entry)

        while bucket and (entry.timestamp - bucket[0].timestamp) > window:
            bucket.popleft()

        if len(bucket) == config.brute_force_attempt_threshold:
            alerts.append(
                Alert(
                    kind="brute_force_attempt",
                    severity="high",
                    message=(
                        f"{len(bucket)} failed logins from IP {entry.ip} in "
                        f"{config.brute_force_window_minutes} minutes"
                    ),
                    username=entry.username,
                    ip=entry.ip,
                    start_time=bucket[0].timestamp.isoformat(),
                    end_time=bucket[-1].timestamp.isoformat(),
                    evidence_count=len(bucket),
                )
            )

    return alerts


def _detect_anomalous_logins(entries: list[AuthLogEntry], config: DetectionConfig) -> list[Alert]:
    alerts: list[Alert] = []
    window = timedelta(minutes=config.anomaly_window_minutes)
    success_by_user: dict[str, deque[AuthLogEntry]] = defaultdict(deque)

    for entry in sorted(entries, key=lambda e: e.timestamp):
        if not entry.is_success:
            continue

        user_bucket = success_by_user[entry.username]
        user_bucket.append(entry)

        while user_bucket and (entry.timestamp - user_bucket[0].timestamp) > window:
            user_bucket.popleft()

        distinct_ips = {e.ip for e in user_bucket}
        if len(distinct_ips) == config.anomaly_distinct_ip_threshold:
            alerts.append(
                Alert(
                    kind="anomalous_login_activity",
                    severity="medium",
                    message=(
                        f"User {entry.username} logged in from {len(distinct_ips)} distinct "
                        f"IPs in {config.anomaly_window_minutes} minutes"
                    ),
                    username=entry.username,
                    ip=entry.ip,
                    start_time=user_bucket[0].timestamp.isoformat(),
                    end_time=user_bucket[-1].timestamp.isoformat(),
                    evidence_count=len(distinct_ips),
                )
            )

    return alerts


def detect_threats(entries: list[AuthLogEntry], config: DetectionConfig | None = None) -> list[Alert]:
    """Detect suspicious behavior using rule-based checks."""
    active_config = config or DetectionConfig()
    alerts = []
    alerts.extend(_detect_bruteforce(entries, active_config))
    alerts.extend(_detect_anomalous_logins(entries, active_config))
    return sorted(alerts, key=lambda alert: alert.start_time)
