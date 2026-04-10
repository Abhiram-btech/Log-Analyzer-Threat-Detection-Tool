from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detector import DetectionConfig, detect_threats
from .parser import parse_auth_log


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Analyze authentication logs for suspicious activity.",
    )
    parser.add_argument("log_file", help="Path to normalized auth log file")
    parser.add_argument("--bf-threshold", type=int, default=5, help="Failed attempts threshold")
    parser.add_argument("--bf-window", type=int, default=5, help="Brute-force time window in minutes")
    parser.add_argument(
        "--anomaly-ips",
        type=int,
        default=3,
        help="Distinct successful-login IP threshold",
    )
    parser.add_argument(
        "--anomaly-window",
        type=int,
        default=60,
        help="Anomalous-login time window in minutes",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    path = Path(args.log_file)
    if not path.exists():
        raise SystemExit(f"Log file not found: {path}")

    entries = parse_auth_log(path.read_text(encoding="utf-8").splitlines())
    config = DetectionConfig(
        brute_force_attempt_threshold=args.bf_threshold,
        brute_force_window_minutes=args.bf_window,
        anomaly_distinct_ip_threshold=args.anomaly_ips,
        anomaly_window_minutes=args.anomaly_window,
    )
    alerts = detect_threats(entries, config)

    output = {
        "parsed_entries": len(entries),
        "alert_count": len(alerts),
        "alerts": [alert.__dict__ for alert in alerts],
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
