# Log Analyzer & Threat Detection Tool

Python-based log analyzer to detect brute-force attempts and anomalous login activity from authentication logs.

## Features

- Parses normalized SSH/auth log lines
- Detects brute-force attempts using failed-login thresholds
- Detects anomalous login behavior using distinct-IP thresholds per user
- Rule-based alerting for faster identification of suspicious behavior
- JSON output for easy SIEM/SOC integration

## Project Structure

```
log_analyzer/
  __init__.py
  __main__.py
  cli.py
  detector.py
  parser.py
data/
  sample_auth.log
tests/
  test_log_analyzer.py
requirements.txt
```

## Log Format

This project expects normalized log lines like:

```text
2026-04-10T10:00:00 srv1 sshd: Failed password for admin from 185.12.1.4 port 51200
2026-04-10T10:15:00 srv1 sshd: Accepted password for analyst from 10.0.0.4 port 61000
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python -m log_analyzer data/sample_auth.log
```

Optional tuning:

```bash
python -m log_analyzer data/sample_auth.log \
  --bf-threshold 5 \
  --bf-window 5 \
  --anomaly-ips 3 \
  --anomaly-window 60
```

## Running Tests

```bash
pytest -q
```

## Example Output

```json
{
  "parsed_entries": 8,
  "alert_count": 2,
  "alerts": [
    {
      "kind": "brute_force_attempt",
      "severity": "high",
      "message": "5 failed logins from IP 185.12.1.4 in 5 minutes",
      "username": "admin",
      "ip": "185.12.1.4",
      "start_time": "2026-04-10T10:00:00",
      "end_time": "2026-04-10T10:03:12",
      "evidence_count": 5
    }
  ]
}
```
