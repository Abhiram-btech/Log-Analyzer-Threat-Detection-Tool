from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Iterable

_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>[\w\-\/\.]+):\s+"
    r"(?P<event>Failed password|Accepted password)\s+for\s+"
    r"(?P<username>[\w\.\-]+)\s+"
    r"from\s+(?P<ip>[\d\.]+)\s+"
    r"port\s+(?P<port>\d+)"
)


@dataclass(frozen=True)
class AuthLogEntry:
    timestamp: datetime
    host: str
    service: str
    event: str
    username: str
    ip: str
    port: int

    @property
    def is_failed(self) -> bool:
        return self.event == "Failed password"

    @property
    def is_success(self) -> bool:
        return self.event == "Accepted password"


def parse_auth_line(line: str) -> AuthLogEntry | None:
    """Parse a normalized auth log line into an AuthLogEntry."""
    match = _LOG_PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    return AuthLogEntry(
        timestamp=datetime.fromisoformat(data["timestamp"]),
        host=data["host"],
        service=data["service"],
        event=data["event"],
        username=data["username"],
        ip=data["ip"],
        port=int(data["port"]),
    )


def parse_auth_log(lines: Iterable[str]) -> list[AuthLogEntry]:
    """Parse all valid lines from auth logs."""
    entries: list[AuthLogEntry] = []
    for line in lines:
        parsed = parse_auth_line(line)
        if parsed is not None:
            entries.append(parsed)
    return entries
