"""Log analyzer package for threat detection."""

from .detector import Alert, DetectionConfig, detect_threats
from .parser import AuthLogEntry, parse_auth_log

__all__ = [
    "Alert",
    "AuthLogEntry",
    "DetectionConfig",
    "detect_threats",
    "parse_auth_log",
]
