from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity {value!r}") from exc


@dataclass
class Finding:
    rule: str
    severity: Severity
    target: str  # table, function, view or file:line
    message: str
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.name.lower(),
            "target": self.target,
            "message": self.message,
            "remediation": self.remediation,
        }
