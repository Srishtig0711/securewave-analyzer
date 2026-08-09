from dataclasses import dataclass, field
from datetime import datetime
from typing import List


@dataclass
class Network:
    """Represents a discovered Wi-Fi network."""

    ssid: str
    signal: int
    security: str

@dataclass
class NetworkAssessment:
    """Represents the security assessment of a Wi-Fi network."""

    network: Network
    score: int
    level: str

@dataclass
class Finding:
    """Represents a security finding detected during an audit."""

    title: str
    description: str
    severity: str
    evidence: str
    recommendation: str


@dataclass
class AuditResult:
    """Represents the complete result of a security audit."""

    findings: List[Finding] = field(default_factory=list)
    score: int = 0
    level: str = "Low"
    timestamp: datetime = field(default_factory=datetime.now)