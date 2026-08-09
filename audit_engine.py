from datetime import datetime

from models import AuditResult, Finding
from detection_engine import detect_traffic_findings


def generate_audit_summary(stats, encryption_type=None):
    """
    Analyse network traffic and encryption configuration
    and return a structured AuditResult.
    """

    findings = []

    # --------------------------
    # Encryption Analysis
    # --------------------------

    if encryption_type == "Open":
        findings.append(
            Finding(
                title="Open Wireless Network",
                description=(
                    "The network does not use wireless encryption, "
                    "which may allow nearby users to observe network traffic."
                ),
                severity="Critical",
                evidence="No wireless encryption was detected.",
                recommendation=(
                    "Enable WPA2 or WPA3 encryption and use a strong "
                    "wireless password."
                )
            )
        )

    elif encryption_type == "WPA":
        findings.append(
            Finding(
                title="Deprecated WPA Encryption",
                description=(
                    "WPA is an outdated wireless security protocol "
                    "with known security weaknesses."
                ),
                severity="High",
                evidence="WPA encryption was detected.",
                recommendation="Upgrade the network to WPA2 or WPA3."
            )
        )

    # --------------------------
    # Traffic Analysis
    # --------------------------

    findings.extend(
    detect_traffic_findings(stats)
    )

    # --------------------------
    # Risk Aggregation
    # --------------------------

    severity_weights = {
        "Critical": 40,
        "High": 25,
        "Medium": 20,
        "Low": 10,
    }

    risk_score = sum(
        severity_weights.get(finding.severity, 0)
        for finding in findings
    )

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return AuditResult(
        findings=findings,
        score=risk_score,
        level=risk_level,
        timestamp=datetime.now()
    )