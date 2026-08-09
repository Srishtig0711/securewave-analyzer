from datetime import datetime

from models import AuditResult, Finding


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

    http_count = stats.get("HTTP", 0)
    icmp_count = stats.get("ICMP", 0)
    dns_count = stats.get("DNS", 0)
    tcp_count = stats.get("TCP", 0)

    if http_count > 0:
        findings.append(
            Finding(
                title="Unencrypted HTTP Traffic",
                description=(
                    "Unencrypted HTTP traffic was observed during "
                    "the monitoring period."
                ),
                severity="Medium",
                evidence=f"{http_count} HTTP packet(s) detected.",
                recommendation=(
                    "Prefer HTTPS connections to protect data "
                    "during transmission."
                )
            )
        )

    if icmp_count > 50:
        findings.append(
            Finding(
                title="Possible ICMP Reconnaissance",
                description=(
                    "A high volume of ICMP traffic was observed. "
                    "This may be consistent with network discovery "
                    "or reconnaissance activity."
                ),
                severity="Medium",
                evidence=f"{icmp_count} ICMP packet(s) detected.",
                recommendation=(
                    "Investigate the traffic sources and monitor "
                    "for repeated reconnaissance patterns."
                )
            )
        )

    if tcp_count > 200:
        findings.append(
            Finding(
                title="Possible TCP Scanning Activity",
                description=(
                    "A high volume of TCP traffic was observed. "
                    "This may indicate connection probing or "
                    "other high-volume network activity."
                ),
                severity="Medium",
                evidence=f"{tcp_count} TCP packet(s) detected.",
                recommendation=(
                    "Review connection patterns and investigate "
                    "unusual source or destination hosts."
                )
            )
        )

    if dns_count > 40:
        findings.append(
            Finding(
                title="Unusually High DNS Activity",
                description=(
                    "A high volume of DNS queries was observed "
                    "during the monitoring period."
                ),
                severity="Low",
                evidence=f"{dns_count} DNS packet(s) detected.",
                recommendation=(
                    "Review DNS activity for unexpected applications "
                    "or unusually frequent domain lookups."
                )
            )
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

    if risk_score >= 60:
        overall_status = "CRITICAL"
    elif risk_score >= 30:
        overall_status = "AT RISK"
    else:
        overall_status = "SECURE"

    if not findings:
        overall_status = "SECURE"

    return AuditResult(
        findings=findings,
        score=risk_score,
        level=risk_level,
        timestamp=datetime.now()
    )