from models import Finding


def detect_traffic_findings(stats):
    """
    Analyse captured network traffic and return
    structured security findings.
    """

    findings = []

    http_count = stats.get("HTTP", 0)
    icmp_count = stats.get("ICMP", 0)
    dns_count = stats.get("DNS", 0)
    tcp_count = stats.get("TCP", 0)

    # --------------------------
    # HTTP Detection
    # --------------------------

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

    # --------------------------
    # ICMP Detection
    # --------------------------

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

    # --------------------------
    # TCP Detection
    # --------------------------

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

    # --------------------------
    # DNS Detection
    # --------------------------

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

    return findings