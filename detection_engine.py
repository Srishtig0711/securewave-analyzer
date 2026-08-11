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

        if http_count >= 10:
            confidence = 95
        else:
            confidence = 85

        findings.append(
            Finding(
                title="Unencrypted HTTP Traffic",
                description=(
                    "Unencrypted HTTP traffic was observed during "
                    "the monitoring period. HTTP does not provide "
                    "the same transport encryption as HTTPS."
                ),
                severity="Medium",
                evidence=f"{http_count} HTTP packet(s) detected.",
                recommendation=(
                    "Prefer HTTPS connections when transmitting "
                    "sensitive information."
                ),
                confidence=confidence
            )
        )

    # --------------------------
    # ICMP Detection
    # --------------------------

    if icmp_count > 50:

        if icmp_count >= 100:
            confidence = 90
        else:
            confidence = 75

        findings.append(
            Finding(
                title="Possible ICMP Reconnaissance",
                description=(
                    "A high volume of ICMP traffic was observed. "
                    "This may be consistent with network discovery "
                    "or reconnaissance activity, although legitimate "
                    "network diagnostics can also generate ICMP traffic."
                ),
                severity="Medium",
                evidence=f"{icmp_count} ICMP packet(s) detected.",
                recommendation=(
                    "Investigate the traffic sources and monitor "
                    "for repeated reconnaissance patterns."
                ),
                confidence=confidence
            )
        )

    # --------------------------
    # TCP Detection
    # --------------------------

    if tcp_count > 200:

        if tcp_count >= 500:
            confidence = 90
        else:
            confidence = 75

        findings.append(
            Finding(
                title="Possible TCP Scanning Activity",
                description=(
                    "A high volume of TCP traffic was observed. "
                    "This may indicate connection probing or other "
                    "high-volume network activity."
                ),
                severity="Medium",
                evidence=f"{tcp_count} TCP packet(s) detected.",
                recommendation=(
                    "Review connection patterns and investigate "
                    "unusual source or destination hosts."
                ),
                confidence=confidence
            )
        )

    # --------------------------
    # DNS Detection
    # --------------------------

    if dns_count > 40:

        if dns_count >= 100:
            confidence = 90
        else:
            confidence = 70

        findings.append(
            Finding(
                title="Unusually High DNS Activity",
                description=(
                    "A high volume of DNS queries was observed "
                    "during the monitoring period. High DNS activity "
                    "can be caused by legitimate applications as well "
                    "as unusual network behaviour."
                ),
                severity="Low",
                evidence=f"{dns_count} DNS packet(s) detected.",
                recommendation=(
                    "Review DNS activity for unexpected applications "
                    "or unusually frequent domain lookups."
                ),
                confidence=confidence
            )
        )

    return findings