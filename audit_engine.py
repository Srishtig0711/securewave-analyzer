from datetime import datetime

def generate_audit_summary(stats, encryption_type=None):
    summary = []
    classifications = []
    recommendations = []
    risk_score = 0

    # --------------------------
    # Encryption Compliance
    # --------------------------
    if encryption_type:
        if encryption_type == "Open":
            summary.append("Open network detected.")
            classifications.append("Critical Security Misconfiguration")
            recommendations.append("Enable WPA2 or WPA3 encryption immediately.")
            risk_score += 40

        elif encryption_type == "WPA":
            summary.append("WPA encryption is deprecated.")
            classifications.append("Weak Encryption Protocol")
            recommendations.append("Upgrade to WPA2 or WPA3.")
            risk_score += 25

        elif encryption_type == "WPA2":
            summary.append("WPA2 encryption detected.")
            recommendations.append("Consider upgrading to WPA3 for enhanced security.")

        elif encryption_type == "WPA3":
            summary.append("WPA3 encryption detected (Strong).")

    # --------------------------
    # Traffic Analysis
    # --------------------------
    http_count = stats.get("HTTP", 0)
    icmp_count = stats.get("ICMP", 0)
    dns_count = stats.get("DNS", 0)
    tcp_count = stats.get("TCP", 0)

    if http_count > 0:
        summary.append("Unencrypted HTTP traffic observed.")
        classifications.append("Unencrypted Data Transmission")
        recommendations.append("Use HTTPS to secure communication.")
        risk_score += 20

    if icmp_count > 50:
        summary.append("High ICMP traffic volume detected.")
        classifications.append("Possible Ping Sweep / Network Scanning")
        recommendations.append("Monitor for reconnaissance behavior.")
        risk_score += 15

    if tcp_count > 200:
        summary.append("High TCP connection volume detected.")
        classifications.append("Possible Port Scanning Activity")
        recommendations.append("Review connection logs for suspicious hosts.")
        risk_score += 15

    if dns_count > 40:
        summary.append("High DNS query volume observed.")
        classifications.append("Excessive DNS Activity")
        recommendations.append("Investigate unusual domain resolution behavior.")
        risk_score += 10

    # --------------------------
    # Risk Classification
    # --------------------------
    if risk_score >= 60:
        risk_level = "HIGH"
        overall_status = "CRITICAL"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
        overall_status = "AT RISK"
    else:
        risk_level = "LOW"
        overall_status = "SECURE"

    if not summary:
        summary.append("No significant anomalies detected.")
        overall_status = "SECURE"

    audit_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "classifications": list(set(classifications)),
        "recommendations": list(set(recommendations)),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "overall_status": overall_status
    }

    return audit_data