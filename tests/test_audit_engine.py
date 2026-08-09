from audit_engine import generate_audit_summary


def test_http_traffic_creates_finding():
    stats = {
        "HTTP": 1
    }

    result = generate_audit_summary(stats)

    assert result.score > 0
    assert result.level in ["LOW", "MEDIUM", "HIGH"]

    titles = [finding.title for finding in result.findings]

    assert "Unencrypted HTTP Traffic" in titles


def test_high_icmp_creates_finding():
    stats = {
        "ICMP": 60
    }

    result = generate_audit_summary(stats)

    titles = [finding.title for finding in result.findings]

    assert "Possible ICMP Reconnaissance" in titles


def test_high_tcp_creates_finding():
    stats = {
        "TCP": 250
    }

    result = generate_audit_summary(stats)

    titles = [finding.title for finding in result.findings]

    assert "Possible TCP Scanning Activity" in titles


def test_high_dns_creates_finding():
    stats = {
        "DNS": 45
    }

    result = generate_audit_summary(stats)

    titles = [finding.title for finding in result.findings]

    assert "Unusually High DNS Activity" in titles


def test_clean_traffic_has_no_findings():
    result = generate_audit_summary({})

    assert result.score == 0
    assert result.level == "LOW"
    assert len(result.findings) == 0