from models import Network


def calculate_risk(network: Network):
    """
    Calculate the baseline security risk of a Wi-Fi network.

    The baseline score is based on the network's security configuration.
    Traffic-based findings will be incorporated into the risk assessment
    in a later version of the audit engine.
    """

    security_scores = {
        "Open": 80,
        "Unknown": 60,
        "WPA": 50,
        "WPA2": 25,
        "WPA3": 10,
    }

    risk_score = security_scores.get(network.security, 60)

    if risk_score >= 70:
        level = "High Risk"
    elif risk_score >= 40:
        level = "Medium Risk"
    else:
        level = "Low Risk"

    return risk_score, level