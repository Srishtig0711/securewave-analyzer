def calculate_risk(network):
    risk_score = 0

    # Open networks are high risk
    if network["security"] == "Open":
        risk_score += 70
    else:
        risk_score += 20

    # Very strong signal means nearby
    if network["signal"] > -50:
        risk_score += 10

    # Weak signal means harder to attack
    if network["signal"] < -80:
        risk_score -= 10

    # Determine level
    if risk_score >= 70:
        level = "High Risk"
    elif risk_score >= 40:
        level = "Medium Risk"
    else:
        level = "Low Risk"

    return risk_score, level