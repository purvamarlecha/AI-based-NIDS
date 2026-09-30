def analyze_threat(attack_name, confidence, packet_count):
    """
    Calculates threat severity and risk score.
    """

    attack = attack_name.upper()

    # -------------------------------
    # Base risk according to attack
    # -------------------------------

    if attack == "BENIGN":
        base_risk = 0

    elif attack == "PORTSCAN":
        base_risk = 45

    elif attack == "DDOS":
        base_risk = 80

    else:
        base_risk = 60


    # -------------------------------
    # Confidence contribution
    # -------------------------------

    confidence_risk = confidence * 0.20


    # -------------------------------
    # Traffic contribution
    # -------------------------------

    traffic_risk = min(packet_count / 10, 20)


    # -------------------------------
    # Final risk score
    # -------------------------------

    risk_score = (
        base_risk
        + confidence_risk
        + traffic_risk
    )

    risk_score = min(
        round(risk_score),
        100
    )


    # -------------------------------
    # Severity
    # -------------------------------

    if attack == "BENIGN":

        severity = "LOW"

    elif risk_score >= 80:

        severity = "CRITICAL"

    elif risk_score >= 60:

        severity = "HIGH"

    elif risk_score >= 40:

        severity = "MEDIUM"

    else:

        severity = "LOW"


    # -------------------------------
    # Recommendation
    # -------------------------------

    if attack == "BENIGN":

        recommendation = (
            "Continue normal network monitoring."
        )

    elif attack == "PORTSCAN":

        recommendation = (
            "Monitor the source IP and "
            "consider restricting unnecessary ports."
        )

    elif attack == "DDOS":

        recommendation = (
            "Increase traffic monitoring and "
            "consider applying rate-limiting or firewall rules."
        )

    else:

        recommendation = (
            "Investigate the source and "
            "apply appropriate firewall restrictions."
        )


    return {
        "attack": attack_name,
        "risk_score": risk_score,
        "severity": severity,
        "recommendation": recommendation
    }