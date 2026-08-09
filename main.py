from report_generator import export_to_csv
from scanner import scan_networks
from risk_engine import calculate_risk
from models import NetworkAssessment
from tabulate import tabulate
from colorama import Fore, init

init(autoreset=True)


def main():
    print("\n=== SecureWave Analyzer ===\n")

    networks = scan_networks()

    if not networks:
        print("No networks found.")
        return

    # Calculate risk assessments
    assessments = []

    for network in networks:
        score, level = calculate_risk(network)

        assessment = NetworkAssessment(
            network=network,
            score=score,
            level=level
        )

        assessments.append(assessment)

    # Sort by highest risk first
    assessments.sort(key=lambda x: x.score, reverse=True)

    table = []

    for assessment in assessments:
        network = assessment.network

        table.append([
            network.ssid,
            network.signal,
            network.security,
            assessment.score,
            assessment.level
        ])

    headers = [
        "SSID",
        "Signal (dBm)",
        "Security",
        "Risk Score",
        "Risk Level"
    ]

    print(tabulate(table, headers=headers, tablefmt="grid"))

    # Export CSV
    export_to_csv(assessments)

    # Colored recommendations
    print("\nSecurity Recommendations:\n")

    for assessment in assessments:
        network = assessment.network

        if assessment.level == "High Risk":
            print(
                Fore.RED
                + f"- {network.ssid} is HIGH RISK. Avoid connecting."
            )
        elif assessment.level == "Medium Risk":
            print(
                Fore.YELLOW
                + f"- {network.ssid} has moderate risk. Use caution."
            )
        else:
            print(
                Fore.GREEN
                + f"- {network.ssid} is relatively safe."
            )


if __name__ == "__main__":
    main()