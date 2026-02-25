from report_generator import export_to_csv
from scanner import scan_networks
from risk_engine import calculate_risk
from tabulate import tabulate
from colorama import Fore, init

init(autoreset=True)


def main():
    print("\n=== SecureWave Analyzer ===\n")

    networks = scan_networks()

    if not networks:
        print("No networks found.")
        return

    # Calculate risk
    for net in networks:
        score, level = calculate_risk(net)
        net["risk_score"] = score
        net["risk_level"] = level

    # Sort by highest risk first
    networks.sort(key=lambda x: x["risk_score"], reverse=True)

    table = []

    for net in networks:
        table.append([
            net["ssid"],
            net["signal"],
            net["security"],
            net["risk_score"],
            net["risk_level"]
        ])

    headers = ["SSID", "Signal (dBm)", "Security", "Risk Score", "Risk Level"]

    print(tabulate(table, headers=headers, tablefmt="grid"))

    # Export CSV
    export_to_csv(networks)

    # Colored recommendations
    print("\nSecurity Recommendations:\n")

    for net in networks:
        if net["risk_level"] == "High Risk":
            print(Fore.RED + f"- {net['ssid']} is HIGH RISK. Avoid connecting.")
        elif net["risk_level"] == "Medium Risk":
            print(Fore.YELLOW + f"- {net['ssid']} has moderate risk. Use caution.")
        else:
            print(Fore.GREEN + f"- {net['ssid']} is relatively safe.")


if __name__ == "__main__":
    main()