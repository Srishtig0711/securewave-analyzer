import csv


def export_to_csv(networks, filename="securewave_report.csv"):
    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        # Header row
        writer.writerow(["SSID", "Signal (dBm)", "Security", "Risk Score", "Risk Level"])

        # Data rows
        for net in networks:
            writer.writerow([
                net["ssid"],
                net["signal"],
                net["security"],
                net["risk_score"],
                net["risk_level"]
            ])

    print(f"\nReport exported successfully as '{filename}'")