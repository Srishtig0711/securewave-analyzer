import csv

from models import NetworkAssessment


def export_to_csv(
    assessments: list[NetworkAssessment],
    filename="securewave_report.csv"
):
    """Export network security assessments to a CSV report."""

    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow([
            "SSID",
            "Signal (dBm)",
            "Security",
            "Risk Score",
            "Risk Level"
        ])

        for assessment in assessments:
            network = assessment.network

            writer.writerow([
                network.ssid,
                network.signal,
                network.security,
                assessment.score,
                assessment.level
            ])

    print(f"\nReport exported successfully as '{filename}'")