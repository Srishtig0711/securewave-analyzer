import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

from scanner import scan_networks
from risk_engine import calculate_risk
from models import NetworkAssessment
from report_generator import export_to_csv

import matplotlib.pyplot as plt

from packet_monitor import run_packet_monitor
from audit_engine import generate_audit_summary
from pdf_report import export_pdf_report


last_scan = []
last_audit_result = None
last_stats = None


# ================= NETWORK SCANNING =================

def scan_and_display():
    global last_scan

    for row in tree.get_children():
        tree.delete(row)

    networks = scan_networks()
    assessments = []

    for network in networks:
        score, level = calculate_risk(network)

        assessment = NetworkAssessment(
            network=network,
            score=score,
            level=level
        )

        assessments.append(assessment)

        if level == "High Risk":
            tag = "high"
        elif level == "Medium Risk":
            tag = "medium"
        else:
            tag = "low"

        tree.insert(
            "",
            "end",
            values=(
                network.ssid,
                network.signal,
                network.security,
                assessment.score,
                assessment.level,
            ),
            tags=(tag,),
        )

    last_scan = assessments


# ================= CSV EXPORT =================

def export_report():
    if last_scan:
        export_to_csv(last_scan)


# ================= SIGNAL GRAPH =================

def show_graph():
    if not last_scan:
        return

    ssids = [
        assessment.network.ssid
        for assessment in last_scan
    ]

    signals = [
        assessment.network.signal
        for assessment in last_scan
    ]

    plt.figure(figsize=(10, 6))

    bars = plt.bar(ssids, signals)

    plt.xlabel(
        "SSID",
        fontsize=12
    )

    plt.ylabel(
        "Signal Strength (dBm)",
        fontsize=12
    )

    plt.title(
        "WiFi Signal Strength Analysis",
        fontsize=14,
        fontweight="bold"
    )

    plt.xticks(
        rotation=45,
        ha="right"
    )

    plt.grid(
        axis="y",
        linestyle="--",
        alpha=0.7
    )

    for bar in bars:
        height = bar.get_height()

        plt.text(
            bar.get_x() + bar.get_width() / 2,
            height,
            f"{height}",
            ha="center",
            va="bottom",
            fontsize=8
        )

    plt.tight_layout()
    plt.show()


# ================= NETWORK AUDIT =================

def run_network_audit():
    global last_audit_result, last_stats

    audit_output.delete(
        "1.0",
        tk.END
    )

    stats = run_packet_monitor(10)

    audit_result = generate_audit_summary(stats)

    last_audit_result = audit_result
    last_stats = stats

    # --------------------------
    # Report Header
    # --------------------------

    audit_output.insert(
        tk.END,
        "WIRELESS SECURITY AUDIT REPORT\n",
        "header"
    )

    audit_output.insert(
        tk.END,
        "\n"
    )

    audit_output.insert(
        tk.END,
        "Timestamp\n",
        "section"
    )

    audit_output.insert(
        tk.END,
        f"{audit_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    )

    # --------------------------
    # Traffic Statistics
    # --------------------------

    audit_output.insert(
        tk.END,
        "TRAFFIC STATISTICS\n",
        "section"
    )

    for key, value in stats.items():
        audit_output.insert(
            tk.END,
            f"  {key}: {value}\n"
        )

    audit_output.insert(
        tk.END,
        "\n"
    )

    # --------------------------
    # Risk Summary
    # --------------------------

    audit_output.insert(
        tk.END,
        "SECURITY SUMMARY\n",
        "section"
    )

    audit_output.insert(
        tk.END,
        f"Risk Score: {audit_result.score}\n"
    )

    audit_output.insert(
        tk.END,
        f"Risk Level: {audit_result.level}\n"
    )

    if audit_result.level == "HIGH":
        overall_status = "CRITICAL"
        status_tag = "critical"

    elif audit_result.level == "MEDIUM":
        overall_status = "AT RISK"
        status_tag = "warning"

    else:
        overall_status = "SECURE"
        status_tag = "secure"

    audit_output.insert(
        tk.END,
        "Overall Status: "
    )

    audit_output.insert(
        tk.END,
        f"{overall_status}\n\n",
        status_tag
    )

    # --------------------------
    # Security Findings
    # --------------------------

    audit_output.insert(
        tk.END,
        "SECURITY FINDINGS\n",
        "section"
    )

    audit_output.insert(
        tk.END,
        "\n"
    )

    if not audit_result.findings:

        audit_output.insert(
            tk.END,
            "No significant security findings were detected.\n\n",
            "secure"
        )

        audit_output.insert(
            tk.END,
            "This means SecureWave did not identify any of the "
            "currently monitored traffic patterns that crossed "
            "its detection thresholds.\n"
        )

        return

    # --------------------------
    # Display Each Finding
    # --------------------------

    for index, finding in enumerate(
        audit_result.findings,
        start=1
    ):

        # Severity colour
        if finding.severity == "Critical":
            severity_tag = "critical"

        elif finding.severity == "High":
            severity_tag = "high"

        elif finding.severity == "Medium":
            severity_tag = "warning"

        else:
            severity_tag = "low"

        audit_output.insert(
            tk.END,
            f"{index}. {finding.title}\n",
            severity_tag
        )

        audit_output.insert(
            tk.END,
            f"Risk Level: {finding.severity}\n"
        )

        audit_output.insert(
            tk.END,
            f"Detection Confidence: "
            f"{finding.confidence}%\n\n"
        )

        audit_output.insert(
            tk.END,
            "What we detected\n",
            "subheading"
        )

        audit_output.insert(
            tk.END,
            f"{finding.evidence}\n\n"
        )

        audit_output.insert(
            tk.END,
            "What this means\n",
            "subheading"
        )

        audit_output.insert(
            tk.END,
            f"{finding.what_it_means}\n\n"
        )

        audit_output.insert(
            tk.END,
            "Why this matters\n",
            "subheading"
        )

        audit_output.insert(
            tk.END,
            f"{finding.description}\n\n"
        )

        audit_output.insert(
            tk.END,
            "What you can do\n",
            "subheading"
        )

        audit_output.insert(
            tk.END,
            f"{finding.recommendation}\n"
        )

        audit_output.insert(
            tk.END,
            "\n"
            + "-" * 70
            + "\n\n"
        )


# ================= PDF EXPORT =================

def export_pdf():
    global last_audit_result, last_stats

    if not last_audit_result or not last_stats:
        print(
            "Please run Network Audit before exporting PDF."
        )
        return

    try:
        export_pdf_report(
            last_stats,
            last_audit_result
        )

        print(
            "PDF generated successfully in project folder."
        )

    except Exception as e:
        print(
            "Error generating PDF:",
            e
        )


# ================= GUI SETUP =================

root = tk.Tk()

root.title(
    "SecureWave Analyzer"
)

root.geometry(
    "1000x700"
)

root.configure(
    bg="#f4f6f9"
)


# ================= TITLE =================

title_label = tk.Label(
    root,
    text="SecureWave Analyzer",
    font=("Arial", 18, "bold"),
    bg="#f4f6f9",
)

title_label.pack(
    pady=12
)


# ================= BUTTONS =================

button_frame = tk.Frame(
    root,
    bg="#f4f6f9"
)

button_frame.pack(
    pady=5
)


scan_button = tk.Button(
    button_frame,
    text="Scan Networks",
    command=scan_and_display,
    width=18,
    bg="#007bff",
    fg="white",
)

scan_button.grid(
    row=0,
    column=0,
    padx=6
)


export_button = tk.Button(
    button_frame,
    text="Export to CSV",
    command=export_report,
    width=18,
    bg="#28a745",
    fg="white",
)

export_button.grid(
    row=0,
    column=1,
    padx=6
)


graph_button = tk.Button(
    button_frame,
    text="Show Signal Graph",
    command=show_graph,
    width=18,
    bg="#6f42c1",
    fg="white",
)

graph_button.grid(
    row=0,
    column=2,
    padx=6
)


audit_button = tk.Button(
    button_frame,
    text="Run Network Audit",
    command=run_network_audit,
    width=18,
    bg="#dc3545",
    fg="white",
)

audit_button.grid(
    row=0,
    column=3,
    padx=6
)


pdf_button = tk.Button(
    button_frame,
    text="Export Audit PDF",
    command=export_pdf,
    width=18,
    bg="#343a40",
    fg="white",
)

pdf_button.grid(
    row=0,
    column=4,
    padx=6
)


# ================= NETWORK TABLE =================

columns = (
    "SSID",
    "Signal (dBm)",
    "Security",
    "Risk Score",
    "Risk Level"
)


tree = ttk.Treeview(
    root,
    columns=columns,
    show="headings",
    height=10
)


for col in columns:

    tree.heading(
        col,
        text=col
    )

    tree.column(
        col,
        width=180,
        anchor="center"
    )


tree.tag_configure(
    "high",
    background="#ffcccc"
)

tree.tag_configure(
    "medium",
    background="#fff3cd"
)

tree.tag_configure(
    "low",
    background="#d4edda"
)


tree.pack(
    fill="both",
    expand=False,
    padx=20,
    pady=10
)


# ================= AUDIT OUTPUT =================

audit_output = ScrolledText(
    root,
    height=18,
    wrap=tk.WORD,
    font=("Consolas", 10)
)

audit_output.pack(
    fill="both",
    expand=True,
    padx=20,
    pady=5
)


# ================= TEXT STYLES =================

audit_output.tag_configure(
    "header",
    font=("Arial", 15, "bold"),
    foreground="#212529"
)

audit_output.tag_configure(
    "section",
    font=("Arial", 11, "bold"),
    foreground="#343a40"
)

audit_output.tag_configure(
    "subheading",
    font=("Arial", 10, "bold"),
    foreground="#495057"
)

audit_output.tag_configure(
    "critical",
    font=("Arial", 11, "bold"),
    foreground="#b02a37"
)

audit_output.tag_configure(
    "high",
    font=("Arial", 11, "bold"),
    foreground="#dc3545"
)

audit_output.tag_configure(
    "warning",
    font=("Arial", 11, "bold"),
    foreground="#856404"
)

audit_output.tag_configure(
    "low",
    font=("Arial", 11, "bold"),
    foreground="#6c757d"
)

audit_output.tag_configure(
    "secure",
    font=("Arial", 11, "bold"),
    foreground="#198754"
)


# ================= START APPLICATION =================

root.mainloop()