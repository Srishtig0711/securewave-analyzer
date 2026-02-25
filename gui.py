import tkinter as tk
from tkinter import ttk
from scanner import scan_networks
from risk_engine import calculate_risk
from report_generator import export_to_csv
import matplotlib.pyplot as plt
from packet_monitor import run_packet_monitor
from audit_engine import generate_audit_summary
from pdf_report import export_pdf_report


last_scan = []
last_audit_data = None
last_stats = None


def scan_and_display():
    global last_scan

    for row in tree.get_children():
        tree.delete(row)

    networks = scan_networks()

    for net in networks:
        score, level = calculate_risk(net)
        net["risk_score"] = score
        net["risk_level"] = level

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
                net["ssid"],
                net["signal"],
                net["security"],
                net["risk_score"],
                net["risk_level"],
            ),
            tags=(tag,),
        )

    last_scan = networks


def export_report():
    if last_scan:
        export_to_csv(last_scan)


def show_graph():
    if not last_scan:
        return

    ssids = [net["ssid"] for net in last_scan]
    signals = [net["signal"] for net in last_scan]

    plt.figure(figsize=(10, 6))

    bars = plt.bar(ssids, signals)

    plt.xlabel("SSID", fontsize=12)
    plt.ylabel("Signal Strength (dBm)", fontsize=12)
    plt.title("WiFi Signal Strength Analysis", fontsize=14, fontweight='bold')

    plt.xticks(rotation=45, ha="right")
    plt.grid(axis="y", linestyle="--", alpha=0.7)

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, height,
                 f"{height}",
                 ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    plt.show()

def run_network_audit():
    audit_output.delete("1.0", tk.END)

    stats = run_packet_monitor(10)

    # For now, pass None as encryption_type
    audit_data = generate_audit_summary(stats)
    global last_audit_data, last_stats
    last_audit_data = audit_data
    last_stats = stats

    audit_output.insert(tk.END, "Wireless Security Audit Report\n\n")
    audit_output.insert(tk.END, f"Timestamp: {audit_data['timestamp']}\n\n")

    audit_output.insert(tk.END, "Traffic Statistics:\n")
    for key, value in stats.items():
        audit_output.insert(tk.END, f"{key}: {value}\n")

    audit_output.insert(tk.END, "\nRisk Score: ")
    audit_output.insert(tk.END, f"{audit_data['risk_score']}\n")
    audit_output.insert(tk.END, f"Risk Level: {audit_data['risk_level']}\n")
    audit_output.insert(tk.END, f"Overall Status: {audit_data['overall_status']}\n\n")

    audit_output.insert(tk.END, "Findings:\n")
    for item in audit_data["summary"]:
        audit_output.insert(tk.END, f"- {item}\n")

    audit_output.insert(tk.END, "\nIntrusion Classifications:\n")
    for item in audit_data["classifications"]:
        audit_output.insert(tk.END, f"- {item}\n")

    audit_output.insert(tk.END, "\nRecommendations:\n")
    for item in audit_data["recommendations"]:
        audit_output.insert(tk.END, f"- {item}\n")

def export_pdf():
    global last_audit_data, last_stats

    if not last_audit_data or not last_stats:
        print("Please run Network Audit before exporting PDF.")
        return

    try:
        export_pdf_report(last_stats, last_audit_data)
        print("PDF generated successfully in project folder.")
    except Exception as e:
        print("Error generating PDF:", e)
# ================= GUI SETUP =================

root = tk.Tk()
root.title("SecureWave Analyzer")
root.geometry("900x500")
root.configure(bg="#f4f6f9")

title_label = tk.Label(
    root,
    text="SecureWave Analyzer",
    font=("Arial", 16, "bold"),
    bg="#f4f6f9",
)
title_label.pack(pady=10)

button_frame = tk.Frame(root, bg="#f4f6f9")
button_frame.pack(pady=5)

scan_button = tk.Button(
    button_frame,
    text="Scan Networks",
    command=scan_and_display,
    width=18,
    bg="#007bff",
    fg="white",
)
scan_button.grid(row=0, column=0, padx=10)

export_button = tk.Button(
    button_frame,
    text="Export to CSV",
    command=export_report,
    width=18,
    bg="#28a745",
    fg="white",
)
export_button.grid(row=0, column=1, padx=10)

graph_button = tk.Button(
    button_frame,
    text="Show Signal Graph",
    command=show_graph,
    width=18,
    bg="#6f42c1",
    fg="white",
)
graph_button.grid(row=0, column=2, padx=10)
audit_button = tk.Button(
    button_frame,
    text="Run Network Audit",
    command=run_network_audit,
    width=18,
    bg="#dc3545",
    fg="white",
)
audit_button.grid(row=0, column=3, padx=10)
pdf_button = tk.Button(
    button_frame,
    text="Export Audit PDF",
    command=export_pdf,
    width=18,
    bg="#343a40",
    fg="white",
)
pdf_button.grid(row=0, column=4, padx=10)

columns = ("SSID", "Signal (dBm)", "Security", "Risk Score", "Risk Level")

tree = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150, anchor="center")

tree.tag_configure("high", background="#ffcccc")
tree.tag_configure("medium", background="#fff3cd")
tree.tag_configure("low", background="#d4edda")

tree.pack(fill="both", expand=True, padx=20, pady=10)
audit_output = tk.Text(root, height=8)
audit_output.pack(fill="x", padx=20, pady=5)

root.mainloop()