import tkinter as tk
from tkinter import ttk
from scanner import scan_networks
from risk_engine import calculate_risk
from report_generator import export_to_csv
import matplotlib.pyplot as plt


last_scan = []


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

    plt.figure()
    plt.bar(ssids, signals)
    plt.xlabel("SSID")
    plt.ylabel("Signal Strength (dBm)")
    plt.title("WiFi Signal Strength Analysis")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


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

columns = ("SSID", "Signal (dBm)", "Security", "Risk Score", "Risk Level")

tree = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150, anchor="center")

tree.tag_configure("high", background="#ffcccc")
tree.tag_configure("medium", background="#fff3cd")
tree.tag_configure("low", background="#d4edda")

tree.pack(fill="both", expand=True, padx=20, pady=10)

root.mainloop()