# 🔐 SecureWave Analyzer – Wireless Security Monitoring & Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![GUI](https://img.shields.io/badge/GUI-Tkinter-green)
![Security](https://img.shields.io/badge/Type-Wireless%20IDS-red)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Release](https://img.shields.io/badge/Version-v2.0.0-purple)

---

SecureWave Analyzer is a Python-based Wireless Security Monitoring and Intrusion Detection prototype designed to assess WiFi encryption standards, analyze live network traffic, detect suspicious activity patterns, and generate structured security audit reports.

---
## 🚀 Project Status

✔ Encryption Compliance Detection  
✔ Passive Packet Monitoring  
✔ Intrusion Classification Engine  
✔ Risk Scoring System  
✔ GUI Dashboard  
✔ Signal Strength Visualization  
✔ CSV Export  
✔ PDF Audit Report Generation  
✔ Standalone Windows Executable  

---
## ✨ Key Features

- WiFi network scanning  
- Encryption compliance detection (Open, WPA, WPA2, WPA3)  
- Risk scoring engine  
- Passive packet monitoring using Scapy  
- Heuristic-based intrusion detection  
- Suspicious traffic classification  
- Security audit dashboard  
- Signal strength visualization (Matplotlib)  
- CSV export functionality  
- PDF audit report generation  

---
## 📸 Screenshots

### 🔹 GUI Dashboard
![GUI Screenshot](screenshots/gui.png)

### 🔹 Signal Strength Graph
![Graph Screenshot](screenshots/graph.png)

---
## 🧠 Intrusion Detection Methodology

The system uses passive packet monitoring to capture live network metadata over a fixed duration.

Instead of signature-based deep packet inspection, the system applies heuristic thresholds to detect suspicious patterns:

- High ICMP traffic → Possible ping sweep  
- Excessive TCP connections → Possible port scanning  
- Unencrypted HTTP traffic → Data exposure risk  
- Deprecated encryption protocols → Configuration vulnerability  

Each anomaly contributes to a cumulative risk score.

Based on the final score, the system assigns:

- LOW – Normal traffic behavior  
- MEDIUM – Suspicious activity detected  
- HIGH – Potential attack patterns identified  

Structured findings and remediation recommendations are generated automatically.

---
## 🛠 Technology Stack

- Python  
- Tkinter (GUI Framework)  
- PyWiFi (Wireless Scanning)  
- Scapy (Packet Monitoring)  
- Matplotlib (Visualization)  
- ReportLab (PDF Report Generation)  
- Tabulate (CLI Formatting)  
- Colorama (CLI Enhancement)  

---
## 🏗 Project Architecture

securewave-analyzer/

- main.py – CLI interface  
- gui.py – Graphical dashboard  
- scanner.py – WiFi scanning logic  
- risk_engine.py – Risk scoring logic  
- packet_monitor.py – Passive packet capture  
- audit_engine.py – Intrusion classification & risk evaluation  
- report_generator.py – CSV export module  
- pdf_report.py – PDF audit generation  
- requirements.txt – Dependencies  

---
## ⚙ Installation

Clone the repository:

git clone https://github.com/srishtig0711/securewave-analyzer.git  
cd securewave-analyzer  

Create virtual environment:

python -m venv venv  

Activate (PowerShell):

venv\Scripts\Activate.ps1  

Install dependencies:

pip install -r requirements.txt  

---
## 🖥 Running the Application

CLI Version:

python main.py  

GUI Version:

python gui.py  

---
## 📄 Output Options

- CLI table output  
- Risk-based GUI dashboard  
- Signal strength graph  
- CSV export file  
- Structured PDF audit report  

---
## 🎯 Use Case

This project demonstrates a lightweight defensive wireless security monitoring system suitable for:

- Educational network auditing  
- Wireless security assessment  
- Intrusion detection prototype development  
- Security engineering portfolio demonstration  

---
## 👩‍💻 Author

Srishti Gupta  
GitHub: https://github.com/srishtig0711  

---

## 📜 License

This project is licensed under the MIT License.
