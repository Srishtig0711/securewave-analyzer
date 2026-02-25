SecureWave Analyzer

SecureWave Analyzer is a Python-based WiFi security analysis tool that scans nearby wireless networks, evaluates their security posture, and provides risk-based insights through both a Command Line Interface (CLI) and a Graphical User Interface (GUI).

The tool integrates real-time network scanning, encryption detection, risk scoring, data visualization, and report generation into a clean and user-friendly system.

Features

WiFi network scanning

Encryption type detection (Open, WPA, WPA2, WPA3)

Risk scoring engine

Risk-based sorting

Colored CLI output

GUI interface using Tkinter

Risk-based row highlighting in GUI

Signal strength graph visualization (Matplotlib)

CSV report export

Clean modular architecture

Technology Stack

Python

Tkinter (GUI)

PyWiFi (WiFi scanning)

Matplotlib (Signal visualization)

Tabulate (CLI formatting)

Colorama (CLI color output)

CSV module (Report generation)

Project Structure
securewave-analyzer/
│
├── main.py                # CLI version
├── gui.py                 # GUI version
├── scanner.py             # WiFi scanning logic
├── risk_engine.py         # Risk scoring logic
├── report_generator.py    # CSV export functionality
├── requirements.txt       # Dependencies
└── README.md
Installation Instructions
1. Clone the Repository
git clone https://github.com/srishtig0711/securewave-analyzer.git
cd securewave-analyzer
2. Create Virtual Environment
python -m venv venv

Activate it:

Windows (PowerShell):

venv\Scripts\Activate.ps1

Windows (Command Prompt):

venv\Scripts\activate
3. Install Dependencies
pip install -r requirements.txt
Running the Application
CLI Version
python main.py

This will:

Scan networks

Display results in table format

Show risk recommendations

Export report to CSV

GUI Version
python gui.py

The GUI provides:

Scan button

Risk-colored table

Signal strength graph

CSV export option

Risk Scoring Logic

The tool assigns a risk score based on:

Encryption type (Open networks receive higher risk scores)

Signal strength proximity

Network security classification

Risk levels are categorized as:

High Risk

Medium Risk

Low Risk

Output

Terminal table (CLI)

GUI table with color grading

Signal strength bar graph

CSV report file: securewave_report.csv

Future Enhancements

Channel detection support

Real-time monitoring mode

Advanced vulnerability mapping

Executable packaging (.exe)

Enhanced UI styling

Author

Srishti Gupta
GitHub: https://github.com/srishtig0711

License

This project is licensed under the MIT License.
