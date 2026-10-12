# Python Security Log Analyzer

A local cybersecurity project that analyzes simulated authentication logs, identifies suspicious login patterns, exports alerts to CSV, and displays findings in an interactive Streamlit dashboard.

## Features

- Detects five or more failed logins from one source IP within a rolling five-minute window.
- Correlates a successful login with five or more preceding failures for the same IP address and username within five minutes.
- Labels these detections **HIGH** and **CRITICAL**, respectively, as lab-defined investigation priorities (not proof of compromise).
- Exports alerts to `security_alerts.csv`.
- Displays alert counts, IPs, usernames, severity filters, searches, and a timeline in Streamlit.
- Includes six unit tests for basic detection scenarios.

## Technology

Python 3, Python standard library (`csv`, `datetime`, `collections`, `unittest`), pandas, Streamlit, and Visual Studio Code.

## Project files

```text
analyzer.py             Read sample logs and export alerts
detection_rules.py      Detection and correlation rules
dashboard.py            Local Streamlit dashboard
sample_logs.csv         Simulated authentication events
test_detection_rules.py Automated tests
requirements.txt        Python dependencies
.gitignore              Excludes local and generated files
```

## Setup

1. Install Python 3.
2. Clone or download this repository and open the folder in VS Code.
3. Install dependencies:

   ```powershell
   py -m pip install -r requirements.txt
   ```

4. Run the automated tests:

   ```powershell
   py -m unittest -v test_detection_rules.py
   ```

5. Generate a report from the included sample data:

   ```powershell
   py analyzer.py
   ```

6. Start the dashboard:

   ```powershell
   py -m streamlit run dashboard.py
   ```

Open the local URL shown by Streamlit (typically `http://localhost:0000`).

## Sample investigation

The synthetic sample includes five failed `admin` logins between 10:00:00 and 10:02:00 on October 10, 2026, followed by a successful login at 10:02:30. The analyzer generates one HIGH possible brute-force alert and one CRITICAL successful-login-after-failures alert. These are indicators requiring investigation, not confirmed malicious activity.

See [Incident Investigation Report](docs/incident_investigation_report.md) for a sample analyst write-up.

## Limitations

- Works with the project's simulated CSV format, not live Windows Event Logs.
- Detection thresholds and severity labels are configured for demonstration.
- Generates at most one brute-force alert per source IP in a single analysis run.
- Successful-login correlation is limited to the same IP and username.
- Does not establish that a successful login was unauthorized.
- The dashboard reads a generated CSV report; it is not a real-time SIEM.



## Future improvements

- Add more edge-case tests and multiple alert windows.
- Improve error handling and input validation.
- Support additional log formats and documented Windows Event Log imports.
- Add investigation status and analyst notes.
