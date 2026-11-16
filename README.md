# Windows Event Analyzer

A Python-based Windows Event Log analysis tool designed for System Administrators and IT Professionals.

The application analyzes Windows Event Logs, correlates common issues, calculates system health, generates recommendations, exports XML data, and builds HTML reports.

---

# Features

## Event Collection

- Read live Windows System Event Logs
- Read offline EVTX files
- By default, analyze events from the previous 24 hours; in the executable,
  enter a custom start and end time (local time) for either source
- Filter by Windows event level; Critical, Error and Warning are selected by
  default
- Filter the result pane by level after analysis, and stop collection or
  processing with the Stop button or the Esc key
- Query one authorized remote computer by IP using a local or domain account;
  credentials are entered for the run and the password is not saved
- Extract Event ID, Source, Level, Computer and Timestamp
- Extract Event Data with available field names and plain-language hints for
  common raw values such as hexadecimal numbers and GUIDs
- Export raw XML

## Event Analysis

- Event Definition Database (JSON)
- Error Code Database (JSON)
- Severity Classification
- Root-Cause Correlation
- Health Score Calculation
- Recommendations Engine
- Automatic Microsoft Learn lookup for up to 20 of the most common unique
  warning/error event IDs per analysis
- Shows the article's Cause and Resolution sections when available

Online lookup requires an internet connection. It sends only the event ID and
provider name to Microsoft Learn; raw event data is not sent.

## Reporting

- Graphical Analysis Output
- HTML Report
- Dashboard Report
- XML Export

---

# Project Structure

```text
EventAnalyzer
│
├── main.py
│
├── database
│   ├── event_definitions.json
│   ├── error_codes.json
│   └── error_code_lookup.py
│
├── modules
│   ├── analyzer.py
│   ├── app_ui.py
│   ├── correlation_engine.py
│   ├── dashboard_generator.py
│   ├── database_loader.py
│   ├── event_reader.py
│   ├── event_levels.py
│   ├── event_data.py
│   ├── evtx_reader.py
│   ├── health_score.py
│   ├── internet_lookup.py
│   ├── paths.py
│   ├── recommendation_engine.py
│   ├── report_generator.py
│   ├── time_range.py
│   └── xml_exporter.py
│
└── reports
```

---

# Run as a standalone Windows app

The standalone executable targets 64-bit Windows 10/11 without requiring
Python or a separate runtime installation. This application uses Windows Event Log
APIs and does not run on macOS or Linux.

Run `WindowsEventAnalyzer.exe` on the target PC. The app opens a window where
you can analyze the local System log, select an offline EVTX file, filter by
event level, or query one remote System log.

Remote access requires authorization, valid credentials, and the target's
**Remote Event Log Management** firewall rule. For a local account, enter the
username and leave the Domain field blank. For a domain account, enter the
domain name or use a UPN. The password is masked and cleared after starting
analysis. Credentials are not saved.

The built executable can be copied to another compatible PC or attached to a
GitHub Release.

To open an EVTX file directly:

```cmd
WindowsEventAnalyzer.exe "C:\Logs\System.evtx"
```

The app shows analysis output and writes reports to:

```text
%LOCALAPPDATA%\WindowsEventAnalyzer\reports
```

## Build the executable

Build on a 64-bit Windows PC. Python is needed only on the build PC; users of
the finished executable do not need Python or pip.

```cmd
build.bat
```

The standalone executable is created at:

```text
dist\WindowsEventAnalyzer.exe
```

---

# Run from source

Create virtual environment:

```cmd
python -m venv venv
```

Activate:

```cmd
venv\Scripts\activate
```

Install runtime dependencies:

```cmd
pip install -r requirements.txt
```

---

# Usage

## Analyze local Windows events from source

```cmd
python main.py
```

The tool reads System log events from the previous 24 hours and generates:

```text
reports/event_report.html
reports/dashboard.html
reports/xml/
```

---

## Analyze EVTX file from source

Export an EVTX file from Event Viewer:

```text
Event Viewer
    Windows Logs
        System
            Save All Events As...
```

Then run:

```cmd
python main.py System.evtx
```

The executable's start and end time fields also apply to EVTX files. Times are
entered in local time; records outside the selected period are excluded.

or

```cmd
python main.py "C:\Logs\System.evtx"
```

---

# Adding New Event Definitions

Edit:

```text
database/event_definitions.json
```

Example:

```json
"4625": {
    "name": "Failed Logon",
    "cause": "Invalid credentials",
    "severity": 40,
    "solutions": [
        "Review account lockouts",
        "Check authentication logs"
    ]
}
```

---

# Adding New Error Codes

Edit:

```text
database/error_codes.json
```

Example:

```json
"0x80070005": {
    "description": "Access denied",
    "recommendation": "Verify permissions and run as Administrator"
}
```

---

# Health Score

The application calculates a system health score:

```text
100% = Healthy
80-99% = Minor Issues
50-79% = Moderate Issues
0-49% = Critical Issues
```

---

# Reports Generated

## event_report.html

Detailed event report including:

- Event ID
- Source
- Severity
- Cause
- Event Data
- Error Codes

## dashboard.html

Summary dashboard including:

- Health Score
- Top Event IDs
- Correlation Findings
- Recommendations
- Severity Counts

---

# Version

Windows Event Analyzer Version 2

---

# Future Roadmap

- Real Event Message Resolution (EvtFormatMessage)
- Charts and Graphs
- Trend Analysis
- Batch EVTX Processing
- AI Root Cause Analysis
- Remote Server Event Collection

---

# Author

Salah Mohammed
System Administrator / IT Manager
