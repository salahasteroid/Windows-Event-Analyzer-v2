# Windows Event Analyzer

A Python-based Windows Event Log analysis tool designed for System Administrators and IT Professionals.

The application analyzes Windows Event Logs, correlates common issues, calculates system health, generates recommendations, exports XML data, and builds HTML reports.

---

# Features

## Event Collection

- Read live Windows System Event Logs
- Read offline EVTX files
- Extract Event ID, Source, Level, Computer and Timestamp
- Extract Event Data
- Export raw XML

## Event Analysis

- Event Definition Database (JSON)
- Error Code Database (JSON)
- Severity Classification
- Root-Cause Correlation
- Health Score Calculation
- Recommendations Engine

## Reporting

- Console Report
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
│   └── error_codes.json
│
├── modules
│   ├── analyzer.py
│   ├── correlation_engine.py
│   ├── dashboard_generator.py
│   ├── database_loader.py
│   ├── error_code_lookup.py
│   ├── event_reader.py
│   ├── evtx_reader.py
│   ├── health_score.py
│   ├── internet_lookup.py
│   ├── recommendation_engine.py
│   ├── report_generator.py
│   └── xml_exporter.py
│
└── reports
```

---

# Installation

Create virtual environment:

```cmd
python -m venv venv
```

Activate:

```cmd
venv\Scripts\activate
```

Install dependencies:

```cmd
pip install -r requirements.txt
```

---

# Usage

## Analyze local Windows events

```cmd
python main.py
```

The tool reads the latest System log events and generates:

```text
reports/event_report.html
reports/dashboard.html
reports/xml/
```

---

## Analyze EVTX file

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

Windows Event Analyzer v1.0

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
