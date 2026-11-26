# Windows Event Analyzer

A Python-based Windows Event Log analysis tool designed for System Administrators and IT Professionals.

The application analyzes Windows Event Logs, correlates common issues using editable rules, calculates system health, tracks trends between runs, generates recommendations, exports XML data, and builds HTML reports.

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
- Query up to 20 authorized remote computers by IP using a local or domain
  account; event collection runs concurrently for up to five computers
- Optionally remember the IP list and domain locally, or forget both from the
  app; passwords are entered for each run and are never saved
- Extract Event ID, Source, Level, Computer and Timestamp
- Extract Event Data with available field names and plain-language hints for
  common raw values such as hexadecimal numbers and GUIDs
- Show the message text Windows displays for an event (resolved from the
  provider's message tables when the log XML has none; falls back to the
  Event Data fields if the provider is not installed on the PC)
- Export raw XML

## Event Analysis

- Event Definition Database (JSON): about 60 common System-log events, matched
  by Event ID **and provider** (the same ID means different things in
  different providers)
- Error Code Database (JSON): Win32/HRESULT/NTSTATUS codes and common
  bugcheck codes; every code found in an event is explained, in any hex
  spelling
- Severity Classification (events without a definition get a severity from
  their Windows level)
- Root-Cause Correlation from editable rules (`database/rules.json`): event
  combinations inside a time window, repeat counts, provider filters
- Health Score Calculation from all Critical/Error/Warning events, with a
  breakdown of what lowered the score
- Trend Analysis: compares a live or remote run with the previous run
  (new, increased, decreased, no longer seen events)
- Recommendations Engine (from the same rules)
- Automatic Microsoft Learn lookup for up to 20 of the most common unique
  warning/error event IDs per analysis
- Shows the article's Cause and Resolution sections when available

Online lookup requires an internet connection. It sends only the event ID and
provider name to Microsoft Learn; raw event data is not sent.

## Reporting

- Analysis Output in the application window
- HTML Report
- Dashboard Report (health score, what lowered it, trends, findings)
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
│   ├── rules.json
│   └── error_code_lookup.py
│
├── modules
│   ├── analyzer.py
│   ├── app_ui.py
│   ├── correlation_engine.py
│   ├── dashboard_generator.py
│   ├── database_loader.py
│   ├── event_catalog.py
│   ├── event_data.py
│   ├── event_levels.py
│   ├── event_reader.py
│   ├── evtx_reader.py
│   ├── health_score.py
│   ├── internet_lookup.py
│   ├── message_formatter.py
│   ├── paths.py
│   ├── recommendation_engine.py
│   ├── remote_settings.py
│   ├── remote_targets.py
│   ├── report_generator.py
│   ├── rules_engine.py
│   ├── time_range.py
│   ├── trend_engine.py
│   ├── version.py
│   └── xml_exporter.py
│
├── tests
│
├── version_info.txt
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
event level, or query a list of remote System logs.

For remote collection, enter one IP address per line (commas and semicolons
also work), enter credentials shared by the targets, then select **Analyze
Remote PCs**. Collection runs in parallel for up to five PCs at once and is
limited to 20 IPs per run. Each computer's reports are kept in a separate
folder under `reports\remote`.

Remote access requires authorization, valid credentials, and the target's
**Remote Event Log Management** firewall rule. For a local account, enter the
username and leave the Domain field blank. For a domain account, enter the
domain name or use a UPN. Use the Remember checkboxes to retain the IP list or
domain locally; **Forget saved IPs/domain** removes them. Passwords are masked,
cleared after starting analysis, and never saved.

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

The build bundles `database\*.json` (see `WindowsEventAnalyzer.spec`; a test
fails if a database file is missing from it), adds the version and file
properties from `version_info.txt`, and does not use UPX packing, which
antivirus products often flag. Raise the version in `modules/version.py` and
`version_info.txt` together when releasing. The executable is not code-signed;
sign it with your organization's certificate before distributing it widely.

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
"7000": {
    "name": "Service failed to start",
    "sources": ["Service Control Manager"],
    "cause": "A service could not start",
    "severity": 55,
    "solutions": [
        "Read the error in the event text",
        "Check the service account and its dependencies"
    ]
}
```

`sources` lists the provider names (the Source column; case does not matter).
The definition only applies to events from those providers. If one Event ID is
used by several providers, give a list of definitions:

```json
"19": [
    { "name": "...", "sources": ["Provider-A"], "cause": "...", "severity": 5, "solutions": ["..."] },
    { "name": "...", "sources": ["Provider-B"], "cause": "...", "severity": 55, "solutions": ["..."] }
]
```

A definition without `sources` applies to any provider. `severity` is 0-100
(90+ Critical, 70+ High, 40+ Medium, below that Low). The files are read once
when the application starts; restart it after editing.

**Editing without rebuilding the .exe.** The built-in databases are inside the
executable. To add or change entries, put a file with the same name
(`event_definitions.json`, `error_codes.json` or `rules.json`) in:

```text
%LOCALAPPDATA%\WindowsEventAnalyzer\database\
```

- `event_definitions.json` / `error_codes.json`: your entries are added, and
  replace built-in entries with the same Event ID or code. Incomplete entries
  are ignored with a warning.
- `rules.json`: rules with a new `id` are added; a rule with an existing `id`
  replaces the built-in one; `{"id": "dcom-noise", "disabled": true}` removes a
  built-in rule; a `health` section overrides those numbers.
- When running from source, edit the project's `database` files directly (or
  set `WINDOWS_EVENT_ANALYZER_DATABASE_DIR` to use a custom folder).

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

Codes are written as `0x` plus eight hex digits in lower case (`0x80070005`);
events may spell them in any case. Add `"event_ids": [1001]` to an entry that
should only be used for those Event IDs (the bugcheck codes work this way).

---

# Correlation Rules

Edit:

```text
database/rules.json
```

A rule finds a pattern across events and produces the finding text, the
recommendations and an optional health-score penalty:

```json
{
  "id": "disk-ntfs-chain",
  "title": "Disk errors with NTFS corruption",
  "finding": "Disk errors and NTFS corruption detected. Storage subsystem failure is likely.",
  "recommendations": ["Backup critical data immediately.", "Run CHKDSK /F."],
  "all_of": [{"id": 7, "sources": ["disk"]}, 55],
  "min_count": 1,
  "window_minutes": 360,
  "severity": 95,
  "score_penalty": 20,
  "suppresses": ["disk-bad-blocks", "ntfs-corruption"]
}
```

- Use `all_of` (every listed event must occur) or `any_of` (at least
  `min_count` of the listed events).
- An event is an Event ID, or `{"id": ..., "sources": [...]}` to also require
  the provider.
- `min_count`: for `all_of`, how many times each event must occur; for
  `any_of`, how many events in total. Default 1.
- `window_minutes`: the events must happen within this time of each other.
- `severity` (0-100) sets the order of the findings; `score_penalty` is taken
  off the health score.
- `suppresses`: ids of more general rules to hide when this rule matches.

A rule with a mistake is skipped and a warning is printed. The shipped rules
are checked by the test suite.

---

# Health Score

The application calculates a system health score:

```text
100% = Healthy
80-99% = Minor Issues
50-79% = Moderate Issues
0-49% = Critical Issues
```

How it is calculated (the dashboard and the output list what lowered it):

1. Critical, Error and Warning events are grouped by provider and Event ID.
   Information and Verbose events never lower the score.
2. Each group has a severity from its event definition, or from the Windows
   level when there is no definition (Critical 75, Error 45, Warning 20).
3. A group's penalty is `20 x (severity / 100)^2`, multiplied by
   `min(1 + log2(count), 2.5)`: a repeating problem costs more than a single
   one, up to a limit.
4. One provider can take at most 40 points off, so a single noisy provider
   cannot zero the score alone.
5. Matching correlation rules add their `score_penalty`.

The three numbers (20, 2.5, 40) are in the `health` section of
`database/rules.json`.

---

# Trend Analysis

Live and remote runs are saved in `history.json` next to the reports (the last
30 runs). A run is compared with the latest earlier run that used the same
event-level filter. Counts are compared per day, so different time ranges can
be compared. Events are listed as new, increased, decreased (a change of at
least 1.5x and 2 events per day) or no longer seen. Offline EVTX files are not
tracked.

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

- Charts and Graphs
- Application, Security and Operational logs
- Batch EVTX Processing
- AI Root Cause Analysis

---

# Author

Salah Mohammed
System Administrator / IT Manager
