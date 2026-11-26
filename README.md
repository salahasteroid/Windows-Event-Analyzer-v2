# Windows Event Analyzer

A Windows Event Log analysis tool for System Administrators and IT Professionals.

It reads the System log (live, from an offline EVTX file, or from remote
computers), explains events in plain language, finds patterns across events
with editable rules, scores system health, compares each run with the
previous one, and writes HTML reports.

Version 2.1.0

---

# Contents

- [Features](#features)
- [How it works](#how-it-works)
- [Project structure](#project-structure)
- [Requirements](#requirements)
- [Run as a standalone Windows app](#run-as-a-standalone-windows-app)
- [Build the executable](#build-the-executable)
- [Run from source](#run-from-source)
- [Usage](#usage)
- [Customizing the databases](#customizing-the-databases)
  - [Adding new event definitions](#adding-new-event-definitions)
  - [Adding new error codes](#adding-new-error-codes)
  - [Correlation rules](#correlation-rules)
  - [Changes without rebuilding the .exe](#changes-without-rebuilding-the-exe)
- [Health score](#health-score)
- [Trend analysis](#trend-analysis)
- [Reports generated](#reports-generated)
- [Where files are stored](#where-files-are-stored)
- [Tests](#tests)
- [Privacy and security notes](#privacy-and-security-notes)
- [Roadmap](#roadmap)
- [Author](#author)

---

# Features

## Event collection

- Read the live Windows **System** log
- Read offline **EVTX** files
- Analyze the previous 24 hours by default; in the executable, enter a custom
  start and end time (local time) for either source
- Filter by Windows event level; Critical, Error and Warning are selected by
  default
- Filter the result pane by level after analysis, and stop collection or
  processing with the Stop button or the Esc key
- Query up to 20 authorized remote computers by IP using a local or domain
  account; collection runs concurrently for up to five computers
- Optionally remember the IP list and domain locally, or forget both from the
  app; passwords are entered for each run and are never saved
- Extract Event ID, Source, Level, Computer and Timestamp
- Extract Event Data with field names and plain-language hints for common raw
  values such as hexadecimal numbers and GUIDs
- Show the message text Windows displays for an event: it is taken from the
  event XML when present, otherwise looked up from the provider's message
  tables (when the provider is not installed on the PC, for example for some
  remote logs, the Event Data fields are shown instead)
- Export raw XML, one file per event

## Event analysis

- **Event definitions** (JSON): about 60 common System-log events, matched by
  Event ID **and provider** (the same ID means different things in different
  providers)
- **Error codes** (JSON): Win32, HRESULT and NTSTATUS codes and common
  bugcheck codes. Every known code found in an event is explained, in any hex
  spelling
- **Severity**: from the definition; events without a definition get a
  severity from their Windows level (Critical, Error, Warning)
- **Correlation rules** (`database/rules.json`): event combinations inside a
  time window, repeat counts, provider filters. The same rules produce the
  findings, the recommendations and the health-score penalties
- **Health score** from all Critical, Error and Warning events, with a
  breakdown of what lowered it
- **Trend analysis**: each live or remote run is compared with the previous
  run (new, increased, decreased and no-longer-seen events)
- **Microsoft Learn lookup** for up to 20 of the most common unique
  warning/error event IDs per analysis, showing the article's Cause and
  Resolution sections when available
- **Your own data**: add or change definitions, error codes and rules in a
  folder next to your user profile without rebuilding the executable

## Reporting

- Analysis output in the application window
- `event_report.html`: every analyzed event
- `dashboard.html`: health score, what lowered it, trends, findings,
  recommendations, top Event IDs and severity counts
- XML export of each event

---

# How it works

```text
collect events  ->  analyze each event  ->  evaluate rules  ->  score, trends  ->  reports
(live / EVTX /      definition (by ID      (database/          (health score,     (HTML, XML,
 remote)             and provider),         rules.json)         history.json)      window)
                    error codes,
                    Microsoft Learn
```

1. **Collect.** `event_reader.py` (live and remote) or `evtx_reader.py`
   (offline) return events inside the chosen time range and levels.
2. **Analyze each event.** `analyzer.py` finds the definition for the Event ID
   and provider, explains every known error code in the Event Data, and adds
   the Microsoft Learn result.
3. **Evaluate rules once.** `rules_engine.py` applies `database/rules.json` to
   all events. Its result feeds the findings (`correlation_engine.py`), the
   recommendations (`recommendation_engine.py`) and the health score
   (`health_score.py`).
4. **Compare with the last run.** `trend_engine.py` reads and updates
   `history.json` (live and remote runs only).
5. **Report.** `report_generator.py`, `dashboard_generator.py` and
   `xml_exporter.py` write the files.

---

# Project structure

```text
EventAnalyzer
│
├── main.py                      Entry point: the analysis run. The packaged
│                                .exe starts the window (modules/app_ui.py)
├── build.bat                    Builds dist\WindowsEventAnalyzer.exe
├── WindowsEventAnalyzer.spec    PyInstaller settings (bundled data, version)
├── version_info.txt             File properties of the .exe (keep in step with
│                                modules/version.py)
├── requirements.txt             Runtime dependencies
├── requirements-build.txt       Build dependencies (PyInstaller)
│
├── database
│   ├── event_definitions.json   Event explanations, by Event ID and provider
│   ├── error_codes.json         Error code explanations
│   ├── rules.json               Correlation rules and health-score settings
│   └── error_code_lookup.py     Error code lookup
│
├── modules
│   ├── analyzer.py              Per-event analysis (definition, error codes)
│   ├── app_ui.py                Window of the packaged app
│   ├── correlation_engine.py    Findings from the rule results
│   ├── dashboard_generator.py   dashboard.html
│   ├── database_loader.py       Loads and caches the JSON databases, custom folder
│   ├── event_catalog.py         Finds a definition by Event ID and provider
│   ├── event_data.py            Event Data field names and plain-language hints
│   ├── event_levels.py          Event level names and defaults
│   ├── event_reader.py          Live and remote System log reader
│   ├── evtx_reader.py           Offline EVTX reader
│   ├── health_score.py          Health score and its breakdown
│   ├── internet_lookup.py       Microsoft Learn lookup
│   ├── message_formatter.py     Message text from the provider's message tables
│   ├── paths.py                 Program, reports and user-data folders
│   ├── recommendation_engine.py Priority actions from the rule results
│   ├── remote_settings.py       Saved IP list and domain
│   ├── remote_targets.py        IP list parsing and limits
│   ├── report_generator.py      event_report.html
│   ├── rules_engine.py          Loads and evaluates the correlation rules
│   ├── time_range.py            Time range handling
│   ├── trend_engine.py          Run history and comparison
│   ├── version.py               Version number
│   └── xml_exporter.py          XML export
│
├── tests                        Automated tests (pytest)
│
└── reports                      Output when run from source (git-ignored)
```

---

# Requirements

- 64-bit Windows 10/11. The application uses the Windows Event Log APIs and
  does not run on macOS or Linux.
- Running the packaged `.exe`: nothing else; Python is not needed.
- Running or building from source: Python 3 on Windows, and the packages in
  `requirements.txt` (`pywin32`, `python-evtx`).
- Internet access is optional and only used for the Microsoft Learn lookup.

---

# Run as a standalone Windows app

Run `WindowsEventAnalyzer.exe` on the target PC. The window lets you analyze
the local System log, open an offline EVTX file, filter by event level, set a
time range, or query remote PCs.

To open an EVTX file directly:

```cmd
WindowsEventAnalyzer.exe "C:\Logs\System.evtx"
```

## Remote PCs

Enter one IP address per line (commas and semicolons also work), enter the
credentials shared by the targets, then select **Analyze Remote PCs**.

- Up to 20 IP addresses per run; collection runs for up to five PCs at once.
- Each computer's reports are kept in their own folder under
  `reports\remote\host-<ip>`, and each has its own trend history.
- Requirements on the target: authorization, valid credentials, and the
  **Remote Event Log Management** firewall rule.
- Local account: enter the username and leave Domain blank. Domain account:
  enter the domain name, or use a UPN as the username.
- **Remember IP list** and **Remember domain** keep those values locally;
  **Forget saved IPs/domain** removes them. Passwords are masked, cleared
  after the analysis starts, and never saved.

The built executable can be copied to another compatible PC or attached to a
GitHub Release.

---

# Build the executable

Build on a 64-bit Windows PC. Python is needed only on the build PC; users of
the finished executable do not need Python or pip.

```cmd
build.bat
```

The executable is created at:

```text
dist\WindowsEventAnalyzer.exe
```

What the build does:

- Bundles every file in `database\` (see `WindowsEventAnalyzer.spec`). A test
  fails if a database file is missing from the spec, so a new JSON file cannot
  be left out of the executable by accident.
- Adds the file properties (company, product, version) from `version_info.txt`.
- Does not use UPX packing, which antivirus products often flag.
- Installs PyInstaller from `requirements-build.txt`.

**Releasing a new version:** change the number in `modules/version.py` and in
`version_info.txt` (`filevers`, `prodvers`, `FileVersion`, `ProductVersion`).
A test checks that they agree.

**Before distributing widely:** the executable is not code-signed. Sign it with
your organization's certificate, otherwise SmartScreen and some antivirus
products may warn about it. Dependencies in `requirements.txt` are version
ranges; run `pip freeze` on your build PC to record exact versions if you need
reproducible builds.

---

# Run from source

Create a virtual environment:

```cmd
python -m venv venv
```

Activate it:

```cmd
venv\Scripts\activate
```

Install the runtime dependencies:

```cmd
pip install -r requirements.txt
```

---

# Usage

From source, the tool runs in the console and writes reports. The window is
part of the packaged `.exe`.

## Analyze local Windows events

```cmd
python main.py
```

The tool reads System log events from the previous 24 hours, prints the
analysis, and writes:

```text
reports\event_report.html
reports\dashboard.html
reports\xml\
reports\history.json
```

(`reports` is created in the folder you run the command from.)

## Analyze an EVTX file

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

In the executable, the start and end time fields also apply to EVTX files.
Times are entered in local time; records outside the selected period are
excluded. Offline EVTX runs are not added to the trend history.

---

# Customizing the databases

All three databases are JSON files in the `database` folder. Entries are
checked when the application starts: an incomplete entry or a rule with a
mistake is skipped and a warning is printed, it does not stop the analysis.
Restart the application after editing.

## Adding new event definitions

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

| Field | Meaning |
|---|---|
| key (`"7000"`) | The Event ID, as text |
| `name` | Short title |
| `sources` | Provider names (the Source column; case does not matter). The definition only applies to events from these providers. Optional |
| `cause` | Plain-language explanation |
| `severity` | 0-100: 90+ Critical, 70+ High, 40+ Medium, below that Low |
| `solutions` | List of suggested steps |

`name`, `cause`, `severity` and `solutions` are required.

If one Event ID is used by several providers, give a list of definitions:

```json
"19": [
    { "name": "...", "sources": ["Provider-A"], "cause": "...", "severity": 5,  "solutions": ["..."] },
    { "name": "...", "sources": ["Provider-B"], "cause": "...", "severity": 55, "solutions": ["..."] }
]
```

A definition without `sources` applies to any provider. When both a
provider-specific and a generic definition exist for an Event ID, the
provider-specific one is used.

## Adding new error codes

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

- Write codes as `0x` plus eight hex digits in lower case. Events may spell
  them in any case or length (`0X80070005`, `0x5`); they are matched after
  normalizing.
- Every known code found in an event's data is explained, not only the first.
- Add `"event_ids": [1001]` to an entry that should only be used for those
  Event IDs. The bugcheck (blue screen) codes work this way, because the same
  number means something else in other events.

## Correlation rules

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

| Field | Meaning |
|---|---|
| `id` | Unique name of the rule |
| `title` | Short name, shown in the health-score breakdown |
| `finding` | Text shown under Correlation Findings |
| `recommendations` | Actions added to Priority Actions (repeated ones are shown once) |
| `all_of` / `any_of` | Use exactly one. `all_of`: every listed event must occur. `any_of`: at least `min_count` of the listed events |
| event entry | An Event ID (`55`), or `{"id": 7, "sources": ["disk"]}` to also require the provider |
| `min_count` | For `all_of`, how many times each event must occur; for `any_of`, how many events in total. Default 1 |
| `window_minutes` | The events must happen within this many minutes of each other. If events have no usable time, the window is not applied |
| `severity` | 0-100; the most severe findings are listed first |
| `score_penalty` | Points taken off the health score. Default 0 |
| `suppresses` | Ids of more general rules to hide when this rule matches |

The shipped rules cover power loss and crashes, disk and file system failure,
repeated storage errors, low disk space, failing services and drivers, domain
and Group Policy connectivity, time synchronization, hardware errors, display
driver resets, IP conflicts, TLS failures, cleared event logs and new
services. The test suite checks that the shipped file is valid.

## Changes without rebuilding the .exe

The built-in databases are inside the executable. To add or change entries,
put a file with the same name (`event_definitions.json`, `error_codes.json`
or `rules.json`) in:

```text
%LOCALAPPDATA%\WindowsEventAnalyzer\database\
```

- `event_definitions.json` and `error_codes.json`: your entries are added, and
  replace built-in entries with the same Event ID or code. An Event ID entry
  replaces everything built in for that ID, including all providers.
- `rules.json`: a rule with a new `id` is added; a rule with an existing `id`
  replaces the built-in one; `{"id": "dcom-noise", "disabled": true}` removes
  a built-in rule; a `health` section overrides those numbers.
- When running from source, edit the project's `database` files directly, or
  set the environment variable `WINDOWS_EVENT_ANALYZER_DATABASE_DIR` to use a
  custom folder.

When a custom file is used, the output says so ("Using custom database file").

---

# Health score

The application calculates a system health score:

```text
100%    = Healthy
80-99%  = Minor Issues
50-79%  = Moderate Issues
0-49%   = Critical Issues
```

How it is calculated (the output and the dashboard list what lowered it):

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

The three numbers (20, 2.5, 40) are the `severity_factor`,
`repeat_multiplier_cap` and `per_source_cap` in the `health` section of
`database/rules.json`.

Examples: one unexpected reboot (Kernel-Power 41 with Event 6008) scores 63%;
a disk error together with NTFS corruption scores 46%; 800 DistributedCOM
warnings score 94%.

---

# Trend analysis

Live and remote runs are saved in `history.json` next to the reports (the last
30 runs). A run is compared with the latest earlier run that used the same
event-level filter.

- Counts are compared per day, so runs over different time ranges can be
  compared.
- Events are listed as **new**, **increased** or **decreased** (a change of at
  least 1.5 times and 2 events per day), or **no longer seen**.
- The first run, or a run with a different level filter, has nothing to
  compare with and becomes the starting point.
- Offline EVTX files are not tracked. A cancelled run is not recorded.
- Delete `history.json` to start over.

---

# Reports generated

## event_report.html

Detailed event report including:

- Event ID, Source, Level, Computer and Time
- Severity and cause
- Event Data
- Every error code found, with its description
- Microsoft Learn explanation, when found

## dashboard.html

Summary dashboard including:

- Health score
- What lowered the score
- Correlation findings
- Recommendations
- Trends since the previous run
- Top 10 Event IDs
- Event counts by severity

---

# Where files are stored

| What | Packaged .exe | From source |
|---|---|---|
| Reports, XML, `history.json` | `%LOCALAPPDATA%\WindowsEventAnalyzer\reports` | `reports\` in the current folder |
| Remote PC reports | `...\reports\remote\host-<ip>` | `reports\remote\host-<ip>` |
| Saved IP list and domain | `%LOCALAPPDATA%\WindowsEventAnalyzer\remote_targets.json` | same |
| Your own database files | `%LOCALAPPDATA%\WindowsEventAnalyzer\database\` | the `database` folder |

The window has **Open Reports Folder** and **Open Dashboard** buttons.

---

# Tests

Install pytest and run the tests from the project folder:

```cmd
pip install pytest
python -m pytest tests
```

The tests cover the rules, health score, analyzer, databases, trends, reports,
readers, remote targets and the build files. On a machine without the Windows
libraries (for example Linux) the tests use small stand-ins for them, and the
window tests are skipped when Tk is not installed.

---

# Privacy and security notes

- The Microsoft Learn lookup sends only the Event ID and provider name;
  raw event data is not sent. It needs an internet connection.
- Remote passwords are never written to disk. The saved IP list and domain are
  stored in plain text in your user profile, and can be forgotten from the app.
- Reports contain event data and computer names. Store and share them like any
  other log data.
- Use remote collection only on computers you are authorized to query.
- The executable is not code-signed (see [Build the executable](#build-the-executable)).

---

# Roadmap

- Charts and graphs
- Application, Security and Operational logs
- Batch EVTX processing
- AI root cause analysis

---

# Author

Salah Mohammed
System Administrator / IT Manager
