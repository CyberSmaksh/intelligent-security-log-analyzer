# Intelligent Security Log Analyzer — Mini-SIEM

A lightweight, self-contained Security Information and Event Management (SIEM)
prototype built with **Python**, **Streamlit**, and **SQLite**.

> ⚠ **Disclaimer** – All log data is synthetic and is provided purely for
> demonstration purposes.  This tool does not connect to any external system,
> does not perform network scanning, and does not represent real attacks.

---

## Features

| Feature | Details |
|---|---|
| **Log ingestion** | Load security events from a local JSON file with full validation and error reporting |
| **Synthetic dataset** | 30 realistic events covering successful logins, failed logins, brute-force bursts, and unusual activity |
| **Brute-force detection** | Sliding-window rule: ≥ N failures from one IP within M minutes → HIGH alert |
| **Unusual-activity detection** | Flags any event tagged `unusual_activity` → MEDIUM alert |
| **Alert enrichment** | Every alert carries severity, evidence JSON, timestamps, and step-by-step investigation guidance |
| **SQLite persistence** | Events and alerts stored in `siem.db`; idempotent inserts prevent duplicate data |
| **Streamlit dashboard** | KPI cards, event-type & severity charts, top-IPs bar chart, searchable event table, filterable alert table, investigation view |
| **Reset button** | One-click wipe and reload so demos always start clean |
| **Error handling** | Missing file, JSON parse error, malformed records → friendly messages, no crashes |

---

## Project Structure

```
siem_project/
├── app.py              ← Streamlit dashboard (entry point)
├── database.py         ← SQLite init + CRUD helpers
├── detector.py         ← Detection rules (brute-force, unusual activity)
├── loader.py           ← JSON parsing, validation, DB persistence
├── sample_logs.json    ← 30-event synthetic dataset
├── requirements.txt    ← Python dependencies
├── gitignore.txt       ← Rename to .gitignore before committing
└── README.md           ← This file
```

### Architecture

```
sample_logs.json
      │
      ▼
  loader.py  ──► database.py (events table)
      │
      ├──► detector.py ──► database.py (alerts table)
      │
      ▼
   app.py  (Streamlit UI reads from database.py)
```

---

## Setup Instructions (Windows)

### 1. Prerequisites

- Python 3.11 or later — https://www.python.org/downloads/
- pip (bundled with Python)

### 2. Create and activate a virtual environment

```powershell
cd siem_project
python -m venv .venv
.venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution, run once:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Run the application

```powershell
streamlit run app.py
```

Streamlit will open **http://localhost:8501** in your default browser automatically.

---

## Quick-start Demo Steps

1. Open the app at http://localhost:8501.
2. Click **⬇ Load Data** in the left sidebar — the sample dataset is loaded.
3. Check the **📊 Overview** tab: KPI cards, event-type chart, severity chart, and top-IPs bar chart.
4. Switch to **📋 Events** and search for `203.0.113.42` to see the failed login burst.
5. Switch to **🚨 Alerts** — you should see HIGH (brute-force) and MEDIUM (unusual activity) alerts.
6. Select a HIGH alert in the dropdown to see the full evidence JSON and recommended investigation steps.
7. Click **♻ Reset & Reload** to wipe and re-import — counts should stay the same (idempotent).
8. Adjust the **Brute-force threshold** slider (e.g. to 3) and reload — more alerts will appear.

---

## Standalone Smoke Test

Run the loader directly to verify database writes without the UI:

```powershell
python loader.py
```

Expected output (approximate):
```
Events in file  : 30
Events inserted : 30
Events skipped  : 0
Events malformed: 0
Alerts inserted : 5
Alerts skipped  : 0
```

---

## Detection Rules

### BruteForceLogin (HIGH)

| Parameter | Default | Configurable via sidebar |
|---|---|---|
| Failure threshold | 5 | Yes |
| Time window | 5 minutes | Yes |

Sliding-window algorithm: for each source IP, all `login_failure` events are
sorted chronologically.  A window anchored at each failure is examined; if it
contains ≥ threshold failures the rule fires once per unique window anchor.
Alerts are deduplicated by `(source_ip, first_failure_timestamp)`.

### UnusualActivity (MEDIUM)

Fires once per event whose `event_type` field equals `unusual_activity`.
Alert ID is derived from the source IP and event ID, so reloading never
creates duplicates.

---

## Limitations

- Detection rules operate on the static in-memory event list, not a live stream.
- No authentication or multi-user support.
- The SQLite database is a local file (`siem.db`) with no encryption.
- Chart data refreshes only after a page interaction or after clicking Load/Reset.
- All data is synthetic; results have no real-world security meaning.
- No unit-test suite is included in this MVP (add with `pytest`).

---

## Dependencies

| Package | Purpose |
|---|---|
| `streamlit` | Web UI framework |
| `pandas` | DataFrame manipulation for tables and charts |
| `sqlite3` | Bundled with Python — no extra install required |

---

## License

This project is released for educational and demonstration purposes only.
