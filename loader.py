"""
loader.py – Load, validate, and persist security log events from a JSON file.

Responsibilities
────────────────
* Read a JSON file that contains a list of log event objects.
* Validate that each record has the required fields and that the timestamp is
  parseable.  Malformed records are skipped with a warning; they do not abort
  the whole load.
* Insert valid records into the SQLite database (idempotent via INSERT OR IGNORE).
* Run all detection rules against the full event list and store resulting alerts.
* Return a LoadResult summary so the caller can display feedback.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

import database
import detector

REQUIRED_FIELDS = {"event_id", "timestamp", "source_ip", "user",
                   "event_type", "service", "message"}

DEFAULT_LOG_PATH = os.path.join(os.path.dirname(__file__), "sample_logs.json")


@dataclass
class LoadResult:
    total_in_file: int = 0
    inserted_events: int = 0
    skipped_events: int = 0
    malformed_events: int = 0
    inserted_alerts: int = 0
    skipped_alerts: int = 0
    errors: list[str] = field(default_factory=list)


def _validate_record(record: object, index: int) -> tuple[bool, str]:
    """
    Return (is_valid, error_message).
    Accepts any object; returns False if it is not a dict or is missing fields.
    """
    if not isinstance(record, dict):
        return False, f"Record #{index} is not a JSON object."
    missing = REQUIRED_FIELDS - record.keys()
    if missing:
        return False, f"Record #{index} missing fields: {sorted(missing)}"
    # Validate timestamp parses without error
    ts = record.get("timestamp", "")
    try:
        ts_clean = ts.replace("Z", "+00:00")
        datetime.fromisoformat(ts_clean)
    except (ValueError, AttributeError):
        return False, f"Record #{index} has an unparseable timestamp: {ts!r}"
    return True, ""


def load_events_from_file(
    path: str = DEFAULT_LOG_PATH,
    brute_threshold: int = 5,
    brute_window_minutes: int = 5,
) -> LoadResult:
    """
    Parse the JSON file at *path*, insert valid events into the database,
    run detection rules, and persist new alerts.

    Parameters
    ----------
    path                 : path to the JSON log file
    brute_threshold      : forwarded to the brute-force detector
    brute_window_minutes : forwarded to the brute-force detector

    Returns
    -------
    LoadResult with counts and any error messages
    """
    result = LoadResult()

    # ── 1. Read and parse the file ────────────────────────────────────────────
    if not os.path.exists(path):
        result.errors.append(f"Log file not found: {path}")
        return result

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except json.JSONDecodeError as exc:
        result.errors.append(f"JSON parse error in {path}: {exc}")
        return result
    except OSError as exc:
        result.errors.append(f"Cannot read {path}: {exc}")
        return result

    if not isinstance(raw, list):
        result.errors.append("Log file must contain a JSON array at the top level.")
        return result

    result.total_in_file = len(raw)

    # ── 2. Validate and insert events ─────────────────────────────────────────
    for i, record in enumerate(raw):
        valid, err_msg = _validate_record(record, i + 1)
        if not valid:
            result.malformed_events += 1
            result.errors.append(err_msg)
            continue

        # Normalize: keep only the required fields (ignore extras)
        clean = {k: str(record[k]).strip() for k in REQUIRED_FIELDS}
        inserted = database.insert_event(clean)
        if inserted:
            result.inserted_events += 1
        else:
            result.skipped_events += 1

    # ── 3. Run detection rules over all stored events ─────────────────────────
    all_events = database.get_all_events()
    alerts = detector.run_all_detections(
        all_events,
        brute_threshold=brute_threshold,
        brute_window_minutes=brute_window_minutes,
    )

    for alert in alerts:
        inserted = database.insert_alert(alert)
        if inserted:
            result.inserted_alerts += 1
        else:
            result.skipped_alerts += 1

    return result


def reset_and_reload(
    path: str = DEFAULT_LOG_PATH,
    brute_threshold: int = 5,
    brute_window_minutes: int = 5,
) -> LoadResult:
    """
    Wipe all existing events and alerts, then reload from *path*.
    Use this for the dashboard "Reset & Reload" button.
    """
    database.clear_alerts()
    database.clear_events()
    return load_events_from_file(path, brute_threshold, brute_window_minutes)


# ── Allow running standalone for a quick smoke-test ──────────────────────────
if __name__ == "__main__":
    database.init_db()
    res = reset_and_reload()
    print(f"Events in file  : {res.total_in_file}")
    print(f"Events inserted : {res.inserted_events}")
    print(f"Events skipped  : {res.skipped_events}")
    print(f"Events malformed: {res.malformed_events}")
    print(f"Alerts inserted : {res.inserted_alerts}")
    print(f"Alerts skipped  : {res.skipped_alerts}")
    if res.errors:
        print("Errors:")
        for e in res.errors:
            print(f"  • {e}")
