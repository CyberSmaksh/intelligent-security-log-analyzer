"""
detector.py – Deterministic detection rules for the SIEM project.

Rules implemented
─────────────────
1. BruteForceLogin   – N or more login_failure events from the same source IP
                       within a configurable time window (default 5 min / 5 failures).
2. UnusualActivity   – Any event whose event_type is 'unusual_activity'.

Each rule returns a list of alert dicts ready to be stored by database.py.
"""

import hashlib
import json
from datetime import datetime, timezone, timedelta
from collections import defaultdict

# ── Rule defaults ──────────────────────────────────────────────────────────────
DEFAULT_BRUTE_THRESHOLD = 5          # minimum failures to trigger
DEFAULT_BRUTE_WINDOW_MINUTES = 5     # rolling window in minutes


def _parse_ts(ts_str: str) -> datetime:
    """Parse an ISO-8601 timestamp string into a UTC-aware datetime."""
    ts_str = ts_str.replace("Z", "+00:00")
    return datetime.fromisoformat(ts_str).astimezone(timezone.utc)


def _make_alert_id(rule_name: str, source_ip: str, window_key: str) -> str:
    """Deterministic alert ID so the same detection window never duplicates."""
    raw = f"{rule_name}:{source_ip}:{window_key}"
    return "ALT-" + hashlib.sha1(raw.encode()).hexdigest()[:10].upper()


# ── Rule 1: Brute-Force / Repeated Login Failures ─────────────────────────────

def detect_brute_force(
    events: list[dict],
    threshold: int = DEFAULT_BRUTE_THRESHOLD,
    window_minutes: int = DEFAULT_BRUTE_WINDOW_MINUTES,
) -> list[dict]:
    """
    Sliding-window brute-force detector.

    For every source IP, the function collects all login_failure timestamps
    in chronological order, then slides a window of `window_minutes` minutes
    over them.  Whenever the window contains >= `threshold` failures it emits
    one alert (deduped by the earliest failure timestamp in that window).

    Parameters
    ----------
    events          : list of event dicts (from database or loader)
    threshold       : minimum failures inside the window to raise an alert
    window_minutes  : width of the rolling window in minutes

    Returns
    -------
    list of alert dicts (may be empty)
    """
    failures_by_ip: defaultdict[str, list[dict]] = defaultdict(list)

    for ev in events:
        if ev.get("event_type") == "login_failure":
            failures_by_ip[ev["source_ip"]].append(ev)

    window = timedelta(minutes=window_minutes)
    alerts: list[dict] = []
    seen_windows: set[str] = set()

    for ip, failures in failures_by_ip.items():
        # Sort by timestamp
        failures_sorted = sorted(failures, key=lambda e: _parse_ts(e["timestamp"]))

        for i, anchor in enumerate(failures_sorted):
            anchor_ts = _parse_ts(anchor["timestamp"])
            window_events = [
                e for e in failures_sorted[i:]
                if _parse_ts(e["timestamp"]) - anchor_ts <= window
            ]
            if len(window_events) < threshold:
                continue

            # Deduplicate: key on IP + earliest timestamp in window
            earliest_ts = anchor["timestamp"]
            window_key = f"{earliest_ts}"
            if (ip, window_key) in seen_windows:
                continue
            seen_windows.add((ip, window_key))

            users = list({e["user"] for e in window_events})
            services = list({e["service"] for e in window_events})
            event_ids = [e["event_id"] for e in window_events]

            evidence = json.dumps({
                "failure_count": len(window_events),
                "window_minutes": window_minutes,
                "event_ids": event_ids,
                "users_targeted": users,
                "services": services,
                "first_seen": window_events[0]["timestamp"],
                "last_seen": window_events[-1]["timestamp"],
            })

            recommendation = (
                "1. Block or rate-limit source IP immediately in the firewall.\n"
                "2. Verify whether any attempt succeeded shortly after the failures.\n"
                "3. Notify the account owner(s) and reset credentials if compromised.\n"
                "4. Review authentication logs for the same IP across all services.\n"
                "5. Correlate with threat-intelligence feeds (this data is synthetic)."
            )

            alert_id = _make_alert_id("BruteForceLogin", ip, window_key)
            alerts.append(
                {
                    "alert_id": alert_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "severity": "HIGH",
                    "rule_name": "BruteForceLogin",
                    "source_ip": ip,
                    "user": ", ".join(users),
                    "evidence": evidence,
                    "recommendation": recommendation,
                }
            )

    return alerts


# ── Rule 2: Unusual Activity ───────────────────────────────────────────────────

def detect_unusual_activity(events: list[dict]) -> list[dict]:
    """
    Raise a MEDIUM alert for every event whose event_type is 'unusual_activity'.

    Parameters
    ----------
    events : list of event dicts

    Returns
    -------
    list of alert dicts (may be empty)
    """
    alerts: list[dict] = []

    for ev in events:
        if ev.get("event_type") != "unusual_activity":
            continue

        evidence = json.dumps(
            {
                "event_id": ev["event_id"],
                "timestamp": ev["timestamp"],
                "source_ip": ev["source_ip"],
                "user": ev["user"],
                "service": ev["service"],
                "message": ev["message"],
            }
        )

        recommendation = (
            "1. Investigate the user's recent activity on the affected service.\n"
            "2. Confirm whether the action was authorized by the user's manager.\n"
            "3. Check for data exfiltration indicators (volume, destination).\n"
            "4. Review DLP and audit logs for the same time window.\n"
            "5. Escalate to the incident response team if action cannot be explained."
        )

        alert_id = _make_alert_id("UnusualActivity", ev["source_ip"], ev["event_id"])
        alerts.append(
            {
                "alert_id": alert_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "severity": "MEDIUM",
                "rule_name": "UnusualActivity",
                "source_ip": ev["source_ip"],
                "user": ev["user"],
                "evidence": evidence,
                "recommendation": recommendation,
            }
        )

    return alerts


# ── Unified entry point ────────────────────────────────────────────────────────

def run_all_detections(
    events: list[dict],
    brute_threshold: int = DEFAULT_BRUTE_THRESHOLD,
    brute_window_minutes: int = DEFAULT_BRUTE_WINDOW_MINUTES,
) -> list[dict]:
    """
    Run every detection rule against the provided event list and return a
    combined, deduplicated list of alert dicts.
    """
    alerts: list[dict] = []
    alerts.extend(
        detect_brute_force(events, brute_threshold, brute_window_minutes)
    )
    alerts.extend(detect_unusual_activity(events))
    # Deduplicate by alert_id in case multiple rules flag the same event
    seen: set[str] = set()
    unique: list[dict] = []
    for a in alerts:
        if a["alert_id"] not in seen:
            seen.add(a["alert_id"])
            unique.append(a)
    return unique
