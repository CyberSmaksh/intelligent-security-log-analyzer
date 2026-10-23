"""
database.py – SQLite initialization and CRUD helpers for the SIEM project.
All tables are created automatically on first use.
"""

import sqlite3
import os
from typing import Any

DB_PATH = os.path.join(os.path.dirname(__file__), "siem.db")


def get_connection() -> sqlite3.Connection:
    """Return a connection with row_factory set to sqlite3.Row."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    """Create tables if they do not already exist."""
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id    TEXT    UNIQUE NOT NULL,
                timestamp   TEXT    NOT NULL,
                source_ip   TEXT    NOT NULL,
                user        TEXT    NOT NULL,
                event_type  TEXT    NOT NULL,
                service     TEXT    NOT NULL,
                message     TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id        TEXT    UNIQUE NOT NULL,
                created_at      TEXT    NOT NULL,
                severity        TEXT    NOT NULL,
                rule_name       TEXT    NOT NULL,
                source_ip       TEXT    NOT NULL,
                user            TEXT    NOT NULL,
                evidence        TEXT    NOT NULL,
                recommendation  TEXT    NOT NULL
            );
            """
        )


# ── Events ────────────────────────────────────────────────────────────────────

def insert_event(event: dict) -> bool:
    """
    Insert one event record.  Returns True on success, False if the
    event_id already exists (idempotent load).
    """
    sql = """
        INSERT OR IGNORE INTO events
            (event_id, timestamp, source_ip, user, event_type, service, message)
        VALUES
            (:event_id, :timestamp, :source_ip, :user, :event_type, :service, :message)
    """
    with get_connection() as conn:
        cur = conn.execute(sql, event)
        return cur.rowcount == 1


def get_all_events() -> list[dict]:
    """Return all events ordered by timestamp ascending."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp ASC"
        ).fetchall()
    return [dict(r) for r in rows]


def event_count() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def clear_events() -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM events")


# ── Alerts ────────────────────────────────────────────────────────────────────

def insert_alert(alert: dict) -> bool:
    """
    Insert one alert record.  Returns True on success, False if the
    alert_id already exists.
    """
    sql = """
        INSERT OR IGNORE INTO alerts
            (alert_id, created_at, severity, rule_name, source_ip, user,
             evidence, recommendation)
        VALUES
            (:alert_id, :created_at, :severity, :rule_name, :source_ip, :user,
             :evidence, :recommendation)
    """
    with get_connection() as conn:
        cur = conn.execute(sql, alert)
        return cur.rowcount == 1


def get_all_alerts() -> list[dict]:
    """Return all alerts ordered by created_at descending."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def alert_count() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


def clear_alerts() -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM alerts")


def severity_counts() -> dict[str, int]:
    """Return {severity: count} for all stored alerts."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
        ).fetchall()
    return {r["severity"]: r["cnt"] for r in rows}
