
import sqlite3
from pathlib import Path
from datetime import datetime

# Database location
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "siem.db"


def get_connection():
    """Create a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    """Create required database tables."""

    conn = get_connection()
    cursor = conn.cursor()

    # Security event logs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            event_type TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT
        )
    """)

    # Security incidents and alerts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'Open'
        )
    """)

    conn.commit()
    conn.close()


def log_security_event(
    username,
    ip_address,
    event_type,
    status,
    details=""
):
    """Store a security event in the database."""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO security_logs
        (timestamp, username, ip_address, event_type, status, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        username,
        ip_address,
        event_type,
        status,
        details
    ))

    conn.commit()
    conn.close()


def create_security_alert(
    ip_address,
    alert_type,
    severity,
    description
):
    """Store a detected security alert."""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO security_alerts
        (timestamp, ip_address, alert_type, severity, description)
        VALUES (?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip_address,
        alert_type,
        severity,
        description
    ))

    conn.commit()
    conn.close()


def get_security_logs(limit=500):
    """Retrieve recent security events."""

    conn = get_connection()

    cursor = conn.execute("""
        SELECT * FROM security_logs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return logs


def get_security_alerts(limit=500):
    """Retrieve recent security alerts."""

    conn = get_connection()

    cursor = conn.execute("""
        SELECT * FROM security_alerts
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return alerts


def update_alert_status(alert_id, status):
    """Update the status of an incident."""

    allowed_statuses = ["Open", "Investigating", "Resolved"]

    if status not in allowed_statuses:
        raise ValueError("Invalid alert status")

    conn = get_connection()

    conn.execute("""
        UPDATE security_alerts
        SET status = ?
        WHERE id = ?
    """, (status, alert_id))

    conn.commit()
    conn.close()
