
from datetime import datetime, timedelta

from core.database import (
    get_connection,
    create_security_alert
)


def check_brute_force(
    ip_address,
    threshold=5,
    window_seconds=60
):
    """
    Detect repeated failed login attempts
    from a single IP address.
    """

    now = datetime.now()
    cutoff = now - timedelta(seconds=window_seconds)

    cutoff_string = cutoff.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()

    # Count failed login attempts within the time window
    cursor = conn.execute("""
        SELECT COUNT(*) AS attempt_count
        FROM security_logs
        WHERE ip_address = ?
        AND event_type = 'LOGIN'
        AND status = 'FAILED'
        AND timestamp >= ?
    """, (ip_address, cutoff_string))

    attempt_count = cursor.fetchone()["attempt_count"]

    conn.close()

    # Threshold not reached
    if attempt_count < threshold:
        return {
            "detected": False,
            "alert_created": False,
            "failed_attempts": attempt_count
        }

    # Check whether an alert already exists
    conn = get_connection()

    cursor = conn.execute("""
        SELECT id
        FROM security_alerts
        WHERE ip_address = ?
        AND alert_type = 'Brute-Force Attack'
        AND timestamp >= ?
        LIMIT 1
    """, (ip_address, cutoff_string))

    existing_alert = cursor.fetchone()
    conn.close()

    alert_created = False

    # Avoid duplicate alerts
    if not existing_alert:
        create_security_alert(
            ip_address=ip_address,
            alert_type="Brute-Force Attack",
            severity="HIGH",
            description=(
                f"{attempt_count} failed login attempts "
                f"detected within {window_seconds} seconds."
            )
        )

        alert_created = True

    return {
        "detected": True,
        "alert_created": alert_created,
        "failed_attempts": attempt_count
    }
