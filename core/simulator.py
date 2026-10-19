
import ipaddress

from core.database import log_security_event
from core.detector import check_brute_force


def simulate_login(username, ip_address, success=False):
    """
    Simulate a login attempt and send it
    to the SIEM detection engine.
    """

    # Validate the IP address
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise ValueError("Invalid IP address")

    status = "SUCCESS" if success else "FAILED"

    # Store the security event
    log_security_event(
        username=username,
        ip_address=ip_address,
        event_type="LOGIN",
        status=status,
        details=f"Simulated {status.lower()} login attempt"
    )

    # Run detection only for failed logins
    if not success:
        detection = check_brute_force(ip_address)
    else:
        detection = {
            "detected": False,
            "alert_created": False,
            "failed_attempts": 0
        }

    return {
        "username": username,
        "ip_address": ip_address,
        "status": status,
        "detection": detection
    }


def simulate_brute_force(username, ip_address, attempts=5):
    """
    Generate multiple failed login attempts
    for controlled security testing.
    """

    if not isinstance(attempts, int) or not 1 <= attempts <= 20:
        raise ValueError("Attempts must be between 1 and 20")

    results = []

    for attempt in range(attempts):
        result = simulate_login(
            username=username,
            ip_address=ip_address,
            success=False
        )

        results.append(result)

    return results
