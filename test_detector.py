
from core.database import (
    initialize_database,
    log_security_event,
    get_security_alerts
)

from core.detector import check_brute_force

initialize_database()

# Use a reserved documentation IP for testing
test_ip = "203.0.113.50"

print("\n===== BRUTE FORCE DETECTION TEST =====")

# Simulate five failed login attempts
for attempt in range(1, 6):

    log_security_event(
        username="admin",
        ip_address=test_ip,
        event_type="LOGIN",
        status="FAILED",
        details=f"Simulated failed login attempt {attempt}"
    )

    result = check_brute_force(test_ip)

    print(f"\nLogin Attempt: {attempt}")
    print(f"Failed Attempts: {result['failed_attempts']}")

    if result["detected"]:
        print("ALERT: BRUTE-FORCE ATTACK DETECTED!")

    else:
        print("Status: Normal monitoring")

    if result["alert_created"]:
        print("HIGH SEVERITY ALERT GENERATED!")

print("\n===== SECURITY ALERTS =====")

for alert in get_security_alerts():
    if alert["ip_address"] == test_ip:
        print(alert)

print("\nDetection test completed!")
