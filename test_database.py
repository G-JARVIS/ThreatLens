
from core.database import (
    initialize_database,
    log_security_event,
    get_security_logs
)

# Initialize database
initialize_database()

# Insert a test security event
log_security_event(
    username="admin",
    ip_address="192.168.1.100",
    event_type="LOGIN",
    status="FAILED",
    details="Test failed login attempt"
)

# Retrieve stored events
logs = get_security_logs()

print("\n===== THREATLENS DATABASE TEST =====")

for log in logs:
    print(log)

print("\nDatabase test completed successfully!")
