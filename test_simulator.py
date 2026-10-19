
from core.database import initialize_database
from core.simulator import (
    simulate_login,
    simulate_brute_force
)

initialize_database()

print("\n===== THREATLENS EVENT SIMULATOR =====")

# Test 1: Normal successful login
print("\n[TEST 1] Normal Login")

result = simulate_login(
    username="student",
    ip_address="198.51.100.20",
    success=True
)

print(result)

# Test 2: Failed login
print("\n[TEST 2] Failed Login")

result = simulate_login(
    username="admin",
    ip_address="198.51.100.30",
    success=False
)

print(result)

# Test 3: Simulated brute-force attack
print("\n[TEST 3] Brute-Force Attack")

results = simulate_brute_force(
    username="admin",
    ip_address="203.0.113.80",
    attempts=5
)

print(f"\nTotal attempts generated: {len(results)}")

if results[-1]["detection"]["detected"]:
    print("SECURITY ALERT: BRUTE-FORCE ATTACK DETECTED!")
else:
    print("No attack detected.")

print("\nSimulator test completed!")
