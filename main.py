
from log_reader import read_log
from log_parser import parse_log_line
from security_analyzer import (
    group_events_by_ip,
    count_failed_attempts,
    detect_brute_force,
    detect_success_after_failures
)

# Read and parse the log file
logs = read_log("samples/test.log")

events = []

for line in logs:
    event = parse_log_line(line)

    if event is not None:
        events.append(event)

# Group events by IP
grouped_events = group_events_by_ip(events)

# Count failed attempts
failed_attempts = count_failed_attempts(grouped_events)

# Detect brute force activity
brute_force_alerts = detect_brute_force(grouped_events)

# Detect successful logins after failures
success_alerts = detect_success_after_failures(grouped_events)

# Display results
print("\n=== FAILED ATTEMPTS ===")
for ip, count in failed_attempts.items():
    print(f"{ip}: {count} failed attempts")

print("\n=== BRUTE FORCE DETECTION ===")
for ip, alert in brute_force_alerts.items():
    print(f"{ip}: {alert}")

print("\n=== SUCCESS AFTER FAILURES ===")
for ip, alerts in success_alerts.items():
    print(f"{ip}: {alerts}")
