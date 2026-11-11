
from datetime import datetime, timedelta

# Brute force detection settings
TIME_WINDOW = 60
SUSPICIOUS_THRESHOLD = 5
HIGH_RISK_THRESHOLD = 10


def parse_timestamp(timestamp):
    # Convert the log timestamp into a datetime object
    return datetime.strptime(timestamp, "%b %d %H:%M:%S")


def group_events_by_ip(events):
    grouped_events = {}

    # Group all valid events by their source IP
    for event in events:
        if event is None:
            continue

        ip = event["ip"]

        if ip not in grouped_events:
            grouped_events[ip] = []

        grouped_events[ip].append(event)

    return grouped_events


def count_failed_attempts(grouped_events):
    failed_attempts = {}

    # Count failed authentication attempts for each IP
    for ip, events in grouped_events.items():
        count = 0

        for event in events:
            if event["status"] == "Failed":
                count += 1

        failed_attempts[ip] = count

    return failed_attempts


def get_failed_events(events):
    failed_events = []

    # Keep only failed authentication events
    for event in events:
        if event["status"] == "Failed":
            failed_events.append(event)

    return failed_events


def detect_brute_force(grouped_events):
    alerts = {}

    for ip, events in grouped_events.items():
        failed_events = get_failed_events(events)

        timestamps = []

        # Extract and convert timestamps from failed events
        for event in failed_events:
            timestamp = parse_timestamp(event["timestamp"])
            timestamps.append(timestamp)

        # Sort timestamps chronologically
        timestamps.sort()

        left = 0
        max_failures = 0

        # Check failed attempts within the time window
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > timedelta(seconds=TIME_WINDOW):
                left += 1

            current_count = right - left + 1

            # Keep track of the highest number of failures
            if current_count > max_failures:
                max_failures = current_count

        # Classify the IP based on its maximum failure count
        if max_failures >= HIGH_RISK_THRESHOLD:
            level = "High Risk"
        elif max_failures >= SUSPICIOUS_THRESHOLD:
            level = "Suspicious"
        else:
            level = "Normal"

        alerts[ip] = {
            "max_failures": max_failures,
            "level": level
        }

    return alerts

def detect_success_after_failures(grouped_events):
    alerts = {}

    for ip, events in grouped_events.items():
        sorted_events = sorted(
            events,
            key=lambda event: parse_timestamp(event["timestamp"])
        )

        failed_timestamps = []

        for event in sorted_events:
            timestamp = parse_timestamp(event["timestamp"])

            if event["status"] == "Failed":
                failed_timestamps.append(timestamp)

            elif event["status"] == "Accepted":
                recent_failures = []

                # Check for failures within the time window
                for failed_timestamp in failed_timestamps:
                    difference = timestamp - failed_timestamp

                    if difference <= timedelta(seconds=TIME_WINDOW):
                        recent_failures.append(failed_timestamp)

                # Record successful logins after failed attempts
                if recent_failures:
                    if ip not in alerts:
                        alerts[ip] = []

                    alerts[ip].append({
                        "failed_attempts": len(recent_failures),
                        "success_timestamp": event["timestamp"],
                        "username": event["username"]
                    })

                # Reset failures after a successful login
                failed_timestamps = []

    return alerts