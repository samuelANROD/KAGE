
# Risk level colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


# Sherlog ASCII banner
BANNER = r"""
 ____  _   _ _____ ____  _      ___   ____ 
/ ___|| | | | ____|  _ \| |    / _ \ / ___|
\___ \| |_| |  _| | |_) | |   | | | | \___ \
 ___) |  _  | |___|  _ <| |___| |_| |  ___) |
|____/|_| |_|_____|_| \_\_____|\___/|_____/

          SSH SECURITY ANALYZER
"""


def generate_report(events, failed_attempts, brute_force_alerts, success_alerts):

    # Display the Sherlog banner
    print(BANNER)

    print("=" * 55)
    print("[ GENERAL SUMMARY ]")
    print()

    # Display general analysis statistics
    print(f"Total events analyzed: {len(events)}")
    print(f"Total IP addresses: {len(failed_attempts)}")

    total_failures = sum(failed_attempts.values())

    print(f"Total failed attempts: {total_failures}")

    print("=" * 55)

    print("\n[ IP ANALYSIS ]")

    # Display the analysis results for each IP
    for ip, failed_count in failed_attempts.items():
        print_ip_report(
            ip,
            failed_count,
            brute_force_alerts[ip],
            success_alerts.get(ip, [])
        )

def print_ip_report(ip, failed_count, brute_force_alert, success_alerts):

    # Get the IP risk level
    level = brute_force_alert["level"]

    # Select color based on risk level
    if level == "Normal":
        color = GREEN
    elif level == "Suspicious":
        color = YELLOW
    else:
        color = RED

    print(f"\nIP Address: {ip}")
    print(f"Failed attempts: {failed_count}")
    print(f"Maximum failures in 60 seconds: {brute_force_alert['max_failures']}")

    print(f"Risk level: {color}{level.upper()}{RESET}")

    # Display successful logins after failures
    for alert in success_alerts:
        print(
            f"Successful login after {alert['failed_attempts']} failures"
        )
        print(f"Username: {alert['username']}")
        print(f"Timestamp: {alert['success_timestamp']}")

    print("-" * 55)

