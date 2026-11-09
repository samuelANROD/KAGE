# NetWard

### SYSTEM SECURITY ANALYTICS
**Linux Authentication Intelligence**

NetWard is a Python-based Linux authentication log analyzer designed to identify suspicious patterns and unusual activity in SSH authentication logs.

The project focuses on processing authentication records, detecting potentially suspicious behavior, and generating readable security reports.

> **Status:** In development — Initial version (0.1.0)

## Overview

NetWard aims to provide a lightweight tool for analyzing Linux authentication logs and identifying patterns that may indicate security threats.

The analyzer will process local log files, extract SSH authentication events, group activity by IP address, and identify suspicious authentication patterns.

NetWard is designed for offline analysis. It does not modify the original log files or attempt to block IP addresses.

## Planned Features

- Read local authentication log files line by line.
- Parse SSH authentication events.
- Extract timestamps, IP addresses, usernames, and authentication results.
- Group authentication activity by IP address.
- Count failed authentication attempts.
- Detect repeated failures within configurable time windows.
- Identify failed authentication attempts followed by successful logins.
- Generate security reports directly in the terminal.
- Handle invalid or unrecognized log entries without interrupting the analysis.

## Project Structure

```text
netward/
├── main.py
├── log_reader.py
├── log_parser.py
├── security_analyzer.py
├── report_generator.py
├── tests/
│   ├── test_parser.py
│   └── test_analyzer.py
├── samples/
│   ├── daily_activity.log
│   ├── suspicious_activity.log
│   └── brute_force_simulation.log
├── README.md
└── .gitignore
```

## Architecture

Each module has a specific responsibility:

| Module | Responsibility |
|---|---|
| `main.py` | Application entry point and execution flow. |
| `log_reader.py` | Reads local log files line by line. |
| `log_parser.py` | Extracts and interprets SSH authentication events. |
| `security_analyzer.py` | Analyzes events and identifies suspicious patterns. |
| `report_generator.py` | Generates readable terminal reports. |
| `tests/` | Contains automated tests for parsing and analysis. |
| `samples/` | Contains synthetic authentication logs for testing. |

## Detection Approach

NetWard will analyze authentication patterns using factors such as:

- Number of failed authentication attempts.
- Frequency of attempts within a time window.
- Repeated activity originating from the same IP address.
- Successful authentication following multiple failures.

These patterns will be treated as security indicators, not definitive proof of an attack.

## Technologies

- Python
- Linux
- Git and GitHub
- Python standard library

## Project Goals

NetWard is also a practical software engineering project focused on developing skills in:

- Python programming and modular architecture.
- File handling and text processing.
- Log analysis and data interpretation.
- Date and time manipulation.
- Automated testing.
- Linux system administration and security concepts.
- Git version control.

## Disclaimer

NetWard is an educational security analysis project.

It does not guarantee the detection of every attack, and its findings should be investigated in context. IP addresses alone cannot establish the identity or intent of a user.

## License

License not yet defined.
