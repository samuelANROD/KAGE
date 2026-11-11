import re

def parse_log_line(line):
    # Define the pattern to extract SSH log information
    pattern = (
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(\S+)\s+(\w+)\[(\d+)\]:\s+"
        r"(Failed|Accepted)\s+(\w+)\s+"
        r"(?:for (?:invalid user )?)([^\s]+)\s+"
        r"from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"port\s+(\d+)\s+(ssh\d+)"
    )

    match = re.search(pattern, line)

    # Ignore lines that do not match the pattern
    if not match:
        return None

    # Extract information from the matched groups
    timestamp = match.group(1)
    server = match.group(2)
    process = match.group(3)
    pid = int(match.group(4))
    status = match.group(5)
    method = match.group(6)
    username = match.group(7)
    ip = match.group(8)
    port = int(match.group(9))
    protocol = match.group(10)

    # Store the extracted information in a dictionary
    event = {
        "timestamp": timestamp,
        "server": server,
        "process": process,
        "pid": pid,
        "status": status,
        "method": method,
        "username": username,
        "ip": ip,
        "port": port,
        "protocol": protocol
    }

    return event
