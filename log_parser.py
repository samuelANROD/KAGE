import re

def parse_log_line(line):
    # Define the pattern to extract SSH log information
    pattern = r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+(\w+)\[(\d+)\]:\s+(Failed|Accepted)\s+(\w+)\s+(?:for (?:invalid user )?)([^\s]+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)"
    match = re.search(pattern, line)

    # Ignore lines that do not match the pattern
    if not match:
        return None

    # Extract information from the matched groups
    server = match.group(1)
    process = match.group(2)
    pid = int(match.group(3))
    status = match.group(4)
    method = match.group(5)
    username = match.group(6)
    ip = match.group(7)
    port = int(match.group(8))

    # Store the extracted information in a dictionary
    event = {
        "server": server,
        "process": process,
        "pid": pid,
        "status": status,
        "method": method,
        "username": username,
        "ip": ip,
        "port": port
    }

    return event