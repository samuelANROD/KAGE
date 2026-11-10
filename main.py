from log_reader import read_log
from log_parser import parse_log_line

logs = read_log("samples/brute_force_simulation.log")

events = []

for line in logs:
    event = parse_log_line(line)

    if event is not None:
        events.append(event)

for event in events:
    print(event)

print(" ")
for line in logs:
    print(line)
