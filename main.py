from log_reader import read_log

logs = read_log("samples/test.log")

for line in logs:
    print(line)