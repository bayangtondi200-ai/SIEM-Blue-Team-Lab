def parse_log(line):
    parts = line.strip().split()

    if len(parts) < 3:
        return None

    event = parts[0]
    ip = parts[1]

    data = {
        "event": event,
        "ip": ip
    }

    if event == "PORT_ACCESS":
        data["port"] = parts[2]

    return data
