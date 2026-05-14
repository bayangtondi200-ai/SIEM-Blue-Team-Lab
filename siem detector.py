from collections import defaultdict
from siem.rules import BRUTEFORCE_THRESHOLD, PORTSCAN_THRESHOLD

class SIEMDetector:
    def __init__(self):
        self.bruteforce = defaultdict(int)
        self.portscan = defaultdict(set)

    def process(self, log):
        alerts = []

        if log["event"] == "FAILED_LOGIN":
            self.bruteforce[log["ip"]] += 1

            if self.bruteforce[log["ip"]] == BRUTEFORCE_THRESHOLD:
                alerts.append(f"🚨 Brute Force: {log['ip']}")

        if log["event"] == "PORT_ACCESS":
            self.portscan[log["ip"]].add(log["port"])

            if len(self.portscan[log["ip"]]) == PORTSCAN_THRESHOLD:
                alerts.append(f"🚨 Port Scan: {log['ip']}")

        return alerts
