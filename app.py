from siem.parser import parse_log
from siem.detector import SIEMDetector
from siem.alert import generate_alert

def run_siem(log_file):
    detector = SIEMDetector()

    with open(log_file, "r") as f:
        for line in f:
            log = parse_log(line)

            if not log:
                continue

            alerts = detector.process(log)

            for alert in alerts:
                print(generate_alert(alert))


if __name__ == "__main__":
    print("🚀 SIEM Blue Team Lab démarré...\n")
    run_siem("logs/sample.log")
