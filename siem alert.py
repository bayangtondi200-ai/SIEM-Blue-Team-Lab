from datetime import datetime

def generate_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"[{timestamp}] {message}"
