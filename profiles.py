def classify(commands):
    if len(commands) > 10:
        return "bruteforce_or_automation"
    if any(cmd in commands for cmd in ["wget", "curl", "nc"]):
        return "payload_delivery"
    if any(cmd in commands for cmd in ["cat /etc/passwd", "whoami", "uname"]):
        return "reconnaissance"
    return "unknown"