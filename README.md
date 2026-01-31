# Honeypot++

Honeypot++ is a low-interaction SSH deception system designed for cybersecurity labs, SOC training, and DFIR research. It emulates a real SSH service, captures attacker credentials and commands, and logs behavior for analysis. All in a safe, controlled environment.

## Features
- Realistic low‑interaction SSH honeypot
- Persistent SSH host key & spoofed OpenSSH banner
- Realistic OS‑based fingerprinting in uname & login banner
- Human‑like per‑command timing delays
- Credential harvesting & full command logging
- Interactive fake shell with virtual filesystem
- Safe, fully emulated (no real command execution)

## Tech Stack
- Python 3
- Paramiko
- Socket & threading

## Usage
Run the honeypot:
```bash
python honeypot.py
```
