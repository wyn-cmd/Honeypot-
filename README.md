# Honeypot++

Honeypot++ is a low-interaction SSH deception system designed for cybersecurity labs, SOC training, and DFIR research. It emulates a real SSH service, captures attacker credentials and commands, and logs behavior for analysis. All in a safe, controlled environment.

## Features
- SSH protocol support (Paramiko)
- Captures usernames, passwords, & commands
- Command emulation with realistic responses
- JSON logging (SIEM-friendly)
- Safe for isolated lab environments

## Tech Stack
- Python 3
- Paramiko
- Socket & threading

## Usage
Run the honeypot:
```bash
python honeypot.py
```
