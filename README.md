# SentinelShield Registry Monitor

A Windows Registry Change Monitoring System built as part of a cybersecurity scholarship programme.

## Overview
This toolkit simulates Windows Registry monitoring on Linux using JSON for registry emulation and SQLite for change logging. It detects malware-like modifications, monitors autorun persistence keys, and generates detailed change reports.

## Features
- Baseline registry snapshot using JSON
- Malware behavior pattern detection
- Autorun persistence monitoring
- SQLite-powered change log database
- Timestamped alerts with severity levels (CRITICAL / WARNING / INFO)
- Consolidated final report export

## Project Structure
registry_monitor/
├── baseline_manager.py      # Registry snapshot and comparison engine
├── alert_engine.py          # Malware pattern matching and SQLite logging
├── registry_monitor.py      # Main monitoring loop
├── report_generator.py      # Final report generator
├── registry_baseline.json   # Simulated registry baseline
├── changes.db               # SQLite change log database
└── registry_report.txt      # Generated change report
## Technologies Used
- Python 3.13
- JSON (registry emulation)
- SQLite3 (change log storage)
- hashlib (baseline integrity checksums)

## How to Run
```bash
# Step 1: Generate baseline
python3 baseline_manager.py

# Step 2: Run monitoring simulation
python3 registry_monitor.py

# Step 3: Export final report
python3 report_generator.py
#Sample Output
[!!!] CRITICAL | Windows Defender service tampered: Start changed to 4
[!!!] CRITICAL | UAC policy modified — privilege escalation risk
[!!!] CRITICAL | Windows Firewall disabled
[!!!] CRITICAL | Winlogon Shell replaced — possible rootkit
[!!!] CRITICAL | Suspicious autorun entry added — possible malware persistence
Note
Built on Linux (Kali) using a simulated registry environment.
The winreg module is Windows-only and was intentionally replaced with
JSON + SQLite for cross-platform compatibility and learning purposes.

##DISCLAIMER
This is for educational purposes only!
EOG
