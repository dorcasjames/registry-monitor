import json
import time
import copy
from datetime import datetime
from baseline_manager import load_baseline, compare_registry, SIMULATED_REGISTRY
from alert_engine import init_database, log_change, save_scan_summary

MONITOR_INTERVAL = 10  # seconds between each scan
MAX_SCANS = 3          # number of scans to run in demo mode


def simulate_registry_changes(registry: dict) -> dict:
    """
    Simulate realistic malware-like registry modifications.
    In a real Windows tool this would read live registry values.
    """
    modified = copy.deepcopy(registry)

    # Simulation 1: Malware adds suspicious autorun entry
    modified["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"][
        "WindowsUpdate"
    ] = "C:\\Users\\User\\AppData\\Roaming\\svchost.exe"

    # Simulation 2: Malware disables Windows Defender
    modified["HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend"][
        "Start"
    ] = "4"

    # Simulation 3: Malware disables UAC
    modified["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"][
        "EnableLUA"
    ] = "0"

    # Simulation 4: Firewall disabled
    modified["HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"][
        "EnableFirewall"
    ] = "0"

    # Simulation 5: Shell replacement (rootkit behavior)
    modified["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"][
        "Shell"
    ] = "explorer.exe, C:\\Windows\\system32\\backdoor.exe"

    return modified


def run_scan(baseline: dict, current: dict, scan_number: int) -> dict:
    """Run a single registry scan and return summary."""
    print(f"\n{'='*60}")
    print(f"  SCAN #{scan_number} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    changes = compare_registry(baseline, current)

    if not changes:
        print("[+] No changes detected.")
        return {"total": 0, "critical": 0, "warning": 0, "info": 0}

    print(f"[!] {len(changes)} change(s) detected:\n")

    critical_count = 0
    warning_count = 0
    info_count = 0

    for change in changes:
        log_change(change)
        severity, _ = __import__('alert_engine').assess_severity(change)
        if severity == "CRITICAL":
            critical_count += 1
        elif severity == "WARNING":
            warning_count += 1
        else:
            info_count += 1

    summary = {
        "total": len(changes),
        "critical": critical_count,
        "warning": warning_count,
        "info": info_count
    }

    save_scan_summary(
        summary["total"],
        summary["critical"],
        summary["warning"],
        summary["info"]
    )

    print(f"\n  Summary: {critical_count} CRITICAL | {warning_count} WARNING | {info_count} INFO")
    return summary


def start_monitoring():
    """Main monitoring loop."""
    print("\n" + "="*60)
    print("   REGISTRY MONITOR — SentinelShield Simulation Mode")
    print("="*60)
    print(f"[+] Monitoring interval: {MONITOR_INTERVAL} seconds")
    print(f"[+] Demo scans: {MAX_SCANS}")
    print(f"[+] Started: {datetime.now().isoformat()}")

    # Initialize database
    init_database()

    # Load baseline
    print("\n[*] Loading baseline registry snapshot...")
    baseline = load_baseline()
    print(f"[+] Baseline ready — {len(baseline)} key paths loaded")

    # Scan 1: Clean state — no changes
    print("\n[*] Scan 1 will run against clean registry (no changes expected)")
    clean_registry = copy.deepcopy(SIMULATED_REGISTRY)
    run_scan(baseline, clean_registry, 1)

    time.sleep(MONITOR_INTERVAL)

    # Scan 2: Inject malware-like changes
    print("\n[*] Simulating malware activity before Scan 2...")
    compromised_registry = simulate_registry_changes(SIMULATED_REGISTRY)
    run_scan(baseline, compromised_registry, 2)

    time.sleep(MONITOR_INTERVAL)

    # Scan 3: Partial recovery — some changes remain
    print("\n[*] Simulating partial remediation before Scan 3...")
    partial_registry = copy.deepcopy(compromised_registry)

    # Restore Defender but leave other changes
    partial_registry["HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend"][
        "Start"
    ] = "2"

    run_scan(baseline, partial_registry, 3)

    print("\n" + "="*60)
    print("  MONITORING COMPLETE")
    print(f"  Ended: {datetime.now().isoformat()}")
    print("  Run report_generator.py to export final report")
    print("="*60 + "\n")


if __name__ == "__main__":
    start_monitoring()
