import json
import os
import hashlib
from datetime import datetime

# Simulated Windows Registry Structure
SIMULATED_REGISTRY = {
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": {
        "OneDrive": "C:\\Program Files\\OneDrive\\onedrive.exe",
        "SecurityHealth": "C:\\Windows\\System32\\SecurityHealth.exe"
    },
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": {
        "WindowsDefender": "C:\\Program Files\\Windows Defender\\MSASCuiL.exe",
        "MicrosoftEdge": "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
    },
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce": {},
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce": {},
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend": {
        "Start": "2",
        "ImagePath": "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
    },
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System": {
        "EnableLUA": "1",
        "ConsentPromptBehaviorAdmin": "2"
    },
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy": {
        "EnableFirewall": "1",
        "DisableNotifications": "0"
    },
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon": {
        "Shell": "explorer.exe",
        "Userinit": "C:\\Windows\\system32\\userinit.exe"
    }
}

BASELINE_FILE = "registry_baseline.json"

def compute_checksum(data: dict) -> str:
    """Generate SHA256 checksum of registry data for integrity verification."""
    encoded = json.dumps(data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

def save_baseline(registry: dict = None) -> None:
    """Save registry snapshot as baseline JSON file."""
    if registry is None:
        registry = SIMULATED_REGISTRY

    baseline = {
        "timestamp": datetime.now().isoformat(),
        "checksum": compute_checksum(registry),
        "registry": registry
    }

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

    print(f"[+] Baseline saved: {BASELINE_FILE}")
    print(f"[+] Checksum: {baseline['checksum']}")
    print(f"[+] Keys monitored: {len(registry)}")

def load_baseline() -> dict:
    """Load existing baseline from JSON file."""
    if not os.path.exists(BASELINE_FILE):
        print("[-] No baseline found. Creating new baseline...")
        save_baseline()

    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    print(f"[+] Baseline loaded from: {baseline['timestamp']}")
    return baseline["registry"]

def compare_registry(baseline: dict, current: dict) -> list:
    """
    Compare baseline registry against current state.
    Returns list of detected changes.
    """
    changes = []

    for key_path, baseline_values in baseline.items():
        if key_path not in current:
            changes.append({
                "type": "DELETED_KEY",
                "key_path": key_path,
                "old_value": baseline_values,
                "new_value": None,
                "timestamp": datetime.now().isoformat()
            })
            continue

        current_values = current[key_path]

        # Detect deleted values
        for value_name, value_data in baseline_values.items():
            if value_name not in current_values:
                changes.append({
                    "type": "DELETED_VALUE",
                    "key_path": key_path,
                    "value_name": value_name,
                    "old_value": value_data,
                    "new_value": None,
                    "timestamp": datetime.now().isoformat()
                })

            # Detect modified values
            elif current_values[value_name] != value_data:
                changes.append({
                    "type": "MODIFIED_VALUE",
                    "key_path": key_path,
                    "value_name": value_name,
                    "old_value": value_data,
                    "new_value": current_values[value_name],
                    "timestamp": datetime.now().isoformat()
                })

    # Detect added keys or values
    for key_path, current_values in current.items():
        if key_path not in baseline:
            changes.append({
                "type": "ADDED_KEY",
                "key_path": key_path,
                "old_value": None,
                "new_value": current_values,
                "timestamp": datetime.now().isoformat()
            })
            continue

        for value_name, value_data in current_values.items():
            if value_name not in baseline[key_path]:
                changes.append({
                    "type": "ADDED_VALUE",
                    "key_path": key_path,
                    "value_name": value_name,
                    "old_value": None,
                    "new_value": value_data,
                    "timestamp": datetime.now().isoformat()
                })

    return changes


if __name__ == "__main__":
    save_baseline()
    loaded = load_baseline()
    print(f"\n[+] Registry structure loaded with {len(loaded)} monitored key paths")
