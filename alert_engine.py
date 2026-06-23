import sqlite3
from datetime import datetime

DB_FILE = "changes.db"

# Known malware behavior patterns
MALWARE_PATTERNS = {
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend": {
        "Start": ["3", "4"],  # 3=manual, 4=disabled — malware disables Defender
        "description": "Windows Defender service tampered"
    },
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System": {
        "EnableLUA": ["0"],  # UAC disabled
        "ConsentPromptBehaviorAdmin": ["0"],  # UAC bypass
        "description": "UAC policy modified — privilege escalation risk"
    },
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy": {
        "EnableFirewall": ["0"],  # Firewall disabled
        "description": "Windows Firewall disabled"
    },
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon": {
        "Shell": None,  # Any change to Shell is suspicious
        "description": "Winlogon Shell replaced — possible rootkit"
    }
}

AUTORUN_KEYS = [
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
]

SUSPICIOUS_PATHS = [
    "appdata", "temp", "tmp", "programdata",
    "%appdata%", "%temp%", "c:\\users\\public"
]


def init_database() -> None:
    """Create SQLite database and tables if they don't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS change_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            change_type TEXT NOT NULL,
            key_path TEXT NOT NULL,
            value_name TEXT,
            old_value TEXT,
            new_value TEXT,
            severity TEXT NOT NULL,
            alert_message TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_summary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT NOT NULL,
            total_changes INTEGER,
            critical_count INTEGER,
            warning_count INTEGER,
            info_count INTEGER
        )
    """)

    conn.commit()
    conn.close()
    print("[+] Database initialized: changes.db")


def assess_severity(change: dict) -> tuple:
    """
    Assess severity of a registry change.
    Returns (severity, alert_message)
    """
    key_path = change.get("key_path", "")
    value_name = change.get("value_name", "")
    new_value = str(change.get("new_value", "")).lower()
    change_type = change.get("type", "")

    # Check autorun keys
    if key_path in AUTORUN_KEYS:
        if change_type in ["ADDED_VALUE", "ADDED_KEY"]:
            # Check if path looks suspicious
            if any(path in new_value for path in SUSPICIOUS_PATHS):
                return ("CRITICAL",
                        f"Suspicious autorun entry added: {new_value} — possible malware persistence")
            return ("WARNING",
                    f"New autorun entry detected: {value_name} -> {new_value}")

    # Check malware patterns
    if key_path in MALWARE_PATTERNS:
        pattern = MALWARE_PATTERNS[key_path]
        description = pattern.get("description", "Suspicious registry change")

        if value_name in pattern:
            trigger_values = pattern[value_name]
            if trigger_values is None or str(change.get("new_value")) in trigger_values:
                return ("CRITICAL", f"{description}: {value_name} changed to {new_value}")

        # Any modification to a sensitive key is at least a warning
        return ("WARNING", f"Sensitive key modified: {key_path}\\{value_name}")

    # Deleted keys are always worth flagging
    if change_type == "DELETED_KEY":
        return ("WARNING", f"Registry key deleted: {key_path}")

    return ("INFO", f"Registry change detected: {change_type} at {key_path}")


def log_change(change: dict) -> None:
    """Log a single registry change to SQLite database."""
    severity, alert_message = assess_severity(change)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO change_log
        (timestamp, change_type, key_path, value_name, old_value, new_value, severity, alert_message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        change.get("timestamp", datetime.now().isoformat()),
        change.get("type", "UNKNOWN"),
        change.get("key_path", ""),
        change.get("value_name", ""),
        str(change.get("old_value", "")),
        str(change.get("new_value", "")),
        severity,
        alert_message
    ))

    conn.commit()
    conn.close()

    # Print alert to screen
    prefix = {
        "CRITICAL": "[!!!] CRITICAL",
        "WARNING":  "[ ! ] WARNING ",
        "INFO":     "[ i ] INFO    "
    }.get(severity, "[ ? ]")

    print(f"{prefix} | {alert_message}")


def save_scan_summary(total: int, critical: int, warning: int, info: int) -> None:
    """Save scan summary to database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_summary
        (scan_time, total_changes, critical_count, warning_count, info_count)
        VALUES (?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), total, critical, warning, info))

    conn.commit()
    conn.close()


def get_all_changes() -> list:
    """Retrieve all logged changes from database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM change_log ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


if __name__ == "__main__":
    init_database()
    print("[+] Alert engine ready")
    print(f"[+] Monitoring {len(MALWARE_PATTERNS)} malware behavior patterns")
    print(f"[+] Monitoring {len(AUTORUN_KEYS)} autorun key paths")
