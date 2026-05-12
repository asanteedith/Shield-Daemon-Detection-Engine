import subprocess
import os
from datetime import datetime


def write_audit(message: str, audit_log: str):
    """Write to audit log."""
    os.makedirs(os.path.dirname(audit_log), exist_ok=True)
    with open(audit_log, "a") as f:
        f.write(message + "\n")


def ban_ip(ip: str, audit_log: str = "/var/log/detector/audit.log"):
    """Add iptables DROP rule for an IP."""
    try:
        # Check if already banned
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        if check.returncode == 0:
            print(f"[BLOCKER] {ip} already banned")
            return True

        # Add ban rule
        result = subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            msg = f"[{timestamp}] BAN ip={ip} | iptables DROP rule added"
            print(f"[BLOCKER] {msg}")
            write_audit(msg, audit_log)
            return True
        else:
            print(f"[BLOCKER] Failed to ban {ip}: {result.stderr}")
            return False
    except Exception as e:
        print(f"[BLOCKER] Error banning {ip}: {e}")
        return False


def unban_ip(ip: str, audit_log: str = "/var/log/detector/audit.log"):
    """Remove iptables DROP rule for an IP."""
    try:
        result = subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            msg = f"[{timestamp}] UNBAN ip={ip} | iptables DROP rule removed"
            print(f"[BLOCKER] {msg}")
            write_audit(msg, audit_log)
            return True
        else:
            print(f"[BLOCKER] Failed to unban {ip}: {result.stderr}")
            return False
    except Exception as e:
        print(f"[BLOCKER] Error unbanning {ip}: {e}")
        return False


def is_banned(ip: str) -> bool:
    """Check if an IP is currently banned."""
    try:
        result = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        return result.returncode == 0
    except Exception:
        return False
