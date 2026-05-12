import time
import threading
from datetime import datetime
from blocker import unban_ip
from notifier import send_unban_alert


class UnbanScheduler:
    """
    Manages automatic unbanning with backoff schedule.
    Schedule: 10 min, 30 min, 2 hours, then permanent.
    Tracks how many times each IP has been banned.
    """

    def __init__(self, config: dict):
        # Ban schedule in seconds [-1 means permanent]
        self.ban_schedule = config.get(
            "ban_schedule", [600, 1800, 7200, -1]
        )
        self.audit_log = config.get(
            "audit_log", "/var/log/detector/audit.log"
        )
        # Track ban count per IP
        self.ban_counts = {}
        # Track active ban timers
        self.active_bans = {}
        self.lock = threading.Lock()

    def get_ban_duration(self, ip: str) -> int:
        """Get ban duration for IP based on how many times banned."""
        count = self.ban_counts.get(ip, 0)
        if count >= len(self.ban_schedule):
            return -1  # Permanent
        return self.ban_schedule[count]

    def get_next_duration_str(self, ip: str) -> str:
        """Get next ban duration as string."""
        count = self.ban_counts.get(ip, 0) + 1
        if count >= len(self.ban_schedule):
            return "PERMANENT"
        seconds = self.ban_schedule[count]
        if seconds == -1:
            return "PERMANENT"
        return f"{seconds} seconds"

    def schedule_unban(self, ip: str):
        """Schedule automatic unban based on backoff schedule."""
        duration = self.get_ban_duration(ip)

        with self.lock:
            self.ban_counts[ip] = self.ban_counts.get(ip, 0) + 1

        if duration == -1:
            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            msg = (
                f"[{timestamp}] BAN ip={ip} | "
                f"duration=PERMANENT | ban_count={self.ban_counts[ip]}"
            )
            print(f"[UNBANNER] {msg}")
            self._write_audit(msg)
            return duration

        # Write audit log
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        msg = (
            f"[{timestamp}] BAN ip={ip} | "
            f"duration={duration}s | ban_count={self.ban_counts[ip]}"
        )
        print(f"[UNBANNER] {msg}")
        self._write_audit(msg)

        # Schedule unban timer
        timer = threading.Timer(duration, self._do_unban, args=[ip])
        timer.daemon = True
        timer.start()

        with self.lock:
            self.active_bans[ip] = timer

        return duration

    def _do_unban(self, ip: str):
        """Execute the unban."""
        next_duration_str = self.get_next_duration_str(ip)
        success = unban_ip(ip, self.audit_log)

        if success:
            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            msg = (
                f"[{timestamp}] UNBAN ip={ip} | "
                f"next_ban_duration={next_duration_str}"
            )
            print(f"[UNBANNER] {msg}")
            self._write_audit(msg)
            send_unban_alert(ip, next_duration_str)

        with self.lock:
            if ip in self.active_bans:
                del self.active_bans[ip]

    def get_banned_ips(self) -> dict:
        """Return currently active bans with time remaining."""
        result = {}
        with self.lock:
            for ip, timer in self.active_bans.items():
                result[ip] = {
                    "ban_count": self.ban_counts.get(ip, 0),
                    "permanent": False
                }
        return result

    def _write_audit(self, message: str):
        """Write to audit log."""
        import os
        os.makedirs(os.path.dirname(self.audit_log), exist_ok=True)
        with open(self.audit_log, "a") as f:
            f.write(message + "\n")
