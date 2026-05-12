import os
import sys
import time
import threading
import yaml
from datetime import datetime

from monitor import tail_log
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import ban_ip
from unbanner import UnbanScheduler
from notifier import send_ban_alert, send_global_alert
from dashboard import run_dashboard, shared_state


def load_config():
    config_path = os.environ.get("CONFIG_PATH", "/app/config.yaml")
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def write_audit(message: str, audit_log: str):
    os.makedirs(os.path.dirname(audit_log), exist_ok=True)
    with open(audit_log, "a") as f:
        f.write(message + "\n")


def main():
    print("[MAIN] Starting ShieldGuard Daemon...")
    config = load_config()

    audit_log = config.get("audit_log", "/var/log/detector/audit.log")
    log_path = config.get("log_path", "/var/log/nginx/hng-access.log")
    dashboard_port = config.get("dashboard_port", 8080)

    # Initialize components
    baseline = BaselineTracker(config)
    detector = AnomalyDetector(config)
    unbanner = UnbanScheduler(config)

    # Track already banned IPs to avoid duplicate bans
    banned_ips = set()

    # Start dashboard in background thread
    dash_thread = threading.Thread(
        target=run_dashboard,
        args=[dashboard_port],
        daemon=True
    )
    dash_thread.start()
    print(f"[MAIN] Dashboard running on port {dashboard_port}")

    # Write startup audit entry
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    write_audit(
        f"[{timestamp}] STARTUP | ShieldGuard Daemon started",
        audit_log
    )

    # Dashboard update thread
    def update_dashboard():
        while True:
            mean, std = baseline.get_baseline()
            shared_state["global_rate"] = detector.get_global_rate()
            shared_state["top_ips"] = detector.get_top_ips(10)
            shared_state["baseline_mean"] = mean
            shared_state["baseline_std"] = std
            shared_state["banned_ips"] = unbanner.get_banned_ips()
            time.sleep(3)

    dash_update = threading.Thread(target=update_dashboard, daemon=True)
    dash_update.start()

    # Callback for each log line
    def on_request(entry: dict):
        now = time.time()
        ip = entry["ip"]
        status = entry["status"]
        is_error = status >= 400

        # Record in baseline and detector
        baseline.record_request(now, is_error=is_error)
        detector.record(ip, now, is_error=is_error)

        # Get current baseline
        mean, std = baseline.get_baseline()
        error_mean = 0.1  # floor error baseline

        # Check per-IP anomaly
        if ip not in banned_ips:
            is_anomalous, reason, rate = detector.check_ip_anomaly(
                ip, mean, std, error_mean
            )
            if is_anomalous:
                print(
                    f"[DETECTOR] ANOMALY detected for {ip} | "
                    f"reason={reason} | rate={rate:.2f}"
                )
                # Ban the IP
                success = ban_ip(ip, audit_log)
                if success:
                    banned_ips.add(ip)
                    duration = unbanner.schedule_unban(ip)
                    send_ban_alert(ip, rate, mean, duration)

                    # Write audit
                    timestamp = datetime.utcnow().strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    )
                    write_audit(
                        f"[{timestamp}] BAN ip={ip} | "
                        f"condition={reason} | "
                        f"rate={rate:.2f} | baseline={mean:.2f} | "
                        f"duration={duration}",
                        audit_log
                    )

        # Check global anomaly
        is_global, global_reason, global_rate = detector.check_global_anomaly(
            mean, std
        )
        if is_global:
            print(
                f"[DETECTOR] GLOBAL ANOMALY | "
                f"reason={global_reason} | rate={global_rate:.2f}"
            )
            send_global_alert(global_rate, mean)

        # Log request to stdout
        print(
            f"[MONITOR] {ip} {entry.get('method')} "
            f"{entry.get('path')} {status}"
        )

    # Handle unban callback - remove from banned set
    original_do_unban = unbanner._do_unban

    def patched_do_unban(ip: str):
        original_do_unban(ip)
        banned_ips.discard(ip)

    unbanner._do_unban = patched_do_unban

    # Start tailing the log - this blocks forever
    print(f"[MAIN] Watching log: {log_path}")
    tail_log(log_path, on_request)


if __name__ == "__main__":
    main()
