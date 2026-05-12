import json
import os
import time
from datetime import datetime


def parse_log_line(line: str) -> dict:
    """Parse a single JSON log line from Nginx."""
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
        # Get real IP - use source_ip or fall back to remote_addr
        ip = data.get('source_ip', '')
        if not ip or ip == '-':
            ip = data.get('remote_addr', '0.0.0.0')
        # Handle comma separated IPs from X-Forwarded-For
        if ',' in ip:
            ip = ip.split(',')[0].strip()
        return {
            'ip': ip,
            'timestamp': data.get('timestamp', ''),
            'method': data.get('method', ''),
            'path': data.get('path', ''),
            'status': int(data.get('status', 0)),
            'response_size': int(data.get('response_size', 0)),
        }
    except (json.JSONDecodeError, ValueError):
        return None


def tail_log(log_path: str, callback):
    """
    Continuously tail a log file and call callback for each new line.
    Uses seek to handle log rotation.
    """
    print(f"[MONITOR] Watching log file: {log_path}")

    # Wait for log file to exist
    while not os.path.exists(log_path):
        print(f"[MONITOR] Waiting for log file: {log_path}")
        time.sleep(5)

    with open(log_path, 'r') as f:
        # Start at end of file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                parsed = parse_log_line(line)
                if parsed:
                    callback(parsed)
            else:
                time.sleep(0.1)
