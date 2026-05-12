import requests
import yaml
from datetime import datetime


def load_config():
    with open('/app/config.yaml', 'r') as f:
        return yaml.safe_load(f)


def send_slack(message: str):
    """Send a message to Slack via webhook."""
    config = load_config()
    webhook_url = config.get('slack_webhook', '')

    if not webhook_url or webhook_url == 'REPLACE_WITH_YOUR_WEBHOOK_URL':
        print(f"[SLACK] Webhook not configured. Message: {message}")
        return

    payload = {"text": message}
    try:
        response = requests.post(webhook_url, json=payload, timeout=5)
        if response.status_code == 200:
            print(f"[SLACK] Alert sent successfully")
        else:
            print(f"[SLACK] Failed to send alert: {response.status_code}")
    except Exception as e:
        print(f"[SLACK] Error sending alert: {e}")


def send_ban_alert(ip: str, rate: float, baseline: float, duration: int):
    """Send a ban notification to Slack."""
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    if duration == -1:
        duration_str = "PERMANENT"
    else:
        duration_str = f"{duration} seconds"

    message = (
        f"🚨 *IP BANNED*\n"
        f"• IP: `{ip}`\n"
        f"• Condition: Anomalous request rate\n"
        f"• Current rate: {rate:.2f} req/s\n"
        f"• Baseline: {baseline:.2f} req/s\n"
        f"• Ban duration: {duration_str}\n"
        f"• Timestamp: {timestamp}"
    )
    send_slack(message)


def send_unban_alert(ip: str, next_duration: str):
    """Send an unban notification to Slack."""
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    message = (
        f"✅ *IP UNBANNED*\n"
        f"• IP: `{ip}`\n"
        f"• Timestamp: {timestamp}\n"
        f"• Next ban duration if re-offending: {next_duration}"
    )
    send_slack(message)


def send_global_alert(rate: float, baseline: float):
    """Send a global traffic anomaly alert to Slack."""
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    message = (
        f"⚠️ *GLOBAL TRAFFIC ANOMALY*\n"
        f"• Condition: Global request rate spike\n"
        f"• Current rate: {rate:.2f} req/s\n"
        f"• Baseline: {baseline:.2f} req/s\n"
        f"• Action: No IP ban — monitoring closely\n"
        f"• Timestamp: {timestamp}"
    )
    send_slack(message)
