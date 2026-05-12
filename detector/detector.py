import time
from collections import deque
from datetime import datetime


class AnomalyDetector:
    def __init__(self, config: dict):
        self.window_seconds = config.get('window_seconds', 60)
        self.z_score_threshold = config.get('z_score_threshold', 3.0)
        self.rate_multiplier = config.get('rate_multiplier', 5.0)
        self.error_rate_multiplier = config.get('error_rate_multiplier', 3.0)
        self.ip_windows = {}
        self.ip_error_windows = {}
        self.global_window = deque()

    def record(self, ip: str, timestamp: float, is_error: bool = False):
        self.global_window.append(timestamp)
        if ip not in self.ip_windows:
            self.ip_windows[ip] = deque()
        self.ip_windows[ip].append(timestamp)
        if is_error:
            if ip not in self.ip_error_windows:
                self.ip_error_windows[ip] = deque()
            self.ip_error_windows[ip].append(timestamp)
        self._evict(timestamp)

    def _evict(self, now: float):
        cutoff = now - self.window_seconds
        while self.global_window and self.global_window[0] < cutoff:
            self.global_window.popleft()
        for ip in list(self.ip_windows.keys()):
            while self.ip_windows[ip] and self.ip_windows[ip][0] < cutoff:
                self.ip_windows[ip].popleft()
            if not self.ip_windows[ip]:
                del self.ip_windows[ip]
        for ip in list(self.ip_error_windows.keys()):
            while self.ip_error_windows[ip] and self.ip_error_windows[ip][0] < cutoff:
                self.ip_error_windows[ip].popleft()
            if not self.ip_error_windows[ip]:
                del self.ip_error_windows[ip]

    def get_ip_rate(self, ip: str) -> float:
        if ip not in self.ip_windows:
            return 0.0
        return len(self.ip_windows[ip]) / self.window_seconds

    def get_global_rate(self) -> float:
        return len(self.global_window) / self.window_seconds

    def get_ip_error_rate(self, ip: str) -> float:
        if ip not in self.ip_error_windows:
            return 0.0
        return len(self.ip_error_windows[ip]) / self.window_seconds

    def get_top_ips(self, n: int = 10) -> list:
        ip_counts = {ip: len(window) for ip, window in self.ip_windows.items()}
        return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def check_ip_anomaly(self, ip, baseline_mean, baseline_std, baseline_error_mean):
        rate = self.get_ip_rate(ip)
        error_rate = self.get_ip_error_rate(ip)
        error_surge = baseline_error_mean > 0 and error_rate > self.error_rate_multiplier * baseline_error_mean
        z_threshold = self.z_score_threshold * 0.6 if error_surge else self.z_score_threshold
        rate_mult = self.rate_multiplier * 0.6 if error_surge else self.rate_multiplier
        z_score = (rate - baseline_mean) / baseline_std if baseline_std > 0 else 0.0
        if z_score > z_threshold:
            return True, f"z-score={z_score:.2f} > threshold={z_threshold:.2f}", rate
        if rate > rate_mult * baseline_mean:
            return True, f"rate={rate:.2f} > {rate_mult}x baseline={baseline_mean:.2f}", rate
        return False, "", rate

    def check_global_anomaly(self, baseline_mean, baseline_std):
        rate = self.get_global_rate()
        z_score = (rate - baseline_mean) / baseline_std if baseline_std > 0 else 0.0
        if z_score > self.z_score_threshold:
            return True, f"global z-score={z_score:.2f} > threshold={self.z_score_threshold}", rate
        if rate > self.rate_multiplier * baseline_mean:
            return True, f"global rate={rate:.2f} > {self.rate_multiplier}x baseline={baseline_mean:.2f}", rate
        return False, "", rate
