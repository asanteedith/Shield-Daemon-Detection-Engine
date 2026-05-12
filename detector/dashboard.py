import os
import time
import psutil
from flask import Flask, jsonify, render_template_string
from datetime import datetime

app = Flask(__name__)

shared_state = {
    "banned_ips": {},
    "global_rate": 0.0,
    "top_ips": [],
    "baseline_mean": 0.0,
    "baseline_std": 0.0,
    "start_time": time.time(),
    "rate_history": [],
}

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>ShieldDaemon - Anomaly Detection Engine</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Inter', sans-serif;
            background: #0b0f1a;
            color: #e2e8f0;
            min-height: 100vh;
        }

        /* Sidebar */
        .sidebar {
            position: fixed;
            left: 0; top: 0;
            width: 220px;
            height: 100vh;
            background: #0d1224;
            border-right: 1px solid #1e2d4a;
            padding: 25px 0;
            z-index: 100;
        }

        .sidebar-logo {
            padding: 0 20px 25px;
            border-bottom: 1px solid #1e2d4a;
            margin-bottom: 20px;
        }

        .sidebar-logo-title {
            font-size: 16px;
            font-weight: 800;
            color: #fff;
            letter-spacing: 1px;
        }

        .sidebar-logo-sub {
            font-size: 10px;
            color: #4a6080;
            margin-top: 3px;
            letter-spacing: 2px;
            text-transform: uppercase;
        }

        .shield-big {
            font-size: 28px;
            margin-bottom: 8px;
            display: block;
            filter: drop-shadow(0 0 8px rgba(99,179,237,0.6));
        }

        .nav-item {
            padding: 10px 20px;
            font-size: 12px;
            color: #4a6080;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.2s;
            letter-spacing: 0.5px;
        }

        .nav-item:hover { color: #fff; background: rgba(99,179,237,0.05); }
        .nav-item.active {
            color: #63b3ed;
            background: rgba(99,179,237,0.1);
            border-right: 2px solid #63b3ed;
        }

        .nav-section {
            font-size: 9px;
            color: #2a3a5a;
            padding: 15px 20px 5px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }

        .status-indicator {
            margin: 20px;
            padding: 12px 15px;
            background: rgba(72,187,120,0.1);
            border: 1px solid rgba(72,187,120,0.3);
            border-radius: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
            position: absolute;
            bottom: 20px;
            left: 0; right: 0;
        }

        .status-dot {
            width: 8px; height: 8px;
            background: #48bb78;
            border-radius: 50%;
            animation: pulse 2s infinite;
            flex-shrink: 0;
        }

        @keyframes pulse {
            0%, 100% { box-shadow: 0 0 0 0 rgba(72,187,120,0.4); }
            50% { box-shadow: 0 0 0 6px rgba(72,187,120,0); }
        }

        .status-text { font-size: 11px; color: #48bb78; font-weight: 600; }
        .status-sub { font-size: 9px; color: #2a5a3a; }

        /* Main content */
        .main {
            margin-left: 220px;
            padding: 25px;
            min-height: 100vh;
        }

        /* Top bar */
        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 25px;
        }

        .page-title {
            font-size: 22px;
            font-weight: 700;
            color: #fff;
        }

        .page-sub {
            font-size: 12px;
            color: #4a6080;
            margin-top: 3px;
        }

        .topbar-right {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .refresh-badge {
            background: rgba(99,179,237,0.1);
            border: 1px solid rgba(99,179,237,0.3);
            color: #63b3ed;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 500;
        }

        .time-display {
            font-size: 12px;
            color: #4a6080;
            font-weight: 500;
        }

        /* Alert banner */
        .alert-banner {
            display: none;
            background: linear-gradient(135deg, rgba(245,101,101,0.15), rgba(254,178,178,0.05));
            border: 1px solid rgba(245,101,101,0.4);
            border-radius: 10px;
            padding: 14px 20px;
            margin-bottom: 20px;
            color: #fc8181;
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
            animation: alertPulse 2s infinite;
        }

        @keyframes alertPulse {
            0%, 100% { border-color: rgba(245,101,101,0.4); }
            50% { border-color: rgba(245,101,101,0.8); }
        }

        /* Metric cards */
        .metrics-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }

        .metric-card {
            background: #0d1224;
            border: 1px solid #1e2d4a;
            border-radius: 12px;
            padding: 20px;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }

        .metric-card:hover {
            border-color: #2a4a7a;
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        }

        .metric-icon {
            font-size: 20px;
            margin-bottom: 12px;
            display: block;
        }

        .metric-label {
            font-size: 11px;
            color: #4a6080;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 500;
            margin-bottom: 8px;
        }

        .metric-number {
            font-size: 32px;
            font-weight: 800;
            color: #fff;
            line-height: 1;
            margin-bottom: 6px;
        }

        .metric-number.green { color: #48bb78; }
        .metric-number.blue { color: #63b3ed; }
        .metric-number.orange { color: #ed8936; }
        .metric-number.red { color: #fc8181; }

        .metric-change {
            font-size: 11px;
            color: #4a6080;
        }

        .metric-badge {
            position: absolute;
            top: 15px; right: 15px;
            width: 35px; height: 35px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
        }

        .badge-green { background: rgba(72,187,120,0.1); }
        .badge-blue { background: rgba(99,179,237,0.1); }
        .badge-orange { background: rgba(237,137,54,0.1); }
        .badge-red { background: rgba(252,129,129,0.1); }

        /* Chart and table row */
        .content-row {
            display: grid;
            grid-template-columns: 1.5fr 1fr;
            gap: 15px;
            margin-bottom: 15px;
        }

        .panel {
            background: #0d1224;
            border: 1px solid #1e2d4a;
            border-radius: 12px;
            overflow: hidden;
        }

        .panel-header {
            padding: 16px 20px;
            border-bottom: 1px solid #1e2d4a;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .panel-title {
            font-size: 13px;
            font-weight: 600;
            color: #fff;
        }

        .panel-sub {
            font-size: 10px;
            color: #4a6080;
            margin-top: 2px;
        }

        .panel-badge {
            font-size: 10px;
            background: rgba(99,179,237,0.1);
            color: #63b3ed;
            padding: 3px 10px;
            border-radius: 10px;
            border: 1px solid rgba(99,179,237,0.2);
        }

        .chart-container {
            padding: 15px 20px 20px;
            height: 200px;
            position: relative;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th {
            padding: 10px 20px;
            text-align: left;
            font-size: 10px;
            color: #4a6080;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 600;
            border-bottom: 1px solid #1e2d4a;
            background: rgba(255,255,255,0.01);
        }

        td {
            padding: 11px 20px;
            font-size: 12px;
            color: #94a3b8;
            border-bottom: 1px solid #0b0f1a;
        }

        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(99,179,237,0.03); color: #e2e8f0; }

        .ip-text {
            font-family: 'Courier New', monospace;
            color: #63b3ed;
            font-size: 12px;
            font-weight: 600;
        }

        .count-text {
            color: #48bb78;
            font-weight: 600;
        }

        .status-active {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            background: rgba(252,129,129,0.1);
            border: 1px solid rgba(252,129,129,0.3);
            color: #fc8181;
            padding: 3px 10px;
            border-radius: 10px;
            font-size: 10px;
            font-weight: 600;
        }

        .status-permanent {
            background: rgba(128,0,0,0.2);
            border-color: rgba(200,0,0,0.4);
            color: #ff4444;
        }

        .empty-msg {
            text-align: center;
            color: #2a3a5a;
            padding: 30px;
            font-size: 12px;
        }

        .footer {
            text-align: right;
            font-size: 10px;
            color: #2a3a5a;
            margin-top: 15px;
            padding-right: 5px;
        }
    </style>
    <script>
        let rateChart;
        let rateData = new Array(30).fill(0);
        let labels = new Array(30).fill('');

        function initChart() {
            const ctx = document.getElementById('rateChart').getContext('2d');
            rateChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Request Rate (req/s)',
                        data: rateData,
                        borderColor: '#63b3ed',
                        backgroundColor: 'rgba(99,179,237,0.08)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                    }, {
                        label: 'Baseline Mean',
                        data: new Array(30).fill(0),
                        borderColor: '#48bb78',
                        backgroundColor: 'transparent',
                        borderWidth: 1.5,
                        borderDash: [5, 5],
                        fill: false,
                        tension: 0,
                        pointRadius: 0,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 300 },
                    plugins: {
                        legend: {
                            labels: {
                                color: '#4a6080',
                                font: { size: 10 },
                                boxWidth: 12,
                            }
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(255,255,255,0.03)' },
                            ticks: { color: '#2a3a5a', font: { size: 9 }, maxTicksLimit: 6 }
                        },
                        y: {
                            grid: { color: 'rgba(255,255,255,0.03)' },
                            ticks: { color: '#4a6080', font: { size: 10 } },
                            beginAtZero: true,
                        }
                    }
                }
            });
        }

        function refresh() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('global-rate').textContent =
                        data.global_rate.toFixed(2);
                    document.getElementById('baseline-mean').textContent =
                        data.baseline_mean.toFixed(2);
                    document.getElementById('baseline-std').textContent =
                        data.baseline_std.toFixed(2);
                    document.getElementById('uptime').textContent = data.uptime;
                    document.getElementById('cpu').textContent = data.cpu + '%';
                    document.getElementById('memory').textContent = data.memory + '%';
                    document.getElementById('banned-count').textContent = data.banned_count;

                    // Alert banner
                    const banner = document.getElementById('alert-banner');
                    if (data.banned_count > 0) {
                        banner.style.display = 'flex';
                        banner.innerHTML = '⚠️ <strong>THREAT DETECTED</strong> — ' +
                            data.banned_count + ' IP(s) currently blocked by iptables';
                    } else {
                        banner.style.display = 'none';
                    }

                    // Update chart
                    const now = new Date().toLocaleTimeString();
                    rateData.push(data.global_rate);
                    rateData.shift();
                    labels.push(now);
                    labels.shift();
                    rateChart.data.datasets[1].data = new Array(30).fill(data.baseline_mean);
                    rateChart.update('none');

                    // Top IPs
                    let ipHtml = '';
                    if (data.top_ips.length === 0) {
                        ipHtml = '<tr><td colspan="2" class="empty-msg">No traffic detected</td></tr>';
                    } else {
                        data.top_ips.forEach(([ip, count]) => {
                            ipHtml += '<tr><td class="ip-text">' + ip +
                                '</td><td class="count-text">' + count + '</td></tr>';
                        });
                    }
                    document.getElementById('top-ips-body').innerHTML = ipHtml;

                    // Banned IPs
                    let banHtml = '';
                    const bannedEntries = Object.entries(data.banned_ips);
                    if (bannedEntries.length === 0) {
                        banHtml = '<tr><td colspan="3" class="empty-msg">No threats detected</td></tr>';
                    } else {
                        bannedEntries.forEach(([ip, info]) => {
                            const cls = info.permanent ? 'status-active status-permanent' : 'status-active';
                            const label = info.permanent ? 'PERMANENT' : 'ACTIVE';
                            banHtml += '<tr><td class="ip-text">' + ip +
                                '</td><td>' + info.ban_count +
                                '</td><td><span class="' + cls + '">' + label + '</span></td></tr>';
                        });
                    }
                    document.getElementById('banned-body').innerHTML = banHtml;

                    document.getElementById('last-update').textContent =
                        'Last updated: ' + new Date().toLocaleTimeString();
                    document.getElementById('current-time').textContent =
                        new Date().toUTCString().slice(0, 25);
                })
                .catch(() => {});
        }

        window.onload = function() {
            initChart();
            refresh();
            setInterval(refresh, 3000);
        };
    </script>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="sidebar-logo">
            <span class="shield-big">🛡️</span>
            <div class="sidebar-logo-title">ShieldDaemon</div>
            <div class="sidebar-logo-sub">Detection Engine</div>
        </div>

        <div class="nav-section">Monitor</div>
        <div class="nav-item active">📊 Live Dashboard</div>
        <div class="nav-item">🚫 Blocked IPs</div>
        <div class="nav-item">📡 Traffic Analysis</div>

        <div class="nav-section">System</div>
        <div class="nav-item">⚙️ Configuration</div>
        <div class="nav-item">📋 Audit Log</div>
        <div class="nav-item">🔔 Alerts</div>

        <div class="status-indicator">
            <div class="status-dot"></div>
            <div>
                <div class="status-text">SYSTEM ACTIVE</div>
                <div class="status-sub">All systems operational</div>
            </div>
        </div>
    </div>

    <!-- Main -->
    <div class="main">
        <div class="topbar">
            <div>
                <div class="page-title">Anomaly Detection Dashboard</div>
                <div class="page-sub">Real-time traffic monitoring and threat detection</div>
            </div>
            <div class="topbar-right">
                <div class="refresh-badge">🔄 Auto-refresh: 3s</div>
                <div class="time-display" id="current-time">Loading...</div>
            </div>
        </div>

        <div class="alert-banner" id="alert-banner" style="display:none;"></div>

        <!-- Metric Cards -->
        <div class="metrics-row">
            <div class="metric-card">
                <div class="metric-badge badge-blue">📡</div>
                <div class="metric-label">Global Request Rate</div>
                <div class="metric-number blue" id="global-rate">0.00</div>
                <div class="metric-change">requests per second</div>
            </div>
            <div class="metric-card">
                <div class="metric-badge badge-green">📈</div>
                <div class="metric-label">Baseline Mean</div>
                <div class="metric-number green" id="baseline-mean">0.00</div>
                <div class="metric-change">30-min rolling average</div>
            </div>
            <div class="metric-card">
                <div class="metric-badge badge-orange">📉</div>
                <div class="metric-label">Std Deviation</div>
                <div class="metric-number orange" id="baseline-std">0.00</div>
                <div class="metric-change">statistical deviation</div>
            </div>
            <div class="metric-card">
                <div class="metric-badge badge-red">🚫</div>
                <div class="metric-label">Blocked IPs</div>
                <div class="metric-number red" id="banned-count">0</div>
                <div class="metric-change">active iptables rules</div>
            </div>
            <div class="metric-card">
                <div class="metric-badge badge-orange">💻</div>
                <div class="metric-label">CPU Usage</div>
                <div class="metric-number orange" id="cpu">0%</div>
                <div class="metric-change">processor load</div>
            </div>
            <div class="metric-card">
                <div class="metric-badge badge-blue">🧠</div>
                <div class="metric-label">Memory Usage</div>
                <div class="metric-number blue" id="memory">0%</div>
                <div class="metric-change">RAM utilization</div>
            </div>
            <div class="metric-card">
                <div class="metric-badge badge-green">⏱️</div>
                <div class="metric-label">System Uptime</div>
                <div class="metric-number green" id="uptime">00:00:00</div>
                <div class="metric-change">since daemon start</div>
            </div>
            <div class="metric-card">
                <div class="metric-badge badge-blue">🎯</div>
                <div class="metric-label">Z-Score Threshold</div>
                <div class="metric-number blue">2.0</div>
                <div class="metric-change">anomaly sensitivity</div>
            </div>
        </div>

        <!-- Chart + Banned IPs -->
        <div class="content-row">
            <div class="panel">
                <div class="panel-header">
                    <div>
                        <div class="panel-title">Traffic Rate Over Time</div>
                        <div class="panel-sub">Global request rate vs baseline</div>
                    </div>
                    <span class="panel-badge">Live</span>
                </div>
                <div class="chart-container">
                    <canvas id="rateChart"></canvas>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <div>
                        <div class="panel-title">🚫 Blocked IPs</div>
                        <div class="panel-sub">Active iptables DROP rules</div>
                    </div>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Bans</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody id="banned-body">
                        <tr><td colspan="3" class="empty-msg">No threats detected</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Top IPs -->
        <div class="panel">
            <div class="panel-header">
                <div>
                    <div class="panel-title">📡 Top 10 Source IPs</div>
                    <div class="panel-sub">Highest request volume in last 60 seconds</div>
                </div>
                <span class="panel-badge">60s window</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Requests</th>
                    </tr>
                </thead>
                <tbody id="top-ips-body">
                    <tr><td colspan="2" class="empty-msg">No traffic detected</td></tr>
                </tbody>
            </table>
        </div>

        <div class="footer" id="last-update">Initializing...</div>
    </div>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/stats")
def stats():
    uptime_seconds = int(time.time() - shared_state["start_time"])
    hours = uptime_seconds // 3600
    minutes = (uptime_seconds % 3600) // 60
    seconds = uptime_seconds % 60
    uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    return jsonify({
        "global_rate": shared_state["global_rate"],
        "baseline_mean": shared_state["baseline_mean"],
        "baseline_std": shared_state["baseline_std"],
        "top_ips": shared_state["top_ips"],
        "banned_ips": shared_state["banned_ips"],
        "banned_count": len(shared_state["banned_ips"]),
        "cpu": psutil.cpu_percent(interval=None),
        "memory": psutil.virtual_memory().percent,
        "uptime": uptime_str,
    })


def run_dashboard(port: int = 8080):
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
