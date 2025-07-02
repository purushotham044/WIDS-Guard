# WiFi Intrusion Detection & Auto Defense System (WIDS-Guard)
# Author: Purushotham T
# Purpose: For GitHub advanced cybersecurity + networking + Python portfolio
# Dependencies: scapy, flask, pandas, matplotlib, subprocess

from scapy.all import ARP, Ether, srp, sniff
from flask import Flask, render_template_string
import threading
import pandas as pd
import matplotlib.pyplot as plt
import subprocess
import os
from datetime import datetime

# ---------- Configuration ---------- #
SCAN_INTERVAL = 60  # seconds
INTERFACE = "wlan0"  # Change as per your interface
REPORT_FOLDER = "reports"
ALERT_MAC_LIST = []  # MAC addresses to watch
LOG_FILE = "wids_log.csv"
PORT = 5000

# ---------- Utility Functions ---------- #
def scan_network():
    target_ip = "192.168.1.0/24"  # Change as per your network
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

def log_event(event_type, message):
    time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{time_now},{event_type},{message}\n")

def monitor_devices():
    known_devices = set()
    while True:
        devices = scan_network()
        for device in devices:
            if device['mac'] not in known_devices:
                log_event("NEW_DEVICE", f"{device['ip']} - {device['mac']}")
                known_devices.add(device['mac'])
                if device['mac'] in ALERT_MAC_LIST:
                    log_event("ALERT", f"Watchlist device connected: {device['mac']}")
        threading.Event().wait(SCAN_INTERVAL)

def packet_callback(packet):
    if packet.haslayer(ARP):
        if packet[ARP].op == 2:  # ARP is at layer 2
            try:
                real_mac = subprocess.check_output(["arp", "-n", packet[ARP].psrc]).decode()
                if packet[ARP].hwsrc not in real_mac:
                    log_event("POTENTIAL_ARP_SPOOF", f"IP: {packet[ARP].psrc}, MAC: {packet[ARP].hwsrc}")
            except:
                pass

def sniff_packets():
    sniff(store=False, prn=packet_callback, iface=INTERFACE)

def generate_report():
    if not os.path.exists(REPORT_FOLDER):
        os.makedirs(REPORT_FOLDER)
    df = pd.read_csv(LOG_FILE, names=["Time", "Event", "Message"])
    plt.figure(figsize=(10, 6))
    df['Event'].value_counts().plot(kind='bar')
    plt.title('Event Distribution')
    plt.savefig(os.path.join(REPORT_FOLDER, 'event_distribution.png'))
    df.to_html(os.path.join(REPORT_FOLDER, 'log_report.html'))
    log_event("REPORT", "Report generated.")

# ---------- Flask Dashboard ---------- #
app = Flask(__name__)

dashboard_template = """
<!DOCTYPE html>
<html>
<head><title>WIDS-Guard Dashboard</title></head>
<body style="font-family: Arial;">
<h2>📡 WIDS-Guard Dashboard</h2>
<p><a href="/generate_report">Generate Report</a></p>
<p><a href="/view_log">View Log</a></p>
</body>
</html>
"""

@app.route('/')
def dashboard():
    return render_template_string(dashboard_template)

@app.route('/generate_report')
def report():
    generate_report()
    return "Report generated in 'reports/' folder. <a href='/'>Back</a>"

@app.route('/view_log')
def view_log():
    with open(LOG_FILE) as f:
        content = f.read().replace('\n', '<br>')
    return f"<h3>WIDS Log</h3><p>{content}</p><a href='/'>Back</a>"

# ---------- Main Execution ---------- #
if __name__ == '__main__':
    threading.Thread(target=monitor_devices, daemon=True).start()
    threading.Thread(target=sniff_packets, daemon=True).start()
    app.run(host='0.0.0.0', port=PORT)

# ---------- Instructions ---------- #
# 1️⃣ Install dependencies:
#     pip install scapy flask pandas matplotlib
# 2️⃣ Run with sudo/root:
#     sudo python wids_guard.py
# 3️⃣ Open browser:
#     http://localhost:5000
# 4️⃣ Monitor new devices, ARP spoof attempts, generate reports for analysis.

# This tool is for educational & lab use to enhance your cybersecurity, Python, and Linux practical skills.
