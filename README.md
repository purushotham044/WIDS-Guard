# WIDS-Guard

**WIDS-Guard** is a simple WiFi Intrusion Detection System built using Python. It can scan your WiFi network, detect ARP spoofing, and show connected devices on a local dashboard. This project is meant for practicing Python, networking, and basic cybersecurity monitoring.

---

## Features

- Scans your WiFi network for connected devices using ARP.
- Detects ARP spoofing attempts.
- Saves logs of all activities.
- Generates a simple report with graphs.
- Runs a Flask web server for local monitoring.

---

## Installation

1️⃣ Clone the repository:
```bash
git clone https://github.com/purushotham044/WIDS-Guard.git
cd WIDS-Guard
2️⃣ Install the required dependencies:

pip install scapy flask pandas matplotlib
Usage
On Linux
Check your WiFi interface:

ip a
and update the script:

INTERFACE = "wlan0"
if needed.

Run the script:

sudo python3 wids_guard.py
Open your browser and go to:

http://localhost:5000
On Windows
You can use ARP scanning and reports on Windows, but sniffing requires Npcap.

Update the interface in the script:

INTERFACE = "Wi-Fi"
or:

INTERFACE = None
Run:

python wids_guard.py
Report Generation
After scanning, you can generate a report by visiting:

http://localhost:5000/generate_report
Reports will be saved in the reports/ folder with:

A .png chart showing event distribution.

A .html log report of the session.

Example Output
[+] Scanning local network for connected devices...
[+] Monitoring ARP spoofing attempts...
[+] Detected device: 192.168.1.10 (Vendor: Unknown)
[+] No ARP spoofing detected.
Contributing
Feel free to open issues or submit pull requests if you would like to improve this project.

License
This project is licensed under the MIT License.

Acknowledgments
Scapy for packet crafting and sniffing.

Flask for the dashboard.

Matplotlib for generating graphs.

About
I am Purushotham T, currently studying B.E CSE (Cybersecurity) and learning Python and networking through practical projects like this one.

If you find this project helpful for learning or your personal labs, feel free to star ⭐ the repository.
