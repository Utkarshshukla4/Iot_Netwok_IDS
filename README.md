# Real-World IoT Network IDS

This project is a simple **Intrusion Detection System (IDS)** for local IoT or Wi-Fi networks.  
It scans connected devices, detects **new or suspicious ones**, and logs all activity.

## 🔍 What it does
- Scans your local network (Wi-Fi or LAN)
- Lists connected devices with IP and MAC address
- Detects:
  - New unknown devices joining
  - IP → MAC address changes (possible ARP spoofing)
- Logs all events to `ids_events.log`
- Saves connected devices in `network_devices.csv`
- Works on **Windows and Linux**
- Optional active blocking (Linux only using iptables)

## 🧠 How it helps
Acts like a **basic IoT network IDS** — it keeps watch for new or suspicious devices  
and helps you understand if someone’s trying to spoof or intrude on your network.

---

## ⚙️ Setup Steps

### 1. Clone or download
```bash
git clone https://github.com/<your-username>/IoT_Network_IDS.git
cd IoT_Network_IDS
2. Create virtual environment

Windows

python -m venv env
env\Scripts\activate


Linux

python3 -m venv env
source env/bin/activate

3. Install dependencies
pip install -r requirements.txt

4. Run the IDS monitor

Windows

python ids_monitor_crossplatform.py


Linux

sudo python3 ids_monitor_crossplatform.py


On Linux, running with sudo is needed for scanning and optional blocking.
On Windows, blocking is automatically disabled (scan & detect only).