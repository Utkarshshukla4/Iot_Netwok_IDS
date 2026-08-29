# Real-World IoT Network IDS

## About the Project

Real-World IoT Network IDS is a Python-based Intrusion Detection System designed to monitor local Wi-Fi and LAN networks.

The system scans connected devices, identifies new or unknown devices, detects IP-to-MAC address changes, and records network activity for further analysis.

It is designed as a simple network security tool for understanding device monitoring, suspicious activity detection, and basic intrusion detection.

---

## Main Features

* Scans local Wi-Fi and LAN networks
* Detects connected devices
* Displays IP and MAC addresses
* Detects new or unknown devices
* Detects IP-to-MAC address changes
* Helps identify possible ARP spoofing activity
* Logs security events
* Saves discovered devices in CSV format
* Supports Windows and Linux
* Optional IP blocking on Linux using `iptables`

---

## Technologies Used

* **Python** – Core development
* **Network Scanning** – Device discovery
* **IP/MAC Analysis** – Device tracking
* **CSV** – Device data storage
* **Logging** – Event recording
* **iptables** – Linux IP blocking

---

## Project Structure

```text id="4f8m0j"
IoT_Network_IDS/
│
├── ids_monitor_crossplatform.py
├── requirements.txt
├── README.md
├── ids_events.log
└── network_devices.csv
```

---

## How It Works

```text id="l3k6q4"
Local Network
      ↓
Network Scan
      ↓
Discover Devices
      ↓
Compare with Previous Scan
      ↓
Detect New / Suspicious Devices
      ↓
Log Security Event
      ↓
Optional IP Blocking
```

The IDS regularly scans the local network and compares the discovered devices with previously recorded information.

When a new device appears or an existing IP address is associated with a different MAC address, the system generates a security event.

---

## Detection

The system monitors for:

```text id="c1dqcw"
New Device
    ↓
Unknown IP / MAC Detected
    ↓
Security Event Logged

IP → MAC Change
    ↓
Possible ARP Spoofing
    ↓
Security Event Logged
```

These checks provide a basic way to identify unexpected devices and possible network manipulation.

---

## Installation

### 1. Clone the Repository

```bash id="k9t4je"
git clone https://github.com/<your-username>/IoT_Network_IDS.git
cd IoT_Network_IDS
```

### 2. Create Virtual Environment

Windows:

```bash id="i4m0af"
python -m venv env
env\Scripts\activate
```

Linux:

```bash id="5j2x9x"
python3 -m venv env
source env/bin/activate
```

### 3. Install Dependencies

```bash id="f7q8re"
pip install -r requirements.txt
```

---

## Run the IDS

### Windows

```bash id="r6x8am"
python ids_monitor_crossplatform.py
```

Windows supports network scanning and detection. Active IP blocking is disabled.

### Linux

```bash id="q8s0xk"
sudo python3 ids_monitor_crossplatform.py
```

Linux may require `sudo` for network scanning and optional IP blocking using `iptables`.

---

## Output Files

The IDS generates two main files:

```text id="y4x9cz"
ids_events.log
→ Stores detected network and security events.

network_devices.csv
→ Stores discovered device information such as IP and MAC addresses.
```

---

## Security Note

This project is intended for monitoring networks that you own or have permission to test.

The IDS provides basic network monitoring and detection capabilities and should not be considered a replacement for a production-grade IDS such as enterprise network security solutions.

---

## Future Improvements

* Add a real-time monitoring dashboard
* Improve ARP spoofing detection
* Add device reputation checking
* Add email or notification alerts
* Support additional network protocols
* Improve automated response capabilities

---

## Author

**Utkarsh Shukla**

Cybersecurity Project | Python | Network Security | Intrusion Detection
