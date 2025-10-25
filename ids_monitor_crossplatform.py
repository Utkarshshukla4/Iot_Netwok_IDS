import csv
import time
import os
import platform
from datetime import datetime
from scapy.all import ARP, Ether, srp
from colorama import Fore, Style, init
from prettytable import PrettyTable
import psutil
import ipaddress

# Initialize colorama
init(autoreset=True)

# ===== SETTINGS =====
SCAN_INTERVAL = 60  # seconds
BASELINE_FILE = "baseline.csv"
NETWORK_FILE = "network_devices.csv"
LOG_FILE = "ids_events.log"

# ===== HELPER FUNCTIONS =====

def get_network_interface():
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2 and not addr.address.startswith("127."):
                return interface
    return None

def get_ip_range():
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:
                ip = addr.address
                if ip.startswith(("127.", "169.")):
                    continue
                try:
                    network = ipaddress.ip_network(ip + '/24', strict=False)
                    return str(network)
                except ValueError:
                    continue
    return "192.168.1.0/24"

def log_event(message, color=None):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    msg = f"{timestamp} {message}"
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")
    color_dict = {"green": Fore.GREEN, "red": Fore.RED, "yellow": Fore.YELLOW}
    print(color_dict.get(color, "") + msg)

def scan_network(target_ip):
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether/arp, timeout=3, verbose=0)[0]
    return [{'ip': r.psrc, 'mac': r.hwsrc} for s, r in result]

def save_devices(filename, devices):
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "mac"])
        writer.writeheader()
        writer.writerows(devices)

def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return []
    with open(BASELINE_FILE, "r") as f:
        return list(csv.DictReader(f))

def compare_devices(baseline, new_devices):
    baseline_macs = {d['mac']: d['ip'] for d in baseline}
    new_macs = {d['mac']: d['ip'] for d in new_devices}
    alerts, results = [], []

    for device in new_devices:
        mac, ip = device['mac'], device['ip']
        if mac not in baseline_macs:
            alerts.append((ip, mac, "NEW DEVICE"))
            results.append((ip, mac, "NEW"))
        elif baseline_macs[mac] != ip:
            alerts.append((ip, mac, "ARP SPOOF DETECTED"))
            results.append((ip, mac, "SUSPICIOUS"))
        else:
            results.append((ip, mac, "KNOWN"))
    return alerts, results

# ===== DASHBOARD =====

def show_dashboard(results):
    os.system('cls' if os.name == 'nt' else 'clear')
    table = PrettyTable()
    table.field_names = ["IP Address", "MAC Address", "Status", "Timestamp"]

    for ip, mac, status in results:
        color = {"NEW": Fore.GREEN, "SUSPICIOUS": Fore.RED, "KNOWN": Fore.YELLOW}.get(status, "")
        table.add_row([color + ip + Style.RESET_ALL,
                       color + mac + Style.RESET_ALL,
                       color + status + Style.RESET_ALL,
                       datetime.now().strftime("%H:%M:%S")])
    print(Fore.CYAN + "=== Real-Time IoT Network IDS Dashboard ===")
    print(table)
    print(Fore.CYAN + f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(Fore.CYAN + "Press Ctrl+C to stop.")

# ===== MAIN =====

def main():
    interface = get_network_interface()
    network_range = get_ip_range()

    log_event(f"Starting IDS monitor on {network_range} [Interface: {interface}] (interval {SCAN_INTERVAL}s)", color="yellow")


    if not os.path.exists(BASELINE_FILE):
        devices = scan_network(network_range)
        save_devices(BASELINE_FILE, devices)
        log_event(f"✅ Baseline initialized with {len(devices)} current devices.", color="green")

    while True:
        devices = scan_network(network_range)
        save_devices(NETWORK_FILE, devices)
        baseline = load_baseline()
        alerts, results = compare_devices(baseline, devices)

        # Show dashboard
        show_dashboard(results)

        # Log alerts
        for ip, mac, alert_type in alerts:
            if alert_type == "NEW DEVICE":
                log_event(f"NEW DEVICE: IP={ip}, MAC={mac}", color="green")
            elif alert_type == "ARP SPOOF DETECTED":
                log_event(f"POSSIBLE ARP SPOOF: IP={ip}, MAC={mac}", color="red")

        if not alerts:
            log_event("No new devices detected.", color="yellow")


        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main()
