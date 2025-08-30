import json
import pandas as pd
from tabulate import tabulate

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# ---- Fingerprinting ----
def fingerprint_device(device):
    ttl = device.get("ttl")
    window_size = device.get("window_size")
    banner = device.get("banner", "").lower()
    open_ports = device.get("open_ports", [])

    # OS guessing
    os_guess = "Unknown"
    if ttl:
        if 120 <= ttl <= 130:
            os_guess = "Windows"
        elif 60 <= ttl <= 70:
            os_guess = "Linux"
        elif ttl >= 250:
            os_guess = "Network Device"
    if "windows" in banner:
        os_guess = "Windows"
    elif "linux" in banner or "ubuntu" in banner:
        os_guess = "Linux"
    elif "ios" in banner or "iphone" in banner or "android" in banner:
        os_guess = "Mobile"

    # Device type
    if os_guess == "Windows":
        device_type = "Windows PC"
    elif os_guess == "Linux":
        if 22 in open_ports or 3306 in open_ports:
            device_type = "Server"
        else:
            device_type = "Linux PC"
    elif os_guess == "Mobile":
        device_type = "Mobile"
    elif os_guess == "Network Device":
        device_type = "Router/IoT"
    else:
        device_type = "Unknown"

    # Role assignment
    if device_type == "Windows PC":
        role = "Work Laptop"
    elif device_type == "Linux PC":
        role = "Workstation"
    elif device_type == "Server":
        role = "Server"
    elif device_type == "Mobile":
        role = "Mobile Device"
    elif device_type == "Router/IoT":
        role = "IoT Device"
    else:
        role = "Unknown"

    # Criticality scoring
    public = device.get("public", False)
    if device_type == "Server" and public:
        criticality = 5
    elif device_type == "Server":
        criticality = 4
    elif device_type == "Windows PC":
        criticality = 3
    elif device_type == "Mobile":
        criticality = 2
    else:
        criticality = 1

    return os_guess, device_type, role, criticality

# ---- Load JSON ----
def load_devices_from_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

# ---- Scan local network ----
def scan_local_network():
    if not NMAP_AVAILABLE:
        print("python-nmap not installed. Cannot scan network.")
        return []

    nm = nmap.PortScanner()
    network_range = input("Enter network range (e.g., 192.168.1.0/24): ").strip()
    print("Scanning network, this may take a few minutes...")
    nm.scan(hosts=network_range, arguments='-O')  # OS detection

    devices = []
    for host in nm.all_hosts():
        os_guess = nm[host]['osmatch'][0]['name'] if nm[host].get('osmatch') else 'Unknown'
        open_ports = [int(p) for p in nm[host]['tcp'].keys()] if 'tcp' in nm[host] else []
        devices.append({
            "ip": host,
            "ttl": None,
            "window_size": None,
            "banner": os_guess,
            "open_ports": open_ports,
            "public": False
        })
    return devices

# ---- Main ----
def main():
    print("Network Device Classification Tool")
    print("Choose a mode:")
    print("1. Scan your local network (requires python-nmap)")
    print("2. Use simulated network data (JSON file)")

    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":
        devices = scan_local_network()
    elif choice == "2":
        file_path = input("Enter JSON file path: ").strip()
        devices = load_devices_from_json(file_path)
    else:
        print("Invalid choice.")
        return

    if not devices:
        print("No devices found. Exiting.")
        return

    # Classify devices
    table = []
    for device in devices:
        os_guess, device_type, role, criticality = fingerprint_device(device)
        table.append({
            "IP": device.get("ip", "Unknown"),
            "OS": os_guess,
            "Device Type": device_type,
            "Role": role,
            "Criticality Score": criticality
        })

    df = pd.DataFrame(table)
    print("\nClassified Devices:")
    print(tabulate(df, headers="keys", tablefmt="grid"))
    df.to_csv("network_classification.csv", index=False)
    print("\nSaved results to network_classification.csv")

if __name__ == "__main__":
    main()

